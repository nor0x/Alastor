using System.Threading.Channels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Alastor.Core.Events;
using Alastor.Server.Data;

namespace Alastor.Server.Services.Alerts;

/// <summary>Encrypts and decrypts channel configs. Secrets are only ever decrypted in memory, right before sending.</summary>
public sealed class ChannelSecrets(IDataProtectionProvider provider)
{
    private readonly IDataProtector _protector = provider.CreateProtector("alastor.notification-channels.v1");

    public string Protect(ChannelConfig config) => _protector.Protect(config.ToJson());
    public ChannelConfig Unprotect(string protectedJson) => ChannelConfig.FromJson(_protector.Unprotect(protectedJson));
}

/// <summary>Alerts admitted by dedup, waiting for delivery. Delivery runs off the request path, so a slow SMTP server never delays an agent.</summary>
public sealed class AlertQueue
{
    private readonly Channel<IReadOnlyList<AlertItem>> _channel = Channel.CreateBounded<IReadOnlyList<AlertItem>>(
        new BoundedChannelOptions(1000) { FullMode = BoundedChannelFullMode.DropOldest });

    public void Enqueue(IReadOnlyList<AlertItem> items) => _channel.Writer.TryWrite(items);
    public ChannelReader<IReadOnlyList<AlertItem>> Reader => _channel.Reader;
}

/// <summary>
/// The alert stage of the event pipeline: runs after events are stored, applies leaky-bucket dedup
/// (see <see cref="AlertBucketMath"/>), marks each event notified or suppressed, and queues the rest for delivery.
/// </summary>
public sealed class AlertPipeline(AlastorDbContext db, AlertQueue queue, IOptions<AlastorOptions> options, TimeProvider time) : IEventSink
{
    public async Task OnEventsStoredAsync(IReadOnlyList<StoredEvent> events, CancellationToken ct)
    {
        var channels = await db.NotificationChannels.AsNoTracking().Where(c => c.Enabled && c.Immediate).Select(c => c.MinSeverity).ToListAsync(ct);
        if (channels.Count == 0) return;
        var threshold = channels.Min();
        var candidates = events.Where(e => e.Severity >= threshold).OrderBy(e => e.OccurredAt).ToList();
        if (candidates.Count == 0) return;

        var now = time.GetUtcNow().UtcDateTime;
        var window = options.Value.AlertDedupWindowValue;
        var hostIds = candidates.Where(e => e.HostId is not null).Select(e => e.HostId!.Value).Distinct().ToList();
        var names = await db.Hosts.Where(h => hostIds.Contains(h.Id)).ToDictionaryAsync(h => h.Id, h => h.Name, ct);
        var keys = candidates.Select(e => AlertBucketMath.Key(e.HostId, e.DedupKey)).Distinct().ToList();
        var buckets = await db.AlertBuckets.Where(b => keys.Contains(b.Key)).ToDictionaryAsync(b => b.Key, ct);

        var admitted = new List<AlertItem>();
        foreach (var e in candidates)
        {
            var key = AlertBucketMath.Key(e.HostId, e.DedupKey);
            if (!buckets.TryGetValue(key, out var bucket)) db.AlertBuckets.Add(buckets[key] = bucket = new AlertBucket { Key = key });
            if (AlertBucketMath.Admit(bucket, e.Severity, now, window, options.Value.AlertBurst))
            {
                admitted.Add(new AlertItem(e.Id, e.HostId, e.HostId is { } h ? names.GetValueOrDefault(h, "unknown host") : "server", e.OccurredAt,
                    e.Severity, e.Capability, e.SourceTool, e.Kind, e.Subject, e.Message, bucket.Suppressed));
                bucket.Suppressed = 0;
                e.Alert = AlertDisposition.Notified;
            }
            else e.Alert = AlertDisposition.Suppressed;
            db.Entry(e).Property(x => x.Alert).IsModified = true;
        }
        await db.SaveChangesAsync(ct);
        if (admitted.Count > 0) queue.Enqueue(admitted);
    }
}

/// <summary>Sends queued alerts and scheduled digests to every matching channel, with retries and a delivery log.</summary>
public sealed class NotificationDispatcher(
    IServiceScopeFactory scopes,
    AlertQueue queue,
    IEnumerable<IChannelSender> senders,
    ChannelSecrets secrets,
    IOptions<AlastorOptions> options,
    TimeProvider time,
    ILogger<NotificationDispatcher> logger) : BackgroundService
{
    private static readonly TimeSpan[] RetryDelays = [TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15)];
    private readonly Dictionary<string, IChannelSender> _senders = senders.ToDictionary(s => s.Type);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var digests = Task.Run(() => DigestLoopAsync(ct), ct);
        await foreach (var batch in queue.Reader.ReadAllAsync(ct))
        {
            try { await DeliverAlertsAsync(batch, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogError(ex, "Alert delivery failed"); }
        }
        await digests;
    }

    public async Task DeliverAlertsAsync(IReadOnlyList<AlertItem> items, CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AlastorDbContext>();
        var channels = await db.NotificationChannels.Where(c => c.Enabled && c.Immediate).ToListAsync(ct);
        await Task.WhenAll(channels.Select(async c =>
        {
            var mine = items.Where(i => Matches(c, i.Severity, i.Capability)).ToList();
            if (mine.Count > 0) await SendAsync(c, AlertMessage.ForAlerts(mine, BaseUrl), retry: true, ct);
        }));
        await TrimDeliveryLogAsync(db, ct);
    }

    private async Task DigestLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1), time);
        while (await timer.WaitForNextTickAsync(ct))
        {
            try { await RunDueDigestsAsync(ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogError(ex, "Digest run failed"); }
        }
    }

    public async Task RunDueDigestsAsync(CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AlastorDbContext>();
        var now = time.GetUtcNow().UtcDateTime;
        foreach (var c in await db.NotificationChannels.Where(c => c.Enabled).ToListAsync(ct))
        {
            if (!DigestSchedule.IsDue(c, now, TimeZoneInfo.Local)) continue;
            var since = c.LastDigestAt ?? c.CreatedAt;
            var query = db.Events.AsNoTracking().Where(e => e.OccurredAt >= since && e.OccurredAt < now && e.Severity >= c.MinSeverity);
            var events = await query.OrderByDescending(e => e.Severity).ThenByDescending(e => e.OccurredAt).Take(2000).ToListAsync(ct);
            events = events.Where(e => Matches(c, e.Severity, e.Capability)).ToList();
            var names = await db.Hosts.AsNoTracking().ToDictionaryAsync(h => h.Id, h => h.Name, ct);
            var items = events.Select(e => new AlertItem(e.Id, e.HostId, e.HostId is { } h ? names.GetValueOrDefault(h, "unknown host") : "server",
                e.OccurredAt, e.Severity, e.Capability, e.SourceTool, e.Kind, e.Subject, e.Message, 0)).ToList();
            await SendAsync(c, AlertMessage.ForDigest(items, items.Count, since, now, BaseUrl), retry: true, ct);
            // Advance even after a failed send (the error is on the channel), so a broken channel isn't retried every minute.
            c.LastDigestAt = now;
            await db.SaveChangesAsync(ct);
        }
    }

    /// <summary>Sends one message to one channel and records the outcome on the channel and in the delivery log. Returns the error, if any.</summary>
    public async Task<string?> SendAsync(NotificationChannel channel, AlertMessage message, bool retry, CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AlastorDbContext>();
        string? error = null;
        var attempts = 0;
        if (!_senders.TryGetValue(channel.Type, out var sender)) error = $"Unknown channel type '{channel.Type}'.";
        else
        {
            var config = secrets.Unprotect(channel.ConfigProtected);
            while (true)
            {
                attempts++;
                try
                {
                    await sender.SendAsync(config, message, ct);
                    error = null;
                    break;
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
                {
                    error = ex is TaskCanceledException ? "Timed out" : ex.Message;
                    if (!retry || attempts > RetryDelays.Length) break;
                    await Task.Delay(RetryDelays[attempts - 1], time, ct);
                }
            }
        }
        var now = time.GetUtcNow().UtcDateTime;
        await db.NotificationChannels.Where(c => c.Id == channel.Id).ExecuteUpdateAsync(s => s
            .SetProperty(c => c.LastAttemptAt, now)
            .SetProperty(c => c.LastError, error)
            .SetProperty(c => c.LastSuccessAt, c => error == null ? now : c.LastSuccessAt), ct);
        db.NotificationDeliveries.Add(new NotificationDelivery
        {
            ChannelId = channel.Id, At = now, Kind = message.Kind, Title = message.Title.Length > 300 ? message.Title[..300] : message.Title,
            EventCount = message.Items.Count, Success = error is null, Attempts = attempts, Error = error is { Length: > 1000 } ? error[..1000] : error,
        });
        await db.SaveChangesAsync(ct);
        if (error is not null) logger.LogWarning("Notification to {Channel} ({Type}) failed after {Attempts} attempt(s): {Error}", channel.Name, channel.Type, attempts, error);
        return error;
    }

    public static bool Matches(NotificationChannel c, Severity severity, Capability capability) =>
        severity >= c.MinSeverity && (c.Capabilities.Count == 0 || c.Capabilities.Contains(capability.ToString()));

    private string? BaseUrl => options.Value.PublicUrl?.TrimEnd('/');

    private static async Task TrimDeliveryLogAsync(AlastorDbContext db, CancellationToken ct)
    {
        // Keep the newest 1000 deliveries; the log is for "did my alert go out?", not an archive.
        var cutoff = await db.NotificationDeliveries.OrderByDescending(d => d.Id).Skip(1000).Select(d => (long?)d.Id).FirstOrDefaultAsync(ct);
        if (cutoff is { } id) await db.NotificationDeliveries.Where(d => d.Id <= id).ExecuteDeleteAsync(ct);
    }
}
