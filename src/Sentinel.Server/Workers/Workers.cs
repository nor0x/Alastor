using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sentinel.Core.Events;
using Sentinel.Server.Data;
using Sentinel.Server.Services;
using Sentinel.Server.Services.ThreatFeed;

namespace Sentinel.Server.Workers;

/// <summary>Marks hosts offline after missed heartbeats (with an alert event) and re-queues commands an agent never acknowledged.</summary>
public sealed class PresenceWorker(IServiceScopeFactory scopes, IOptions<SentinelOptions> options, TimeProvider time, ILogger<PresenceWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(options.Value.PresenceCheckIntervalValue, time);
        do
        {
            try { await TickAsync(ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogError(ex, "Presence check failed"); }
        } while (await timer.WaitForNextTickAsync(ct));
    }

    public async Task TickAsync(CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        var ingest = scope.ServiceProvider.GetRequiredService<EventIngestService>();
        var notifier = scope.ServiceProvider.GetRequiredService<DashboardNotifier>();
        var now = time.GetUtcNow().UtcDateTime;
        var opt = options.Value;

        // Each host is judged against its own heartbeat interval: a host on a 10-minute heartbeat isn't "offline" after 3 minutes.
        var online = await db.Hosts.Where(h => h.IsOnline).ToListAsync(ct);
        var stale = online.Where(h => h.LastSeenAt < now - opt.OfflineAfter(TimeSpan.FromSeconds(h.HeartbeatIntervalSeconds))).ToList();
        foreach (var host in stale)
        {
            host.IsOnline = false;
            await db.SaveChangesAsync(ct);
            await ingest.IngestAsync(host.Id,
            [
                new SecurityEvent
                {
                    Id = Guid.NewGuid(),
                    OccurredAt = now,
                    Capability = Capability.Agent,
                    Severity = Severity.High,
                    SourceTool = "sentinel-server",
                    Kind = EventKinds.HostOffline,
                    Subject = host.Name,
                    Message = $"{host.Name} stopped sending heartbeats (last seen {host.LastSeenAt:u})",
                    DedupKey = $"host.offline:{host.Id}",
                },
            ], ct);
            await notifier.HostUpdatedAsync(new { host.Id, host.IsOnline }, ct);
        }

        // Commands delivered but not acknowledged go back to pending (CommandRedeliverAfter), up to CommandMaxAttempts.
        var redeliverBefore = now - opt.CommandRedeliverAfterValue;
        var maxAttempts = opt.CommandMaxAttempts;
        await db.Commands
            .Where(c => c.Status == CommandStatus.Delivered && c.DeliveredAt < redeliverBefore && c.Attempts < maxAttempts)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.Status, CommandStatus.Pending), ct);
        await db.Commands
            .Where(c => c.Status == CommandStatus.Delivered && c.DeliveredAt < redeliverBefore && c.Attempts >= maxAttempts)
            .ExecuteUpdateAsync(s => s
                .SetProperty(c => c.Status, CommandStatus.Expired)
                .SetProperty(c => c.CompletedAt, now)
                .SetProperty(c => c.ResultMessage, "Agent never acknowledged the command"), ct);
        // Commands for hosts that stay offline expire (PendingCommandTtl), so a returning host doesn't replay stale bans.
        var expireBefore = now - opt.PendingCommandTtlValue;
        await db.Commands
            .Where(c => c.Status == CommandStatus.Pending && c.CreatedAt < expireBefore)
            .ExecuteUpdateAsync(s => s
                .SetProperty(c => c.Status, CommandStatus.Expired)
                .SetProperty(c => c.CompletedAt, now)
                .SetProperty(c => c.ResultMessage, "Expired before the agent picked it up"), ct);
    }
}

/// <summary>Prunes metric samples, old events, expired bans and old threat-feed items, using EF Core bulk deletes.</summary>
public sealed class RetentionWorker(IServiceScopeFactory scopes, IOptions<SentinelOptions> options, TimeProvider time, ILogger<RetentionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(options.Value.RetentionRunIntervalValue, time);
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
                var now = time.GetUtcNow().UtcDateTime;
                var metricsBefore = now - options.Value.MetricRetentionValue;
                var eventsBefore = now - options.Value.EventRetentionValue;
                var m = await db.MetricSamples.Where(s => s.At < metricsBefore).ExecuteDeleteAsync(ct);
                var e = await db.Events.Where(x => x.OccurredAt < eventsBefore).ExecuteDeleteAsync(ct);
                var b = await db.Bans.Where(x => x.ExpiresAt != null && x.ExpiresAt < now).ExecuteDeleteAsync(ct);
                var c = await db.Commands.Where(x => x.CompletedAt != null && x.CompletedAt < eventsBefore).ExecuteDeleteAsync(ct);
                var feedBefore = now - options.Value.ThreatFeedRetentionValue;
                var f = await db.FeedItems.Where(x => x.PublishedAt < feedBefore).ExecuteDeleteAsync(ct);
                // Drained dedup buckets carry no information once the window has long passed.
                var bucketsBefore = now - options.Value.AlertDedupWindowValue * 4 - TimeSpan.FromDays(1);
                await db.AlertBuckets.Where(x => x.UpdatedAt < bucketsBefore && x.Suppressed == 0).ExecuteDeleteAsync(ct);
                if (m + e + b + c + f > 0)
                    logger.LogInformation("Retention: removed {Metrics} samples, {Events} events, {Bans} expired bans, {Commands} commands, {FeedItems} feed items", m, e, b, c, f);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogError(ex, "Retention run failed"); }
        } while (await timer.WaitForNextTickAsync(ct));
    }
}

/// <summary>
/// Drives <see cref="ThreatFeedService"/>: checks every minute which feed sources are due (each keeps its own
/// interval and backoff), starting right after startup. Runs off the request path, so a slow or failing source
/// never delays the dashboard.
/// </summary>
public sealed class ThreatFeedWorker(IServiceScopeFactory scopes, TimeProvider time, ILogger<ThreatFeedWorker> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(1);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.Yield(); // never hold up host startup
        using var timer = new PeriodicTimer(CheckInterval, time);
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<ThreatFeedService>().RunDueAsync(ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogError(ex, "Threat feed run failed"); }
        } while (await timer.WaitForNextTickAsync(ct));
    }
}

/// <summary>Checks every 5 minutes which blocklists in use are due (<see cref="SentinelOptions.BlocklistRefreshInterval"/>, with backoff on failure).</summary>
public sealed class BlocklistWorker(IServiceScopeFactory scopes, TimeProvider time, ILogger<BlocklistWorker> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.Yield();
        using var timer = new PeriodicTimer(CheckInterval, time);
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<Sentinel.Server.Services.Blocklists.BlocklistService>().RunDueAsync(ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogError(ex, "Blocklist run failed"); }
        } while (await timer.WaitForNextTickAsync(ct));
    }
}

/// <summary>Keeps the scanner databases agents use up to date, and fetches one right away when an agent first asks for it.</summary>
public sealed class VulnDbWorker(Sentinel.Server.Services.Vulnerabilities.VulnDbMirror mirror, ILogger<VulnDbWorker> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(15);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.Yield();
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await mirror.RunDueAsync(ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogError(ex, "Vulnerability database refresh failed"); }

            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
            wait.CancelAfter(CheckInterval);
            try
            {
                var scanner = await mirror.Requests.ReadAsync(wait.Token);
                if (mirror.State(scanner).Etag is null) await mirror.RefreshAsync(scanner, ct);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        }
    }
}
