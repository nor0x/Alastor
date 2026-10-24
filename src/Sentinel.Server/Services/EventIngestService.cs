using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Events;
using Sentinel.Server.Data;

namespace Sentinel.Server.Services;

/// <summary>
/// The entry point of the alert pipeline: normalized events go in, are stored idempotently (by agent-assigned
/// id), and are broadcast. Deliverable 4 adds leaky-bucket dedup and channel routing behind <see cref="IEventSink"/>.
/// </summary>
public sealed class EventIngestService(SentinelDbContext db, DashboardNotifier notifier, IEnumerable<IEventSink> sinks, TimeProvider time)
{
    private const int MaxRawLength = 8_000;
    private const int MaxMessageLength = 1_000;

    public async Task<(int Accepted, int Duplicates)> IngestAsync(Guid? hostId, IReadOnlyList<SecurityEvent> events, CancellationToken ct)
    {
        if (events.Count == 0) return (0, 0);
        var ids = events.Select(e => e.Id).Distinct().ToList();
        var existing = (await db.Events.Where(e => ids.Contains(e.Id)).Select(e => e.Id).ToListAsync(ct)).ToHashSet();
        var now = time.GetUtcNow().UtcDateTime;

        var fresh = events.DistinctBy(e => e.Id).Where(e => !existing.Contains(e.Id)).Select(e => new StoredEvent
        {
            Id = e.Id,
            HostId = hostId,
            OccurredAt = e.OccurredAt.Kind == DateTimeKind.Utc ? e.OccurredAt : e.OccurredAt.ToUniversalTime(),
            ReceivedAt = now,
            Capability = e.Capability,
            Severity = e.Severity,
            SourceTool = Clip(e.SourceTool, 64),
            Kind = Clip(e.Kind, 64),
            Subject = e.Subject is null ? null : Clip(e.Subject, 256),
            Message = Clip(e.Message, MaxMessageLength),
            Raw = e.Raw is null ? null : Clip(e.Raw, MaxRawLength),
            Metadata = e.Metadata.Take(32).ToDictionary(kv => Clip(kv.Key, 64), kv => Clip(kv.Value, 512)),
            DedupKey = Clip(e.EffectiveDedupKey, 256),
        }).ToList();

        if (fresh.Count > 0)
        {
            db.Events.AddRange(fresh);
            await db.SaveChangesAsync(ct);
            foreach (var sink in sinks) await sink.OnEventsStoredAsync(fresh, ct);
            await notifier.EventsCreatedAsync(fresh.Select(Dto.Event).ToList(), ct);
        }
        return (fresh.Count, events.Count - fresh.Count);
    }

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max];
}

/// <summary>Extension point for the alert pipeline (dedup, routing, notification channels, digests).</summary>
public interface IEventSink
{
    Task OnEventsStoredAsync(IReadOnlyList<StoredEvent> events, CancellationToken ct);
}
