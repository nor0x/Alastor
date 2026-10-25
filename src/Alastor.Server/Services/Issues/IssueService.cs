using Microsoft.EntityFrameworkCore;
using Alastor.Core.Baseline;
using Alastor.Core.Events;
using Alastor.Server.Data;

namespace Alastor.Server.Services.Issues;

/// <summary>
/// Keeps <see cref="HostIssue"/> rows in step with <see cref="IssueRules"/>: opens new conditions, touches ones that
/// persist, resolves ones that cleared and reopens ones that came back. Opening and resolving are logged as Info events,
/// so they show on the timeline without a second notification for a condition that already alerted.
/// </summary>
public sealed class IssueService(AlastorDbContext db, EventIngestService ingest, DashboardNotifier notifier, TimeProvider time)
{
    public const string OpenedKind = "issue.opened";
    public const string ResolvedKind = "issue.resolved";

    public Task ReconcileAsync(Guid hostId, CancellationToken ct) => ReconcileAsync([hostId], ct);

    /// <summary>Re-evaluates the given hosts (every host when null). Returns whether any issue opened or resolved.</summary>
    public async Task<bool> ReconcileAsync(IReadOnlyCollection<Guid>? hostIds, CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var query = db.Hosts.AsNoTracking().Include(h => h.Tools).AsQueryable();
        if (hostIds is not null) query = query.Where(h => hostIds.Contains(h.Id));
        var hosts = await query.ToListAsync(ct);
        if (hosts.Count == 0) return false;
        var ids = hosts.Select(h => h.Id).ToList();

        var kev = (await db.Vulnerabilities.AsNoTracking()
                .Where(v => ids.Contains(v.HostId) && !v.Accepted && db.KevEntries.Any(k => k.CveId == v.VulnId))
                .Select(v => new { v.HostId, v.VulnId }).Distinct().ToListAsync(ct))
            .ToLookup(x => x.HostId, x => x.VulnId);
        var failing = (await db.BaselineChecks.AsNoTracking()
                .Where(c => ids.Contains(c.HostId) && c.Status == CheckStatus.Fail && !c.Accepted)
                .Select(c => new { c.HostId, c.CheckId }).ToListAsync(ct))
            .ToLookup(x => x.HostId, x => x.CheckId);
        var stored = (await db.Issues.Where(i => ids.Contains(i.HostId)).ToListAsync(ct)).ToLookup(i => i.HostId);

        var events = new List<(Guid HostId, SecurityEvent Event)>();
        foreach (var h in hosts)
        {
            var open = IssueRules.Evaluate(h, new IssueRules.Facts(kev[h.Id].ToList(), failing[h.Id].ToList()))
                .DistinctBy(c => (c.Rule, c.Subject)).ToDictionary(c => (c.Rule, c.Subject));
            var rows = stored[h.Id].ToDictionary(i => (i.Rule, i.Subject));

            foreach (var (key, c) in open)
            {
                if (!rows.TryGetValue(key, out var row))
                {
                    row = new HostIssue { HostId = h.Id, Rule = c.Rule, Subject = c.Subject, Title = c.Title, FirstSeenAt = now };
                    db.Issues.Add(row);
                    events.Add((h.Id, Event(h, row, c, OpenedKind, now)));
                }
                else if (row.ResolvedAt is not null)
                {
                    // The condition came back: a fresh occurrence, not acknowledged yet.
                    row.ResolvedAt = null;
                    row.FirstSeenAt = now;
                    row.Occurrences++;
                    row.AcknowledgedAt = null;
                    row.AcknowledgedBy = null;
                    row.AckNote = null;
                    events.Add((h.Id, Event(h, row, c, OpenedKind, now)));
                }
                row.Severity = c.Severity;
                row.Title = Clip(c.Title, 256);
                row.Detail = c.Detail is null ? null : Clip(c.Detail, 1024);
                row.Tab = c.Tab;
                row.LastSeenAt = now;
            }
            foreach (var row in rows.Values.Where(r => r.ResolvedAt is null && !open.ContainsKey((r.Rule, r.Subject))))
            {
                row.ResolvedAt = now;
                events.Add((h.Id, Event(h, row, null, ResolvedKind, now)));
            }
        }
        await db.SaveChangesAsync(ct);

        foreach (var g in events.GroupBy(e => e.HostId))
            await ingest.IngestAsync(g.Key, g.Select(e => e.Event).ToList(), ct);
        if (events.Count > 0) await notifier.IssuesChangedAsync(ct);
        return events.Count > 0;
    }

    private static SecurityEvent Event(ManagedHost h, HostIssue row, IssueRules.Condition? c, string kind, DateTime now) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = now,
        Capability = Capability.Agent,
        Severity = Severity.Info,
        SourceTool = "alastor-server",
        Kind = kind,
        Subject = row.Subject.Length > 0 ? row.Subject : row.Rule,
        Message = kind == OpenedKind ? $"{h.Name}: {c!.Title}" : $"{h.Name}: resolved: {row.Title}",
        Metadata = new Dictionary<string, string> { ["rule"] = row.Rule, ["severity"] = (c?.Severity ?? row.Severity).ToString() },
        DedupKey = $"{kind}:{row.Rule}:{row.Subject}",
    };

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max];
}
