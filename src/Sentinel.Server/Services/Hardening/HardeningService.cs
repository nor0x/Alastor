using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Contracts;
using Sentinel.Core.Hardening;
using Sentinel.Core.Policy;
using Sentinel.Server.Data;

namespace Sentinel.Server.Services.Hardening;

/// <summary>
/// Stores Lynis audit results per host. Like CVEs, accepted items (<c>hardening.ignore</c>, by test id) are applied here,
/// so accepting a suggestion in the dashboard takes effect without a new audit. The server also works out which test ids
/// the previous audit reported and this one didn't, so the checklist can show what a change fixed.
/// </summary>
public sealed class HardeningService(SentinelDbContext db, PolicyService policies, TimeProvider time)
{
    public const string ReportKind = "hardening";

    /// <summary>More than Lynis ever reports (a busy host has ~60 suggestions); bounds what an agent can store.</summary>
    public const int MaxItems = 500;

    public async Task ReceiveAsync(Guid hostId, AgentReport report, CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var row = await db.HostReports.FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == ReportKind, ct);
        var h = report.Hardening;
        if (!report.Success || h is null)
        {
            // A failed audit keeps the last good checklist; only the outcome changes.
            if (row is null)
                db.HostReports.Add(new HostReport
                {
                    HostId = hostId, Kind = ReportKind, JobId = report.JobId, Success = false, Error = report.Error, StartedAt = report.StartedAtUtc,
                    FinishedAt = report.FinishedAtUtc, ReceivedAt = now, Json = JsonSerializer.Serialize(report with { Hardening = null }, AgentJsonContext.Default.AgentReport),
                });
            else
            {
                row.Success = false;
                row.Error = report.Error;
                row.FinishedAt = report.FinishedAtUtc;
                row.ReceivedAt = now;
            }
            await db.SaveChangesAsync(ct);
            return;
        }

        var existing = await db.HardeningItems.Where(x => x.HostId == hostId).Select(x => new { x.TestId, x.Kind, x.Text, x.FirstSeenAt }).ToListAsync(ct);
        var firstSeen = existing.GroupBy(x => Key(x.TestId, x.Kind, x.Text)).ToDictionary(g => g.Key, g => g.Min(x => x.FirstSeenAt));
        var items = h.Items.Take(MaxItems).ToList();
        var current = items.Select(i => i.TestId).ToHashSet(StringComparer.Ordinal);
        // Only meaningful against a previous audit: the first audit resolved nothing.
        var resolved = existing.Count == 0 && row is null ? [] : existing.Select(x => x.TestId).Distinct().Where(id => !current.Contains(id)).Order(StringComparer.Ordinal).ToList();

        // The items live in their own table; the report row keeps the audit's metadata only.
        var meta = report with { Hardening = h with { Items = [], ResolvedSinceLast = resolved } };
        var json = JsonSerializer.Serialize(meta, AgentJsonContext.Default.AgentReport);
        if (row is null) db.HostReports.Add(row = new HostReport { HostId = hostId, Kind = ReportKind, JobId = report.JobId, Json = json });
        row.JobId = report.JobId;
        row.Json = json;
        row.Success = true;
        row.Error = null;
        row.StartedAt = report.StartedAtUtc;
        row.FinishedAt = report.FinishedAtUtc;
        row.ReceivedAt = now;

        var accepted = await AcceptedAsync(hostId, ct);
        await db.HardeningItems.Where(x => x.HostId == hostId).ExecuteDeleteAsync(ct);
        var rows = items.Select(i => new HostHardeningItem
        {
            HostId = hostId,
            TestId = Clip(i.TestId, 32),
            Kind = i.Kind,
            Text = Clip(i.Text, 512),
            Details = i.Details is null ? null : Clip(i.Details, 512),
            Solution = i.Solution is null ? null : Clip(i.Solution, 512),
            Accepted = accepted.Contains(i.TestId),
            FirstSeenAt = firstSeen.GetValueOrDefault(Key(i.TestId, i.Kind, i.Text), now),
        }).ToList();
        db.HardeningItems.AddRange(rows);

        var host = await db.Hosts.FirstAsync(x => x.Id == hostId, ct);
        host.HardeningIndex = h.HardeningIndex;
        host.HardeningAuditedAt = report.FinishedAtUtc;
        Summarize(host, rows);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Re-applies <c>hardening.ignore</c> after a policy change in <paramref name="scope"/>.</summary>
    public async Task RefreshAcceptedAsync(PolicyScope scope, Guid? targetId, CancellationToken ct)
    {
        var hostIds = scope switch
        {
            PolicyScope.Host when targetId is { } id => [id],
            PolicyScope.Group => await db.Hosts.Where(h => h.GroupId == targetId).Select(h => h.Id).ToListAsync(ct),
            _ => await db.Hosts.Select(h => h.Id).ToListAsync(ct),
        };
        var audited = await db.HardeningItems.Where(i => hostIds.Contains(i.HostId)).Select(i => i.HostId).Distinct().ToListAsync(ct);
        foreach (var hostId in audited)
        {
            var accepted = (await AcceptedAsync(hostId, ct)).ToList();
            // Two updates rather than "Accepted != ids.Contains(...)": EF renders that as "Accepted <> TestId IN (...)", which SQLite reads as "(Accepted <> TestId) IN (...)".
            var changed = await db.HardeningItems.Where(i => i.HostId == hostId && !i.Accepted && accepted.Contains(i.TestId))
                .ExecuteUpdateAsync(s => s.SetProperty(i => i.Accepted, true), ct);
            changed += await db.HardeningItems.Where(i => i.HostId == hostId && i.Accepted && !accepted.Contains(i.TestId))
                .ExecuteUpdateAsync(s => s.SetProperty(i => i.Accepted, false), ct);
            if (changed == 0) continue;
            var host = await db.Hosts.FirstAsync(h => h.Id == hostId, ct);
            Summarize(host, await db.HardeningItems.AsNoTracking().Where(i => i.HostId == hostId).ToListAsync(ct));
            await db.SaveChangesAsync(ct);
        }
    }

    private async Task<HashSet<string>> AcceptedAsync(Guid hostId, CancellationToken ct) =>
        ((await policies.GetEffectiveAsync(hostId, ct)).Document.Hardening?.Ignore ?? []).ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static void Summarize(ManagedHost host, IEnumerable<HostHardeningItem> rows)
    {
        // Per test id, as the checklist shows them: NETW-3200 reports once per protocol but is one decision. A test id
        // with a warning counts as a warning only (Lynis often repeats it as a suggestion).
        var open = rows.Where(r => !r.Accepted).ToList();
        var warnings = open.Where(r => r.Kind == LynisItemKind.Warning).Select(r => r.TestId).ToHashSet(StringComparer.Ordinal);
        host.HardeningWarnings = warnings.Count;
        host.HardeningSuggestions = open.Where(r => r.Kind == LynisItemKind.Suggestion && !warnings.Contains(r.TestId)).Select(r => r.TestId).Distinct().Count();
    }

    private static string Key(string testId, LynisItemKind kind, string text) => $"{kind}|{testId}|{text}";

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max];
}
