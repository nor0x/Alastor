using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrity;
using Alastor.Core.Malware;
using Alastor.Server.Data;

namespace Alastor.Server.Services.Integrity;

/// <summary>
/// Stores each host's latest AIDE run and rkhunter check. A failed run keeps the last good result and records the
/// error. rkhunter warnings matching <c>malware.rootkitIgnore</c> are counted out on the server, so ignoring one takes
/// effect at once.
/// </summary>
public sealed class IntegrityService(AlastorDbContext db, PolicyService policies, TimeProvider time)
{
    public const string IntegrityKind = "integrity";
    public const string RootkitKind = "rootkit";

    public async Task ReceiveAsync(Guid hostId, AgentReport report, CancellationToken ct)
    {
        var kind = report.Rootkit is not null || report.JobId.StartsWith("malware.rootkits", StringComparison.Ordinal) ? RootkitKind : IntegrityKind;
        var row = await db.HostReports.FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == kind, ct);
        var json = JsonSerializer.Serialize(report, AgentJsonContext.Default.AgentReport);
        if (row is null) db.HostReports.Add(row = new HostReport { HostId = hostId, Kind = kind, JobId = report.JobId, Json = json });
        if (report.Success && (report.Integrity is not null || report.Rootkit is not null))
        {
            row.Json = json;
            row.StartedAt = report.StartedAtUtc;
        }
        row.JobId = report.JobId;
        row.Success = report.Success;
        row.Error = report.Error;
        row.FinishedAt = report.FinishedAtUtc;
        row.ReceivedAt = time.GetUtcNow().UtcDateTime;

        var host = await db.Hosts.FirstAsync(h => h.Id == hostId, ct);
        if (report.Success && report.Integrity is { } i)
        {
            host.IntegrityChanges = i.Changes.Count;
            host.IntegrityCritical = i.Changes.Count(c => c.Critical);
            host.IntegrityCheckedAt = report.FinishedAtUtc;
        }
        if (report.Success && report.Rootkit is { } rk)
        {
            Summarize(host, rk, (await policies.GetEffectiveAsync(hostId, ct)).Document.Malware?.RootkitIgnore);
            host.RootkitCheckedAt = report.FinishedAtUtc;
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Re-counts rkhunter warnings after a policy change in <paramref name="scope"/> (rootkitIgnore may have changed).</summary>
    public async Task RefreshAsync(PolicyScope scope, Guid? targetId, CancellationToken ct)
    {
        var rows = await db.HostReports.AsNoTracking().Where(r => r.Kind == RootkitKind).ToListAsync(ct);
        foreach (var row in rows)
        {
            if (ReadRootkit(row) is not { } report) continue;
            var host = await db.Hosts.FirstAsync(h => h.Id == row.HostId, ct);
            if (scope == PolicyScope.Host && host.Id != targetId || scope == PolicyScope.Group && host.GroupId != targetId) continue;
            Summarize(host, report, (await policies.GetEffectiveAsync(host.Id, ct)).Document.Malware?.RootkitIgnore);
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Warnings that count: Medium and up, not ignored. Low ones (configuration notes) stay listed only.</summary>
    public static List<RootkitWarning> Open(RootkitReport report, IEnumerable<string>? ignore) =>
        report.Warnings.Where(w => w.Severity >= Severity.Medium && !w.IsIgnored(ignore)).ToList();

    private static void Summarize(ManagedHost host, RootkitReport report, IReadOnlyList<string>? ignore)
    {
        var open = Open(report, ignore);
        host.RootkitWarnings = open.Count;
        host.RootkitSeverity = open.Count == 0 ? null : open.Max(w => w.Severity);
    }

    public static IntegrityReport? ReadIntegrity(HostReport? row) =>
        row is null ? null : JsonSerializer.Deserialize(row.Json, AgentJsonContext.Default.AgentReport)?.Integrity;

    public static RootkitReport? ReadRootkit(HostReport? row) =>
        row is null ? null : JsonSerializer.Deserialize(row.Json, AgentJsonContext.Default.AgentReport)?.Rootkit;
}
