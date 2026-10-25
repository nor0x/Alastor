using Microsoft.EntityFrameworkCore;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;

namespace Alastor.Server.Endpoints;

public static class EventEndpoints
{
    public sealed record EventPage(IReadOnlyList<EventDto> Items, DateTime? NextBefore);

    public sealed record OverviewDto(
        int HostsTotal,
        int HostsOnline,
        int HostsOffline,
        int Alerts24h,
        int Events24h,
        int ActiveBans,
        int Bans24h,
        int HostsWithToolProblems,
        int HostsPolicyPending,
        int? HostsWithPendingSecurityUpdates,
        int? HostsWithHighCves,
        int? HostsWithPublicSsh,
        int? HostsWithMalware,
        double? AverageHardeningIndex,
        double? AverageBaselineScore,
        int HostsFailingBaselineHigh,
        IReadOnlyList<EventDto> RecentAlerts,
        IReadOnlyList<TopOffender> TopOffenders);

    public sealed record TopOffender(string Target, int Events, int Hosts);

    public static void MapEventEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/events", async (Guid? hostId, Severity? minSeverity, Capability? capability, string? ip, string? kind, string? q,
            DateTime? from, DateTime? before, int? limit, AlastorDbContext db, CancellationToken ct) =>
        {
            var query = db.Events.AsNoTracking().AsQueryable();
            if (hostId is { } h) query = query.Where(e => e.HostId == h);
            if (minSeverity is { } s) query = query.Where(e => e.Severity >= s);
            if (capability is { } c) query = query.Where(e => e.Capability == c);
            if (!string.IsNullOrWhiteSpace(ip)) query = query.Where(e => e.Subject == ip);
            if (!string.IsNullOrWhiteSpace(kind)) query = query.Where(e => e.Kind == kind);
            if (!string.IsNullOrWhiteSpace(q)) query = query.Where(e => e.Message.Contains(q));
            if (from is { } f) query = query.Where(e => e.OccurredAt >= f.ToUniversalTime());
            if (before is { } b) query = query.Where(e => e.OccurredAt < b.ToUniversalTime());
            var take = Math.Clamp(limit ?? 100, 1, 500);
            var items = await query.OrderByDescending(e => e.OccurredAt).Take(take).ToListAsync(ct);
            return new EventPage(items.Select(Dto.Event).ToList(), items.Count == take ? items[^1].OccurredAt : null);
        }).WithTags("Events").RequireAuthorization(AuthPolicies.Reader);

        app.MapGet("/api/overview", async (AlastorDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var since = time.GetUtcNow().UtcDateTime.AddHours(-24);
            var hosts = await db.Hosts.AsNoTracking().Include(h => h.Tools).ToListAsync(ct);
            var recent = await db.Events.AsNoTracking().Where(e => e.OccurredAt >= since && e.Severity >= Severity.Medium)
                .OrderByDescending(e => e.OccurredAt).Take(10).ToListAsync(ct);
            // Count per (subject, host) in SQL, then fold hosts in memory. COUNT(DISTINCT) inside GROUP BY is not portable through EF.
            var perHost = await db.Events.AsNoTracking()
                .Where(e => e.OccurredAt >= since && e.Capability == Capability.Banning && e.Subject != null
                            && (e.Kind == EventKinds.BanAdded || e.Kind == EventKinds.AuthFailures || e.Kind == EventKinds.BanIncreased))
                .GroupBy(e => new { e.Subject, e.HostId })
                .Select(grp => new { grp.Key.Subject, grp.Key.HostId, Count = grp.Count() })
                .ToListAsync(ct);
            var offenders = perHost.GroupBy(x => x.Subject!)
                .Select(grp => new TopOffender(grp.Key, grp.Sum(x => x.Count), grp.Count()))
                .OrderByDescending(o => o.Events).Take(10).ToList();
            var scored = hosts.Where(h => h.BaselineScore is not null).ToList();
            var highSeverityChecks = Alastor.Core.Baseline.BaselineCatalog.All.Where(i => i.Severity >= Severity.High).Select(i => i.Id).ToList();
            var hostsFailingHigh = await db.BaselineChecks
                .Where(c => c.Status == Alastor.Core.Baseline.CheckStatus.Fail && !c.Accepted && highSeverityChecks.Contains(c.CheckId))
                .Select(c => c.HostId).Distinct().CountAsync(ct);

            return new OverviewDto(
                hosts.Count,
                hosts.Count(h => h.IsOnline),
                hosts.Count(h => !h.IsOnline),
                await db.Events.CountAsync(e => e.OccurredAt >= since && e.Severity >= Severity.Medium, ct),
                await db.Events.CountAsync(e => e.OccurredAt >= since, ct),
                await db.Bans.CountAsync(ct),
                await db.Events.CountAsync(e => e.OccurredAt >= since && e.Kind == EventKinds.BanAdded, ct),
                hosts.Count(h => h.Tools.Any(t => t.Availability == Availability.Unavailable || (t.Installed && !t.Running)
                                                  || t.ConfigState == ConfigState.Drifted || t.ConfigState == ConfigState.Conflict || t.ConfigState == ConfigState.Rejected)),
                hosts.Count(h => h.PolicyApplySuccess != true),
                // Hosts that never reported updates don't count; Alpine reports no security flag, so any pending update counts.
                hosts.Any(h => h.PendingUpdates is not null) ? hosts.Count(h => (h.SecurityUpdates ?? h.PendingUpdates ?? 0) > 0) : null,
                // Hosts with an open (not accepted) High or Critical CVE; null until some host has scanned.
                hosts.Any(h => h.VulnScannedAt is not null) ? hosts.Count(h => (h.VulnCritical ?? 0) + (h.VulnHigh ?? 0) > 0) : null,
                hosts.Any(h => h.NetworkCheckedAt is not null)
                    ? hosts.Count(h => h.SshExposure is Alastor.Core.Network.SshExposureLevel.Public or Alastor.Core.Network.SshExposureLevel.PossiblyPublic && !h.SshExposureAccepted)
                    : null,
                hosts.Any(h => h.MalwareScannedAt is not null) ? hosts.Count(h => h.MalwareFindings > 0) : null,
                hosts.Any(h => h.HardeningIndex is not null) ? Math.Round(hosts.Where(h => h.HardeningIndex is not null).Average(h => h.HardeningIndex!.Value), 0) : null,
                scored.Count == 0 ? null : Math.Round(scored.Average(h => h.BaselineScore!.Value), 0),
                hostsFailingHigh,
                recent.Select(Dto.Event).ToList(),
                offenders);
        }).WithTags("Overview").RequireAuthorization(AuthPolicies.Reader);
    }
}
