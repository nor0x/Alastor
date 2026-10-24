using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Server.Auth;
using Sentinel.Server.Data;
using Sentinel.Server.Services;

namespace Sentinel.Server.Endpoints;

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
        double? AverageHardeningIndex,
        IReadOnlyList<EventDto> RecentAlerts,
        IReadOnlyList<TopOffender> TopOffenders);

    public sealed record TopOffender(string Target, int Events, int Hosts);

    public static void MapEventEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/events", async (Guid? hostId, Severity? minSeverity, Capability? capability, string? ip, string? kind, string? q,
            DateTime? from, DateTime? before, int? limit, SentinelDbContext db, CancellationToken ct) =>
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

        app.MapGet("/api/overview", async (SentinelDbContext db, TimeProvider time, CancellationToken ct) =>
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
                // Filled in by the updates, CVE and Lynis integrations (deliverables 6-8).
                null,
                null,
                null,
                recent.Select(Dto.Event).ToList(),
                offenders);
        }).WithTags("Overview").RequireAuthorization(AuthPolicies.Reader);
    }
}
