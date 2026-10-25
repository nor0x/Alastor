using Microsoft.EntityFrameworkCore;
using Alastor.Core.Events;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services.Posture;

namespace Alastor.Server.Endpoints;

/// <summary>
/// Aggregates for the dashboard's charts: events per day, bans per hour, posture trends from the daily snapshots,
/// and the host × capability matrix. Read-only; everything is bucketed on the server so the browser draws, not counts.
/// </summary>
public static class StatsEndpoints
{
    public sealed record DayBucket(DateOnly Day, int Critical, int High, int Medium, int Low, int Info);

    public sealed record NamedCount(string Key, int Count);

    public sealed record EventStatsDto(IReadOnlyList<DayBucket> Days, IReadOnlyList<NamedCount> ByCapability, IReadOnlyList<NamedCount> TopKinds);

    public sealed record HourBucket(DateTime At, int Bans, int AuthFailures);

    public sealed record PosturePoint(
        DateOnly Day,
        int Hosts,
        int Online,
        double? BaselineScore,
        double? HardeningIndex,
        int? VulnCritical,
        int? VulnHigh,
        int? VulnKev,
        int? HostsWithHighCves,
        int? SecurityUpdates,
        int? HostsNeedingUpdates,
        int RebootRequired,
        int? PublicSsh,
        int? MalwareFindings);

    public sealed record MatrixRow(Guid HostId, string Name, bool Online, IReadOnlyDictionary<string, PostureMatrix.Cell> Cells);

    public sealed record MatrixDto(IReadOnlyList<PostureMatrix.Column> Columns, IReadOnlyList<MatrixRow> Rows);

    public static void MapStatsEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/stats").WithTags("Stats").RequireAuthorization(AuthPolicies.Reader);

        // utcOffsetMinutes lets the browser get days in its own time zone (east of UTC is positive, e.g. 120 for CEST).
        g.MapGet("/events", async (int? days, Guid? hostId, int? utcOffsetMinutes, AlastorDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var n = Math.Clamp(days ?? 14, 1, 90);
            var offset = TimeSpan.FromMinutes(Math.Clamp(utcOffsetMinutes ?? 0, -14 * 60, 14 * 60));
            var today = DateOnly.FromDateTime(time.GetUtcNow().UtcDateTime + offset);
            var first = today.AddDays(1 - n);
            var since = first.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc) - offset;

            var query = db.Events.AsNoTracking().Where(e => e.OccurredAt >= since);
            if (hostId is { } h) query = query.Where(e => e.HostId == h);
            // Bucketing by date in SQL isn't portable across SQLite and PostgreSQL through EF; three narrow columns stream cheaply.
            var buckets = new Dictionary<DateOnly, int[]>();
            var byCapability = new Dictionary<Capability, int>();
            var byKind = new Dictionary<string, int>();
            await foreach (var e in query.Select(e => new { e.OccurredAt, e.Severity, e.Capability, e.Kind }).AsAsyncEnumerable().WithCancellation(ct))
            {
                var day = DateOnly.FromDateTime(e.OccurredAt + offset);
                if (!buckets.TryGetValue(day, out var counts)) buckets[day] = counts = new int[5];
                counts[Math.Clamp((int)e.Severity, 0, 4)]++;
                byCapability[e.Capability] = byCapability.GetValueOrDefault(e.Capability) + 1;
                byKind[e.Kind] = byKind.GetValueOrDefault(e.Kind) + 1;
            }
            var series = Enumerable.Range(0, n).Select(i => first.AddDays(i)).Select(d =>
            {
                var c = buckets.GetValueOrDefault(d) ?? new int[5];
                return new DayBucket(d, c[(int)Severity.Critical], c[(int)Severity.High], c[(int)Severity.Medium], c[(int)Severity.Low], c[(int)Severity.Info]);
            }).ToList();
            return new EventStatsDto(series,
                byCapability.OrderByDescending(x => x.Value).Select(x => new NamedCount(x.Key.ToString(), x.Value)).ToList(),
                byKind.OrderByDescending(x => x.Value).Take(10).Select(x => new NamedCount(x.Key, x.Value)).ToList());
        });

        g.MapGet("/bans", async (int? hours, Guid? hostId, AlastorDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var n = Math.Clamp(hours ?? 24, 1, 168);
            var now = time.GetUtcNow().UtcDateTime;
            var currentHour = new DateTime(now.Year, now.Month, now.Day, now.Hour, 0, 0, DateTimeKind.Utc);
            var since = currentHour.AddHours(1 - n);
            var query = db.Events.AsNoTracking().Where(e => e.OccurredAt >= since && e.Capability == Capability.Banning
                                                            && (e.Kind == EventKinds.BanAdded || e.Kind == EventKinds.AuthFailures));
            if (hostId is { } h) query = query.Where(e => e.HostId == h);
            var bans = new int[n];
            var failures = new int[n];
            await foreach (var e in query.Select(e => new { e.OccurredAt, e.Kind }).AsAsyncEnumerable().WithCancellation(ct))
            {
                var i = (int)((e.OccurredAt - since).TotalHours);
                if (i < 0 || i >= n) continue;
                if (e.Kind == EventKinds.BanAdded) bans[i]++;
                else failures[i]++;
            }
            return Enumerable.Range(0, n).Select(i => new HourBucket(since.AddHours(i), bans[i], failures[i])).ToList();
        });

        g.MapGet("/posture", async (int? days, Guid? hostId, AlastorDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var n = Math.Clamp(days ?? 30, 2, 365);
            var first = DateOnly.FromDateTime(time.GetUtcNow().UtcDateTime).AddDays(1 - n);
            var query = db.PostureSnapshots.AsNoTracking().Where(s => s.Day >= first);
            if (hostId is { } h) query = query.Where(s => s.HostId == h);
            var rows = await query.ToListAsync(ct);
            return rows.GroupBy(s => s.Day).OrderBy(d => d.Key).Select(d => Aggregate(d.Key, d.ToList())).ToList();
        });

        g.MapGet("/matrix", async (AlastorDbContext db, CancellationToken ct) =>
        {
            var hosts = await db.Hosts.AsNoTracking().Include(h => h.Tools).OrderBy(h => h.Name).ToListAsync(ct);
            var ids = hosts.Select(h => h.Id).ToList();
            var highChecks = Alastor.Core.Baseline.BaselineCatalog.All.Where(i => i.Severity >= Severity.High).Select(i => i.Id).ToList();
            var failingHigh = (await db.BaselineChecks.AsNoTracking()
                .Where(c => c.Status == Alastor.Core.Baseline.CheckStatus.Fail && !c.Accepted && highChecks.Contains(c.CheckId))
                .Select(c => c.HostId).Distinct().ToListAsync(ct)).ToHashSet();
            var kev = await PostureService.KevCountsAsync(db, ids, ct);
            var rows = hosts.Select(h => new MatrixRow(h.Id, h.Name, h.IsOnline,
                PostureMatrix.Row(h, new PostureMatrix.Extra(failingHigh.Contains(h.Id), kev.GetValueOrDefault(h.Id))))).ToList();
            return new MatrixDto(PostureMatrix.Columns, rows);
        });
    }

    /// <summary>Fleet values for one day. A measure is null when no host had reported it yet, so charts show a gap, not a zero.</summary>
    public static PosturePoint Aggregate(DateOnly day, IReadOnlyList<HostPostureSnapshot> s)
    {
        static double? Avg(IEnumerable<int?> v) { var l = v.Where(x => x is not null).ToList(); return l.Count == 0 ? null : Math.Round(l.Average(x => x!.Value), 1); }
        static int? Sum(IEnumerable<int?> v) { var l = v.Where(x => x is not null).ToList(); return l.Count == 0 ? null : l.Sum(x => x!.Value); }
        static int? CountWhere(IReadOnlyList<HostPostureSnapshot> s, Func<HostPostureSnapshot, bool?> f)
        {
            var l = s.Select(f).Where(x => x is not null).ToList();
            return l.Count == 0 ? null : l.Count(x => x == true);
        }
        return new PosturePoint(day, s.Count, s.Count(x => x.Online),
            Avg(s.Select(x => x.BaselineScore)), Avg(s.Select(x => x.HardeningIndex)),
            Sum(s.Select(x => x.VulnCritical)), Sum(s.Select(x => x.VulnHigh)), Sum(s.Select(x => x.VulnKev)),
            CountWhere(s, x => x.VulnCritical is null ? null : x.VulnCritical + x.VulnHigh > 0),
            Sum(s.Select(x => x.SecurityUpdates)),
            CountWhere(s, x => x.SecurityUpdates is null ? null : x.SecurityUpdates > 0),
            s.Count(x => x.RebootRequired),
            CountWhere(s, x => x.PublicSsh),
            Sum(s.Select(x => x.MalwareFindings)));
    }
}
