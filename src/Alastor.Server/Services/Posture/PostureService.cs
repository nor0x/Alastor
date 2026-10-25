using Microsoft.EntityFrameworkCore;
using Alastor.Core.Network;
using Alastor.Server.Data;

namespace Alastor.Server.Services.Posture;

/// <summary>
/// Keeps one <see cref="HostPostureSnapshot"/> per host per UTC day. Report and presence handlers call
/// <see cref="SnapshotAsync"/> for the host they changed; <see cref="Workers.PostureWorker"/> calls it hourly for every
/// host, which carries values forward into days where nothing was reported.
/// </summary>
public sealed class PostureService(AlastorDbContext db, TimeProvider time, ILogger<PostureService> logger)
{
    public Task SnapshotAsync(Guid hostId, CancellationToken ct) => SnapshotAsync([hostId], ct);

    /// <summary>Writes today's row for the given hosts (every host when null) from their current denormalized columns.</summary>
    public async Task SnapshotAsync(IReadOnlyCollection<Guid>? hostIds, CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var day = DateOnly.FromDateTime(now);
        var query = db.Hosts.AsNoTracking();
        if (hostIds is not null) query = query.Where(h => hostIds.Contains(h.Id));
        var hosts = await query.ToListAsync(ct);
        if (hosts.Count == 0) return;
        var ids = hosts.Select(h => h.Id).ToList();
        var kev = await KevCountsAsync(db, ids, ct);
        var existing = await db.PostureSnapshots.Where(s => s.Day == day && ids.Contains(s.HostId)).ToDictionaryAsync(s => s.HostId, ct);

        foreach (var h in hosts)
        {
            var next = From(h, kev.GetValueOrDefault(h.Id), day, now);
            if (!existing.TryGetValue(h.Id, out var row)) db.PostureSnapshots.Add(next);
            else if (!SameValues(row, next)) db.Entry(row).CurrentValues.SetValues(next);
        }
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException ex)
        {
            // Two writers raced to insert today's row (heartbeat and report at once). The next call brings it up to date.
            logger.LogDebug(ex, "Posture snapshot insert raced; skipped");
            db.ChangeTracker.Clear();
        }
    }

    /// <summary>Distinct open (not accepted) CVEs per host that are in the KEV catalog.</summary>
    public static async Task<Dictionary<Guid, int>> KevCountsAsync(AlastorDbContext db, IReadOnlyCollection<Guid> hostIds, CancellationToken ct)
    {
        // Distinct pairs in SQL, counted in memory: COUNT(DISTINCT) inside GROUP BY is not portable through EF.
        var pairs = await db.Vulnerabilities.AsNoTracking()
            .Where(v => hostIds.Contains(v.HostId) && !v.Accepted && db.KevEntries.Any(k => k.CveId == v.VulnId))
            .Select(v => new { v.HostId, v.VulnId }).Distinct().ToListAsync(ct);
        return pairs.GroupBy(p => p.HostId).ToDictionary(g => g.Key, g => g.Count());
    }

    public static HostPostureSnapshot From(ManagedHost h, int kev, DateOnly day, DateTime now) => new()
    {
        HostId = h.Id,
        Day = day,
        UpdatedAt = now,
        Online = h.IsOnline,
        BaselineScore = h.BaselineScore,
        HardeningIndex = h.HardeningIndex,
        VulnCritical = h.VulnScannedAt is null ? null : h.VulnCritical ?? 0,
        VulnHigh = h.VulnScannedAt is null ? null : h.VulnHigh ?? 0,
        VulnKev = h.VulnScannedAt is null ? null : kev,
        // Alpine reports no security flag, so every pending update counts there (same rule as the overview).
        SecurityUpdates = h.PendingUpdates is null ? null : h.SecurityUpdates ?? h.PendingUpdates,
        RebootRequired = h.RebootRequired,
        PublicSsh = h.NetworkCheckedAt is null ? null : IsPublicSsh(h),
        PublicServices = h.PublicServices?.Count,
        MalwareFindings = h.MalwareScannedAt is null ? null : h.MalwareFindings ?? 0,
    };

    public static bool IsPublicSsh(ManagedHost h) =>
        h.SshExposure is SshExposureLevel.Public or SshExposureLevel.PossiblyPublic && !h.SshExposureAccepted;

    private static bool SameValues(HostPostureSnapshot a, HostPostureSnapshot b) =>
        a.Online == b.Online && a.BaselineScore == b.BaselineScore && a.HardeningIndex == b.HardeningIndex
        && a.VulnCritical == b.VulnCritical && a.VulnHigh == b.VulnHigh && a.VulnKev == b.VulnKev
        && a.SecurityUpdates == b.SecurityUpdates && a.RebootRequired == b.RebootRequired && a.PublicSsh == b.PublicSsh
        && a.PublicServices == b.PublicServices
        && a.MalwareFindings == b.MalwareFindings;
}
