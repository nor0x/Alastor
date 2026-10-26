using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Alastor.Server.Data;
using Alastor.Server.Services.Vulnerabilities;

namespace Alastor.Server.Services.Storage;

public sealed record TableSizeDto(string Table, long Rows, long? Bytes);
public sealed record DataFolderDto(string Path, string Description, long Bytes);
public sealed record ServerCleanupDto(string Id, string Title, string Description, long Bytes, int Items);
public sealed record RetentionDto(string Key, string Value, string Description);
public sealed record ServerDataDto(
    string Provider,
    string? DatabasePath,
    long DatabaseBytes,
    long? FreeBytesInDatabase,
    DateTime? LastCompactedAt,
    long? DiskFreeBytes,
    IReadOnlyList<TableSizeDto> Tables,
    IReadOnlyList<DataFolderDto> Folders,
    IReadOnlyList<ServerCleanupDto> Cleanups,
    IReadOnlyList<RetentionDto> Retention);

public sealed record PruneResult(Dictionary<string, int> Removed, long FreedFileBytes);

/// <summary>
/// The server's own data: what the database and mirrors take up, retention for every table that would otherwise grow
/// forever, compacting SQLite, and removing mirrors and extraction folders nothing uses any more.
/// </summary>
public sealed class ServerDataService(AlastorDbContext db, VulnDbMirror mirror, IOptions<AlastorOptions> options, TimeProvider time, ILogger<ServerDataService> logger)
{
    public const string UnusedMirrors = "mirrors.unused";
    public const string OldExtractions = "extract-cache.old";

    /// <summary>Compact automatically once free pages are both this share of the file and this many bytes.</summary>
    private const double CompactShare = 0.25;
    private const long CompactMinBytes = 50L << 20;

    private static DateTime? _lastCompactedAt;
    private static DateTime _lastDaily;

    private bool IsSqlite => db.Database.ProviderName?.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>One retention pass. The heavier jobs (orphaned OSV advisories, policy history, compaction) run once a day.</summary>
    public async Task<PruneResult> PruneAsync(bool force, CancellationToken ct)
    {
        var o = options.Value;
        var now = time.GetUtcNow().UtcDateTime;
        var removed = new Dictionary<string, int>();
        void Add(string table, int n) { if (n > 0) removed[table] = n; }

        var eventsBefore = now - o.EventRetentionValue;
        Add("metrics", await db.MetricSamples.Where(s => s.At < now - o.MetricRetentionValue).ExecuteDeleteAsync(ct));
        Add("events", await db.Events.Where(x => x.OccurredAt < eventsBefore).ExecuteDeleteAsync(ct));
        Add("expired bans", await db.Bans.Where(x => x.ExpiresAt != null && x.ExpiresAt < now).ExecuteDeleteAsync(ct));
        Add("commands", await db.Commands.Where(x => x.CompletedAt != null && x.CompletedAt < eventsBefore).ExecuteDeleteAsync(ct));
        Add("feed items", await db.FeedItems.Where(x => x.PublishedAt < now - o.ThreatFeedRetentionValue).ExecuteDeleteAsync(ct));
        var postureBefore = DateOnly.FromDateTime(now - o.PostureRetentionValue);
        Add("posture snapshots", await db.PostureSnapshots.Where(x => x.Day < postureBefore).ExecuteDeleteAsync(ct));
        Add("resolved issues", await db.Issues.Where(x => x.ResolvedAt != null && x.ResolvedAt < eventsBefore).ExecuteDeleteAsync(ct));
        // Drained dedup buckets carry no information once the window has long passed.
        var bucketsBefore = now - o.AlertDedupWindowValue * 4 - TimeSpan.FromDays(1);
        await db.AlertBuckets.Where(x => x.UpdatedAt < bucketsBefore && x.Suppressed == 0).ExecuteDeleteAsync(ct);
        Add("audit entries", await db.Audit.Where(a => a.At < now - o.AuditRetentionValue).ExecuteDeleteAsync(ct));
        Add("login sources", await db.LoginSources.Where(s => s.LastSeenAt < now - o.LoginSourceRetentionValue).ExecuteDeleteAsync(ct));
        Add("sessions", await db.Sessions.Where(s => s.ExpiresAt < now - TimeSpan.FromDays(1) || s.RevokedAt < now - TimeSpan.FromDays(1)).ExecuteDeleteAsync(ct));
        var tokensBefore = now - TimeSpan.FromDays(30);
        Add("enrollment tokens", await db.EnrollmentTokens.Where(t => (t.ConsumedAt != null && t.ConsumedAt < tokensBefore) || t.ExpiresAt < tokensBefore).ExecuteDeleteAsync(ct));

        long freed = mirror.DeleteStalePartials();
        if (force || now - _lastDaily > TimeSpan.FromDays(1))
        {
            _lastDaily = now;
            Add("policy versions", await PrunePolicyVersionsAsync(o.PolicyVersionsKeep, ct));
            Add("OSV advisories", await PruneOrphanedAdvisoriesAsync(ct));
            if (!force && await ShouldCompactAsync(ct)) await CompactAsync(ct);
        }
        if (removed.Count > 0)
            logger.LogInformation("Retention removed {Removed}", string.Join(", ", removed.Select(r => $"{r.Value} {r.Key}")));
        return new(removed, freed);
    }

    private async Task<int> PrunePolicyVersionsAsync(int keep, CancellationToken ct)
    {
        var layers = await db.PolicyLayers.AsNoTracking().Select(l => new { l.Id, l.CurrentVersion }).ToListAsync(ct);
        var removed = 0;
        foreach (var l in layers)
        {
            var cutoff = await db.PolicyVersions.Where(v => v.LayerId == l.Id).OrderByDescending(v => v.Version)
                .Skip(keep).Select(v => (int?)v.Version).FirstOrDefaultAsync(ct);
            if (cutoff is null) continue;
            removed += await db.PolicyVersions.Where(v => v.LayerId == l.Id && v.Version <= cutoff && v.Version != l.CurrentVersion).ExecuteDeleteAsync(ct);
        }
        return removed;
    }

    /// <summary>OSV advisory details no package version on any host points at any more (packages were upgraded or hosts removed).</summary>
    private async Task<int> PruneOrphanedAdvisoriesAsync(CancellationToken ct)
    {
        var referenced = (await db.OsvPackages.AsNoTracking().Select(p => p.VulnIds).ToListAsync(ct)).SelectMany(v => v).ToHashSet();
        var orphans = (await db.OsvVulnerabilities.AsNoTracking().Select(v => v.Id).ToListAsync(ct)).Where(id => !referenced.Contains(id)).ToList();
        var removed = 0;
        foreach (var chunk in orphans.Chunk(500))
            removed += await db.OsvVulnerabilities.Where(v => chunk.Contains(v.Id)).ExecuteDeleteAsync(ct);
        return removed;
    }

    // ---- SQLite compaction ----

    private async Task<(long PageSize, long Pages, long Free)?> PagesAsync(CancellationToken ct)
    {
        if (!IsSqlite) return null;
        var pageSize = await db.Database.SqlQueryRaw<long>("SELECT page_size AS Value FROM pragma_page_size()").SingleAsync(ct);
        var pages = await db.Database.SqlQueryRaw<long>("SELECT page_count AS Value FROM pragma_page_count()").SingleAsync(ct);
        var free = await db.Database.SqlQueryRaw<long>("SELECT freelist_count AS Value FROM pragma_freelist_count()").SingleAsync(ct);
        return (pageSize, pages, free);
    }

    private async Task<bool> ShouldCompactAsync(CancellationToken ct)
    {
        if (_lastCompactedAt is { } last && time.GetUtcNow().UtcDateTime - last < TimeSpan.FromDays(7)) return false;
        return await PagesAsync(ct) is { } p && p.Pages > 0 && p.Free * p.PageSize >= CompactMinBytes && (double)p.Free / p.Pages >= CompactShare;
    }

    /// <summary>
    /// Rewrites the SQLite file without its free pages (deleted rows leave them behind) and truncates the WAL. Needs about the
    /// database's size in free disk space while it runs, and blocks writes until it's done.
    /// </summary>
    public async Task<(bool Ok, string? Error, long Freed)> CompactAsync(CancellationToken ct)
    {
        if (!IsSqlite) return (false, "PostgreSQL compacts on its own (autovacuum).", 0);
        var before = DatabaseBytes();
        if (DiskFree() is { } free && free < before)
            return (false, $"Compacting needs about {before / (1 << 20)} MB of free disk space; only {free / (1 << 20)} MB is free.", 0);
        await db.Database.ExecuteSqlRawAsync("PRAGMA wal_checkpoint(TRUNCATE);", ct);
        await db.Database.ExecuteSqlRawAsync("VACUUM;", ct);
        await db.Database.ExecuteSqlRawAsync("PRAGMA wal_checkpoint(TRUNCATE);", ct);
        _lastCompactedAt = time.GetUtcNow().UtcDateTime;
        var freed = Math.Max(0, before - DatabaseBytes());
        logger.LogInformation("Compacted the database: {Freed} bytes freed", freed);
        return (true, null, freed);
    }

    // ---- what takes up space ----

    public async Task<ServerDataDto> OverviewAsync(CancellationToken ct)
    {
        var o = options.Value;
        var tables = new List<TableSizeDto>();
        var sizes = await TableBytesAsync(ct);
        foreach (var e in db.Model.GetEntityTypes().Where(e => e.GetTableName() is not null && e.GetViewName() is null).DistinctBy(e => e.GetTableName()))
        {
            var name = e.GetTableName()!;
            // Table names come from the EF model, never from input.
            var sql = "SELECT COUNT(*) AS \"Value\" FROM \"" + name + "\"";
            var rows = await db.Database.SqlQueryRaw<long>(sql).SingleAsync(ct);
            tables.Add(new(name, rows, sizes.TryGetValue(name, out var b) ? b : null));
        }
        var pages = await PagesAsync(ct);
        return new ServerDataDto(
            IsSqlite ? "sqlite" : "postgres",
            IsSqlite ? DatabasePath() : null,
            IsSqlite ? DatabaseBytes() : sizes.Values.Sum(),
            pages is { } p ? p.Free * p.PageSize : null,
            _lastCompactedAt,
            DiskFree(),
            tables.OrderByDescending(t => t.Bytes ?? 0).ThenByDescending(t => t.Rows).ToList(),
            Folders(),
            Cleanups(),
            [
                new("MetricRetention", o.MetricRetention, "Host metrics"),
                new("EventRetention", o.EventRetention, "Events, finished commands and resolved issues"),
                new("PostureRetention", o.PostureRetention, "Daily posture snapshots (trend charts)"),
                new("ThreatFeedRetention", o.ThreatFeedRetention, "Threat feed items"),
                new("AuditRetention", o.AuditRetention, "Audit log"),
                new("LoginSourceRetention", o.LoginSourceRetention, "Known SSH login sources not seen since"),
                new("PolicyVersionsKeep", o.PolicyVersionsKeep.ToString(System.Globalization.CultureInfo.InvariantCulture), "Policy versions kept per layer"),
                new("RetentionRunInterval", o.RetentionRunInterval, "How often old data is pruned"),
            ]);
    }

    /// <summary>Bytes per table on PostgreSQL. The bundled SQLite has no dbstat table, so SQLite shows row counts only.</summary>
    private async Task<Dictionary<string, long>> TableBytesAsync(CancellationToken ct)
    {
        if (IsSqlite) return [];
        var rows = await db.Database.SqlQueryRaw<TableBytes>(
            "SELECT relname AS \"Name\", pg_total_relation_size(relid) AS \"Bytes\" FROM pg_catalog.pg_statio_user_tables").ToListAsync(ct);
        return rows.GroupBy(r => r.Name).ToDictionary(g => g.Key, g => g.Sum(r => r.Bytes));
    }

    private sealed record TableBytes(string Name, long Bytes);

    private List<DataFolderDto> Folders()
    {
        var data = options.Value.DataDir;
        var list = new List<DataFolderDto>();
        void Add(string path, string description) { if (Directory.Exists(path)) list.Add(new(path, description, DirectoryBytes(path))); }
        foreach (var dir in Directory.Exists(Path.Combine(data, "vulndb")) ? Directory.GetDirectories(Path.Combine(data, "vulndb")) : [])
            Add(dir, Path.GetFileName(dir) == "clamav" ? "ClamAV signatures mirrored for agents" : $"{Path.GetFileName(dir)} vulnerability database mirrored for agents");
        Add(Path.Combine(data, "keys"), "Data-protection keys (keep)");
        Add(options.Value.AgentDownloadDir, "Agent binaries served to new hosts");
        if (ExtractBase() is { } extract) Add(extract, ".NET single-file extraction cache");
        return list;
    }

    private List<ServerCleanupDto> Cleanups()
    {
        var unused = mirror.Unused();
        var old = OldExtractionDirs();
        return
        [
            new(UnusedMirrors, "Mirrored databases no agent uses",
                $"Vulnerability databases and ClamAV signatures no agent has asked for in {VulnDbMirror.UnusedAfter.TotalDays:0} days. They're downloaded again when an agent needs them.",
                unused.Sum(u => u.Bytes), unused.Count),
            new(OldExtractions, "Extraction folders of older server versions",
                "Each server version unpacks its native libraries into its own folder; upgrades leave the old ones behind.",
                old.Sum(d => DirectoryBytes(d.FullName)), old.Count),
        ];
    }

    public async Task<(bool Ok, string? Error, long Freed)> CleanupAsync(string id, CancellationToken ct)
    {
        switch (id)
        {
            case UnusedMirrors:
                return (true, null, await mirror.RemoveUnusedAsync(ct));
            case OldExtractions:
                long freed = 0;
                foreach (var d in OldExtractionDirs())
                {
                    try
                    {
                        var bytes = DirectoryBytes(d.FullName);
                        d.Delete(true);
                        freed += bytes;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { logger.LogWarning("Could not remove {Dir}: {Error}", d.FullName, ex.Message); }
                }
                return (true, null, freed);
            default:
                return (false, "Unknown cleanup.", 0);
        }
    }

    /// <summary>DOTNET_BUNDLE_EXTRACT_BASE_DIR/alastor-server: one folder per bundle (server build).</summary>
    private static string? ExtractBase()
    {
        var root = Environment.GetEnvironmentVariable("DOTNET_BUNDLE_EXTRACT_BASE_DIR");
        if (string.IsNullOrEmpty(root)) return null;
        var dir = Path.Combine(root, "alastor-server");
        return Directory.Exists(dir) ? dir : null;
    }

    /// <summary>Extraction folders other than the one this process loaded its native libraries from.</summary>
    private static List<DirectoryInfo> OldExtractionDirs()
    {
        if (ExtractBase() is not { } dir) return [];
        string? current = null;
        try
        {
            current = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                .Select(m => m.FileName)
                .Where(f => f is not null && f.StartsWith(dir + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                .Select(f => f![(dir.Length + 1)..].Split(Path.DirectorySeparatorChar)[0])
                .FirstOrDefault();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
        // Without knowing which one is in use, remove nothing.
        if (current is null) return [];
        return new DirectoryInfo(dir).GetDirectories().Where(d => d.Name != current).ToList();
    }

    private string? DatabasePath() => IsSqlite ? db.Database.GetDbConnection().DataSource : null;

    private long DatabaseBytes()
    {
        if (DatabasePath() is not { Length: > 0 } path) return 0;
        return new[] { path, path + "-wal", path + "-shm" }.Where(File.Exists).Sum(f => new FileInfo(f).Length);
    }

    private long? DiskFree()
    {
        try { return new DriveInfo(Path.GetFullPath(options.Value.DataDir)).AvailableFreeSpace; }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException) { return null; }
    }

    private static long DirectoryBytes(string path)
    {
        try { return new DirectoryInfo(path).EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 0; }
    }
}
