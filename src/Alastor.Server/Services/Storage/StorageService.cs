using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Contracts;
using Alastor.Core.Storage;
using Alastor.Server.Data;
using ScheduleDto = Alastor.Server.Endpoints.ReportEndpoints.ScheduleDto;

namespace Alastor.Server.Services.Storage;

/// <summary>A cleanup that applies to a host: the catalog entry with what the agent measured.</summary>
public sealed record CleanupDto(string Id, string Title, string Description, CleanupRisk Risk, string Command, long? Bytes, int? Items, string? Detail, string? Blocked);

/// <summary>A cleanup the dashboard queued that hasn't reported back yet.</summary>
public sealed record RunningCleanupDto(Guid CommandId, string Id, DateTime StartedAt);

public sealed record HostStorageDto(
    Guid HostId, string Name, bool Online, DateTime? ScannedAt, DateTime? ReportedAt, bool? Success, string? Error,
    IReadOnlyList<FilesystemUsage> Filesystems, IReadOnlyList<DirectoryUsage> Directories, IReadOnlyList<LargeFile> LargestFiles,
    IReadOnlyList<CleanupDto> Cleanups, long ReclaimableBytes, CleanupResult? LastCleanup, RunningCleanupDto? Running,
    IReadOnlyList<string> Notes, IReadOnlyList<ScheduleDto> Schedules);

public sealed record FleetCleanup(string Id, long? Bytes, int? Items, bool Blocked);

public sealed record FleetStorageRow(
    Guid HostId, string Name, bool Online, string? GroupName, double DiskPercent, long DiskUsedBytes, long DiskTotalBytes,
    long? ReclaimableBytes, DateTime? ScannedAt, IReadOnlyList<FleetCleanup> Cleanups, string? Running);

public sealed record FleetStorageDto(IReadOnlyList<CleanupDefinition> Catalog, IReadOnlyList<FleetStorageRow> Hosts);

/// <summary>
/// Keeps each host's latest storage report (one <see cref="HostReport"/> row of kind <c>storage</c>) and builds the Storage
/// views from it. A cleanup's report replaces the scan's, but carries the scan's folder tree along.
/// </summary>
public sealed class StorageService(AlastorDbContext db, TimeProvider time)
{
    public const string ReportKind = "storage";

    /// <summary>A queued cleanup that never reports back stops showing as running after this long.</summary>
    private static readonly TimeSpan RunningFor = TimeSpan.FromHours(1);

    public static bool IsTooLarge(StorageReport r) =>
        r.Directories.Count > StorageIntegration.MaxDirectories || r.LargestFiles.Count > StorageIntegration.MaxFiles
        || r.Filesystems.Count > 100 || r.Cleanups.Count > StorageCleanups.All.Count || r.Notes.Count > 50;

    public async Task ReceiveAsync(Guid hostId, AgentReport report, CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var row = await db.HostReports.FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == ReportKind, ct);
        if (row is null) db.HostReports.Add(row = new HostReport { HostId = hostId, Kind = ReportKind, JobId = report.JobId, Json = "" });
        // A failed scan without data keeps showing the last good one, with the error.
        if (report.Storage is not null || row.Json.Length == 0) row.Json = JsonSerializer.Serialize(report, AgentJsonContext.Default.AgentReport);
        row.JobId = report.JobId;
        row.Success = report.Success;
        row.Error = report.Error;
        row.StartedAt = report.StartedAtUtc;
        row.FinishedAt = report.FinishedAtUtc;
        row.ReceivedAt = now;
        await db.SaveChangesAsync(ct);
    }

    public async Task<StorageReport?> ReportAsync(Guid hostId, CancellationToken ct)
    {
        var row = await db.HostReports.AsNoTracking().FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == ReportKind, ct);
        return Parse(row?.Json);
    }

    public async Task<HostStorageDto?> HostAsync(Guid hostId, IReadOnlyList<ScheduleDto> schedules, CancellationToken ct)
    {
        var h = await db.Hosts.AsNoTracking().FirstOrDefaultAsync(x => x.Id == hostId, ct);
        if (h is null) return null;
        var row = await db.HostReports.AsNoTracking().FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == ReportKind, ct);
        var s = Parse(row?.Json);
        var running = (await RunningAsync([hostId], ct)).GetValueOrDefault(hostId);
        if (running is not null && s?.LastCleanup is { } last && last.Id == running.Id && last.AtUtc >= running.StartedAt) running = null;
        return new HostStorageDto(h.Id, h.Name, h.IsOnline, s?.ScannedAtUtc, row?.FinishedAt, row?.Success, row is { Success: false } ? row.Error : null,
            s?.Filesystems ?? [], s?.Directories ?? [], s?.LargestFiles ?? [], (s?.Cleanups ?? []).Select(ToDto).OfType<CleanupDto>().ToList(),
            s?.ReclaimableBytes ?? 0, s?.LastCleanup, running, s?.Notes ?? [], schedules);
    }

    public async Task<FleetStorageDto> FleetAsync(CancellationToken ct)
    {
        var hosts = await db.Hosts.AsNoTracking().Include(h => h.Group).OrderBy(h => h.Name).ToListAsync(ct);
        var reports = await db.HostReports.AsNoTracking().Where(r => r.Kind == ReportKind).ToDictionaryAsync(r => r.HostId, ct);
        var running = await RunningAsync(null, ct);
        var rows = hosts.Select(h =>
        {
            var s = Parse(reports.GetValueOrDefault(h.Id)?.Json);
            var run = running.GetValueOrDefault(h.Id);
            if (run is not null && s?.LastCleanup is { } last && last.Id == run.Id && last.AtUtc >= run.StartedAt) run = null;
            return new FleetStorageRow(h.Id, h.Name, h.IsOnline, h.Group?.Name, Dto.Percent(h.DiskUsedBytes, h.DiskTotalBytes), h.DiskUsedBytes, h.DiskTotalBytes,
                s?.ReclaimableBytes, s?.ScannedAtUtc, (s?.Cleanups ?? []).Select(c => new FleetCleanup(c.Id, c.Bytes, c.Items, c.Blocked is not null)).ToList(), run?.Id);
        }).OrderByDescending(r => r.DiskPercent).ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();
        return new FleetStorageDto(StorageCleanups.All, rows);
    }

    /// <summary>The latest cleanup command per host that is queued, or was acknowledged within the last hour.</summary>
    private async Task<Dictionary<Guid, RunningCleanupDto>> RunningAsync(IReadOnlyCollection<Guid>? hostIds, CancellationToken ct)
    {
        var since = time.GetUtcNow().UtcDateTime - RunningFor;
        var q = db.Commands.AsNoTracking().Where(c => c.Type == AgentCommandTypes.StorageCleanup && c.CreatedAt >= since
            && (c.Status == CommandStatus.Pending || c.Status == CommandStatus.Delivered || c.Status == CommandStatus.Succeeded));
        if (hostIds is not null) q = q.Where(c => hostIds.Contains(c.HostId));
        var cmds = await q.ToListAsync(ct);
        return cmds.GroupBy(c => c.HostId).ToDictionary(g => g.Key, g =>
        {
            var c = g.OrderByDescending(x => x.CreatedAt).First();
            return new RunningCleanupDto(c.Id, c.Payload.GetValueOrDefault("cleanup") ?? "", c.CreatedAt);
        });
    }

    public static CleanupDto? ToDto(CleanupCandidate c) =>
        StorageCleanups.Find(c.Id) is { } d ? new CleanupDto(d.Id, d.Title, d.Description, d.Risk, d.Display, c.Bytes, c.Items, c.Detail, c.Blocked) : null;

    private static StorageReport? Parse(string? json)
    {
        if (string.IsNullOrEmpty(json)) return null;
        try { return JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentReport)?.Storage; }
        catch (JsonException) { return null; }
    }
}
