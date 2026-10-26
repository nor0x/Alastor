namespace Alastor.Core.Storage;

/// <summary>One mounted filesystem, as <c>df</c> reports it.</summary>
public sealed record FilesystemUsage(string Mount, string Device, string Type, long TotalBytes, long UsedBytes, long AvailableBytes)
{
    /// <summary>Share of inodes in use (<c>df -i</c>). A filesystem can run out of inodes with plenty of space left.</summary>
    public int? InodesUsedPercent { get; init; }
}

/// <summary>A folder and everything below it on the same filesystem (<c>du -x</c>).</summary>
public sealed record DirectoryUsage(string Path, long Bytes);

/// <summary>One of the biggest files on the host.</summary>
public sealed record LargeFile(string Path, long Bytes, DateTime? ModifiedUtc);

/// <summary>One cleanup from <see cref="StorageCleanups"/> that applies to this host, with what it would free.</summary>
/// <param name="Bytes">Space the cleanup would free, as measured; null when the tool can't tell (it's then listed by <see cref="Items"/>).</param>
/// <param name="Items">How many things it would remove (images, packages, revisions, files), when that's known.</param>
/// <param name="Detail">What exactly would go, e.g. the old kernels autoremove would take.</param>
/// <param name="Blocked">Why the agent refuses to run it here (it would remove a protected package). Null means it can run.</param>
public sealed record CleanupCandidate(string Id, long? Bytes, int? Items = null, string? Detail = null, string? Blocked = null);

/// <summary>The outcome of one cleanup started from the dashboard.</summary>
/// <param name="FreedBytes">Free space gained on the host's filesystems, measured with df before and after.</param>
public sealed record CleanupResult(DateTime AtUtc, string Id, bool Success, long FreedBytes, string? Error, string LogTail);

/// <summary>Disk usage on one host: filesystems, where the space goes, and what can be cleaned up.</summary>
/// <param name="Directories">Folders down to <see cref="StorageIntegration.TreeDepth"/> levels below each scanned mount, biggest first, small ones left out.</param>
/// <param name="ScannedAtUtc">When <see cref="Directories"/> and <see cref="LargestFiles"/> were measured. A cleanup refreshes only the filesystems and candidates.</param>
public sealed record StorageReport(
    IReadOnlyList<FilesystemUsage> Filesystems,
    IReadOnlyList<DirectoryUsage> Directories,
    IReadOnlyList<LargeFile> LargestFiles,
    IReadOnlyList<CleanupCandidate> Cleanups,
    DateTime? ScannedAtUtc,
    CleanupResult? LastCleanup)
{
    /// <summary>Things the scan couldn't do (no <c>find -printf</c> on BusyBox, Docker not answering), shown under the report.</summary>
    public IReadOnlyList<string> Notes { get; init; } = [];

    /// <summary>What the non-destructive cleanups would free together. Destructive ones (unused Docker volumes) are left out.</summary>
    public long ReclaimableBytes => Cleanups
        .Where(c => c.Blocked is null && StorageCleanups.Find(c.Id) is { Risk: not CleanupRisk.Destructive })
        .Sum(c => c.Bytes ?? 0);
}

public enum CleanupRisk
{
    /// <summary>Removes only caches and old copies that are rebuilt or downloaded again when needed.</summary>
    Safe,

    /// <summary>Removes things that are usually unused but someone might still want (stopped containers, unused images, old temp files).</summary>
    Caution,

    /// <summary>Deletes data that can't be recovered (unused Docker volumes). The dashboard asks for the host name before running it.</summary>
    Destructive,
}
