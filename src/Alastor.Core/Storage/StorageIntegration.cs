using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Policy;
using Alastor.Core.Software;

namespace Alastor.Core.Storage;

/// <summary>
/// Where the disk space goes, and getting some back:
/// <list type="bullet">
/// <item>Filesystems from <c>df</c>; the folder tree from <c>du -x</c> and the biggest files from <c>find -xdev</c>, per local disk
/// mount, at the lowest CPU and IO priority (<c>nice</c>, <c>ionice -c 3</c>).</item>
/// <item>Every <see cref="StorageCleanups">cleanup</see> that applies to the host, measured with the tool it belongs to
/// (<c>docker system df</c>, <c>journalctl --disk-usage</c>, an apt dry run, …).</item>
/// <item>One cleanup on request: re-measured first, then exactly its commands, with df before and after.</item>
/// </list>
/// The server only ever names a cleanup by id; every path and argument comes from here.
/// </summary>
public sealed class StorageIntegration(
    ICommandRunner runner,
    IFileSystem fs,
    IStateStore state,
    OsInfo os,
    ILogger<StorageIntegration> logger,
    TimeProvider time) : IToolIntegration, IScheduledJobProvider
{
    public const string ScanJob = "storage.scan";
    public const string CleanupJob = "storage.cleanup";
    public const int TreeDepth = 3;
    public const int MaxDirectories = 400;
    public const int MaxFiles = 50;
    public const int MaxMounts = 8;

    private const long MinDirectoryBytes = 25L << 20;
    private const int MaxChildren = 15;
    private const string LargeFileFind = "+100M";
    private const string LargeFileBlocks = "+204800"; // the same 100 MiB in 512-byte blocks, for BusyBox find
    private const string StateLastReport = "storage.lastReport";

    private static readonly CommandOptions Measure = new() { Timeout = TimeSpan.FromMinutes(3) };
    private static readonly CommandOptions Walk = new() { Timeout = TimeSpan.FromMinutes(20) };
    private static readonly CommandOptions Change = new() { Timeout = TimeSpan.FromMinutes(30), Environment = new Dictionary<string, string> { ["DEBIAN_FRONTEND"] = "noninteractive" } };

    private static readonly string[] RotatedLogPatterns = ["*.gz", "*.xz", "*.bz2", "*.zst", "*.[0-9]", "*.[0-9].log", "*.old"];
    private static readonly string[] DevCacheSuffixes = ["*/.cache/pip", "*/.npm/_cacache", "*/.cache/yarn", "*/.cache/go-build", "*/.cache/composer", "*/.composer/cache"];

    private readonly Queue<SecurityEvent> _events = new();

    public static readonly ToolDescriptor Info = new(
        "storage",
        "Storage (df / du / find)",
        Capability.Storage,
        "GPL-3.0 (coreutils, findutils)",
        "https://www.gnu.org/software/coreutils/",
        new Dictionary<DistroFamily, string> { [DistroFamily.Debian] = "coreutils", [DistroFamily.RedHat] = "coreutils", [DistroFamily.Alpine] = "busybox" },
        "Measures disk usage per folder, finds the biggest files, and cleans up caches, old logs and unused container data on request.");

    public ToolDescriptor Descriptor => Info;

    public IReadOnlyList<ScheduledJob> Jobs =>
    [
        new(ScanJob, "Scan disk usage", "storage.scanSchedule", RunOnFirstStart: true, (_, _, ct) => ScanAsync(ct)),
    ];

    public bool IsWanted(PolicyDocument policy) => true;

    public Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        if (runner.Which("df") is null || runner.Which("du") is null)
            return Task.FromResult(new ToolStatus { ToolId = Info.Id, Availability = Availability.Unavailable, UnavailableReason = "df and du aren't installed." });
        var details = new Dictionary<string, string>();
        var last = LastReport();
        if (last?.Storage is { } s) details["reclaimableBytes"] = s.ReclaimableBytes.ToString(CultureInfo.InvariantCulture);
        return Task.FromResult(new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Running = true,
            Ownership = Ownership.Adopted,
            ConfigState = ConfigState.InSync,
            LastError = last is { Success: false } ? last.Error : null,
            LastSuccessAt = last is { Success: true } ? last.FinishedAtUtc : null,
            Details = details,
        });
    }

    public Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct) => DetectAsync(ct);

    public Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct) =>
        Task.FromResult(new ReconcilePlan(Info.Id, request.Revision, [], [], ConfigState.InSync));

    public Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        await Task.CompletedTask;
        while (_events.TryDequeue(out var e)) yield return e;
    }

    public Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    // ---- scan ----

    public async Task<AgentReport> ScanAsync(CancellationToken ct)
    {
        var started = time.GetUtcNow().UtcDateTime;
        var filesystems = await FilesystemsAsync(ct);
        if (filesystems.Count == 0)
        {
            var failed = new AgentReport(ScanJob, started, time.GetUtcNow().UtcDateTime, false, "df reported no filesystems.");
            await SaveReportAsync(failed with { Storage = LastReport()?.Storage }, ct);
            return failed;
        }

        var notes = new List<string>();
        var mounts = filesystems.Where(StorageParsers.IsScannable).Select(f => f.Mount)
            .OrderBy(m => m == "/" ? 0 : 1).ThenBy(m => m, StringComparer.Ordinal).Take(MaxMounts).ToList();
        if (mounts.Count == 0) mounts = filesystems.Any(f => f.Mount == "/") ? ["/"] : [];
        var sizes = new Dictionary<string, long>(StringComparer.Ordinal);
        var files = new List<LargeFile>();
        foreach (var mount in mounts)
        {
            var du = await runner.RunAsync(LowPriority("du"), [.. LowPriorityArgs("du"), "-xk", "-d", TreeDepth.ToString(CultureInfo.InvariantCulture), mount], Walk, ct);
            // du exits 1 when a folder vanished or wasn't readable, and still prints everything else.
            var parsed = StorageParsers.ParseDu(du.StdOut);
            if (parsed.Count == 0) notes.Add($"du couldn't measure {mount}: {Tail(du.CombinedOutput, 200)}");
            foreach (var (path, bytes) in parsed) sizes[path] = bytes;
            files.AddRange(await LargeFilesAsync(mount, notes, ct));
        }

        var report = new StorageReport(
            filesystems,
            StorageParsers.PruneTree(sizes, mounts, MinDirectoryBytes, MaxChildren, MaxDirectories),
            files.DistinctBy(f => f.Path).OrderByDescending(f => f.Bytes).Take(MaxFiles).ToList(),
            (await MeasureAsync(_ => true, notes, ct)).Select(m => m.Candidate).ToList(),
            time.GetUtcNow().UtcDateTime,
            LastReport()?.Storage?.LastCleanup) { Notes = notes };
        var result = new AgentReport(ScanJob, started, time.GetUtcNow().UtcDateTime, true, null) { Storage = report };
        await SaveReportAsync(result, ct);
        logger.LogInformation("Storage scan: {Dirs} folders, {Files} large files, {Reclaimable} MiB reclaimable", report.Directories.Count, report.LargestFiles.Count, report.ReclaimableBytes >> 20);
        return result;
    }

    private async Task<List<FilesystemUsage>> FilesystemsAsync(CancellationToken ct)
    {
        var df = await runner.RunAsync("df", ["-PTk"], Measure, ct);
        var list = StorageParsers.ParseDf(df.StdOut);
        if (list.Count == 0)
        {
            // BusyBox df without -T: no types, so every mount looks like a disk.
            df = await runner.RunAsync("df", ["-Pk"], Measure, ct);
            list = StorageParsers.ParseDf(df.StdOut, hasType: false);
        }
        var inodes = await runner.RunAsync("df", ["-Pi"], Measure, ct) is { StdOut.Length: > 0 } i ? StorageParsers.ParseDfInodes(i.StdOut) : [];
        return list.Select(f => inodes.TryGetValue(f.Mount, out var pct) ? f with { InodesUsedPercent = pct } : f).ToList();
    }

    private async Task<List<LargeFile>> LargeFilesAsync(string mount, List<string> notes, CancellationToken ct)
    {
        var find = await runner.RunAsync(LowPriority("find"), [.. LowPriorityArgs("find"), mount, "-xdev", "-type", "f", "-size", LargeFileFind, "-printf", "%s %T@ %p\n"], Walk, ct);
        if (!find.Success && find.StdOut.Length == 0)
        {
            // BusyBox find has neither -printf nor M sizes.
            find = await runner.RunAsync(LowPriority("find"), [.. LowPriorityArgs("find"), mount, "-xdev", "-type", "f", "-size", LargeFileBlocks, "-exec", "stat", "-c", "%s %Y %n", "{}", "+"], Walk, ct);
            if (!find.Success && find.StdOut.Length == 0)
            {
                notes.Add($"Couldn't list the biggest files on {mount}: {Tail(find.CombinedOutput, 200)}");
                return [];
            }
        }
        return StorageParsers.ParseLargeFiles(find.StdOut, MaxFiles);
    }

    private string LowPriority(string program) => runner.Which("nice") is not null ? "nice" : program;

    private string[] LowPriorityArgs(string program) =>
        runner.Which("nice") is null ? []
        : runner.Which("ionice") is not null ? ["-n", "19", "ionice", "-c", "3", program]
        : ["-n", "19", program];

    // ---- measuring cleanups ----

    /// <summary>A cleanup as it applies here: what it would free, and the exact commands that would do it.</summary>
    private sealed record Measured(CleanupCandidate Candidate, IReadOnlyList<PackageCommand> Commands);

    private async Task<List<Measured>> MeasureAsync(Func<string, bool> wanted, List<string> notes, CancellationToken ct)
    {
        var result = new List<Measured>();
        async Task Add(string id, Func<Task<Measured?>> measure)
        {
            if (!wanted(id)) return;
            try
            {
                if (await measure() is { } m) result.Add(m);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Measuring {Cleanup} failed", id);
                notes.Add($"Couldn't measure {id}: {ex.Message}");
            }
        }

        if (os.Family == DistroFamily.Debian && runner.Which("apt-get") is not null)
            await Add(StorageCleanups.AptCache, () => DirectoriesAsync(StorageCleanups.AptCache, ["/var/cache/apt"], [new("apt-get", ["clean"])], ct));
        if (runner.Which("dnf") is not null)
            await Add(StorageCleanups.DnfCache, () => DirectoriesAsync(StorageCleanups.DnfCache, ["/var/cache/dnf", "/var/cache/libdnf5", "/var/cache/yum"], [new("dnf", ["clean", "all"])], ct));
        if (runner.Which("apk") is not null && fs.DirectoryExists("/etc/apk/cache"))
            await Add(StorageCleanups.ApkCache, () => DirectoriesAsync(StorageCleanups.ApkCache, ["/etc/apk/cache/"], [new("apk", ["cache", "clean"])], ct));
        if (runner.Which("journalctl") is not null)
            await Add(StorageCleanups.JournalVacuum, () => JournalAsync(ct));
        if (fs.DirectoryExists("/var/log"))
            await Add(StorageCleanups.RotatedLogs, () => FindAsync(StorageCleanups.RotatedLogs, RotatedLogsArgs(), ["-delete"], ct));
        if (runner.Which("docker") is not null && StorageCleanups.All.Any(c => c.Id.StartsWith("docker.", StringComparison.Ordinal) && wanted(c.Id)))
            result.AddRange((await DockerAsync(notes, ct)).Where(m => wanted(m.Candidate.Id)));
        if (runner.Which("docker") is not null && fs.DirectoryExists("/var/lib/docker/containers"))
            await Add(StorageCleanups.DockerLogs, () => FindAsync(StorageCleanups.DockerLogs, ["/var/lib/docker/containers", "-type", "f", "-name", "*-json.log"], ["-exec", "truncate", "-s", "0", "{}", "+"], ct));
        if (runner.Which("podman") is not null)
            await Add(StorageCleanups.PodmanPrune, () => PodmanAsync(notes, ct));
        if (os.Family == DistroFamily.Debian && runner.Which("apt-get") is not null)
            await Add(StorageCleanups.AptAutoremove, () => AptAutoremoveAsync(ct));
        if (runner.Which("dnf") is not null)
            await Add(StorageCleanups.DnfAutoremove, () => DnfAutoremoveAsync(ct));
        if (runner.Which("snap") is not null)
            await Add(StorageCleanups.SnapRevisions, () => SnapAsync(ct));
        await Add(StorageCleanups.DevCaches, () => DevCachesAsync(ct));
        var crash = new[] { "/var/crash", "/var/lib/systemd/coredump" }.Where(fs.DirectoryExists).ToArray();
        if (crash.Length > 0)
            await Add(StorageCleanups.CrashDumps, () => FindAsync(StorageCleanups.CrashDumps, [.. crash, "-xdev", "-type", "f"], ["-delete"], ct));
        var tmp = new[] { "/tmp", "/var/tmp" }.Where(fs.DirectoryExists).ToArray();
        if (tmp.Length > 0)
            await Add(StorageCleanups.OldTempFiles, () => FindAsync(StorageCleanups.OldTempFiles, [.. tmp, "-xdev", "-type", "f", "-mtime", "+10", "-atime", "+10"], ["-delete"], ct));
        return result.OrderBy(m => StorageCleanups.All.ToList().FindIndex(c => c.Id == m.Candidate.Id)).ToList();
    }

    private static string[] RotatedLogsArgs()
    {
        var names = RotatedLogPatterns.SelectMany((p, i) => i == 0 ? new[] { "-name", p } : ["-o", "-name", p]);
        return ["/var/log", "-xdev", "-type", "f", "!", "-path", "/var/log/journal/*", "(", .. names, ")"];
    }

    private async Task<Measured?> DirectoriesAsync(string id, string[] dirs, PackageCommand[] commands, CancellationToken ct)
    {
        var existing = dirs.Where(fs.DirectoryExists).ToArray();
        if (existing.Length == 0) return new(new CleanupCandidate(id, 0), commands);
        var du = await runner.RunAsync("du", ["-sk", .. existing], Measure, ct);
        return new(new CleanupCandidate(id, StorageParsers.ParseDuTotal(du.StdOut)), commands);
    }

    /// <summary>Files matched by <c>find <paramref name="match"/></c>; the cleanup is the same find with <paramref name="action"/> appended.</summary>
    private async Task<Measured?> FindAsync(string id, string[] match, string[] action, CancellationToken ct)
    {
        var (bytes, files) = await SumFilesAsync(match, ct);
        // Empty files free nothing (a fresh container log), so they alone don't make the cleanup worth running.
        return new(new CleanupCandidate(id, bytes, files), bytes == 0 ? [] : [new("find", [.. match, .. action])]);
    }

    private async Task<(long Bytes, int Files)> SumFilesAsync(string[] match, CancellationToken ct)
    {
        var r = await runner.RunAsync("find", [.. match, "-printf", "%s\n"], Measure, ct);
        if (!r.Success && r.StdOut.Length == 0) r = await runner.RunAsync("find", [.. match, "-exec", "stat", "-c", "%s", "{}", "+"], Measure, ct);
        return StorageParsers.ParseSizeList(r.StdOut);
    }

    private async Task<Measured?> JournalAsync(CancellationToken ct)
    {
        var r = await runner.RunAsync("journalctl", ["--disk-usage"], Measure, ct);
        if (StorageParsers.ParseJournalUsage(r.CombinedOutput) is not { } usage) return null;
        var keep = StorageParsers.ParseHumanSize(StorageCleanups.JournalKeep)!.Value;
        var bytes = Math.Max(0, usage - keep);
        return new(new CleanupCandidate(StorageCleanups.JournalVacuum, bytes, Detail: $"The journal uses {Format(usage)}."),
            bytes == 0 ? [] : [new("journalctl", [$"--vacuum-size={StorageCleanups.JournalKeep}"])]);
    }

    private async Task<List<Measured>> DockerAsync(List<string> notes, CancellationToken ct)
    {
        var r = await runner.RunAsync("docker", ["system", "df", "--format", "{{json .}}"], Measure, ct);
        var rows = StorageParsers.ParseDockerDf(r.StdOut);
        if (rows.Count == 0)
        {
            notes.Add($"Docker didn't report its disk usage: {Tail(r.CombinedOutput, 200)}");
            return [];
        }
        Measured Row(string type, string id, string noun, PackageCommand command)
        {
            var row = rows.FirstOrDefault(x => x.Type.Equals(type, StringComparison.OrdinalIgnoreCase));
            var bytes = row?.ReclaimableBytes ?? 0;
            int? unused = type == "Build Cache" ? null : row?.Unused ?? 0;
            var detail = unused is > 0 ? $"{unused} unused {noun}{(unused == 1 ? "" : "s")}" : null;
            return new(new CleanupCandidate(id, bytes, unused, detail), bytes == 0 && unused is null or 0 ? [] : [command]);
        }
        return
        [
            Row("Build Cache", StorageCleanups.DockerBuildCache, "entry", new("docker", ["builder", "prune", "-a", "-f"])),
            Row("Containers", StorageCleanups.DockerContainers, "container", new("docker", ["container", "prune", "-f"])),
            Row("Images", StorageCleanups.DockerImages, "image", new("docker", ["image", "prune", "-a", "-f"])),
            Row("Local Volumes", StorageCleanups.DockerVolumes, "volume", new("docker", ["volume", "prune", "-a", "-f"])),
        ];
    }

    private async Task<Measured?> PodmanAsync(List<string> notes, CancellationToken ct)
    {
        var r = await runner.RunAsync("podman", ["system", "df", "--format", "{{.Type}}\t{{.RawReclaimable}}"], Measure, ct);
        var rows = StorageParsers.ParsePodmanDf(r.StdOut);
        if (rows.Count == 0)
        {
            notes.Add($"Podman didn't report its disk usage: {Tail(r.CombinedOutput, 200)}");
            return null;
        }
        var bytes = rows.Where(kv => !kv.Key.Contains("volume", StringComparison.OrdinalIgnoreCase)).Sum(kv => kv.Value);
        return new(new CleanupCandidate(StorageCleanups.PodmanPrune, bytes), bytes == 0 ? [] : [new("podman", ["system", "prune", "-a", "-f"])]);
    }

    private async Task<Measured?> AptAutoremoveAsync(CancellationToken ct)
    {
        var sim = await runner.RunAsync("apt-get", ["-s", "-o", "Debug::NoLocking=1", "autoremove"], Measure, ct);
        if (!sim.Success) return null;
        var names = SoftwareParsers.ParseAptPlan(sim.StdOut).Where(p => p.Action == "remove").Select(p => p.Name).Distinct().ToList();
        if (names.Count == 0) return new(new CleanupCandidate(StorageCleanups.AptAutoremove, 0, 0), []);
        long? bytes = null;
        if (runner.Which("dpkg-query") is not null
            && await runner.RunAsync("dpkg-query", ["-W", "-f=${Installed-Size}\n", .. names], Measure, ct) is { StdOut.Length: > 0 } q)
            bytes = StorageParsers.ParseSizeList(q.StdOut).Bytes * 1024;
        return new(new CleanupCandidate(StorageCleanups.AptAutoremove, bytes, names.Count, Describe(names), await BlockedAsync(names, ct)),
            [new("apt-get", ["autoremove", "-y", "-q", "-o", "DPkg::Lock::Timeout=300"])]);
    }

    private async Task<Measured?> DnfAutoremoveAsync(CancellationToken ct)
    {
        // --assumeno always exits 1 after printing the transaction, so the table is the only signal.
        var sim = await runner.RunAsync("dnf", ["--assumeno", "autoremove"], Measure, ct);
        var names = SoftwareParsers.ParseDnfPlan(sim.StdOut).Where(p => p.Action == "remove").Select(p => p.Name).Distinct().ToList();
        if (names.Count == 0)
            return sim.CombinedOutput.Contains("Nothing to do", StringComparison.OrdinalIgnoreCase) ? new(new CleanupCandidate(StorageCleanups.DnfAutoremove, 0, 0), []) : null;
        return new(new CleanupCandidate(StorageCleanups.DnfAutoremove, null, names.Count, Describe(names), await BlockedAsync(names, ct)),
            [new("dnf", ["-y", "-q", "autoremove"])]);
    }

    /// <summary>
    /// Autoremove may take old kernels (that's much of what it frees) but never the running one, nor any other protected package.
    /// </summary>
    private async Task<string?> BlockedAsync(IReadOnlyList<string> names, CancellationToken ct)
    {
        var running = (await fs.ReadAllTextAsync("/proc/sys/kernel/osrelease", ct))?.Trim() ?? "";
        var blocked = names.Where(n => IsVersionedKernel(n) ? running.Length > 0 && n.Contains(running, StringComparison.Ordinal) : ProtectedPackages.IsProtected(n)).ToList();
        return blocked.Count == 0 ? null : $"It would remove protected package{(blocked.Count == 1 ? "" : "s")} {string.Join(", ", blocked)}.";
    }

    /// <summary>A kernel package for one specific version (linux-image-6.8.0-45-generic, kernel-core-6.11.4-…), not the meta package that pulls in new ones.</summary>
    public static bool IsVersionedKernel(string name) =>
        new[] { "linux-image-", "linux-modules-", "linux-headers-", "kernel-core-", "kernel-modules-", "kernel-" }
            .Any(p => name.StartsWith(p, StringComparison.Ordinal) && name.Length > p.Length && char.IsAsciiDigit(name[p.Length]));

    private async Task<Measured?> SnapAsync(CancellationToken ct)
    {
        var r = await runner.RunAsync("snap", ["list", "--all"], Measure, ct);
        if (!r.Success) return null;
        var disabled = StorageParsers.ParseSnapDisabled(r.StdOut);
        var files = disabled.Select(d => $"/var/lib/snapd/snaps/{d.Name}_{d.Revision}.snap").Where(fs.FileExists).ToArray();
        long bytes = files.Length == 0 ? 0 : StorageParsers.ParseDuTotal((await runner.RunAsync("du", ["-sk", .. files], Measure, ct)).StdOut);
        return new(new CleanupCandidate(StorageCleanups.SnapRevisions, bytes, disabled.Count, Describe(disabled.Select(d => $"{d.Name} rev {d.Revision}").ToList())),
            disabled.Select(d => new PackageCommand("snap", ["remove", d.Name, $"--revision={d.Revision}"])).ToList());
    }

    private async Task<Measured?> DevCachesAsync(CancellationToken ct)
    {
        var roots = new[] { "/root", "/home" }.Where(fs.DirectoryExists).ToArray();
        if (roots.Length == 0) return null;
        var names = DevCacheSuffixes.SelectMany((p, i) => i == 0 ? new[] { "-path", p } : ["-o", "-path", p]);
        var r = await runner.RunAsync("find", [.. roots, "-mindepth", "2", "-maxdepth", "3", "-type", "d", "(", .. names, ")", "-prune", "-print"], Measure, ct);
        // Only the exact cache folders: anything else find printed (a symlinked home, an odd name) is never deleted.
        var dirs = r.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(StorageParsers.IsDevCachePath).Distinct().Order(StringComparer.Ordinal).ToArray();
        if (dirs.Length == 0) return null;
        var bytes = StorageParsers.ParseDuTotal((await runner.RunAsync("du", ["-sk", .. dirs], Measure, ct)).StdOut);
        return new(new CleanupCandidate(StorageCleanups.DevCaches, bytes, dirs.Length, Describe(dirs)), [new("rm", ["-rf", "--", .. dirs])]);
    }

    private static string Describe(IReadOnlyList<string> items) =>
        items.Count <= 6 ? string.Join(", ", items) : $"{string.Join(", ", items.Take(5))} and {items.Count - 5} more";

    // ---- cleanup ----

    /// <summary>
    /// Runs one cleanup: measures it again (so it acts on what is there now, not at the last scan), runs its commands in
    /// order, and reports the fresh filesystems and candidates with the outcome in <see cref="StorageReport.LastCleanup"/>.
    /// </summary>
    public async Task<AgentReport> RunCleanupAsync(string id, CancellationToken ct)
    {
        var started = time.GetUtcNow().UtcDateTime;
        var before = await FilesystemsAsync(ct);
        var notes = new List<string>();
        var measured = StorageCleanups.Find(id) is null ? null : (await MeasureAsync(x => x == id, notes, ct)).FirstOrDefault(m => m.Candidate.Id == id);

        var log = new StringBuilder();
        string? error = null;
        if (StorageCleanups.Find(id) is null) error = $"Unknown cleanup '{id}'.";
        else if (measured is null) error = notes.Count > 0 ? notes[0] : "This cleanup doesn't apply to this host (the tool it needs isn't installed).";
        else if (measured.Candidate.Blocked is { } blocked) error = $"Refused: {blocked}";
        else
        {
            var packages = id is StorageCleanups.AptAutoremove or StorageCleanups.DnfAutoremove;
            if (packages) await PackageManagerLock.Instance.WaitAsync(ct);
            try
            {
                foreach (var cmd in measured.Commands)
                {
                    var r = await runner.RunAsync(cmd.FileName, cmd.Args, Change, ct);
                    // Docker before 23 has no -a for volume prune; without it, only anonymous volumes go.
                    if (!r.Success && id == StorageCleanups.DockerVolumes && r.CombinedOutput.Contains("unknown shorthand flag", StringComparison.Ordinal))
                        r = await runner.RunAsync("docker", ["volume", "prune", "-f"], Change, ct);
                    log.AppendLine($"$ {cmd.FileName} {string.Join(' ', cmd.Args)}").AppendLine(r.CombinedOutput.Trim());
                    if (!r.Success)
                    {
                        error = $"{cmd.FileName} failed: {Tail(r.CombinedOutput, 400)}";
                        break;
                    }
                }
            }
            finally
            {
                if (packages) PackageManagerLock.Instance.Release();
            }
        }

        var after = await FilesystemsAsync(ct);
        var freed = Math.Max(0, after.Sum(a => a.AvailableBytes - (before.FirstOrDefault(b => b.Mount == a.Mount)?.AvailableBytes ?? a.AvailableBytes)));
        var result = new CleanupResult(time.GetUtcNow().UtcDateTime, id, error is null, freed, error, Tail(log.ToString(), 3000));
        RaiseCleanupEvent(result);
        logger.LogInformation("Storage cleanup {Cleanup}: success={Success}, freed {Freed} MiB", id, result.Success, freed >> 20);

        var last = LastReport()?.Storage;
        var report = new StorageReport(after.Count > 0 ? after : last?.Filesystems ?? [], last?.Directories ?? [], last?.LargestFiles ?? [],
            (await MeasureAsync(_ => true, notes, ct)).Select(m => m.Candidate).ToList(), last?.ScannedAtUtc, result) { Notes = notes };
        var finished = time.GetUtcNow().UtcDateTime;
        await SaveReportAsync(new AgentReport(ScanJob, started, finished, true, null) { Storage = report }, ct);
        return new AgentReport(CleanupJob, started, finished, result.Success, error) { Storage = report };
    }

    private void RaiseCleanupEvent(CleanupResult r)
    {
        var title = StorageCleanups.Find(r.Id)?.Title ?? r.Id;
        _events.Enqueue(new SecurityEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = r.AtUtc,
            Capability = Capability.Storage,
            Severity = r.Success ? Severity.Info : Severity.Medium,
            SourceTool = Info.Id,
            Kind = r.Success ? EventKinds.StorageCleaned : EventKinds.StorageCleanupFailed,
            Subject = r.Id,
            Message = r.Success ? $"{title}: freed {Format(r.FreedBytes)}" : $"{title}: cleanup failed: {r.Error}",
            Raw = r.Success ? null : r.LogTail,
            Metadata = new Dictionary<string, string> { ["cleanup"] = r.Id, ["freedBytes"] = r.FreedBytes.ToString(CultureInfo.InvariantCulture) },
        });
    }

    // ---- state ----

    private AgentReport? LastReport() =>
        state.Get(StateLastReport) is { } json ? JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentReport) : null;

    private Task SaveReportAsync(AgentReport report, CancellationToken ct) =>
        state.SetAsync(StateLastReport, JsonSerializer.Serialize(report, AgentJsonContext.Default.AgentReport), ct);

    /// <summary>Binary units, the way df -h prints them.</summary>
    public static string Format(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = bytes;
        var u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? $"{bytes} B" : string.Create(CultureInfo.InvariantCulture, $"{v:0.#} {units[u]}");
    }

    private static string Tail(string s, int max)
    {
        s = s.Trim();
        return s.Length <= max ? s : "…" + s[^max..];
    }
}
