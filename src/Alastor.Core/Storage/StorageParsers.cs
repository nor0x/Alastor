using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Alastor.Core.Storage;

/// <summary>Pure parsers for the disk tools the storage scan runs. Each one tolerates partial output: du and find keep going past unreadable folders.</summary>
public static partial class StorageParsers
{
    /// <summary>Kernel and memory filesystems: not disk space, and not worth showing.</summary>
    private static readonly HashSet<string> VirtualTypes = new(StringComparer.Ordinal)
    {
        "tmpfs", "devtmpfs", "ramfs", "overlay", "squashfs", "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "nsfs",
        "tracefs", "debugfs", "securityfs", "pstore", "bpf", "configfs", "hugetlbfs", "fusectl", "binfmt_misc", "efivarfs",
        "autofs", "rpc_pipefs", "nfsd", "fuse.lxcfs", "fuse.snapfuse", "fuse.portal", "shm", "none", "aufs",
    };

    /// <summary>Local disk filesystems the scan walks with du and find. Network mounts are shown, never walked.</summary>
    private static readonly HashSet<string> ScannableTypes = new(StringComparer.Ordinal)
    {
        "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "bcachefs",
    };

    public static bool IsScannable(FilesystemUsage fs) => ScannableTypes.Contains(fs.Type);

    /// <summary>
    /// <c>df -PTk</c>: <c>Filesystem Type 1024-blocks Used Available Capacity Mounted-on</c>. With <paramref name="hasType"/> false,
    /// <c>df -Pk</c> (BusyBox without -T), which has no type column. Virtual filesystems and duplicates of a mount are left out.
    /// </summary>
    public static List<FilesystemUsage> ParseDf(string output, bool hasType = true)
    {
        var result = new List<FilesystemUsage>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n').Skip(1))
        {
            var f = raw.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var n = hasType ? 7 : 6;
            if (f.Length < n) continue;
            var o = hasType ? 1 : 0;
            var type = hasType ? f[1] : "?";
            if (!long.TryParse(f[1 + o], CultureInfo.InvariantCulture, out var total) || !long.TryParse(f[2 + o], CultureInfo.InvariantCulture, out var used)
                || !long.TryParse(f[3 + o], CultureInfo.InvariantCulture, out var avail)) continue;
            var mount = string.Join(' ', f.Skip(5 + o));
            if (total == 0 || VirtualTypes.Contains(type) || type.StartsWith("fuse.", StringComparison.Ordinal) && type != "fuse.mergerfs") continue;
            if (!mount.StartsWith('/') || !seen.Add(mount)) continue;
            result.Add(new FilesystemUsage(mount, f[0], type, total * 1024, used * 1024, avail * 1024));
        }
        return result;
    }

    /// <summary><c>df -Pi</c>: <c>Filesystem Inodes IUsed IFree IUse% Mounted-on</c>, as mount → percent used. Filesystems without inode counts (btrfs) report "-".</summary>
    public static Dictionary<string, int> ParseDfInodes(string output)
    {
        var result = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n').Skip(1))
        {
            var f = raw.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (f.Length < 6 || !int.TryParse(f[4].TrimEnd('%'), CultureInfo.InvariantCulture, out var pct)) continue;
            result[string.Join(' ', f.Skip(5))] = pct;
        }
        return result;
    }

    /// <summary><c>du -k</c> lines: <c>size-in-KiB TAB path</c>. Later lines for the same path (a second run) win.</summary>
    public static Dictionary<string, long> ParseDu(string output)
    {
        var result = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var tab = line.IndexOf('\t');
            if (tab <= 0 || !long.TryParse(line.AsSpan(0, tab), NumberStyles.None, CultureInfo.InvariantCulture, out var kb)) continue;
            var path = line[(tab + 1)..];
            if (path.Length > 1) path = path.TrimEnd('/');
            if (path.StartsWith('/')) result[path] = kb * 1024;
        }
        return result;
    }

    /// <summary>Sum of the first column of <c>du -sk</c> output, in bytes.</summary>
    public static long ParseDuTotal(string output) => ParseDu(output).Values.Sum();

    /// <summary>
    /// The folder tree to show: starting at each root, the biggest children (at most <paramref name="maxChildren"/> per folder,
    /// none smaller than <paramref name="minBytes"/>), biggest first, until <paramref name="maxTotal"/> entries.
    /// </summary>
    public static List<DirectoryUsage> PruneTree(IReadOnlyDictionary<string, long> sizes, IEnumerable<string> roots, long minBytes, int maxChildren, int maxTotal)
    {
        var children = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var path in sizes.Keys)
        {
            if (path == "/") continue;
            var parent = ParentOf(path);
            if (!children.TryGetValue(parent, out var list)) children[parent] = list = [];
            list.Add(path);
        }
        var result = new List<DirectoryUsage>();
        var queue = new Queue<string>();
        foreach (var root in roots)
        {
            if (!sizes.TryGetValue(root, out var bytes) || result.Any(r => r.Path == root)) continue;
            result.Add(new DirectoryUsage(root, bytes));
            queue.Enqueue(root);
        }
        // Breadth first, so every top-level folder is in before any deep one when the cap is reached.
        while (queue.TryDequeue(out var dir) && result.Count < maxTotal)
        {
            if (!children.TryGetValue(dir, out var kids)) continue;
            foreach (var kid in kids.Where(k => sizes[k] >= minBytes && !result.Any(r => r.Path == k))
                         .OrderByDescending(k => sizes[k]).ThenBy(k => k, StringComparer.Ordinal).Take(maxChildren))
            {
                if (result.Count >= maxTotal) break;
                result.Add(new DirectoryUsage(kid, sizes[kid]));
                queue.Enqueue(kid);
            }
        }
        return result;
    }

    public static string ParentOf(string path)
    {
        var i = path.LastIndexOf('/');
        return i <= 0 ? "/" : path[..i];
    }

    /// <summary>
    /// <c>find -printf '%s %T@ %p\n'</c> (GNU) or <c>-exec stat -c '%s %Y %n' {} +</c> (BusyBox): size in bytes, modification time
    /// in Unix seconds (GNU adds a fraction), path. Biggest first, at most <paramref name="max"/>.
    /// </summary>
    public static List<LargeFile> ParseLargeFiles(string output, int max)
    {
        var result = new List<LargeFile>();
        foreach (var raw in output.Split('\n'))
        {
            var f = raw.TrimEnd('\r').Split(' ', 3);
            if (f.Length < 3 || !f[2].StartsWith('/') || !long.TryParse(f[0], NumberStyles.None, CultureInfo.InvariantCulture, out var size)) continue;
            DateTime? modified = double.TryParse(f[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var secs) && secs > 0
                ? DateTime.UnixEpoch.AddSeconds(Math.Floor(secs)) : null;
            result.Add(new LargeFile(f[2], size, modified));
        }
        return result.DistinctBy(f => f.Path).OrderByDescending(f => f.Bytes).ThenBy(f => f.Path, StringComparer.Ordinal).Take(max).ToList();
    }

    /// <summary>One size in bytes per line (<c>find -printf '%s\n'</c>, <c>stat -c %s</c>): the total and how many files.</summary>
    public static (long Bytes, int Files) ParseSizeList(string output)
    {
        long total = 0;
        var files = 0;
        foreach (var raw in output.Split('\n'))
            if (long.TryParse(raw.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var size))
            {
                total += size;
                files++;
            }
        return (total, files);
    }

    /// <summary>One row of <c>docker system df</c>. <see cref="Unused"/> is how many of them nothing uses (total − active).</summary>
    public sealed record DockerUsage(string Type, long ReclaimableBytes, int Unused);

    /// <summary><c>docker system df --format '{{json .}}'</c>: one JSON object per line, sizes in Docker's decimal units ("1.2GB (45%)").</summary>
    public static List<DockerUsage> ParseDockerDf(string output)
    {
        var result = new List<DockerUsage>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith('{')) continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                var r = doc.RootElement;
                string? Str(string name) => r.TryGetProperty(name, out var v) ? v.ValueKind == JsonValueKind.Number ? v.GetRawText() : v.GetString() : null;
                if (Str("Type") is not { } type) continue;
                var reclaimable = ParseHumanSize(Str("Reclaimable")?.Split(' ')[0]) ?? 0;
                var total = int.TryParse(Str("TotalCount"), CultureInfo.InvariantCulture, out var t) ? t : 0;
                var active = int.TryParse(Str("Active"), CultureInfo.InvariantCulture, out var a) ? a : 0;
                result.Add(new DockerUsage(type, reclaimable, Math.Max(0, total - active)));
            }
            catch (JsonException)
            {
            }
        }
        return result;
    }

    /// <summary><c>podman system df --format '{{.Type}}\t{{.RawReclaimable}}'</c>: type and reclaimable bytes per line.</summary>
    public static Dictionary<string, long> ParsePodmanDf(string output)
    {
        var result = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in output.Split('\n'))
        {
            var f = raw.Trim().Split('\t');
            if (f.Length == 2 && long.TryParse(f[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var bytes)) result[f[0].Trim()] = bytes;
        }
        return result;
    }

    /// <summary>
    /// Sizes as Docker ("1.2GB", "512kB", "0B": powers of 1000) and systemd ("1.2G", "88.0K": powers of 1024) print them.
    /// "KiB"/"MiB" style is always 1024-based.
    /// </summary>
    public static long? ParseHumanSize(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || HumanSizeRegex().Match(text.Trim()) is not { Success: true } m) return null;
        if (!double.TryParse(m.Groups["n"].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var n)) return null;
        var unit = m.Groups["u"].Value;
        var power = unit.Length == 0 ? 0 : "BKMGTP".IndexOf(char.ToUpperInvariant(unit[0]));
        if (power < 0) return null;
        // "1.2GB" and "512kB" are Docker's decimal units; a bare letter ("1.2G") or "GiB" is binary.
        var decimalUnit = unit.Length == 2 && unit[1] == 'B' && power > 0;
        return (long)Math.Round(n * Math.Pow(decimalUnit ? 1000 : 1024, power));
    }

    [GeneratedRegex(@"^(?<n>[0-9]+(?:\.[0-9]+)?)\s*(?<u>[BbKkMmGgTtPp](?:i?B)?)?$")]
    private static partial Regex HumanSizeRegex();

    /// <summary><c>journalctl --disk-usage</c>: "Archived and active journals take up 1.2G in the file system."</summary>
    public static long? ParseJournalUsage(string output) =>
        JournalRegex().Match(output) is { Success: true } m ? ParseHumanSize(m.Groups[1].Value) : null;

    [GeneratedRegex(@"take up ([0-9.]+\s*[A-Za-z]*) in the file ?system", RegexOptions.IgnoreCase)]
    private static partial Regex JournalRegex();

    /// <summary><c>snap list --all</c>: the revisions snapd keeps but doesn't use (Notes column says "disabled").</summary>
    public static List<(string Name, string Revision)> ParseSnapDisabled(string output)
    {
        var result = new List<(string, string)>();
        foreach (var raw in output.Split('\n').Skip(1))
        {
            var f = raw.TrimEnd('\r').Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length >= 3 && f.Skip(3).Any(n => n.Split(',').Contains("disabled")) && SnapNameRegex().IsMatch(f[0]) && f[2].All(char.IsAsciiDigit))
                result.Add((f[0], f[2]));
        }
        return result;
    }

    [GeneratedRegex(@"^[a-z0-9][a-z0-9-]{0,39}$")]
    private static partial Regex SnapNameRegex();

    /// <summary>
    /// Package-manager caches in home folders that <see cref="StorageCleanups.DevCaches"/> may delete: only these exact
    /// folders, directly in /root or a /home/&lt;user&gt; folder.
    /// </summary>
    public static bool IsDevCachePath(string path) => DevCacheRegex().IsMatch(path);

    [GeneratedRegex(@"^/(root|home/[A-Za-z0-9._][A-Za-z0-9._-]{0,63})/(\.cache/(pip|yarn|go-build|composer)|\.npm/_cacache|\.composer/cache)$")]
    private static partial Regex DevCacheRegex();
}
