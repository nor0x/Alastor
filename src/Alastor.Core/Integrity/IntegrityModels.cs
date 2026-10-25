using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Alastor.Core.Integrity;

/// <summary>One file AIDE found added, removed or changed since the baseline.</summary>
/// <param name="Change"><c>added</c>, <c>removed</c> or <c>changed</c>.</param>
/// <param name="Flags">AIDE's summary string for the entry (<c>f &gt; ... ....H</c>: type, then one column per attribute).</param>
/// <param name="Attributes">What changed, from the detailed section: size, sha256, perm, uid, …</param>
public sealed record IntegrityChange(string Path, string Change, string Flags, IReadOnlyList<string> Attributes)
{
    /// <summary>Binaries, SSH, accounts and sudo: places an intruder edits to keep access.</summary>
    public bool Critical => IntegrityRules.IsCritical(Path);
}

/// <summary>The result of one AIDE run.</summary>
/// <param name="Mode"><c>init</c> (baseline recorded), <c>check</c> or <c>accept</c> (baseline updated to the current files).</param>
/// <param name="Entries">Files and directories in the database.</param>
public sealed record IntegrityReport(string? AideVersion, string Mode, int Entries, IReadOnlyList<IntegrityChange> Changes, IReadOnlyList<string> Paths, bool Truncated = false);

public static class IntegrityRules
{
    private static readonly string[] CriticalPrefixes =
        ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/etc/ssh/", "/root/.ssh/", "/etc/sudoers", "/etc/pam.d/", "/usr/lib/systemd/system/"];

    private static readonly string[] CriticalFiles = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/ld.so.preload", "/etc/crontab"];

    public static bool IsCritical(string path) =>
        CriticalFiles.Contains(path, StringComparer.Ordinal) || CriticalPrefixes.Any(p => path.StartsWith(p, StringComparison.Ordinal));
}

/// <summary>
/// Reads AIDE's reports: the JSON report (<c>report_format=json</c>, AIDE 0.18+: <c>added</c>/<c>removed</c>/<c>changed</c>
/// maps of path to summary string, <c>details</c> per changed path) and, for older versions, the plain report (the
/// "Added/Removed/Changed entries:" sections and the "File: … " detail blocks). Both captured from AIDE 0.18.6.
/// </summary>
public static partial class AideParser
{
    /// <summary>AIDE's exit code is a bit mask of found differences: 1 added, 2 removed, 4 changed. 14 and up are errors.</summary>
    public static bool IsSuccess(int exitCode) => exitCode is >= 0 and < 8;

    /// <summary>"AIDE 0.18.6" (newer) or "Aide 0.16" (older) on the first line of <c>aide --version</c> (some versions print it to stderr).</summary>
    public static Version? ParseVersion(string output) =>
        VersionLine().Match(output) is { Success: true } m && Version.TryParse(m.Groups[1].Value, out var v) ? v : null;

    public static (int Entries, List<IntegrityChange> Changes) Parse(string output)
    {
        var trimmed = output.TrimStart();
        return trimmed.StartsWith('{') ? ParseJson(trimmed) : ParsePlain(output);
    }

    public static (int Entries, List<IntegrityChange> Changes) ParseJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var entries = root.TryGetProperty("number_of_entries", out var n) && n.TryGetProperty("total", out var t) && t.TryGetInt32(out var total) ? total : 0;
        var details = root.TryGetProperty("details", out var d) && d.ValueKind == JsonValueKind.Object ? d : default;
        var changes = new List<IntegrityChange>();
        foreach (var kind in new[] { "added", "removed", "changed" })
        {
            if (!root.TryGetProperty(kind, out var map) || map.ValueKind != JsonValueKind.Object) continue;
            foreach (var entry in map.EnumerateObject())
            {
                var attrs = details.ValueKind == JsonValueKind.Object && details.TryGetProperty(entry.Name, out var a) && a.ValueKind == JsonValueKind.Object
                    ? a.EnumerateObject().Select(x => x.Name).ToList()
                    : [];
                changes.Add(new IntegrityChange(entry.Name, kind, (entry.Value.GetString() ?? "").TrimEnd(), attrs));
            }
        }
        return (entries, changes);
    }

    public static (int Entries, List<IntegrityChange> Changes) ParsePlain(string output)
    {
        var changes = new List<IntegrityChange>();
        var attributes = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        int entries = 0;
        string? section = null;
        string? detailFile = null;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (TotalEntries().Match(line) is { Success: true } te) entries = int.Parse(te.Groups[1].Value, CultureInfo.InvariantCulture);
            var header = line.Trim();
            if (header is "Added entries:" or "Removed entries:" or "Changed entries:" or "Detailed information about changes:")
            {
                section = header.Split(' ')[0].ToLowerInvariant();
                detailFile = null;
                continue;
            }
            if (header.StartsWith("The attributes of the", StringComparison.Ordinal)) { section = null; continue; }
            if (section is "added" or "removed" or "changed" && EntryLine().Match(line) is { Success: true } e)
                changes.Add(new IntegrityChange(e.Groups["path"].Value, section, e.Groups["flags"].Value.TrimEnd(), []));
            else if (section == "detailed")
            {
                if (line.StartsWith("File: ", StringComparison.Ordinal) || line.StartsWith("Directory: ", StringComparison.Ordinal) || line.StartsWith("Link: ", StringComparison.Ordinal))
                    detailFile = line[(line.IndexOf(':') + 2)..];
                else if (detailFile is not null && DetailAttribute().Match(line) is { Success: true } da)
                {
                    if (!attributes.TryGetValue(detailFile, out var list)) attributes[detailFile] = list = [];
                    list.Add(da.Groups[1].Value.ToLowerInvariant());
                }
            }
        }
        return (entries, changes.Select(c => attributes.TryGetValue(c.Path, out var a) ? c with { Attributes = a } : c).ToList());
    }

    [GeneratedRegex(@"\b(?:AIDE|Aide) (\d+(?:\.\d+){1,3})")]
    private static partial Regex VersionLine();

    [GeneratedRegex(@"^\s*(?:Total number of entries|Number of entries):\s*(\d+)")]
    private static partial Regex TotalEntries();

    // "f+++++++++++++++++: /etc/x", "f > ... ....H     : /usr/bin/ls" (0.18), "f   ...    .C... : /etc/x" (0.16/0.17).
    [GeneratedRegex(@"^(?<flags>[-a-zA-Z!?][^:]*?)\s*: (?<path>/.*)$")]
    private static partial Regex EntryLine();

    // " Size      : 2      | 8" — the attribute name before the colon; continuation lines start with spaces only.
    [GeneratedRegex(@"^ ([A-Za-z][A-Za-z0-9]*)\s+: ")]
    private static partial Regex DetailAttribute();
}

/// <summary>The aide.conf the agent writes into its own state directory, so the distribution's configuration is never touched.</summary>
public static class AideConfig
{
    /// <summary>Volatile files under /etc that change in normal operation, and everything the agent itself manages.</summary>
    public static readonly IReadOnlyList<string> BuiltInExcludes =
        ["/etc/mtab", "/etc/adjtime", "/etc/resolv.conf", "/etc/ld.so.cache", "/etc/.pwd.lock", "/etc/aide", "/etc/rkhunter.conf", "/var/lib/rkhunter"];

    public static string Render(string dbDir, Version? aideVersion, IEnumerable<string> paths, IEnumerable<string> exclude)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("# Written by the Alastor agent for its own AIDE runs (integrity.paths / integrity.exclude). Regenerated before every run.");
        sb.AppendLine($"database_in=file:{dbDir}/aide.db");
        sb.AppendLine($"database_out=file:{dbDir}/aide.db.new");
        sb.AppendLine("gzip_dbout=no");
        // report_format exists from AIDE 0.18 and applies to the report_url lines that follow it.
        if (aideVersion is not null && aideVersion >= new Version(0, 18)) sb.AppendLine("report_format=json");
        sb.AppendLine("report_url=stdout");
        // Permissions, owner, group, size, mtime and content hash. Inode and ctime are left out: they change on every
        // package upgrade and copy without the content changing.
        sb.AppendLine("AlastorChecks = p+u+g+s+m+sha256");
        foreach (var p in paths.Distinct(StringComparer.Ordinal)) sb.AppendLine($"{Escape(p.TrimEnd('/'))} AlastorChecks");
        foreach (var e in BuiltInExcludes.Concat(exclude).Distinct(StringComparer.Ordinal)) sb.AppendLine($"!{Escape(e.TrimEnd('/'))}");
        sb.AppendLine("!/etc/.*alastor");
        return sb.ToString();
    }

    /// <summary>AIDE selection lines are regular expressions; a path must match literally.</summary>
    private static string Escape(string path) => Regex.Replace(path, @"[.\[\]()*+?{}|^$\\]", m => "\\" + m.Value);
}
