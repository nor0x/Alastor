using System.Text.RegularExpressions;

namespace Alastor.Core.Updates;

/// <summary>One package with a newer version available.</summary>
/// <param name="Security">True if the candidate comes from a security repository or advisory; null where the package manager can't tell (Alpine).</param>
public sealed record PendingUpdate(string Name, string? Installed, string Candidate, string? Source, bool? Security);

/// <summary>The result of installing updates.</summary>
public sealed record UpdateApplyResult(DateTime AtUtc, bool Success, IReadOnlyList<string> Upgraded, string? Error, string LogTail);

/// <summary>Pending updates on one host, as counted by its own package manager.</summary>
public sealed record UpdatesReport(
    string Manager,
    IReadOnlyList<PendingUpdate> Packages,
    bool RebootRequired,
    IReadOnlyList<string> RebootPackages,
    UpdateApplyResult? LastApply)
{
    public int Pending => Packages.Count;

    /// <summary>Security updates, or null if the package manager can't tell (then every update counts as possibly one).</summary>
    public int? Security => Packages.Any(p => p.Security is null) ? null : Packages.Count(p => p.Security == true);
}

/// <summary>
/// Reads the package managers' own reports of pending updates. apt has no machine-readable "list upgrades" (and
/// <c>apt list</c> warns that its CLI is unstable), so we read <c>apt-get -s</c>'s simulation lines, the format
/// unattended-upgrades' own tooling and most monitoring plugins rely on. dnf and apk print fixed columns.
/// </summary>
public static partial class UpdateParsers
{
    /// <summary>
    /// <c>apt-get -s dist-upgrade</c>: <c>Inst name [installed] (candidate origin/suite[, origin/suite] [arch])</c>. A candidate
    /// is a security update if one of its origins is a security pocket (<c>noble-security</c>, <c>Debian-Security:</c>).
    /// </summary>
    public static List<PendingUpdate> ParseAptSimulation(string output)
    {
        var result = new List<PendingUpdate>();
        foreach (var line in output.Split('\n'))
        {
            var m = AptInstRegex().Match(line.TrimEnd('\r'));
            if (!m.Success) continue;
            var origins = m.Groups["origins"].Value;
            var security = origins.Split(',').Any(o => o.Contains("-security", StringComparison.OrdinalIgnoreCase) || o.TrimStart().StartsWith("Debian-Security", StringComparison.OrdinalIgnoreCase));
            result.Add(new PendingUpdate(m.Groups["name"].Value, m.Groups["installed"].Success ? m.Groups["installed"].Value : null,
                m.Groups["candidate"].Value, origins.Trim(), security));
        }
        return result;
    }

    /// <summary>
    /// <c>dnf -q check-update [--security]</c>: <c>name.arch  version  repo</c> per line, exit code 100 when updates exist.
    /// The "Obsoleting Packages" section that may follow lists replacements, not updates, and is skipped.
    /// </summary>
    public static List<(string Name, string Candidate, string Repo)> ParseDnfCheckUpdate(string output)
    {
        var result = new List<(string, string, string)>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith("Obsoleting", StringComparison.Ordinal)) break;
            if (line.Length == 0 || char.IsWhiteSpace(line[0])) continue;
            var cols = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length != 3 || !cols[0].Contains('.')) continue;
            result.Add((cols[0], cols[1], cols[2]));
        }
        return result;
    }

    /// <summary><c>apk list --upgradable</c>: <c>name-ver-rN arch {origin} (license) [upgradable from: name-old-rN]</c>.</summary>
    public static List<PendingUpdate> ParseApkUpgradable(string output)
    {
        var result = new List<PendingUpdate>();
        foreach (var line in output.Split('\n'))
        {
            var m = ApkRegex().Match(line.TrimEnd('\r'));
            if (!m.Success) continue;
            var installed = m.Groups["from"].Value;
            var name = m.Groups["name"].Value;
            result.Add(new PendingUpdate(name, installed.StartsWith(name + "-", StringComparison.Ordinal) ? installed[(name.Length + 1)..] : installed,
                m.Groups["ver"].Value, m.Groups["origin"].Value, Security: null));
        }
        return result;
    }

    /// <summary>The packages <c>unattended-upgrade -v</c> reports installing ("Packages that will be upgraded: a b c").</summary>
    public static List<string> ParseUnattendedUpgrade(string output)
    {
        foreach (var line in output.Split('\n'))
            if (line.StartsWith("Packages that will be upgraded:", StringComparison.Ordinal))
                return line["Packages that will be upgraded:".Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        return [];
    }

    [GeneratedRegex(@"^Inst (?<name>\S+) (?:\[(?<installed>[^\]]+)\] )?\((?<candidate>\S+) (?<origins>.+?) \[[^\]]+\]\)")]
    private static partial Regex AptInstRegex();

    [GeneratedRegex(@"^(?<name>.+?)-(?<ver>[^-\s]+-r\d+) \S+ \{(?<origin>[^}]*)\} \([^)]*\) \[upgradable from: (?<from>[^\]]+)\]")]
    private static partial Regex ApkRegex();
}
