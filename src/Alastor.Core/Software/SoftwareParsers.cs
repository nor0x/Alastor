using System.Globalization;
using System.Text.RegularExpressions;

namespace Alastor.Core.Software;

/// <summary>
/// Reads the package databases (dpkg, rpm, apk) and the package managers' dry-run output. Everything is plain text
/// with fixed columns or a query format we choose, so no tool's unstable "pretty" output is involved.
/// </summary>
public static partial class SoftwareParsers
{
    /// <summary>The <c>dpkg-query -W -f</c> format <see cref="ParseDpkgQuery"/> reads: tab-separated, one package per line.</summary>
    public const string DpkgFormat = "${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${Installed-Size}\t${Priority}\t${Essential}\t${Source}\n";

    /// <summary>The <c>rpm -qa --qf</c> format <see cref="ParseRpmQuery"/> reads. The epoch is only printed when set, as dnf does.</summary>
    public const string RpmFormat = "%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{SOURCERPM}\n";

    /// <summary>
    /// <c>dpkg-query -W -f=<see cref="DpkgFormat"/></c>. Packages whose status isn't installed (removed with config files
    /// left, half-removed) are skipped. <c>Source</c> is empty when it equals the package name and may carry a version
    /// in parentheses (<c>openssl (3.0.13-1)</c>).
    /// </summary>
    public static List<InstalledPackage> ParseDpkgQuery(string output, IReadOnlySet<string> manual)
    {
        var result = new List<InstalledPackage>();
        foreach (var raw in output.Split('\n'))
        {
            var cols = raw.TrimEnd('\r').Split('\t');
            if (cols.Length < 8 || cols[0].Length == 0) continue;
            // db:Status-Abbrev is "<want><status><error>", e.g. "ii ", "rc ", "iU ".
            var status = cols[3].Length >= 2 ? cols[3][1] : ' ';
            if (status is 'n' or 'c' or ' ') continue;
            var name = cols[0];
            var source = cols[7].Split(' ')[0];
            var isProtected = cols[6] == "yes" || cols[5] == "required" || ProtectedPackages.IsProtected(name);
            result.Add(new InstalledPackage(name, cols[1], NullIfEmpty(cols[2]), source.Length == 0 ? name : source, manual.Contains(name), isProtected)
            {
                SizeKb = long.TryParse(cols[4], NumberStyles.Integer, CultureInfo.InvariantCulture, out var kb) ? kb : null,
            });
        }
        return Dedupe(result);
    }

    /// <summary><c>rpm -qa --qf <see cref="RpmFormat"/></c>. The gpg-pubkey pseudo-packages (imported signing keys) are skipped.</summary>
    public static List<InstalledPackage> ParseRpmQuery(string output, IReadOnlySet<string> manual)
    {
        var result = new List<InstalledPackage>();
        foreach (var raw in output.Split('\n'))
        {
            var cols = raw.TrimEnd('\r').Split('\t');
            if (cols.Length < 5 || cols[0].Length == 0 || cols[0] == "gpg-pubkey") continue;
            var name = cols[0];
            result.Add(new InstalledPackage(name, cols[1], NullIfEmpty(cols[2]), SourceFromSrpm(cols[4]) ?? name, manual.Contains(name), ProtectedPackages.IsProtected(name))
            {
                SizeKb = long.TryParse(cols[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out var bytes) ? bytes / 1024 : null,
            });
        }
        return Dedupe(result);
    }

    /// <summary><c>apk list --installed</c>: <c>name-ver-rN arch {origin} (license) [installed]</c>.</summary>
    public static List<InstalledPackage> ParseApkInstalled(string output, IReadOnlySet<string> manual)
    {
        var result = new List<InstalledPackage>();
        foreach (var raw in output.Split('\n'))
        {
            var m = ApkInstalledRegex().Match(raw.TrimEnd('\r'));
            if (!m.Success) continue;
            var name = m.Groups["name"].Value;
            var origin = m.Groups["origin"].Value;
            result.Add(new InstalledPackage(name, m.Groups["ver"].Value, m.Groups["arch"].Value, origin.Length == 0 ? name : origin,
                manual.Contains(name), ProtectedPackages.IsProtected(name)));
        }
        return Dedupe(result);
    }

    /// <summary>
    /// One name per line: <c>apt-mark showmanual</c> (may add <c>:arch</c>) and <c>dnf repoquery --userinstalled</c>. dnf 4
    /// prints a literal <c>\n</c> where dnf 5 prints a newline, so both are accepted.
    /// </summary>
    public static HashSet<string> ParseNameList(string output) =>
        output.Replace("\\n", "\n", StringComparison.Ordinal).Split('\n')
            .Select(l => l.Trim().Split(':')[0])
            .Where(l => l.Length > 0 && !l.Contains(' '))
            .ToHashSet(StringComparer.Ordinal);

    /// <summary><c>/etc/apk/world</c>: the packages asked for explicitly, with optional constraints (<c>curl&gt;8</c>, <c>pkg@edge</c>).</summary>
    public static HashSet<string> ParseApkWorld(string world) =>
        world.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Select(w => w.Split('<', '>', '=', '~', '@')[0])
            .Where(w => w.Length > 0 && !w.StartsWith("so:", StringComparison.Ordinal) && !w.StartsWith("cmd:", StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// <c>apt-get -s install|remove</c>: <c>Inst name [installed] (candidate origin [arch])</c> and <c>Remv name [installed]</c>.
    /// An <c>Inst</c> without an installed version is a new dependency.
    /// </summary>
    public static List<PlannedPackage> ParseAptPlan(string output)
    {
        var result = new List<PlannedPackage>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (AptInstRegex().Match(line) is { Success: true } i)
            {
                var from = i.Groups["installed"].Success ? i.Groups["installed"].Value : null;
                result.Add(new PlannedPackage(i.Groups["name"].Value, from is null ? "install" : "upgrade", from, i.Groups["candidate"].Value));
            }
            else if (AptRemvRegex().Match(line) is { Success: true } r)
            {
                result.Add(new PlannedPackage(r.Groups["name"].Value, "remove", r.Groups["installed"].Success ? r.Groups["installed"].Value : null, null));
            }
        }
        return result;
    }

    /// <summary>
    /// The transaction table <c>dnf --assumeno</c> prints before aborting (dnf 4 and 5): section headers such as
    /// <c>Upgrading:</c>, <c>Removing dependent packages:</c> or <c>Installing dependencies:</c>, then one indented
    /// <c>name arch version repo size</c> line per package. dnf 4 wraps long names onto a line of their own.
    /// </summary>
    public static List<PlannedPackage> ParseDnfPlan(string output)
    {
        var result = new List<PlannedPackage>();
        string? action = null;
        string? wrapped = null;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            if (!char.IsWhiteSpace(line[0]))
            {
                wrapped = null;
                if (line.StartsWith("Transaction Summary", StringComparison.Ordinal)) break;
                action = !line.TrimEnd().EndsWith(':') ? action
                    : line.StartsWith("Upgrading", StringComparison.Ordinal) ? "upgrade"
                    : line.StartsWith("Removing", StringComparison.Ordinal) ? "remove"
                    : line.StartsWith("Installing", StringComparison.Ordinal) ? "install"
                    : line.StartsWith("Downgrading", StringComparison.Ordinal) ? "downgrade"
                    : null;
                continue;
            }
            if (action is null) continue;
            var cols = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length == 0) continue;
            // dnf 5 lists the version being replaced on an indented "replacing name arch version repo size" line after the upgrade.
            if (cols[0] == "replacing")
            {
                if (cols.Length >= 4 && result.Count > 0 && result[^1].Action is "upgrade" or "downgrade") result[^1] = result[^1] with { From = cols[3] };
                continue;
            }
            if (cols.Length == 1) { wrapped = cols[0]; continue; }
            if (wrapped is not null) { cols = [wrapped, .. cols]; wrapped = null; }
            if (cols.Length < 3) continue;
            result.Add(action == "remove"
                ? new PlannedPackage(cols[0], action, cols[2], null)
                : new PlannedPackage(cols[0], action, null, cols[2]));
        }
        return result;
    }

    /// <summary>
    /// <c>apk upgrade|del --simulate</c>: <c>(1/3) Upgrading name (old -&gt; new)</c>, <c>(2/3) Purging name (ver)</c>,
    /// <c>(3/3) Installing name (ver)</c>.
    /// </summary>
    public static List<PlannedPackage> ParseApkPlan(string output)
    {
        var result = new List<PlannedPackage>();
        foreach (var raw in output.Split('\n'))
        {
            var m = ApkPlanRegex().Match(raw.TrimEnd('\r'));
            if (!m.Success) continue;
            var ver = m.Groups["ver"].Value;
            var arrow = ver.IndexOf(" -> ", StringComparison.Ordinal);
            var (from, to) = arrow > 0 ? (ver[..arrow], ver[(arrow + 4)..]) : (null, ver);
            var name = m.Groups["name"].Value;
            result.Add(m.Groups["verb"].Value switch
            {
                "Purging" or "Deleting" => new PlannedPackage(name, "remove", to, null),
                "Installing" => new PlannedPackage(name, "install", null, to),
                "Downgrading" => new PlannedPackage(name, "downgrade", from, to),
                _ => new PlannedPackage(name, "upgrade", from, to),
            });
        }
        return result;
    }

    /// <summary><c>openssl-3.0.7-27.el9.src.rpm</c> → <c>openssl</c>: the name is everything before the last two dashes.</summary>
    public static string? SourceFromSrpm(string srpm)
    {
        if (!srpm.EndsWith(".src.rpm", StringComparison.Ordinal) && !srpm.EndsWith(".nosrc.rpm", StringComparison.Ordinal)) return null;
        var release = srpm.LastIndexOf('-');
        var version = release > 0 ? srpm.LastIndexOf('-', release - 1) : -1;
        return version > 0 ? srpm[..version] : null;
    }

    private static string? NullIfEmpty(string s) => s.Length == 0 || s == "(none)" ? null : s;

    // Multi-arch installs list the same name once per architecture; one row per name keeps joins by name simple.
    private static List<InstalledPackage> Dedupe(List<InstalledPackage> list) =>
        list.GroupBy(p => p.Name, StringComparer.Ordinal).Select(g => g.First()).OrderBy(p => p.Name, StringComparer.Ordinal).ToList();

    [GeneratedRegex(@"^(?<name>.+?)-(?<ver>[^-\s]+-r\d+) (?<arch>\S+) \{(?<origin>[^}]*)\} \([^)]*\) \[installed\]")]
    private static partial Regex ApkInstalledRegex();

    [GeneratedRegex(@"^Inst (?<name>\S+) (?:\[(?<installed>[^\]]+)\] )?\((?<candidate>\S+)")]
    private static partial Regex AptInstRegex();

    [GeneratedRegex(@"^Remv (?<name>\S+)(?: \[(?<installed>[^\]]+)\])?")]
    private static partial Regex AptRemvRegex();

    [GeneratedRegex(@"^\(\d+/\d+\) (?<verb>Upgrading|Downgrading|Installing|Purging|Deleting|Replacing) (?<name>\S+) \((?<ver>[^)]+)\)")]
    private static partial Regex ApkPlanRegex();
}
