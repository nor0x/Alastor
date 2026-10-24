using System.Text.Json;
using Sentinel.Core.Events;

namespace Sentinel.Core.Vulnerabilities;

/// <summary>Whether the distribution or upstream ships a fixed version.</summary>
public enum FixState
{
    /// <summary>A fixed version exists: updating the package resolves it.</summary>
    Fixable,
    /// <summary>Affected and no fix released yet.</summary>
    NoFix,
    /// <summary>The vendor decided not to fix it (or deferred it, or the release is end of life).</summary>
    WontFix,
    Unknown,
}

/// <summary>One vulnerability in one installed package, normalized from Trivy or Grype JSON.</summary>
/// <param name="Id">CVE id where the scanner knows one, otherwise the advisory id (GHSA-…, ALSA-…).</param>
/// <param name="PkgType">The scanner's package type: <c>deb</c>, <c>rpm</c>, <c>apk</c>, <c>npm</c>, <c>python</c>, …</param>
/// <param name="Path">For language packages, where the package was found.</param>
public sealed record VulnFinding(
    string Id,
    string Package,
    string Installed,
    string? Fixed,
    Severity Severity,
    double? Cvss,
    FixState Fix,
    string? Title,
    string PkgType,
    string? Path);

/// <summary>The result of one scan.</summary>
/// <param name="Ignored">Findings dropped by <c>vulnerabilities.ignorePackages</c>, per package, so the UI can say what was hidden.</param>
public sealed record VulnScanReport(
    string Scanner,
    string? ScannerVersion,
    DateTime? DbUpdatedAt,
    string? Os,
    IReadOnlyList<VulnFinding> Findings,
    IReadOnlyDictionary<string, int> Ignored,
    bool Truncated = false);

/// <summary>
/// Reads the scanners' own JSON reports (<c>trivy --format json</c>, <c>grype -o json</c>). Both formats are documented and
/// versioned (Trivy <c>SchemaVersion</c> 2, Grype's <c>descriptor</c>); only the fields below are read, so additions don't break us.
/// </summary>
public static class VulnParsers
{
    /// <summary>OS package types. Everything else is a language package (npm, pip, gem, Go binaries, jars, …).</summary>
    public static readonly IReadOnlySet<string> OsPackageTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "deb", "rpm", "apk", "debian", "ubuntu", "alpine", "redhat", "centos", "rocky", "alma", "amazon", "oracle", "fedora", "opensuse", "suse", "photon", "wolfi", "chainguard", "azurelinux", "cbl-mariner",
    };

    public static (List<VulnFinding> Findings, string? Version, string? Os) ParseTrivy(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var version = root.TryGetProperty("Trivy", out var t) && t.TryGetProperty("Version", out var tv) ? tv.GetString() : null;
        string? os = null;
        if (root.TryGetProperty("Metadata", out var meta) && meta.TryGetProperty("OS", out var o))
            os = $"{Str(o, "Family")} {Str(o, "Name")}".Trim();

        var result = new List<VulnFinding>();
        if (!root.TryGetProperty("Results", out var results) || results.ValueKind != JsonValueKind.Array) return (result, version, os);
        foreach (var r in results.EnumerateArray())
        {
            if (!r.TryGetProperty("Vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array) continue;
            var cls = Str(r, "Class");
            var type = Str(r, "Type") ?? "";
            // Trivy names the OS result by distro (ubuntu, alpine); normalize to the package format.
            var pkgType = cls == "os-pkgs" ? OsPkgType(type) : type;
            var target = cls == "os-pkgs" ? null : Str(r, "Target");
            foreach (var v in vulns.EnumerateArray())
            {
                var fixedVersion = Str(v, "FixedVersion");
                var status = Str(v, "Status");
                var fix = status switch
                {
                    "fixed" => FixState.Fixable,
                    "affected" or "under_investigation" => FixState.NoFix,
                    "will_not_fix" or "fix_deferred" or "end_of_life" => FixState.WontFix,
                    // Older Trivy versions without Status: a FixedVersion means fixable.
                    null or "" => string.IsNullOrEmpty(fixedVersion) ? FixState.Unknown : FixState.Fixable,
                    _ => FixState.Unknown,
                };
                result.Add(new VulnFinding(
                    Str(v, "VulnerabilityID") ?? "?",
                    Str(v, "PkgName") ?? "?",
                    Str(v, "InstalledVersion") ?? "",
                    string.IsNullOrEmpty(fixedVersion) ? null : fixedVersion,
                    MapSeverity(Str(v, "Severity")),
                    TrivyCvss(v),
                    fix,
                    Trim(Str(v, "Title")),
                    pkgType,
                    Str(v, "PkgPath") ?? target));
            }
        }
        return (result, version, os);
    }

    public static (List<VulnFinding> Findings, string? Version, string? Os, DateTime? DbBuilt) ParseGrype(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        string? version = null;
        DateTime? built = null;
        if (root.TryGetProperty("descriptor", out var desc))
        {
            version = Str(desc, "version");
            if (desc.TryGetProperty("db", out var db))
            {
                // v6: db.status.built; v5: db.built.
                var b = db.TryGetProperty("status", out var st) ? Str(st, "built") : Str(db, "built");
                if (DateTime.TryParse(b, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var d)) built = d;
            }
        }
        string? os = null;
        if (root.TryGetProperty("distro", out var distro))
            os = $"{Str(distro, "name")} {Str(distro, "version")}".Trim();

        var result = new List<VulnFinding>();
        if (!root.TryGetProperty("matches", out var matches) || matches.ValueKind != JsonValueKind.Array) return (result, version, os == "" ? null : os, built);
        foreach (var m in matches.EnumerateArray())
        {
            if (!m.TryGetProperty("vulnerability", out var v) || !m.TryGetProperty("artifact", out var a)) continue;
            var id = Str(v, "id") ?? "?";
            // Grype reports the advisory it matched (GHSA-…, ALSA-…, ELSA-…); prefer the CVE it's about, so hosts and the feed line up.
            if (!id.StartsWith("CVE-", StringComparison.Ordinal) && m.TryGetProperty("relatedVulnerabilities", out var related) && related.ValueKind == JsonValueKind.Array)
                foreach (var rv in related.EnumerateArray())
                    if (Str(rv, "id") is { } rid && rid.StartsWith("CVE-", StringComparison.Ordinal)) { id = rid; break; }

            string? fixedVersion = null;
            var fix = FixState.Unknown;
            if (v.TryGetProperty("fix", out var f))
            {
                if (f.TryGetProperty("versions", out var vs) && vs.ValueKind == JsonValueKind.Array && vs.GetArrayLength() > 0)
                    fixedVersion = string.Join(", ", vs.EnumerateArray().Select(x => x.GetString()).Where(x => !string.IsNullOrEmpty(x)));
                fix = Str(f, "state") switch
                {
                    "fixed" => FixState.Fixable,
                    "not-fixed" => FixState.NoFix,
                    "wont-fix" => FixState.WontFix,
                    _ => FixState.Unknown,
                };
            }

            string? path = null;
            if (a.TryGetProperty("locations", out var locs) && locs.ValueKind == JsonValueKind.Array && locs.GetArrayLength() > 0)
                path = Str(locs[0], "path");
            var pkgType = Str(a, "type") ?? "";
            result.Add(new VulnFinding(
                id,
                Str(a, "name") ?? "?",
                Str(a, "version") ?? "",
                string.IsNullOrEmpty(fixedVersion) ? null : fixedVersion,
                MapSeverity(Str(v, "severity")),
                GrypeCvss(v, m),
                fix,
                Trim(Str(v, "description")),
                pkgType,
                OsPackageTypes.Contains(pkgType) ? null : path));
        }
        return (result, version, os == "" ? null : os, built);
    }

    /// <summary>Unknown and negligible map to Info: they never page anyone.</summary>
    public static Severity MapSeverity(string? s) => s?.ToUpperInvariant() switch
    {
        "CRITICAL" => Severity.Critical,
        "HIGH" => Severity.High,
        "MEDIUM" => Severity.Medium,
        "LOW" => Severity.Low,
        _ => Severity.Info,
    };

    private static string OsPkgType(string distro) => distro switch
    {
        "debian" or "ubuntu" => "deb",
        "alpine" or "wolfi" or "chainguard" => "apk",
        _ => "rpm",
    };

    // NVD's score first (what the threat feed shows), then the vendor's, then the highest of any source.
    private static double? TrivyCvss(JsonElement v)
    {
        if (!v.TryGetProperty("CVSS", out var cvss) || cvss.ValueKind != JsonValueKind.Object) return null;
        double? Score(JsonElement e) =>
            e.TryGetProperty("V3Score", out var s3) && s3.ValueKind == JsonValueKind.Number ? s3.GetDouble()
            : e.TryGetProperty("V40Score", out var s4) && s4.ValueKind == JsonValueKind.Number ? s4.GetDouble()
            : null;
        if (cvss.TryGetProperty("nvd", out var nvd) && Score(nvd) is { } n) return n;
        if (Str(v, "SeveritySource") is { } src && cvss.TryGetProperty(src, out var vendor) && Score(vendor) is { } vs) return vs;
        return cvss.EnumerateObject().Select(p => Score(p.Value)).Where(x => x is not null).Max();
    }

    private static double? GrypeCvss(JsonElement v, JsonElement match)
    {
        static double? Best(JsonElement holder)
        {
            if (!holder.TryGetProperty("cvss", out var list) || list.ValueKind != JsonValueKind.Array) return null;
            double? best = null;
            foreach (var c in list.EnumerateArray())
            {
                if (!c.TryGetProperty("metrics", out var m) || !m.TryGetProperty("baseScore", out var s) || s.ValueKind != JsonValueKind.Number) continue;
                var ver = Str(c, "version") ?? "";
                // Prefer a v3/v4 score; v2 only if nothing else exists.
                if (ver.StartsWith('2') && best is not null) continue;
                best = Math.Max(best ?? 0, s.GetDouble());
            }
            return best;
        }
        if (Best(v) is { } own) return own;
        if (match.TryGetProperty("relatedVulnerabilities", out var related) && related.ValueKind == JsonValueKind.Array)
            foreach (var rv in related.EnumerateArray())
                if (Best(rv) is { } r) return r;
        return null;
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    private static string? Trim(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.ReplaceLineEndings(" ").Trim();
        return s.Length <= 200 ? s : s[..197] + "…";
    }
}
