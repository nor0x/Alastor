using System.Globalization;
using System.Text.Json;
using Alastor.Core.Events;

namespace Alastor.Server.Services.Osv;

/// <summary>One advisory as OSV.dev publishes it (https://ossf.github.io/osv-schema/), reduced to what the Software view shows.</summary>
public sealed record OsvAdvisory(string Id, string? Summary, Severity? Severity, double? Cvss, IReadOnlyList<string> Aliases, IReadOnlyDictionary<string, string> Fixed, DateTime? Modified);

/// <summary>Reads OSV.dev API responses: <c>POST /v1/querybatch</c> and <c>GET /v1/vulns/{id}</c>.</summary>
public static class OsvParsers
{
    /// <summary>The batch answer: one entry per query, in order, each with the ids of the advisories affecting that version.</summary>
    public static List<List<(string Id, DateTime? Modified)>> ParseQueryBatch(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var result = new List<List<(string, DateTime?)>>();
        if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array) return result;
        foreach (var r in results.EnumerateArray())
        {
            var ids = new List<(string, DateTime?)>();
            if (r.TryGetProperty("vulns", out var vulns) && vulns.ValueKind == JsonValueKind.Array)
                foreach (var v in vulns.EnumerateArray())
                    if (Str(v, "id") is { } id) ids.Add((id, Date(Str(v, "modified"))));
            result.Add(ids);
        }
        return result;
    }

    /// <summary>
    /// One advisory. Severity is the distribution's own rating (Ubuntu priority, Debian urgency,
    /// <c>database_specific.severity</c>) when it has one, else derived from the CVSS v3 vector. <see cref="OsvAdvisory.Aliases"/> merges
    /// <c>aliases</c> and <c>upstream</c> (Debian's DEBIAN-CVE-* records name their CVE only there).
    /// </summary>
    public static OsvAdvisory ParseVuln(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var id = Str(root, "id") ?? throw new JsonException("OSV record without an id");
        var aliases = Strings(root, "aliases").Concat(Strings(root, "upstream")).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        double? cvss = null;
        Severity? rating = null;
        if (root.TryGetProperty("severity", out var sev) && sev.ValueKind == JsonValueKind.Array)
            foreach (var s in sev.EnumerateArray())
            {
                var type = Str(s, "type");
                var score = Str(s, "score");
                if (score is null) continue;
                if (type == "CVSS_V3" && Cvss3BaseScore(score) is { } v3) cvss = Math.Max(cvss ?? 0, v3);
                else if (type is not ("CVSS_V2" or "CVSS_V3" or "CVSS_V4")) rating ??= FromText(score); // "Ubuntu": "medium"
            }

        var fixedVersions = new Dictionary<string, string>(StringComparer.Ordinal);
        if (root.TryGetProperty("affected", out var affected) && affected.ValueKind == JsonValueKind.Array)
            foreach (var a in affected.EnumerateArray())
            {
                if (!a.TryGetProperty("package", out var pkg) || Str(pkg, "ecosystem") is not { } eco || Str(pkg, "name") is not { } name) continue;
                if (a.TryGetProperty("ecosystem_specific", out var es) && es.ValueKind == JsonValueKind.Object)
                    rating ??= FromText(Str(es, "urgency") ?? Str(es, "severity"));
                if (a.TryGetProperty("database_specific", out var ds) && ds.ValueKind == JsonValueKind.Object)
                    rating ??= FromText(Str(ds, "severity"));
                if (!a.TryGetProperty("ranges", out var ranges) || ranges.ValueKind != JsonValueKind.Array) continue;
                foreach (var range in ranges.EnumerateArray())
                    if (range.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
                        foreach (var e in events.EnumerateArray())
                            if (Str(e, "fixed") is { } f) fixedVersions.TryAdd($"{eco}/{name}", f);
            }
        if (root.TryGetProperty("database_specific", out var rootDs) && rootDs.ValueKind == JsonValueKind.Object)
            rating ??= FromText(Str(rootDs, "severity"));

        var summary = Str(root, "summary") ?? FirstLine(Str(root, "details"));
        if (summary is { Length: > 512 }) summary = summary[..509] + "…";
        // The distribution's own rating wins, as with Trivy: it weighs the CVE as packaged and configured there.
        return new OsvAdvisory(id, summary, rating ?? (cvss is { } c ? FromScore(c) : null), cvss, aliases, fixedVersions, Date(Str(root, "modified")));
    }

    /// <summary>
    /// The CVSS v3.0/v3.1 base score of a vector such as <c>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</c>, per the
    /// FIRST specification (section 7.1, including its Roundup function). Null when a base metric is missing.
    /// </summary>
    public static double? Cvss3BaseScore(string vector)
    {
        if (!vector.StartsWith("CVSS:3.", StringComparison.Ordinal)) return null;
        var m = vector.Split('/').Skip(1).Select(p => p.Split(':')).Where(p => p.Length == 2).GroupBy(p => p[0]).ToDictionary(g => g.Key, g => g.First()[1]);
        string? Get(string k) => m.GetValueOrDefault(k);
        var changed = Get("S") switch { "C" => true, "U" => false, _ => (bool?)null };
        double? av = Get("AV") switch { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => null };
        double? ac = Get("AC") switch { "L" => 0.77, "H" => 0.44, _ => null };
        double? pr = Get("PR") switch { "N" => 0.85, "L" => changed == true ? 0.68 : 0.62, "H" => changed == true ? 0.5 : 0.27, _ => null };
        double? ui = Get("UI") switch { "N" => 0.85, "R" => 0.62, _ => null };
        static double? Cia(string? v) => v switch { "H" => 0.56, "L" => 0.22, "N" => 0, _ => null };
        var (c, i, a) = (Cia(Get("C")), Cia(Get("I")), Cia(Get("A")));
        if (changed is null || av is null || ac is null || pr is null || ui is null || c is null || i is null || a is null) return null;

        var iss = 1 - (1 - c.Value) * (1 - i.Value) * (1 - a.Value);
        var impact = changed.Value ? 7.52 * (iss - 0.029) - 3.25 * Math.Pow(iss - 0.02, 15) : 6.42 * iss;
        var exploitability = 8.22 * av.Value * ac.Value * pr.Value * ui.Value;
        if (impact <= 0) return 0;
        return Roundup(Math.Min(changed.Value ? 1.08 * (impact + exploitability) : impact + exploitability, 10));

        static double Roundup(double x)
        {
            var n = (long)Math.Round(x * 100_000);
            return n % 10_000 == 0 ? n / 100_000.0 : (Math.Floor(n / 10_000.0) + 1) / 10.0;
        }
    }

    public static Severity FromScore(double score) => score switch
    {
        >= 9 => Severity.Critical,
        >= 7 => Severity.High,
        >= 4 => Severity.Medium,
        > 0 => Severity.Low,
        _ => Severity.Info,
    };

    /// <summary>Distribution ratings: Ubuntu priorities, Debian urgencies (<c>low**</c>), GHSA and Red Hat words.</summary>
    public static Severity? FromText(string? text) => text?.Trim().TrimEnd('*').ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" or "important" => Severity.High,
        "medium" or "moderate" => Severity.Medium,
        "low" or "negligible" or "unimportant" => Severity.Low,
        _ => null,
    };

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static IEnumerable<string> Strings(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!)
            : [];

    private static DateTime? Date(string? s) =>
        DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;

    private static string? FirstLine(string? s) => s?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
}
