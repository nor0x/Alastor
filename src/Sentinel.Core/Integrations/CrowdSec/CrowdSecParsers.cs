using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentinel.Core.Integrations.CrowdSec;

/// <summary>One decision from <c>cscli decisions list -o json</c> / <c>cscli alerts list -o json</c>.</summary>
/// <param name="Origin"><c>crowdsec</c> (a scenario fired here), <c>cscli</c> (added by hand or by SentinelVPS), <c>CAPI</c> or <c>lists</c> (community blocklists).</param>
public sealed record CrowdSecDecision(long Id, string Type, string Scope, string Value, string Origin, string Scenario, TimeSpan? Remaining, bool Simulated);

public sealed record CrowdSecAlert(
    long Id,
    string Scenario,
    string Message,
    string? SourceScope,
    string? SourceValue,
    int EventsCount,
    DateTime CreatedAt,
    bool Simulated,
    IReadOnlyList<CrowdSecDecision> Decisions);

/// <summary>
/// Reads cscli's own JSON output. Both lists have the same shape: an array of alerts, each carrying its decisions; an
/// empty result prints <c>null</c>. No log parsing anywhere: cscli is CrowdSec's supported client for its Local API.
/// </summary>
public static partial class CrowdSecParsers
{
    public static IReadOnlyList<CrowdSecAlert> ParseAlerts(string json)
    {
        json = json.Trim();
        if (json is "" or "null") return [];
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) return [];
        var result = new List<CrowdSecAlert>();
        foreach (var a in doc.RootElement.EnumerateArray())
        {
            var decisions = new List<CrowdSecDecision>();
            if (a.TryGetProperty("decisions", out var ds) && ds.ValueKind == JsonValueKind.Array)
                foreach (var d in ds.EnumerateArray())
                    decisions.Add(new CrowdSecDecision(
                        d.TryGetProperty("id", out var id) && id.TryGetInt64(out var i) ? i : 0,
                        Str(d, "type") ?? "",
                        Str(d, "scope") ?? "",
                        Str(d, "value") ?? "",
                        Str(d, "origin") ?? "",
                        Str(d, "scenario") ?? "",
                        ParseGoDuration(Str(d, "duration")),
                        Bool(d, "simulated")));
            string? scope = null, value = null;
            if (a.TryGetProperty("source", out var src) && src.ValueKind == JsonValueKind.Object)
            {
                scope = Str(src, "scope");
                value = Str(src, "value") ?? Str(src, "ip");
            }
            result.Add(new CrowdSecAlert(
                a.TryGetProperty("id", out var aid) && aid.TryGetInt64(out var ai) ? ai : 0,
                Str(a, "scenario") ?? "",
                Str(a, "message") ?? "",
                scope,
                value,
                a.TryGetProperty("events_count", out var ec) && ec.TryGetInt32(out var e) ? e : 0,
                DateTime.TryParse(Str(a, "created_at"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var c) ? c : DateTime.MinValue,
                Bool(a, "simulated"),
                decisions));
        }
        return result;
    }

    /// <summary>Go's <c>time.Duration</c> string, as cscli prints the time left on a decision: <c>3h59m51.825539104s</c>, <c>-1.5s</c> once expired.</summary>
    public static TimeSpan? ParseGoDuration(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var m = GoDurationRegex().Match(value.Trim());
        if (!m.Success) return null;
        double seconds = 0;
        foreach (Capture cap in m.Groups["part"].Captures)
        {
            var p = GoPartRegex().Match(cap.Value);
            var n = double.Parse(p.Groups[1].Value, CultureInfo.InvariantCulture);
            seconds += p.Groups[2].Value switch
            {
                "h" => n * 3600,
                "m" => n * 60,
                "s" => n,
                "ms" => n / 1e3,
                "us" or "µs" => n / 1e6,
                "ns" => n / 1e9,
                _ => 0,
            };
        }
        if (m.Groups["neg"].Success) seconds = -seconds;
        return TimeSpan.FromSeconds(seconds);
    }

    /// <summary>A duration for <c>cscli decisions add --duration</c>. CrowdSec has no permanent decision, so "permanent" becomes ten years.</summary>
    public static string FormatDuration(long seconds) =>
        seconds < 0 ? "87600h" : seconds % 3600 == 0 ? $"{seconds / 3600}h" : seconds % 60 == 0 ? $"{seconds / 60}m" : $"{seconds}s";

    /// <summary><c>cscli version</c> prints "version: v1.4.6-10.1-debian" (to stderr, with a log timestamp in some builds).</summary>
    public static string? ParseVersion(string output) =>
        VersionRegex().Match(output) is { Success: true } m ? m.Groups[1].Value : null;

    /// <summary>cscli logs "N decision(s) deleted" after <c>decisions delete</c>.</summary>
    public static int? ParseDeletedCount(string output) =>
        DeletedRegex().Match(output) is { Success: true } m ? int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) : null;

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool Bool(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    [GeneratedRegex(@"^(?<neg>-)?(?<part>[0-9]+(?:\.[0-9]+)?(?:h|ms|us|µs|ns|m|s))+$")]
    private static partial Regex GoDurationRegex();

    [GeneratedRegex(@"^([0-9]+(?:\.[0-9]+)?)(h|ms|us|µs|ns|m|s)$")]
    private static partial Regex GoPartRegex();

    [GeneratedRegex(@"version:\s*v?([0-9][^\s]*)")]
    private static partial Regex VersionRegex();

    [GeneratedRegex(@"(\d+) decision\(s\) deleted")]
    private static partial Regex DeletedRegex();
}
