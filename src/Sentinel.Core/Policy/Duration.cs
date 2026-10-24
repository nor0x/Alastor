using System.Globalization;
using System.Text.RegularExpressions;

namespace Sentinel.Core.Policy;

/// <summary>Durations in policy YAML: <c>90s</c>, <c>10m</c>, <c>1h</c>, <c>7d</c>, <c>2w</c>, a bare number of seconds, or <c>permanent</c>.</summary>
public static partial class Duration
{
    public const long Permanent = -1;

    public static bool TryParseSeconds(string? value, out long seconds)
    {
        seconds = 0;
        if (string.IsNullOrWhiteSpace(value)) return false;
        value = value.Trim().ToLowerInvariant();
        if (value is "permanent" or "forever" or "-1") { seconds = Permanent; return true; }
        var m = DurationRegex().Match(value);
        if (!m.Success) return false;
        var n = long.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
        seconds = m.Groups[2].Value switch
        {
            "" or "s" => n,
            "m" => n * 60,
            "h" => n * 3600,
            "d" => n * 86400,
            "w" => n * 604800,
            _ => -2,
        };
        return seconds > 0;
    }

    public static string Format(long seconds) => seconds switch
    {
        Permanent => "permanent",
        _ when seconds % 604800 == 0 => $"{seconds / 604800}w",
        _ when seconds % 86400 == 0 => $"{seconds / 86400}d",
        _ when seconds % 3600 == 0 => $"{seconds / 3600}h",
        _ when seconds % 60 == 0 => $"{seconds / 60}m",
        _ => $"{seconds}s",
    };

    [GeneratedRegex(@"^(\d{1,9})\s*([smhdw]?)$")]
    private static partial Regex DurationRegex();
}
