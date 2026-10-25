using System.Globalization;
using System.Text.RegularExpressions;

namespace Alastor.Core.Integrations.Fail2Ban;

public sealed record Fail2BanBan(string Jail, string Target, DateTime BannedAtUtc, long BanSeconds, DateTime? ExpiresAtUtc);

public sealed record Fail2BanLogRecord(DateTime TimestampUtc, string Logger, int Pid, string Level, string? Jail, string Message, string Raw);

/// <summary>
/// Parsers for fail2ban's own output. Where possible we query <c>fail2ban-client</c> (its control socket API).
/// The log parser is the documented-format fallback for real-time events, which the client cannot stream.
/// </summary>
public static partial class Fail2BanParsers
{
    private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

    /// <summary>Parses <c>fail2ban-client status</c>, e.g. <c>`- Jail list:	alastor-manual, sshd</c>.</summary>
    public static IReadOnlyList<string> ParseJailList(string statusOutput)
    {
        var m = JailListRegex().Match(statusOutput);
        if (!m.Success) return [];
        return m.Groups[1].Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    /// <summary>Parses <c>fail2ban-client get &lt;jail&gt; banip --with-time</c> (fail2ban ≥ 0.11). Timestamps are server-local time.</summary>
    public static IReadOnlyList<Fail2BanBan> ParseBanList(string jail, string output, TimeZoneInfo tz)
    {
        var bans = new List<Fail2BanBan>();
        foreach (var line in output.Split('\n'))
        {
            var m = BanLineRegex().Match(line.Trim());
            if (!m.Success) continue;
            var banned = ToUtc(m.Groups[2].Value, tz);
            var seconds = long.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture);
            bans.Add(new Fail2BanBan(jail, m.Groups[1].Value, banned, seconds, seconds < 0 ? null : banned.AddSeconds(seconds)));
        }
        return bans;
    }

    /// <summary>Parses <c>fail2ban-client version</c> (<c>1.1.0</c>) or <c>--version</c> (<c>Fail2Ban v1.1.0</c>).</summary>
    public static string? ParseVersion(string output)
    {
        var m = VersionRegex().Match(output);
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>
    /// Parses <c>fail2ban-client get logtarget</c>. Returns a file path, or null when fail2ban logs to
    /// SYSLOG, SYSTEMD-JOURNAL or STDOUT. In that case we rely on ban-list snapshots only.
    /// </summary>
    public static string? ParseLogTarget(string output)
    {
        var m = LogTargetRegex().Match(output);
        return m.Success && m.Groups[1].Value.StartsWith('/') ? m.Groups[1].Value.Trim() : null;
    }

    /// <summary>Extracts the error messages from <c>fail2ban-client -t</c> output.</summary>
    public static IReadOnlyList<string> ParseTestErrors(string output) =>
        output.Split('\n')
            .Select(l => ParseLogLine(l, TimeZoneInfo.Utc))
            .Where(r => r is { Level: "ERROR" })
            .Select(r => r!.Message)
            .Where(m => !m.StartsWith("ERROR: test configuration failed", StringComparison.Ordinal))
            .ToList();

    /// <summary>Parses one line of fail2ban's log (format <c>%(asctime)s %(name)-24s[%(process)d]: %(levelname)-7s %(message)s</c>).</summary>
    public static Fail2BanLogRecord? ParseLogLine(string line, TimeZoneInfo tz)
    {
        var m = LogLineRegex().Match(line.TrimEnd('\r'));
        if (!m.Success) return null;
        var ts = ToUtc(m.Groups["ts"].Value, tz).AddMilliseconds(int.Parse(m.Groups["ms"].Value, CultureInfo.InvariantCulture));
        return new Fail2BanLogRecord(
            ts,
            m.Groups["logger"].Value,
            int.Parse(m.Groups["pid"].Value, CultureInfo.InvariantCulture),
            m.Groups["level"].Value,
            m.Groups["jail"].Success ? m.Groups["jail"].Value : null,
            m.Groups["msg"].Value.Trim(),
            line.TrimEnd('\r'));
    }

    private static DateTime ToUtc(string local, TimeZoneInfo tz)
    {
        var dt = DateTime.ParseExact(local, TimeFormat, CultureInfo.InvariantCulture, DateTimeStyles.None);
        if (dt.Year >= 9999) return DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc);
        return TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(dt, DateTimeKind.Unspecified), tz);
    }

    [GeneratedRegex(@"Jail list:\s*(.*)$", RegexOptions.Multiline)]
    private static partial Regex JailListRegex();

    [GeneratedRegex(@"^(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \+ (-?\d+) = (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)$")]
    private static partial Regex BanLineRegex();

    [GeneratedRegex(@"(?:Fail2Ban v)?(\d+\.\d+(?:\.\d+)?(?:[\w.\-]*))")]
    private static partial Regex VersionRegex();

    [GeneratedRegex(@"`-\s+(\S.*)$", RegexOptions.Multiline)]
    private static partial Regex LogTargetRegex();

    [GeneratedRegex(@"^(?<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),(?<ms>\d{3}) (?<logger>fail2ban[\w.]*)\s*\[(?<pid>\d+)\]: (?<level>[A-Z]+)\s+(?:\[(?<jail>[^\]\s]+)\] )?(?<msg>.*)$")]
    private static partial Regex LogLineRegex();
}
