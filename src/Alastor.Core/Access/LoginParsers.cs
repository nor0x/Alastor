using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Alastor.Core.Access;

/// <summary>One successful SSH login, as sshd logs it ("Accepted publickey for root from 203.0.113.5 port 39750 ssh2: ED25519 SHA256:…").</summary>
/// <param name="Key">"ED25519 SHA256:…" for key logins.</param>
/// <param name="Cursor">The journald cursor (or the raw log line) the login came from; it makes the event id stable.</param>
public sealed record LoginRecord(DateTime AtUtc, string User, string Address, int Port, string Method, string? Key, string Cursor);

/// <summary>
/// Reads sshd's "Accepted …" messages from <c>journalctl -o json</c> (systemd.journal-fields(7): <c>MESSAGE</c>,
/// <c>__REALTIME_TIMESTAMP</c> in microseconds, <c>__CURSOR</c>) or from syslog files (<c>/var/log/auth.log</c> with
/// RFC 3339 timestamps, <c>/var/log/secure</c> with traditional ones). The message text is sshd's own, stable for decades.
/// </summary>
public static partial class LoginParsers
{
    public static LoginRecord? ParseMessage(string message, DateTime atUtc, string cursor)
    {
        var m = Accepted().Match(message);
        if (!m.Success || !IPAddress.TryParse(m.Groups["addr"].Value, out var ip)) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return new LoginRecord(atUtc, m.Groups["user"].Value, ip.ToString(), int.Parse(m.Groups["port"].Value, CultureInfo.InvariantCulture),
            m.Groups["method"].Value, m.Groups["key"].Success ? m.Groups["key"].Value : null, cursor);
    }

    /// <summary>Returns the logins and the cursor of the last entry read (null when the output had no entries).</summary>
    public static (List<LoginRecord> Logins, string? LastCursor) ParseJournal(string output)
    {
        var logins = new List<LoginRecord>();
        string? last = null;
        foreach (var line in output.Split('\n'))
        {
            if (line.Length == 0 || line[0] != '{') continue;
            JsonDocument doc;
            try { doc = JsonDocument.Parse(line); }
            catch (JsonException) { continue; }
            using (doc)
            {
                var root = doc.RootElement;
                if (root.TryGetProperty("__CURSOR", out var c) && c.ValueKind == JsonValueKind.String) last = c.GetString();
                // MESSAGE is a byte array when it isn't valid UTF-8; sshd's accept messages always are.
                if (!root.TryGetProperty("MESSAGE", out var msg) || msg.ValueKind != JsonValueKind.String) continue;
                var at = root.TryGetProperty("__REALTIME_TIMESTAMP", out var ts) && long.TryParse(ts.GetString(), CultureInfo.InvariantCulture, out var us)
                    ? DateTime.UnixEpoch.AddTicks(us * 10)
                    : DateTime.UtcNow;
                if (ParseMessage(msg.GetString()!, at, last ?? line) is { } login) logins.Add(login);
            }
        }
        return (logins, last);
    }

    /// <summary>
    /// A syslog line from sshd (<c>sshd[pid]:</c> or <c>sshd-session[pid]:</c>). Traditional timestamps carry no year or
    /// zone; they are read as local time in the year closest to <paramref name="nowUtc"/>.
    /// </summary>
    public static LoginRecord? ParseSyslogLine(string line, DateTime nowUtc)
    {
        var m = SyslogSshd().Match(line);
        if (!m.Success) return null;
        DateTime at;
        if (DateTime.TryParse(m.Groups["ts"].Value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var iso)
            && m.Groups["ts"].Value.Contains('T'))
            at = iso;
        else if (DateTime.TryParseExact(Regex.Replace(m.Groups["ts"].Value, @"\s+", " "), "MMM d HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var local))
        {
            at = local.ToUniversalTime();
            if (at > nowUtc.AddDays(1)) at = at.AddYears(-1); // December lines read in January
        }
        else at = nowUtc;
        return ParseMessage(m.Groups["msg"].Value, at, line);
    }

    [GeneratedRegex(@"^Accepted (?<method>\S+) for (?<user>\S+) from (?<addr>\S+) port (?<port>\d+)(?: ssh2)?(?:: (?<key>\S+ \S+))?")]
    private static partial Regex Accepted();

    [GeneratedRegex(@"^(?<ts>\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd(?:-session)?\[\d+\]: (?<msg>.*)$")]
    private static partial Regex SyslogSshd();
}
