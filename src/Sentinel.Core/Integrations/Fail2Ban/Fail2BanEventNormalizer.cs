using System.Globalization;
using System.Text.RegularExpressions;
using Sentinel.Core.Events;

namespace Sentinel.Core.Integrations.Fail2Ban;

/// <summary>
/// Maps fail2ban log records to <see cref="SecurityEvent"/>s. It holds no state between calls, apart from the
/// "Found" aggregation inside one batch: every failed login becomes one aggregated auth.failures event per
/// (jail, IP) per batch, never one event per log line, so a brute-force wave cannot flood the pipeline.
/// </summary>
public static partial class Fail2BanEventNormalizer
{
    public const string ToolId = "fail2ban";

    public static IReadOnlyList<SecurityEvent> Normalize(IEnumerable<Fail2BanLogRecord> records)
    {
        var events = new List<SecurityEvent>();
        var found = new Dictionary<(string Jail, string Ip), List<Fail2BanLogRecord>>();

        foreach (var r in records)
        {
            if (r.Logger == "fail2ban.filter" && r.Jail is not null && FoundRegex().Match(r.Message) is { Success: true } fm)
            {
                var key = (r.Jail, fm.Groups[1].Value);
                if (!found.TryGetValue(key, out var list)) found[key] = list = [];
                list.Add(r);
                continue;
            }
            if (NormalizeOne(r) is { } e) events.Add(e);
        }

        foreach (var ((jail, ip), list) in found)
        {
            var first = list[0];
            var last = list[^1];
            events.Add(new SecurityEvent
            {
                Id = SecurityEvent.StableId(ToolId, first.Raw),
                OccurredAt = last.TimestampUtc,
                Capability = Capability.Banning,
                Severity = Severity.Info,
                SourceTool = ToolId,
                Kind = EventKinds.AuthFailures,
                Subject = ip,
                Message = $"{list.Count} failed attempt{(list.Count == 1 ? "" : "s")} from {ip} matched jail {jail}",
                Raw = string.Join('\n', list.Take(20).Select(l => l.Raw)),
                Metadata = new Dictionary<string, string>
                {
                    ["jail"] = jail,
                    ["count"] = list.Count.ToString(CultureInfo.InvariantCulture),
                    ["firstSeen"] = first.TimestampUtc.ToString("O"),
                    ["lastSeen"] = last.TimestampUtc.ToString("O"),
                },
                DedupKey = $"{ToolId}:{EventKinds.AuthFailures}:{jail}:{ip}",
            });
        }
        return events.OrderBy(e => e.OccurredAt).ToList();
    }

    public static SecurityEvent? NormalizeOne(Fail2BanLogRecord r)
    {
        if (r.Logger == "fail2ban.actions" && r.Level == "NOTICE" && r.Jail is not null)
        {
            var m = BanRegex().Match(r.Message);
            if (!m.Success) return null; // "Flush ticket(s)", "already banned", ...
            var verb = m.Groups["verb"].Value;
            var ip = m.Groups["ip"].Value;
            var manual = r.Jail == Policy.PolicyYaml.ManualJailName;
            var (kind, severity, text) = verb switch
            {
                "Ban" => (EventKinds.BanAdded, manual ? Severity.Info : Severity.Low, manual ? $"Banned {ip} (manual ban from dashboard)" : $"Banned {ip} in jail {r.Jail}"),
                "Restore Ban" => (EventKinds.BanRestored, Severity.Info, $"Restored ban of {ip} in jail {r.Jail} after fail2ban restart"),
                "Increase Ban" => (EventKinds.BanIncreased, Severity.Medium, $"Repeat offender {ip}: ban increased in jail {r.Jail}"),
                "Unban" => (EventKinds.BanRemoved, Severity.Info, $"Unbanned {ip} from jail {r.Jail}"),
                _ => (EventKinds.BanAdded, Severity.Low, r.Message),
            };
            var meta = new Dictionary<string, string> { ["jail"] = r.Jail, ["manual"] = manual ? "true" : "false" };
            if (m.Groups["detail"].Success) meta["detail"] = m.Groups["detail"].Value;
            return Build(r, kind, severity, ip, text, meta, $"{ToolId}:{kind}:{r.Jail}:{ip}");
        }

        if (r.Level is "ERROR" or "CRITICAL")
        {
            // fail2ban.utils lines are the stderr lines of a failed action command. The fail2ban.actions
            // summary line that follows carries the meaning, so we skip the detail to avoid ten events per failure.
            if (r.Logger == "fail2ban.utils") return null;

            var af = ActionFailedRegex().Match(r.Message);
            if (af.Success)
            {
                var ip = IpInActionInfoRegex().Match(r.Message) is { Success: true } im ? im.Groups[1].Value : null;
                var jail = af.Groups["jail"].Value;
                var action = af.Groups["action"].Value;
                return Build(r, EventKinds.ToolError, Severity.High, ip,
                    $"fail2ban could not enforce the {af.Groups["op"].Value} of {ip ?? "an address"} in jail {jail}: action '{action}' failed",
                    new Dictionary<string, string> { ["jail"] = jail, ["action"] = action, ["operation"] = af.Groups["op"].Value },
                    $"{ToolId}:action-failed:{jail}:{action}");
            }
            return Build(r, EventKinds.ToolError, r.Level == "CRITICAL" ? Severity.High : Severity.Medium, r.Jail,
                $"fail2ban error: {Truncate(r.Message, 300)}",
                new Dictionary<string, string> { ["logger"] = r.Logger },
                $"{ToolId}:{EventKinds.ToolError}:{r.Logger}");
        }

        return null;
    }

    private static SecurityEvent Build(Fail2BanLogRecord r, string kind, Severity sev, string? subject, string message, Dictionary<string, string> meta, string dedup)
    {
        meta["pid"] = r.Pid.ToString(CultureInfo.InvariantCulture);
        return new SecurityEvent
        {
            Id = SecurityEvent.StableId(ToolId, r.Raw),
            OccurredAt = r.TimestampUtc,
            Capability = Capability.Banning,
            Severity = sev,
            SourceTool = ToolId,
            Kind = kind,
            Subject = subject,
            Message = message,
            Raw = r.Raw,
            Metadata = meta,
            DedupKey = dedup,
        };
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    [GeneratedRegex(@"^Found (\S+?),? - ")]
    private static partial Regex FoundRegex();

    // "Ban 1.2.3.4", "Restore Ban 1.2.3.4", "Unban 1.2.3.4", "Increase Ban 1.2.3.4 (2 # 2:00:00 -> 2026-10-24 10:00:00)"
    [GeneratedRegex(@"^(?<verb>Restore Ban|Increase Ban|Unban|Ban) (?<ip>\S+)(?: \((?<detail>.*)\))?$")]
    private static partial Regex BanRegex();

    [GeneratedRegex(@"^Failed to execute (?<op>ban|unban) jail '(?<jail>[^']+)' action '(?<action>[^']+)'")]
    private static partial Regex ActionFailedRegex();

    [GeneratedRegex(@"'ip': '([^']+)'")]
    private static partial Regex IpInActionInfoRegex();
}
