using System.Globalization;
using System.Text.RegularExpressions;
using Alastor.Core.Net;

namespace Alastor.Core.Firewall;

/// <summary>
/// One allow rule the agent owns in ufw. <see cref="Protocol"/> null means both TCP and UDP; <see cref="From"/> null means
/// any source; <see cref="Interface"/> limits it to traffic arriving on one interface (tailscale0).
/// </summary>
public sealed record UfwRule(int Port, int? PortEnd, string? Protocol, string? From, string? Interface)
{
    public const string Comment = "alastor";

    public string PortText => PortEnd is { } end ? $"{Port}:{end}" : Port.ToString(CultureInfo.InvariantCulture);

    /// <summary>"443/tcp", "5432/tcp from 10.0.0.0/8", "9100/tcp on tailscale0": the policy syntax, also used for display.</summary>
    public override string ToString() =>
        $"{(PortEnd is null ? PortText : $"{Port}-{PortEnd}")}{(Protocol is null ? "" : "/" + Protocol)}{(From is null ? "" : " from " + From)}{(Interface is null ? "" : " on " + Interface)}";

    /// <summary>The arguments after <c>ufw</c> that add this rule, in the form <c>ufw show added</c> prints back.</summary>
    public IReadOnlyList<string> AddArgs()
    {
        if (From is null && Interface is null)
            return ["allow", Protocol is null ? PortText : $"{PortText}/{Protocol}", "comment", Comment];
        var args = new List<string> { "allow" };
        if (Interface is not null) args.AddRange(["in", "on", Interface]);
        if (From is not null) args.AddRange(["from", From]);
        args.AddRange(["to", "any", "port", PortText]);
        if (Protocol is not null) args.AddRange(["proto", Protocol]);
        args.AddRange(["comment", Comment]);
        return args;
    }

    /// <summary><c>ufw delete allow …</c> matches the rule whether or not the comment is repeated (checked with ufw 0.36.2).</summary>
    public IReadOnlyList<string> DeleteArgs() => ["delete", .. AddArgs()];
}

public static partial class UfwRules
{
    /// <summary>
    /// Policy syntax: <c>PORT[-END][/tcp|/udp] [from ADDRESS|CIDR] [on INTERFACE]</c>, e.g. <c>443/tcp</c>,
    /// <c>5432/tcp from 10.0.0.0/8</c>, <c>9100/tcp on tailscale0</c>. A range needs a protocol (ufw's rule).
    /// </summary>
    public static bool TryParse(string? text, out UfwRule? rule, out string? error)
    {
        rule = null;
        error = null;
        var tokens = (text ?? "").Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0) { error = "Empty rule."; return false; }
        if (!Network.ServiceExposureAssessor.TryParsePortSpec(tokens[0], out var lo, out var hi, out var proto))
        {
            error = $"'{tokens[0]}' is not a port: use 443, 443/tcp, 51820/udp or a range like 60000-61000/udp.";
            return false;
        }
        if (hi != lo && proto is null) { error = "A port range needs a protocol, e.g. 60000-61000/udp."; return false; }
        string? from = null, iface = null;
        for (var i = 1; i < tokens.Length; i += 2)
        {
            if (i + 1 >= tokens.Length) { error = $"'{tokens[i]}' needs a value."; return false; }
            switch (tokens[i])
            {
                case "from" when IpTarget.TryParse(tokens[i + 1], out var t):
                    from = t.Value.Network.PrefixLength == (t.Value.Network.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128)
                        ? t.Value.Network.BaseAddress.ToString() : t.Value.Network.ToString();
                    break;
                case "on" when Interface().IsMatch(tokens[i + 1]):
                    iface = tokens[i + 1];
                    break;
                default:
                    error = $"Expected 'from ADDRESS' or 'on INTERFACE', not '{tokens[i]} {tokens[i + 1]}'.";
                    return false;
            }
        }
        rule = new UfwRule(lo, hi == lo ? null : hi, proto, from, iface);
        return true;
    }

    /// <summary>
    /// <c>firewall.ssh</c> entries: <c>any</c>, <c>from CIDR</c>, <c>on INTERFACE</c> or both, applied to each of sshd's ports.
    /// </summary>
    public static bool TryParseSshSource(string? text, int port, out UfwRule? rule, out string? error)
    {
        var t = (text ?? "").Trim();
        return TryParse(t is "any" or "" ? $"{port}/tcp" : $"{port}/tcp {t}", out rule, out error);
    }

    /// <summary>
    /// The rules carrying <c>comment 'alastor'</c> in <c>ufw show added</c> output ("ufw allow 22/tcp comment 'alastor'",
    /// "ufw allow from 10.0.0.0/8 to any port 5432 proto tcp comment 'alastor'", "ufw allow in on tailscale0 to any port
    /// 9100 proto tcp comment 'alastor'"). Everyone else's rules are left alone.
    /// </summary>
    public static List<UfwRule> ParseShowAdded(string output)
    {
        var result = new List<UfwRule>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith("ufw allow ", StringComparison.Ordinal) || !line.EndsWith($"comment '{UfwRule.Comment}'", StringComparison.Ordinal)) continue;
            var tokens = line[..^$" comment '{UfwRule.Comment}'".Length].Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(2).ToList();
            if (ParseTokens(tokens) is { } rule) result.Add(rule);
        }
        return result.Distinct().ToList();
    }

    private static UfwRule? ParseTokens(List<string> t)
    {
        if (t.Count == 1)
        {
            var parts = t[0].Split('/');
            return PortRange(parts[0]) is { } p ? new UfwRule(p.Lo, p.Hi, parts.Length == 2 ? parts[1] : null, null, null) : null;
        }
        string? from = null, iface = null, proto = null;
        (int Lo, int? Hi)? port = null;
        for (var i = 0; i < t.Count; i++)
        {
            switch (t[i])
            {
                case "in": break;
                case "on" when i + 1 < t.Count: iface = t[++i]; break;
                case "from" when i + 1 < t.Count: from = t[++i] == "any" ? null : t[i]; break;
                case "to" when i + 1 < t.Count: i++; break;
                case "port" when i + 1 < t.Count: port = PortRange(t[++i]); break;
                case "proto" when i + 1 < t.Count: proto = t[++i]; break;
                default: return null;
            }
        }
        return port is { } pr ? new UfwRule(pr.Lo, pr.Hi, proto, from, iface) : null;
    }

    private static (int Lo, int? Hi)? PortRange(string text)
    {
        var r = text.Split(':');
        if (!int.TryParse(r[0], CultureInfo.InvariantCulture, out var lo)) return null;
        if (r.Length == 1) return (lo, null);
        return int.TryParse(r[1], CultureInfo.InvariantCulture, out var hi) ? (lo, hi) : null;
    }

    /// <summary><c>ufw status verbose</c>: active, and the default for incoming traffic (deny, reject or allow).</summary>
    public static (bool Active, string? DefaultIncoming) ParseStatus(string output)
    {
        var active = output.Split('\n').Any(l => l.Trim().Equals("Status: active", StringComparison.OrdinalIgnoreCase));
        var m = DefaultIncoming().Match(output);
        return (active, m.Success ? m.Groups[1].Value.ToLowerInvariant() : null);
    }

    [GeneratedRegex(@"^[A-Za-z0-9_.:-]{1,15}$")]
    private static partial Regex Interface();

    [GeneratedRegex(@"\b(allow|deny|reject) \(incoming\)", RegexOptions.IgnoreCase)]
    private static partial Regex DefaultIncoming();
}
