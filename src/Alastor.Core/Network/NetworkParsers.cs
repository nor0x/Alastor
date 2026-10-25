using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Alastor.Core.Network;

/// <summary>
/// Readers for the structured output the exposure check uses: <c>tailscale status --json</c>, <c>ip -j addr</c>,
/// <c>sshd -T</c>, <c>ss -tulpnH</c> (iproute2's socket list with owning processes) and, without it, the kernel's
/// <c>/proc/net/{tcp,udp}{,6}</c> (documented in the kernel's proc_net_tcp.txt), <c>/proc/&lt;pid&gt;/cgroup</c> for the
/// systemd unit, <c>systemd-analyze security --json=short</c>, <c>nft -j list ruleset</c> (libnftables-json) and
/// <c>ufw status verbose</c> (ufw has no machine-readable output). All are tested against fixtures.
/// </summary>
public static partial class NetworkParsers
{
    // ---- Tailscale ----

    public static TailscaleInfo ParseTailscaleStatus(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var self = root.TryGetProperty("Self", out var s) && s.ValueKind == JsonValueKind.Object ? s : default;
        var peers = root.TryGetProperty("Peer", out var p) && p.ValueKind == JsonValueKind.Object ? p.EnumerateObject().Select(x => x.Value).ToList() : [];
        DateTime? expiry = null;
        if (self.ValueKind == JsonValueKind.Object && self.TryGetProperty("KeyExpiry", out var ke) && ke.ValueKind == JsonValueKind.String
            && DateTime.TryParse(ke.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var exp))
            expiry = exp;
        string? tailnet = root.TryGetProperty("CurrentTailnet", out var ct) && ct.ValueKind == JsonValueKind.Object ? Str(ct, "Name") : null;
        var dns = self.ValueKind == JsonValueKind.Object ? Str(self, "DNSName")?.TrimEnd('.') : null;
        return new TailscaleInfo(
            Str(root, "Version"),
            Str(root, "BackendState") ?? "NoState",
            StrArray(root, "TailscaleIPs"),
            string.IsNullOrEmpty(dns) ? null : dns,
            string.IsNullOrEmpty(tailnet) ? null : tailnet,
            peers.Count,
            peers.Count(x => x.TryGetProperty("Online", out var o) && o.ValueKind == JsonValueKind.True),
            null,
            expiry,
            StrArray(root, "Health"));
    }

    /// <summary><c>tailscale debug prefs</c>: ipn.Prefs as JSON; <c>RunSSH</c> is whether Tailscale SSH is on.</summary>
    public static bool? ParseTailscaleRunSsh(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("RunSSH", out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False ? v.GetBoolean() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // ---- addresses and sockets ----

    /// <summary><c>ip -j addr show</c>: interfaces with <c>addr_info[]</c> entries of family inet/inet6.</summary>
    public static List<HostAddress> ParseIpAddr(string json)
    {
        var result = new List<HostAddress>();
        using var doc = JsonDocument.Parse(json);
        foreach (var iface in doc.RootElement.EnumerateArray())
        {
            var name = Str(iface, "ifname") ?? "?";
            if (!iface.TryGetProperty("addr_info", out var infos) || infos.ValueKind != JsonValueKind.Array) continue;
            foreach (var a in infos.EnumerateArray())
            {
                if (Str(a, "family") is not ("inet" or "inet6") || Str(a, "local") is not { } local) continue;
                var prefix = a.TryGetProperty("prefixlen", out var pl) && pl.TryGetInt32(out var n) ? n : 0;
                result.Add(new HostAddress(name, local, prefix, AddressClassifier.Classify(local)));
            }
        }
        return result;
    }

    /// <summary>
    /// <c>/proc/net/tcp</c> or <c>tcp6</c>: rows of "sl local_address rem_address st …". Addresses are hex, each 32-bit word
    /// in host (little-endian) byte order; ports are hex in network order; state 0A is LISTEN.
    /// </summary>
    public static List<TcpListenSocket> ParseProcNetTcp(string content) =>
        ParseProcNet(content, "tcp").Select(s => new TcpListenSocket(s.Address, s.Port)).Distinct().ToList();

    /// <summary>
    /// Listening sockets from <c>/proc/net/{tcp,tcp6,udp,udp6}</c>, without owners. TCP: state 0A (LISTEN). UDP: state 07
    /// (unconnected) with no remote address, which is how a bound, receiving UDP socket appears.
    /// </summary>
    public static List<ListenSocket> ParseProcNet(string content, string protocol)
    {
        var result = new List<ListenSocket>();
        foreach (var line in content.Split('\n').Skip(1))
        {
            var cols = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length < 4) continue;
            if (protocol == "tcp" ? cols[3] != "0A" : cols[3] != "07" || cols[2].Trim('0', ':').Length > 0) continue;
            var colon = cols[1].IndexOf(':');
            if (colon <= 0) continue;
            var hex = cols[1][..colon];
            if (!int.TryParse(cols[1][(colon + 1)..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var port)) continue;
            if (hex.Length is not (8 or 32)) continue;
            var bytes = new byte[hex.Length / 2];
            for (var word = 0; word < hex.Length / 8; word++)
                for (var b = 0; b < 4; b++)
                    bytes[word * 4 + b] = byte.Parse(hex.AsSpan(word * 8 + (3 - b) * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var ip = new IPAddress(bytes);
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            result.Add(new ListenSocket(protocol, ip.ToString(), port));
        }
        return result.Distinct().ToList();
    }

    /// <summary>
    /// <c>ss -tulpnH</c>: "Netid State Recv-Q Send-Q Local:Port Peer:Port [users:((name,pid=N,fd=N),…)]". Local addresses
    /// look like <c>0.0.0.0:22</c>, <c>[::]:443</c>, <c>*:80</c> (any family), <c>127.0.0.53%lo:53</c> or
    /// <c>[fe80::1]%eth0:546</c>. The process column needs root; without it the owner is null.
    /// </summary>
    public static List<ListenSocket> ParseSs(string output)
    {
        var result = new List<ListenSocket>();
        foreach (var raw in output.Split('\n'))
        {
            var cols = raw.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length < 5 || cols[0] is not ("tcp" or "udp") || cols[1] is not ("LISTEN" or "UNCONN")) continue;
            var local = cols[4];
            var colon = local.LastIndexOf(':');
            if (colon <= 0 || !int.TryParse(local[(colon + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) || port is <= 0 or > 65535) continue;
            var host = local[..colon];
            var pct = host.IndexOf('%');
            if (pct >= 0) host = host[..pct];
            host = host.Trim('[', ']');
            if (host == "*") host = "::";
            if (!IPAddress.TryParse(host, out var ip)) continue;
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            var users = SsUsers().Match(raw);
            result.Add(new ListenSocket(cols[0], ip.ToString(), port,
                users.Success ? users.Groups[1].Value : null,
                users.Success && int.TryParse(users.Groups[2].Value, CultureInfo.InvariantCulture, out var pid) ? pid : null));
        }
        return result.Distinct().ToList();
    }

    /// <summary>
    /// <c>/proc/&lt;pid&gt;/cgroup</c>: the systemd service the process runs in, from the unified (<c>0::/system.slice/nginx.service</c>)
    /// or the v1 <c>name=systemd</c> hierarchy. Null for processes outside a service (sessions, containers' own init).
    /// </summary>
    public static string? ParseCgroupUnit(string content)
    {
        foreach (var line in content.Split('\n'))
        {
            var parts = line.Trim().Split(':', 3);
            if (parts.Length != 3 || !(parts[0] == "0" && parts[1] == "" || parts[1] == "name=systemd")) continue;
            var unit = parts[2].Split('/').LastOrDefault(seg => seg.EndsWith(".service", StringComparison.Ordinal));
            if (unit is not null) return unit;
        }
        return null;
    }

    /// <summary>
    /// <c>systemd-analyze security --json=short UNIT…</c> (systemd 250+): <c>[{"unit":…,"exposure":…,"predicate":…}]</c>, the
    /// exposure score from 0.0 (locked down) to 10.0 (no sandboxing) and its rating (OK, MEDIUM, EXPOSED, UNSAFE).
    /// The score is printed as a string by some versions and a number by others.
    /// </summary>
    public static Dictionary<string, (double Exposure, string Rating)> ParseSystemdSecurity(string json)
    {
        var result = new Dictionary<string, (double, string)>(StringComparer.Ordinal);
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) return result;
        foreach (var e in doc.RootElement.EnumerateArray())
        {
            if (Str(e, "unit") is not { } unit || !e.TryGetProperty("exposure", out var x)) continue;
            double? exposure = x.ValueKind == JsonValueKind.Number ? x.GetDouble()
                : x.ValueKind == JsonValueKind.String && double.TryParse(x.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;
            if (exposure is { } v) result[unit] = (v, Str(e, "predicate") ?? "");
        }
        return result;
    }

    /// <summary>
    /// <c>sshd -T</c>: every <c>port</c> line, plus the auth settings. Returns the ports sshd serves, defaulting to 22.
    /// </summary>
    public static (List<int> Ports, bool PasswordAuthentication, string PermitRootLogin) ParseSshdSettings(string output)
    {
        var ports = new List<int>();
        var password = true;
        var root = "prohibit-password";
        foreach (var raw in output.Split('\n'))
        {
            var parts = raw.Trim().Split(' ', 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2) continue;
            switch (parts[0].ToLowerInvariant())
            {
                case "port" when int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var p) && p is > 0 and < 65536:
                    if (!ports.Contains(p)) ports.Add(p);
                    break;
                case "passwordauthentication":
                    password = parts[1].Equals("yes", StringComparison.OrdinalIgnoreCase);
                    break;
                case "permitrootlogin":
                    root = parts[1].ToLowerInvariant();
                    break;
            }
        }
        return (ports.Count > 0 ? ports : [22], password, root);
    }

    // ---- firewall: ufw ----

    /// <summary>
    /// <c>ufw status verbose</c>. ufw is first-match: the first rule covering the SSH port decides. Returns null when ufw is
    /// inactive (the caller then reads nftables) or the output isn't recognized.
    /// </summary>
    public static FirewallAssessment? ParseUfwSsh(string output, IReadOnlyCollection<int> ports) => ParseUfw(output, ports, "tcp", PortText(ports));

    /// <summary>
    /// The same first-match reading for any ports and protocol; <paramref name="label"/> names them in the detail text
    /// (<c>port 443/tcp</c>).
    /// </summary>
    public static FirewallAssessment? ParseUfw(string output, IReadOnlyCollection<int> ports, string protocol, string label)
    {
        var lines = output.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var status = lines.FirstOrDefault(l => l.StartsWith("Status:", StringComparison.OrdinalIgnoreCase));
        if (status is null || !status[7..].Trim().Equals("active", StringComparison.OrdinalIgnoreCase)) return null;
        var defaultLine = lines.FirstOrDefault(l => l.StartsWith("Default:", StringComparison.OrdinalIgnoreCase)) ?? "";
        var defaultAllow = DefaultIncoming().Match(defaultLine) is { Success: true } m && m.Groups[1].Value is "allow";

        var portText = label;
        var restrictions = new List<string>();
        var start = lines.FindIndex(l => l.StartsWith("--", StringComparison.Ordinal));
        foreach (var line in start < 0 ? [] : lines.Skip(start + 1))
        {
            var cols = Columns().Split(line.Trim());
            if (cols.Length < 3) continue;
            var (to, action, from) = (cols[0], cols[1].ToUpperInvariant(), cols[2]);
            if (action.EndsWith(" OUT", StringComparison.Ordinal) || action.EndsWith(" FWD", StringComparison.Ordinal)) continue;
            var on = to.IndexOf(" on ", StringComparison.Ordinal);
            var iface = on > 0 ? to[(on + 4)..].Replace(" (v6)", "").Trim() : null;
            var target = (on > 0 ? to[..on] : to).Replace(" (v6)", "").Trim();
            if (!UfwCovers(target, ports, protocol)) continue;
            var anywhere = from.StartsWith("Anywhere", StringComparison.OrdinalIgnoreCase) && iface is null;
            var allows = action.StartsWith("ALLOW", StringComparison.Ordinal) || action.StartsWith("LIMIT", StringComparison.Ordinal);
            if (allows && anywhere)
                return new("ufw", FirewallSshVerdict.OpenToAnywhere,
                    $"ufw {(action.StartsWith("LIMIT", StringComparison.Ordinal) ? "allows (rate-limited)" : "allows")} {portText} from anywhere (rule \"{target}\").");
            if (!allows && anywhere)
                return restrictions.Count > 0
                    ? new("ufw", FirewallSshVerdict.Restricted, $"ufw allows {portText} only {string.Join(", ", restrictions.Distinct())}.")
                    : new("ufw", FirewallSshVerdict.Blocked, $"ufw denies {portText}.");
            if (allows) restrictions.Add(iface is not null ? $"on {iface}" : $"from {from.Replace(" (v6)", "")}");
        }
        if (restrictions.Count > 0) return new("ufw", FirewallSshVerdict.Restricted, $"ufw allows {portText} only {string.Join(", ", restrictions.Distinct())}.");
        return defaultAllow
            ? new("ufw", FirewallSshVerdict.OpenToAnywhere, $"ufw is active but allows incoming traffic by default, including {portText}.")
            : new("ufw", FirewallSshVerdict.Blocked, $"ufw denies incoming traffic by default and no rule allows {portText}.");
    }

    /// <summary>
    /// "22/tcp", "22" (tcp and udp), "22,80/tcp", "1000:2000/tcp", "Anywhere" (every port), or an app profile like
    /// "OpenSSH" or "Nginx Full".
    /// </summary>
    private static bool UfwCovers(string target, IReadOnlyCollection<int> ports, string protocol)
    {
        if (target.Equals("Anywhere", StringComparison.OrdinalIgnoreCase)) return true;
        var slash = target.IndexOf('/');
        if (slash > 0 && target[(slash + 1)..] != protocol) return false;
        var spec = slash > 0 ? target[..slash] : target;
        if (!char.IsDigit(spec.FirstOrDefault()))
            return protocol == "tcp" && UfwProfilePorts(spec).Any(ports.Contains);
        foreach (var part in spec.Split(','))
        {
            var range = part.Split(':');
            if (range.Length == 1 && int.TryParse(range[0], out var single) && ports.Contains(single)) return true;
            if (range.Length == 2 && int.TryParse(range[0], out var lo) && int.TryParse(range[1], out var hi) && ports.Any(p => p >= lo && p <= hi)) return true;
        }
        return false;
    }

    /// <summary>
    /// Ports of the app profiles distributions ship in /etc/ufw/applications.d (OpenSSH, nginx, Apache). Other profiles
    /// are unknown here and don't count as covering a port.
    /// </summary>
    private static int[] UfwProfilePorts(string profile)
    {
        var p = profile.ToLowerInvariant();
        if (p.Contains("ssh", StringComparison.Ordinal)) return [22];
        if (p is "nginx full" or "apache full" or "www full") return [80, 443];
        if (p is "nginx http" or "apache" or "www") return [80];
        if (p is "nginx https" or "apache secure" or "www secure") return [443];
        return [];
    }

    // ---- firewall: nftables ----

    /// <summary>
    /// <c>nft -j list ruleset</c>: reads every base chain on the input hook in order, following jumps, and finds the first
    /// rule that decides the SSH port. Rules for established connections and loopback are skipped. This reads rules; it
    /// doesn't simulate packets, so unusual matches (marks, sets of interfaces, xt compat matches) count as restrictions.
    /// </summary>
    public static FirewallAssessment ParseNftSsh(string json, IReadOnlyCollection<int> ports) => ParseNft(json, ports, "tcp", PortText(ports));

    /// <summary>The same reading for any ports and protocol; <paramref name="label"/> names them in the detail text.</summary>
    public static FirewallAssessment ParseNft(string json, IReadOnlyCollection<int> ports, string protocol, string label)
    {
        using var doc = JsonDocument.Parse(json);
        var chains = new Dictionary<(string, string, string), (string? Hook, string? Policy)>();
        var rules = new Dictionary<(string, string, string), List<JsonElement>>();
        if (doc.RootElement.TryGetProperty("nftables", out var items))
            foreach (var item in items.EnumerateArray())
            {
                if (item.TryGetProperty("chain", out var c))
                    chains[(Str(c, "family") ?? "", Str(c, "table") ?? "", Str(c, "name") ?? "")] = (Str(c, "hook"), Str(c, "policy"));
                else if (item.TryGetProperty("rule", out var r))
                {
                    var key = (Str(r, "family") ?? "", Str(r, "table") ?? "", Str(r, "chain") ?? "");
                    if (!rules.TryGetValue(key, out var list)) rules[key] = list = [];
                    list.Add(r.Clone());
                }
            }

        var portText = label;
        var bases = chains.Where(c => c.Value.Hook == "input").ToList();
        if (bases.Count == 0) return new("nftables", FirewallSshVerdict.NoFirewall, "No nftables chain filters incoming traffic.");

        var restrictions = new List<string>();
        var verdicts = new List<FirewallSshVerdict>();
        foreach (var (key, (_, policy)) in bases)
        {
            var outcome = Walk(key, 0);
            verdicts.Add(outcome switch
            {
                "accept" => FirewallSshVerdict.OpenToAnywhere,
                "drop" => FirewallSshVerdict.Blocked,
                _ => policy == "drop" ? FirewallSshVerdict.Blocked : FirewallSshVerdict.NoFirewall,
            });
        }

        // Every input chain must let a packet through; the strictest one decides.
        if (verdicts.Contains(FirewallSshVerdict.Blocked))
            return restrictions.Count > 0
                ? new("nftables", FirewallSshVerdict.Restricted, $"nftables accepts {portText} only {string.Join(", ", restrictions.Distinct())}.")
                : new("nftables", FirewallSshVerdict.Blocked, $"nftables drops {portText}.");
        if (verdicts.Contains(FirewallSshVerdict.OpenToAnywhere))
            return new("nftables", FirewallSshVerdict.OpenToAnywhere, $"nftables accepts {portText} from anywhere.");
        return new("nftables", FirewallSshVerdict.NoFirewall, $"nftables doesn't filter {portText}.");

        // "accept" or "drop" when a rule decides unconditionally for the port; null to fall through to the chain policy.
        string? Walk((string Family, string Table, string Chain) chain, int depth)
        {
            if (depth > 8 || !rules.TryGetValue(chain, out var list)) return null;
            foreach (var rule in list)
            {
                if (!rule.TryGetProperty("expr", out var exprs) || exprs.ValueKind != JsonValueKind.Array) continue;
                var applies = true;
                var restricted = new List<string>();
                string? verdict = null;
                string? target = null;
                foreach (var e in exprs.EnumerateArray())
                {
                    if (e.TryGetProperty("match", out var m))
                    {
                        switch (ClassifyMatch(m, ports, protocol, out var detail))
                        {
                            case MatchEffect.NotForPort: applies = false; break;
                            case MatchEffect.Restricts: restricted.Add(detail!); break;
                        }
                    }
                    else if (e.TryGetProperty("accept", out _)) verdict = "accept";
                    else if (e.TryGetProperty("drop", out _) || e.TryGetProperty("reject", out _)) verdict = "drop";
                    else if (e.TryGetProperty("return", out _)) verdict = "return";
                    else if (e.TryGetProperty("jump", out var j)) (verdict, target) = ("jump", Str(j, "target"));
                    else if (e.TryGetProperty("goto", out var g)) (verdict, target) = ("goto", Str(g, "target"));
                    else if (e.TryGetProperty("xt", out _)) restricted.Add("by an iptables-compat match");
                }
                if (!applies || verdict is null) continue;
                if (verdict is "jump" or "goto" && target is not null)
                {
                    var inner = Walk((chain.Family, chain.Table, target), depth + 1);
                    if (restricted.Count > 0)
                    {
                        // A jump guarded by a source/interface match only applies to some traffic: what it accepts is a restriction.
                        if (inner == "accept") restrictions.AddRange(restricted);
                        continue;
                    }
                    if (inner is not null || verdict == "goto") return inner;
                    continue;
                }
                if (verdict == "return")
                {
                    if (restricted.Count > 0) continue;
                    return null;
                }
                if (restricted.Count > 0)
                {
                    if (verdict == "accept") restrictions.AddRange(restricted);
                    continue;
                }
                return verdict;
            }
            return null;
        }
    }

    private enum MatchEffect { Neutral, NotForPort, Restricts }

    private static readonly Dictionary<string, int> ProtocolNumbers = new() { ["tcp"] = 6, ["udp"] = 17 };

    private static MatchEffect ClassifyMatch(JsonElement m, IReadOnlyCollection<int> ports, string protocol, out string? detail)
    {
        var number = ProtocolNumbers.GetValueOrDefault(protocol);
        detail = null;
        var op = Str(m, "op") ?? "==";
        if (!m.TryGetProperty("left", out var left) || !m.TryGetProperty("right", out var right)) return MatchEffect.Neutral;
        if (left.TryGetProperty("payload", out var payload))
        {
            var proto = Str(payload, "protocol");
            var field = Str(payload, "field");
            if (field == "dport" && (proto == protocol || proto == "th"))
            {
                var hit = Values(right).Any(v => v switch
                {
                    int p => ports.Contains(p),
                    (int lo, int hi) => ports.Any(p => p >= lo && p <= hi),
                    _ => false,
                });
                return (op == "!=" ? !hit : hit) ? MatchEffect.Neutral : MatchEffect.NotForPort;
            }
            if (field == "dport" && proto is "tcp" or "udp" or "udplite" or "sctp" or "dccp") return MatchEffect.NotForPort;
            if (field == "saddr" && proto is "ip" or "ip6")
            {
                detail = $"from {(op == "!=" ? "anywhere except " : "")}{string.Join(", ", Values(right).Select(v => v.ToString()))}";
                return MatchEffect.Restricts;
            }
            if (field == "protocol" && proto == "ip" || field == "nexthdr" && proto == "ip6")
                return Values(right).Any(v => v is string n && n == protocol || v is int i && i == number) ? MatchEffect.Neutral : MatchEffect.NotForPort;
            if (field is "sport" or "daddr") return MatchEffect.Neutral;
        }
        if (left.TryGetProperty("meta", out var meta))
        {
            switch (Str(meta, "key"))
            {
                case "iifname" or "iif":
                    var names = Values(right).Select(v => v.ToString()).ToList();
                    if (op == "==" && names.All(n => n == "lo")) return MatchEffect.NotForPort;
                    detail = $"on {(op == "!=" ? "interfaces other than " : "")}{string.Join(", ", names)}";
                    return MatchEffect.Restricts;
                case "l4proto":
                    return Values(right).Any(v => v is string n && n == protocol || v is int i && i == number) == (op != "!=") ? MatchEffect.Neutral : MatchEffect.NotForPort;
                case "nfproto" or "pkttype" or "oifname" or "oif":
                    return MatchEffect.Neutral;
            }
        }
        if (left.TryGetProperty("ct", out var ct) && Str(ct, "key") == "state")
        {
            // Rules for established/related/invalid traffic never decide a new connection.
            var states = Values(right).Select(v => v.ToString()).ToList();
            return op != "!=" && !states.Contains("new") ? MatchEffect.NotForPort : MatchEffect.Neutral;
        }
        detail = "under extra conditions";
        return MatchEffect.Restricts;
    }

    /// <summary>A match's right side: a scalar, a set, a range, a prefix, or a named set (treated as a restriction value).</summary>
    private static IEnumerable<object> Values(JsonElement v)
    {
        switch (v.ValueKind)
        {
            case JsonValueKind.Number when v.TryGetInt32(out var n): yield return n; break;
            case JsonValueKind.String: yield return v.GetString()!.StartsWith('@') ? $"set {v.GetString()![1..]}" : v.GetString()!; break;
            case JsonValueKind.Array:
                foreach (var x in v.EnumerateArray()) foreach (var y in Values(x)) yield return y;
                break;
            case JsonValueKind.Object:
                if (v.TryGetProperty("set", out var set)) foreach (var y in Values(set)) yield return y;
                else if (v.TryGetProperty("range", out var range) && range.GetArrayLength() == 2 && range[0].TryGetInt32(out var lo) && range[1].TryGetInt32(out var hi))
                    yield return (lo, hi);
                else if (v.TryGetProperty("prefix", out var prefix)) yield return $"{Str(prefix, "addr")}/{(prefix.TryGetProperty("len", out var len) ? len.ToString() : "?")}";
                else yield return v.ToString();
                break;
        }
    }

    private static string PortText(IReadOnlyCollection<int> ports) => ports.Count == 1 ? $"SSH (port {ports.First()})" : $"SSH (ports {string.Join(", ", ports)})";

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static List<string> StrArray(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
            : [];

    [GeneratedRegex(@"\b(allow|deny|reject) \(incoming\)", RegexOptions.IgnoreCase)]
    private static partial Regex DefaultIncoming();

    [GeneratedRegex(@"\s{2,}")]
    private static partial Regex Columns();

    [GeneratedRegex(@"users:\(\(""([^""]+)"",pid=(\d+)")]
    private static partial Regex SsUsers();
}
