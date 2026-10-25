using System.Net;
using System.Net.Sockets;

namespace Alastor.Core.Network;

public enum AddressKind
{
    Public,
    Private,
    /// <summary>Tailscale's ranges: CGNAT 100.64.0.0/10 and fd7a:115c:a1e0::/48.</summary>
    Tailnet,
    Loopback,
    LinkLocal,
    Other,
}

public sealed record HostAddress(string Interface, string Address, int PrefixLength, AddressKind Kind);

/// <summary>A listening TCP socket from <c>/proc/net/tcp{,6}</c>. Wildcards are <c>0.0.0.0</c> and <c>::</c>.</summary>
public sealed record TcpListenSocket(string Address, int Port)
{
    public bool IsWildcard => Address is "0.0.0.0" or "::";
}

/// <summary>
/// A socket accepting TCP connections or UDP datagrams, from <c>ss -tulpn</c> (with the owning process) or, without
/// <c>ss</c>, from <c>/proc/net/{tcp,udp}{,6}</c>. Wildcards are <c>0.0.0.0</c> and <c>::</c>.
/// </summary>
public sealed record ListenSocket(string Protocol, string Address, int Port, string? Process = null, int? Pid = null)
{
    public bool IsWildcard => Address is "0.0.0.0" or "::";
}

/// <summary>How far a listening service reaches, judged like SSH exposure: bound addresses, then the host firewall.</summary>
public enum ServiceReach
{
    /// <summary>Bound to a public address and the host firewall lets anyone reach it.</summary>
    Public,
    /// <summary>Bound to a public address, but the firewall limits or blocks it.</summary>
    Restricted,
    Private,
    Tailnet,
    Local,
}

/// <summary>One service (port and protocol) the host listens on, with what owns it and how far it reaches.</summary>
/// <param name="Addresses">The addresses it is bound to, as the sockets report them.</param>
/// <param name="ReachableOn">Non-loopback host addresses it answers on.</param>
/// <param name="SystemdExposure">The unit's <c>systemd-analyze security</c> score, 0 (locked down) to 10 (unprotected).</param>
public sealed record ListeningService(
    string Protocol,
    int Port,
    IReadOnlyList<string> Addresses,
    string? Process,
    string? Unit,
    ServiceReach Reach,
    IReadOnlyList<string> ReachableOn,
    FirewallSshVerdict Firewall,
    string FirewallDetail,
    double? SystemdExposure = null,
    string? SystemdRating = null)
{
    /// <summary><c>443/tcp</c>: the form <c>network.allowPublicPorts</c> uses.</summary>
    public string Key => $"{Port}/{Protocol}";

    /// <summary>"nginx on 443/tcp", or just the port when the owner is unknown.</summary>
    public string Label => Process is null ? $"port {Key}" : $"{Process} on {Key}";
}

/// <summary>From <c>tailscale status --json</c> (ipnstate.Status) and, best effort, <c>tailscale debug prefs</c>.</summary>
public sealed record TailscaleInfo(
    string? Version,
    string BackendState,
    IReadOnlyList<string> Ips,
    string? DnsName,
    string? Tailnet,
    int PeersTotal,
    int PeersOnline,
    bool? SshEnabled,
    DateTime? KeyExpiry,
    IReadOnlyList<string> Health)
{
    public bool Running => BackendState == "Running";
}

/// <summary>The host firewall's verdict for one port (named for SSH, where it was first used; services use it too).</summary>
public enum FirewallSshVerdict
{
    /// <summary>Nothing filters incoming traffic.</summary>
    NoFirewall,
    /// <summary>The firewall filters, but a rule accepts the SSH port from any source.</summary>
    OpenToAnywhere,
    /// <summary>The SSH port is accepted only from some sources or interfaces.</summary>
    Restricted,
    /// <summary>No rule accepts the SSH port.</summary>
    Blocked,
    Unknown,
}

/// <param name="Tool">ufw or nftables; null when neither could be read.</param>
public sealed record FirewallAssessment(string? Tool, FirewallSshVerdict Verdict, string Detail);

public enum SshExposureLevel
{
    /// <summary>sshd listens on a public address and the host firewall lets anyone reach it.</summary>
    Public,
    /// <summary>Only private addresses, but the server sees the host from a public one (cloud 1:1 NAT is common).</summary>
    PossiblyPublic,
    /// <summary>Reachable addresses exist, but the host firewall limits who can connect.</summary>
    Restricted,
    PrivateOnly,
    TailnetOnly,
    LocalOnly,
    /// <summary>sshd is installed, but nothing listens on its ports.</summary>
    NotListening,
    NoSsh,
    Unknown,
}

public sealed record SshFacts(
    IReadOnlyList<int> Ports,
    bool PasswordAuthentication,
    string PermitRootLogin,
    IReadOnlyList<TcpListenSocket> Listeners,
    string? Error = null);

/// <param name="ReachableOn">The non-loopback addresses sshd answers on.</param>
public sealed record SshExposure(SshExposureLevel Level, IReadOnlyList<string> ReachableOn, IReadOnlyList<string> Reasons, bool Accepted);

public sealed record NetworkReport(
    TailscaleInfo? Tailscale,
    string? TailscaleError,
    IReadOnlyList<HostAddress> Addresses,
    SshFacts? Ssh,
    FirewallAssessment Firewall,
    SshExposure Exposure)
{
    /// <summary>Every listening service, SSH included. Null from agents older than the exposure inventory.</summary>
    public IReadOnlyList<ListeningService>? Services { get; init; }
}

public static class AddressClassifier
{
    private static readonly IPNetwork[] Private =
        [IPNetwork.Parse("10.0.0.0/8"), IPNetwork.Parse("172.16.0.0/12"), IPNetwork.Parse("192.168.0.0/16"), IPNetwork.Parse("fc00::/7")];
    private static readonly IPNetwork[] Tailnet = [IPNetwork.Parse("100.64.0.0/10"), IPNetwork.Parse("fd7a:115c:a1e0::/48")];
    private static readonly IPNetwork[] LinkLocal = [IPNetwork.Parse("169.254.0.0/16"), IPNetwork.Parse("fe80::/10")];
    // Unspecified, IETF protocol assignments, benchmarking, multicast and reserved space: never a server's address.
    // Documentation ranges (192.0.2.0/24, 203.0.113.0/24, 2001:db8::/32) count as public, so examples and fixtures read naturally.
    private static readonly IPNetwork[] Other =
    [
        IPNetwork.Parse("0.0.0.0/8"), IPNetwork.Parse("192.0.0.0/24"), IPNetwork.Parse("198.18.0.0/15"), IPNetwork.Parse("224.0.0.0/3"),
        IPNetwork.Parse("ff00::/8"), IPNetwork.Parse("::/128"),
    ];

    public static AddressKind Classify(string address, IReadOnlyCollection<string>? tailnetIps = null)
    {
        if (!IPAddress.TryParse(address, out var ip)) return AddressKind.Other;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (tailnetIps?.Contains(ip.ToString()) == true) return AddressKind.Tailnet;
        if (IPAddress.IsLoopback(ip)) return AddressKind.Loopback;
        if (Tailnet.Any(n => n.Contains(ip))) return AddressKind.Tailnet;
        if (Private.Any(n => n.Contains(ip))) return AddressKind.Private;
        if (LinkLocal.Any(n => n.Contains(ip))) return AddressKind.LinkLocal;
        if (Other.Any(n => n.Contains(ip))) return AddressKind.Other;
        // IPv6 global unicast is 2000::/3; anything else left over isn't routable.
        if (ip.AddressFamily == AddressFamily.InterNetworkV6 && (ip.GetAddressBytes()[0] & 0xE0) != 0x20) return AddressKind.Other;
        return AddressKind.Public;
    }

    public static bool IsPublic(string? address) => address is not null && Classify(address) == AddressKind.Public;
}

/// <summary>
/// Decides how reachable SSH is from what the agent sees: sshd's listening sockets, the host's addresses, and the host
/// firewall. It can't see provider firewalls or security groups, and says so; the server adds the address it sees the
/// agent connect from, which catches 1:1 NAT (common on AWS, GCP, Azure) where the interface only has a private address.
/// </summary>
public static class ExposureAssessor
{
    public static SshExposure Assess(SshFacts? ssh, IReadOnlyList<HostAddress> addresses, FirewallAssessment firewall, TailscaleInfo? tailscale,
        string? observedAddress, bool accepted)
    {
        if (ssh is null) return new(SshExposureLevel.NoSsh, [], ["No SSH server is installed."], accepted);
        if (ssh.Listeners.Count == 0)
            return ssh.Error is not null
                ? new(SshExposureLevel.Unknown, [], [$"Couldn't read sshd's settings: {ssh.Error}"], accepted)
                : new(SshExposureLevel.NotListening, [], [$"Nothing listens on the SSH port{(ssh.Ports.Count == 1 ? "" : "s")} {string.Join(", ", ssh.Ports)}."], accepted);

        var tailnetIps = tailscale?.Ips ?? [];
        var reachable = new List<(string Address, AddressKind Kind)>();
        var wildcard = false;
        foreach (var l in ssh.Listeners)
        {
            if (l.IsWildcard)
            {
                wildcard = true;
                // A "::" socket also takes IPv4 unless bindv6only is set (it rarely is); sshd usually opens both anyway.
                var v4Only = l.Address == "0.0.0.0";
                foreach (var a in addresses.Where(a => !v4Only || !a.Address.Contains(':')))
                    reachable.Add((a.Address, AddressClassifier.Classify(a.Address, tailnetIps)));
                foreach (var t in tailnetIps.Where(t => !v4Only || !t.Contains(':'))) reachable.Add((t, AddressKind.Tailnet));
            }
            else reachable.Add((l.Address, AddressClassifier.Classify(l.Address, tailnetIps)));
        }
        reachable = reachable.Where(r => r.Kind is AddressKind.Public or AddressKind.Private or AddressKind.Tailnet).DistinctBy(r => r.Address).ToList();
        var on = reachable.Select(r => r.Address).ToList();
        var ports = string.Join(", ", ssh.Ports);
        var reasons = new List<string>();
        var filtered = firewall.Verdict is FirewallSshVerdict.Restricted or FirewallSshVerdict.Blocked;

        SshExposureLevel level;
        var publicAddrs = reachable.Where(r => r.Kind == AddressKind.Public).Select(r => r.Address).ToList();
        if (publicAddrs.Count > 0)
        {
            reasons.Add($"sshd listens on port {ports} on the public address{(publicAddrs.Count == 1 ? "" : "es")} {string.Join(", ", publicAddrs)}.");
            level = filtered ? SshExposureLevel.Restricted : SshExposureLevel.Public;
        }
        else if (reachable.Any(r => r.Kind == AddressKind.Private))
        {
            if (wildcard && AddressClassifier.IsPublic(observedAddress))
            {
                reasons.Add($"The host only has private addresses, but the server sees it connect from the public address {observedAddress}. " +
                            "Cloud providers often map such an address to the host (1:1 NAT), which makes port " + ports + " reachable unless the provider's firewall blocks it.");
                level = filtered ? SshExposureLevel.Restricted : SshExposureLevel.PossiblyPublic;
            }
            else
            {
                reasons.Add($"sshd listens on port {ports} on private addresses only.");
                level = SshExposureLevel.PrivateOnly;
            }
        }
        else if (reachable.Count > 0)
        {
            reasons.Add($"sshd answers on the tailnet only ({string.Join(", ", on)}).");
            level = SshExposureLevel.TailnetOnly;
        }
        else
        {
            reasons.Add($"sshd listens on loopback only.");
            level = SshExposureLevel.LocalOnly;
        }

        if (level is SshExposureLevel.Public or SshExposureLevel.PossiblyPublic or SshExposureLevel.Restricted)
        {
            reasons.Add(firewall.Detail);
            if (level != SshExposureLevel.Restricted)
                reasons.Add("A provider firewall or security group may still block it; Alastor can only see the host's own firewall.");
            if (level != SshExposureLevel.Restricted && ssh.PasswordAuthentication)
                reasons.Add("Password logins are enabled, so anyone can try to guess passwords (fail2ban slows this down, but keys only is safer).");
        }
        return new(level, on, reasons, accepted);
    }
}

/// <summary>
/// Judges every listening service the way <see cref="ExposureAssessor"/> judges SSH, and decides which public ones are
/// unexpected: not SSH (which has its own check) and not listed in <c>network.allowPublicPorts</c>.
/// </summary>
public static class ServiceExposureAssessor
{
    /// <param name="firewall">The host firewall's verdict for (ports, protocol).</param>
    /// <param name="units">systemd unit per process id, where known.</param>
    /// <param name="systemd">Per unit: <c>systemd-analyze security</c> exposure score and rating.</param>
    public static List<ListeningService> Assess(IReadOnlyList<ListenSocket> sockets, IReadOnlyList<HostAddress> addresses, TailscaleInfo? tailscale,
        Func<int, string, FirewallAssessment> firewall, IReadOnlyDictionary<int, string>? units = null,
        IReadOnlyDictionary<string, (double Exposure, string Rating)>? systemd = null)
    {
        var tailnetIps = tailscale?.Ips ?? [];
        var result = new List<ListeningService>();
        foreach (var group in sockets.GroupBy(s => (s.Protocol, s.Port)).OrderBy(g => g.Key.Port).ThenBy(g => g.Key.Protocol, StringComparer.Ordinal))
        {
            var reachable = new List<(string Address, AddressKind Kind)>();
            foreach (var l in group)
            {
                if (l.IsWildcard)
                {
                    var v4Only = l.Address == "0.0.0.0";
                    foreach (var a in addresses.Where(a => !v4Only || !a.Address.Contains(':')))
                        reachable.Add((a.Address, AddressClassifier.Classify(a.Address, tailnetIps)));
                    foreach (var t in tailnetIps.Where(t => !v4Only || !t.Contains(':'))) reachable.Add((t, AddressKind.Tailnet));
                }
                else reachable.Add((l.Address, AddressClassifier.Classify(l.Address, tailnetIps)));
            }
            reachable = reachable.Where(r => r.Kind is AddressKind.Public or AddressKind.Private or AddressKind.Tailnet).DistinctBy(r => r.Address).ToList();

            var owner = group.FirstOrDefault(s => s.Process is not null);
            var unit = owner?.Pid is { } pid && units?.TryGetValue(pid, out var u) == true ? u : null;
            (double Exposure, string Rating)? score = unit is not null && systemd?.TryGetValue(unit, out var sc) == true ? sc : null;

            ServiceReach reach;
            var fw = new FirewallAssessment(null, FirewallSshVerdict.Unknown, "");
            if (reachable.Any(r => r.Kind == AddressKind.Public))
            {
                fw = firewall(group.Key.Port, group.Key.Protocol);
                reach = fw.Verdict is FirewallSshVerdict.Restricted or FirewallSshVerdict.Blocked ? ServiceReach.Restricted : ServiceReach.Public;
            }
            else reach = reachable.Any(r => r.Kind == AddressKind.Private) ? ServiceReach.Private
                : reachable.Count > 0 ? ServiceReach.Tailnet
                : ServiceReach.Local;

            result.Add(new ListeningService(group.Key.Protocol, group.Key.Port, group.Select(s => s.Address).Distinct().ToList(), owner?.Process, unit,
                reach, reachable.Select(r => r.Address).ToList(), fw.Verdict, fw.Detail, score?.Exposure, score?.Rating));
        }
        return result;
    }

    /// <summary>
    /// Entries of <c>network.allowPublicPorts</c>: <c>443</c> (any protocol), <c>443/tcp</c>, <c>51820/udp</c>, or a range
    /// <c>60000-61000/udp</c>.
    /// </summary>
    public static bool IsAllowed(ListeningService service, IEnumerable<string>? allowPublicPorts)
    {
        foreach (var raw in allowPublicPorts ?? [])
            if (TryParsePortSpec(raw, out var lo, out var hi, out var proto) && service.Port >= lo && service.Port <= hi
                && (proto is null || proto == service.Protocol))
                return true;
        return false;
    }

    public static bool TryParsePortSpec(string? spec, out int lo, out int hi, out string? protocol)
    {
        lo = hi = 0;
        protocol = null;
        if (string.IsNullOrWhiteSpace(spec)) return false;
        var parts = spec.Trim().ToLowerInvariant().Split('/');
        if (parts.Length > 2) return false;
        if (parts.Length == 2)
        {
            if (parts[1] is not ("tcp" or "udp")) return false;
            protocol = parts[1];
        }
        var range = parts[0].Split('-');
        if (range.Length > 2 || !int.TryParse(range[0], out lo) || !int.TryParse(range[^1], out hi)) return false;
        return lo is > 0 and < 65536 && hi is > 0 and < 65536 && lo <= hi;
    }

    /// <summary>Public, not one of sshd's ports (SSH has its own check and issue), and not allowed by policy.</summary>
    public static IEnumerable<ListeningService> Unexpected(IReadOnlyList<ListeningService>? services, IReadOnlyCollection<int> sshPorts, IEnumerable<string>? allowPublicPorts)
    {
        var allow = allowPublicPorts?.ToList();
        return (services ?? []).Where(s => s.Reach == ServiceReach.Public && !(s.Protocol == "tcp" && sshPorts.Contains(s.Port)) && !IsAllowed(s, allow));
    }
}
