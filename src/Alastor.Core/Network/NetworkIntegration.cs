using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Core.Network;

/// <summary>
/// Tailscale detection, SSH exposure and the exposure inventory. Tailscale is opt-in and never installed by the agent (it
/// comes from Tailscale's own package repository, and joining a tailnet needs the admin's login anyway); the agent reports
/// whether it's up and on which tailnet. The exposure check (<c>network.checkSchedule</c>) works out whether sshd can be
/// reached from the internet: its ports from <c>sshd -T</c>, listening sockets from <c>/proc/net/tcp{,6}</c>, addresses
/// from <c>ip -j addr</c>, and the host firewall from ufw or nftables. The same check lists every listening service
/// (<c>ss -tulpn</c>, or <c>/proc/net</c> without it), its systemd unit and <c>systemd-analyze security</c> score, and
/// judges each against the firewall. It only reads; nothing is changed.
/// </summary>
public sealed class NetworkIntegration(
    ICommandRunner runner,
    IFileSystem fs,
    IStateStore state,
    ILogger<NetworkIntegration> logger,
    TimeProvider time) : IToolIntegration, IScheduledJobProvider
{
    public const string CheckJob = "network.check";
    private const string StateLastLevel = "network.lastLevel";
    private const string StateKeyExpiryWarned = "network.tailscaleExpiryWarned";
    private const string StatePublicServices = "network.publicServices";

    /// <summary>Services kept in a report; a host with more is unusual (and the rest would only add noise).</summary>
    public const int MaxServices = 200;

    /// <summary>Warn this long before the node key expires.</summary>
    public static readonly TimeSpan KeyExpiryWarning = TimeSpan.FromDays(14);

    private readonly Queue<SecurityEvent> _events = new();
    private readonly SemaphoreSlim _lock = new(1, 1);

    public static readonly ToolDescriptor Info = new(
        "tailscale",
        "Tailscale",
        Capability.Network,
        "BSD-3-Clause",
        "https://tailscale.com/",
        new Dictionary<DistroFamily, string> { [DistroFamily.Debian] = "tailscale", [DistroFamily.RedHat] = "tailscale", [DistroFamily.Alpine] = "tailscale" },
        "WireGuard-based private networking. Detected, never installed: reach hosts over the tailnet and keep SSH off the internet.");

    public ToolDescriptor Descriptor => Info;

    public IReadOnlyList<ScheduledJob> Jobs =>
    [
        new(CheckJob, "Check SSH exposure and Tailscale", "network.checkSchedule", RunOnFirstStart: true, (policy, _, ct) => CheckAsync(policy, ct)),
    ];

    public bool IsWanted(PolicyDocument policy) => !ScheduleDefaults.For(policy, "network.checkSchedule").IsDisabled;

    public async Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        if (runner.Which("tailscale") is null)
            return new ToolStatus
            {
                ToolId = Info.Id,
                Availability = Availability.Disabled,
                UnavailableReason = "Tailscale isn't installed. It's optional: install it from Tailscale's package repository to reach this host privately.",
            };
        var (ts, error) = await TailscaleAsync(ct);
        var details = new Dictionary<string, string>();
        if (ts?.Tailnet is { } tn) details["tailnet"] = tn;
        if (ts?.Ips.FirstOrDefault() is { } ip) details["ip"] = ip;
        if (ts is not null) details["backendState"] = ts.BackendState;
        return new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Running = ts?.Running == true,
            Version = ts?.Version?.Split('-')[0],
            Ownership = Ownership.Adopted,
            ConfigState = ConfigState.InSync,
            LastError = ts?.Running == true ? null : error ?? (ts is null ? null : $"Tailscale is {ts.BackendState}."),
            Details = details,
        };
    }

    /// <summary>Opt-in and from the vendor's repository: never installed by the agent.</summary>
    public Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct) => DetectAsync(ct);

    public Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct) =>
        Task.FromResult(new ReconcilePlan(Info.Id, request.Revision, [], [], ConfigState.InSync));

    public Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        await Task.CompletedTask;
        while (_events.TryDequeue(out var e)) yield return e;
    }

    /// <summary>Nothing to clean up: the check only reads.</summary>
    public Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    // ---- check ----

    public async Task<AgentReport> CheckAsync(PolicyDocument policy, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        var started = time.GetUtcNow().UtcDateTime;
        try
        {
            var (ts, tsError) = runner.Which("tailscale") is null ? (null, null) : await TailscaleAsync(ct);
            var addresses = await AddressesAsync(ct);
            var ssh = await SshAsync(ct);
            var judge = await FirewallAsync(ct);
            var firewall = judge(ssh?.Ports ?? [22], "tcp", null);
            var accepted = policy.Network?.AllowPublicSsh == true;
            var exposure = ExposureAssessor.Assess(ssh, addresses, firewall, ts, null, accepted);
            var services = await ServicesAsync(addresses, ts, judge, ct);
            var report = new NetworkReport(ts, tsError, addresses, ssh, firewall, exposure) { Services = services };
            await RaiseEventsAsync(report, policy, ct);
            logger.LogInformation("Network check: SSH {Level}{Accepted}; firewall {Verdict}; Tailscale {Tailscale}", exposure.Level,
                accepted ? " (accepted)" : "", firewall.Verdict, ts?.BackendState ?? "not installed");
            return new AgentReport(CheckJob, started, time.GetUtcNow().UtcDateTime, true, null) { Network = report };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Network check failed");
            return new AgentReport(CheckJob, started, time.GetUtcNow().UtcDateTime, false, ex.Message);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<(TailscaleInfo?, string?)> TailscaleAsync(CancellationToken ct)
    {
        var options = new CommandOptions { Timeout = TimeSpan.FromSeconds(15) };
        var r = await runner.RunAsync("tailscale", ["status", "--json"], options, ct);
        if (!r.Success)
            // "failed to connect to local tailscaled; it doesn't appear to be running"
            return (new TailscaleInfo(null, "NotRunning", [], null, null, 0, 0, null, null, []), FirstLine(r.CombinedOutput));
        TailscaleInfo ts;
        try
        {
            ts = NetworkParsers.ParseTailscaleStatus(r.StdOut);
        }
        catch (System.Text.Json.JsonException ex)
        {
            return (null, $"Couldn't read tailscale status: {ex.Message}");
        }
        if (ts.Running)
        {
            // Tailscale SSH isn't in the status; "debug prefs" has it. Best effort: older clients may not have the command.
            var prefs = await runner.RunAsync("tailscale", ["debug", "prefs"], options, ct);
            if (prefs.Success) ts = ts with { SshEnabled = NetworkParsers.ParseTailscaleRunSsh(prefs.StdOut) };
        }
        return (ts, null);
    }

    private async Task<IReadOnlyList<HostAddress>> AddressesAsync(CancellationToken ct)
    {
        if (runner.Which("ip") is not null)
        {
            var r = await runner.RunAsync("ip", ["-j", "addr", "show"], null, ct);
            if (r.Success)
            {
                try
                {
                    return NetworkParsers.ParseIpAddr(r.StdOut);
                }
                catch (System.Text.Json.JsonException)
                {
                    // Very old iproute2 without -j: fall through.
                }
            }
        }
        return NetworkInterface.GetAllNetworkInterfaces()
            .SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(u => (n.Name, u)))
            .Where(x => x.u.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .Select(x => new HostAddress(x.Name, x.u.Address.ToString().Split('%')[0], x.u.PrefixLength, AddressClassifier.Classify(x.u.Address.ToString().Split('%')[0])))
            .ToList();
    }

    private async Task<SshFacts?> SshAsync(CancellationToken ct)
    {
        if (runner.Which("sshd") is null) return null;
        var r = await runner.RunAsync("sshd", ["-T"], null, ct);
        var (ports, password, root) = r.Success ? NetworkParsers.ParseSshdSettings(r.StdOut) : ([22], true, "unknown");
        var listeners = new List<TcpListenSocket>();
        foreach (var path in new[] { "/proc/net/tcp", "/proc/net/tcp6" })
            if (await fs.ReadAllTextAsync(path, ct) is { } content)
                listeners.AddRange(NetworkParsers.ParseProcNetTcp(content).Where(l => ports.Contains(l.Port)));
        return new SshFacts(ports, password, root, listeners.Distinct().ToList(), r.Success ? null : FirstLine(r.CombinedOutput));
    }

    /// <summary>
    /// Reads the host firewall once (ufw, then nftables) and returns a judge for (ports, protocol, label): the verdict for
    /// those ports. A null label means SSH. Each service is judged from the same snapshot of the rules.
    /// </summary>
    private async Task<Func<IReadOnlyCollection<int>, string, string?, FirewallAssessment>> FirewallAsync(CancellationToken ct)
    {
        var errors = new List<string>();
        string? ufwStatus = null;
        if (runner.Which("ufw") is not null)
        {
            var r = await runner.RunAsync("ufw", ["status", "verbose"], null, ct);
            if (r.Success) ufwStatus = r.StdOut;
            else errors.Add($"ufw: {FirstLine(r.CombinedOutput)}");
        }
        string? nftJson = null;
        var legacyRules = false;
        if (runner.Which("nft") is not null)
        {
            var r = await runner.RunAsync("nft", ["-j", "list", "ruleset"], null, ct);
            if (r.Success) nftJson = r.StdOut;
            else errors.Add($"nft: {FirstLine(r.CombinedOutput)}");
            if (runner.Which("iptables-legacy") is not null)
            {
                // Rules loaded with iptables-legacy don't show up in nftables.
                var legacy = await runner.RunAsync("iptables-legacy", ["-S", "INPUT"], null, ct);
                legacyRules = legacy.Success && legacy.StdOut.Split('\n').Any(l => l.StartsWith("-A INPUT", StringComparison.Ordinal) || l.Trim() is "-P INPUT DROP");
            }
        }

        return (ports, protocol, label) =>
        {
            var text = label ?? (ports.Count == 1 ? $"SSH (port {ports.First()})" : $"SSH (ports {string.Join(", ", ports)})");
            var nftErrors = new List<string>();
            if (ufwStatus is not null && NetworkParsers.ParseUfw(ufwStatus, ports, protocol, text) is { } ufw) return ufw;
            if (nftJson is not null)
            {
                try
                {
                    var nft = NetworkParsers.ParseNft(nftJson, ports, protocol, text);
                    if (nft.Verdict != FirewallSshVerdict.NoFirewall || !legacyRules) return nft;
                    return new(null, FirewallSshVerdict.Unknown, $"The firewall uses iptables-legacy rules, which Alastor doesn't read. Check that {text} is restricted there.");
                }
                catch (System.Text.Json.JsonException ex)
                {
                    nftErrors.Add($"nft: {ex.Message}");
                }
            }
            var all = errors.Concat(nftErrors).ToList();
            return new(null, FirewallSshVerdict.Unknown, all.Count > 0
                ? $"Couldn't read the firewall ({string.Join("; ", all)})."
                : "Neither ufw nor nftables is installed, so the host firewall couldn't be read.");
        };
    }

    /// <summary>Every listening TCP and UDP service, with its owner, systemd unit and hardening score where available.</summary>
    private async Task<IReadOnlyList<ListeningService>> ServicesAsync(IReadOnlyList<HostAddress> addresses, TailscaleInfo? ts,
        Func<IReadOnlyCollection<int>, string, string?, FirewallAssessment> judge, CancellationToken ct)
    {
        var sockets = new List<ListenSocket>();
        if (runner.Which("ss") is not null)
        {
            var r = await runner.RunAsync("ss", ["-tulpnH"], null, ct);
            if (r.Success) sockets = NetworkParsers.ParseSs(r.StdOut);
        }
        if (sockets.Count == 0)
            foreach (var (path, proto) in new[] { ("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp"), ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp") })
                if (await fs.ReadAllTextAsync(path, ct) is { } content)
                    sockets.AddRange(NetworkParsers.ParseProcNet(content, proto));

        var units = new Dictionary<int, string>();
        foreach (var pid in sockets.Where(s => s.Pid is not null).Select(s => s.Pid!.Value).Distinct())
            if (await fs.ReadAllTextAsync($"/proc/{pid}/cgroup", ct) is { } cg && NetworkParsers.ParseCgroupUnit(cg) is { } unit)
                units[pid] = unit;

        // systemd 250+ prints JSON; older versions reject the flag, and then services simply carry no score.
        var scores = new Dictionary<string, (double, string)>();
        if (units.Count > 0 && runner.Which("systemd-analyze") is not null)
        {
            var r = await runner.RunAsync("systemd-analyze", ["security", "--json=short", "--no-pager", .. units.Values.Distinct().Order(StringComparer.Ordinal)],
                new CommandOptions { Timeout = TimeSpan.FromSeconds(60) }, ct);
            if (r.Success)
            {
                try { scores = NetworkParsers.ParseSystemdSecurity(r.StdOut); }
                catch (System.Text.Json.JsonException ex) { logger.LogDebug(ex, "Unreadable systemd-analyze output"); }
            }
        }
        return ServiceExposureAssessor.Assess(sockets, addresses, ts, (port, proto) => judge([port], proto, $"port {port}/{proto}"), units, scores)
            .Take(MaxServices).ToList();
    }

    private async Task RaiseEventsAsync(NetworkReport report, PolicyDocument policy, CancellationToken ct)
    {
        var level = report.Exposure.Level;
        var previous = state.Get(StateLastLevel);
        if (level == SshExposureLevel.Public && !report.Exposure.Accepted && previous != nameof(SshExposureLevel.Public))
        {
            var password = report.Ssh?.PasswordAuthentication == true;
            _events.Enqueue(Event(EventKinds.ExposureDetected, password ? Severity.High : Severity.Medium,
                $"SSH (port {string.Join(", ", report.Ssh!.Ports)}) is reachable from the internet on {string.Join(", ", report.Exposure.ReachableOn.Where(AddressClassifier.IsPublic))}" +
                (password ? ", and password logins are enabled." : ". Logins are key-only.") +
                (report.Tailscale?.Running == true ? " Tailscale is up, so SSH could be limited to the tailnet." : ""),
                "ssh"));
        }
        await state.SetAsync(StateLastLevel, report.Exposure.Accepted && level == SshExposureLevel.Public ? "PublicAccepted" : level.ToString(), ct);

        // Alert once per service when it becomes reachable from the internet without being in network.allowPublicPorts.
        var unexpected = ServiceExposureAssessor.Unexpected(report.Services, report.Ssh?.Ports ?? [22], policy.Network?.AllowPublicPorts).ToList();
        var known = (state.Get(StatePublicServices) ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        foreach (var svc in unexpected.Where(s => !known.Contains(s.Key)))
            _events.Enqueue(Event(EventKinds.ServiceExposed, Severity.Medium,
                $"{svc.Label} is reachable from the internet on {string.Join(", ", svc.ReachableOn.Where(AddressClassifier.IsPublic))}. " +
                $"{svc.FirewallDetail} If that's intended, add {svc.Key} to network.allowPublicPorts; otherwise bind it to localhost or a private address, or firewall it.",
                svc.Key) with { DedupKey = $"network:{EventKinds.ServiceExposed}:{svc.Key}" });
        await state.SetAsync(StatePublicServices, string.Join(',', unexpected.Select(s => s.Key)), ct);

        if (report.Tailscale is { Running: true, KeyExpiry: { } expiry })
        {
            var left = expiry - time.GetUtcNow().UtcDateTime;
            var stamp = expiry.ToString("O", CultureInfo.InvariantCulture);
            if (left < KeyExpiryWarning && state.Get(StateKeyExpiryWarned) != stamp)
            {
                _events.Enqueue(Event(EventKinds.TailscaleKeyExpiring, Severity.Medium,
                    left <= TimeSpan.Zero
                        ? "This host's Tailscale node key has expired; it can't reach the tailnet until it's re-authenticated."
                        : $"This host's Tailscale node key expires in {Math.Max(1, (int)left.TotalDays)} day(s) ({expiry:yyyy-MM-dd}). Re-authenticate it, or disable key expiry for servers in the Tailscale admin console.",
                    "tailscale"));
                await state.SetAsync(StateKeyExpiryWarned, stamp, ct);
            }
        }
    }

    private SecurityEvent Event(string kind, Severity severity, string message, string subject) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow().UtcDateTime,
        Capability = Capability.Network,
        Severity = severity,
        SourceTool = "alastor-agent",
        Kind = kind,
        Subject = subject,
        Message = message,
        DedupKey = $"network:{kind}",
    };

    private static string FirstLine(string s) => s.Trim().Split('\n')[0].Trim();
}
