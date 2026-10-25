using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Network;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Core.Firewall;

/// <summary>
/// Manages ufw on Debian/Ubuntu when <c>firewall.manage</c> is on. The agent owns only rules tagged
/// <c>comment 'alastor'</c>: it allows SSH on sshd's ports from <c>firewall.ssh</c>, every port in
/// <c>network.allowPublicPorts</c>, and <c>firewall.allow</c>, sets the default for incoming traffic and enables ufw.
/// Everyone else's rules stay as they are.
///
/// Lockout guards, checked before anything changes: sshd's ports come from <c>sshd -T</c>; the plan is refused when no
/// rule would allow one of them, or when an SSH rule needs an interface (tailscale0) that isn't up. Every new rule is
/// validated with <c>ufw --dry-run</c> first, and a failed step rolls back the steps before it. Turning
/// <c>firewall.manage</c> off leaves the rules in place (removing them could cut SSH); uninstalling removes all but the
/// SSH rules while ufw is active.
/// </summary>
public sealed class UfwIntegration(ICommandRunner runner, IPackageManager? packages, OsInfo os, ILogger<UfwIntegration> logger, TimeProvider time)
    : IToolIntegration
{
    private const char Sep = '\n';

    public static readonly ToolDescriptor Info = new(
        "ufw",
        "ufw",
        Capability.Firewall,
        "GPL-3.0",
        "https://launchpad.net/ufw",
        new Dictionary<DistroFamily, string> { [DistroFamily.Debian] = "ufw", [DistroFamily.Alpine] = "ufw" },
        "Host firewall. With firewall.manage the agent keeps its own allow rules (SSH, public ports, firewall.allow) and enables ufw.");

    public ToolDescriptor Descriptor => Info;

    public bool IsWanted(PolicyDocument policy) => policy.Firewall?.Manage == true;

    public async Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        if (os.Family == DistroFamily.RedHat)
            return new ToolStatus { ToolId = Info.Id, Availability = Availability.Unavailable, UnavailableReason = "RHEL-family hosts use firewalld; Alastor manages ufw only." };
        if (runner.Which("ufw") is null)
        {
            var available = packages is not null && await packages.IsAvailableAsync("ufw", ct);
            return new ToolStatus { ToolId = Info.Id, Availability = available ? Availability.Available : Availability.Unavailable,
                UnavailableReason = available ? null : "ufw isn't available from this host's package repositories." };
        }
        var status = await runner.RunAsync("ufw", ["status", "verbose"], null, ct);
        var (active, defaultIn) = UfwRules.ParseStatus(status.StdOut);
        var warnings = new List<string>();
        if (runner.Which("firewall-cmd") is not null && (await runner.RunAsync("firewall-cmd", ["--state"], null, ct)).Success)
            warnings.Add("firewalld is running too. Two firewall managers fight over the same rules; stop one of them.");
        var version = (await runner.RunAsync("ufw", ["version"], null, ct)).StdOut.Split('\n')[0].Replace("ufw ", "").Trim();
        return new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Running = active,
            Version = version.Length > 0 ? version : null,
            Ownership = Ownership.Adopted,
            ConfigState = ConfigState.InSync,
            Warnings = warnings,
            Details = new Dictionary<string, string> { ["status"] = active ? "active" : "inactive", ["defaultIncoming"] = defaultIn ?? "?" },
        };
    }

    public async Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct)
    {
        var status = await DetectAsync(ct);
        if (status.Installed || status.Availability == Availability.Unavailable || packages is null || !request.AllowInstall) return status;
        var r = await packages.InstallAsync("ufw", ct);
        return r.Success ? await DetectAsync(ct) with { Ownership = Ownership.Managed }
            : status with { Availability = Availability.Unavailable, UnavailableReason = $"Installing ufw failed: {r.Error}" };
    }

    /// <summary>The rules the policy asks for on this host (SSH per sshd port, public ports, extra rules).</summary>
    public static (List<UfwRule> Rules, List<string> Errors) DesiredRules(PolicyDocument policy, IReadOnlyCollection<int> sshPorts)
    {
        var rules = new List<UfwRule>();
        var errors = new List<string>();
        foreach (var port in sshPorts)
            foreach (var src in policy.Firewall?.Ssh ?? ["any"])
                if (UfwRules.TryParseSshSource(src, port, out var r, out var e)) rules.Add(r!);
                else errors.Add($"firewall.ssh '{src}': {e}");
        foreach (var p in policy.Network?.AllowPublicPorts ?? [])
            if (UfwRules.TryParse(p, out var r, out var e)) rules.Add(r!);
            else errors.Add($"network.allowPublicPorts '{p}': {e}");
        foreach (var a in policy.Firewall?.Allow ?? [])
            if (UfwRules.TryParse(a, out var r, out var e)) rules.Add(r!);
            else errors.Add($"firewall.allow '{a}': {e}");
        return (rules.Distinct().ToList(), errors);
    }

    public async Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct)
    {
        // Not managed (any more): leave every rule in place. Removing the SSH rule from an active firewall could lock admins out.
        if (!IsWanted(request.Policy) || runner.Which("ufw") is null)
            return new ReconcilePlan(Info.Id, request.Revision, [], [], ConfigState.InSync);

        var ssh = await runner.RunAsync("sshd", ["-T"], null, ct);
        var sshPorts = ssh.Success ? NetworkParsers.ParseSshdSettings(ssh.StdOut).Ports : [22];
        var (desired, errors) = DesiredRules(request.Policy, sshPorts);
        var refusals = errors.ToList();
        foreach (var port in sshPorts)
            if (!desired.Any(r => r.Port <= port && port <= (r.PortEnd ?? r.Port) && r.Protocol is null or "tcp"))
                refusals.Add($"No rule would allow SSH on port {port}, so enabling the firewall could lock you out. Set firewall.ssh.");
        var interfaces = await InterfacesAsync(ct);
        foreach (var r in desired.Where(r => r.Interface is not null && sshPorts.Contains(r.Port)))
            if (interfaces is not null && !interfaces.Contains(r.Interface!))
                refusals.Add($"SSH is limited to {r.Interface}, which isn't up on this host. Bring it up (tailscale up) or allow SSH another way.");
        if (refusals.Count > 0)
            return new ReconcilePlan(Info.Id, request.Revision, [], refusals.Select(m => new PlanWarning(EventKinds.ConfigRejected, m)).ToList(), ConfigState.Rejected);

        var current = UfwRules.ParseShowAdded((await runner.RunAsync("ufw", ["show", "added"], null, ct)).StdOut);
        var (active, defaultIn) = UfwRules.ParseStatus((await runner.RunAsync("ufw", ["status", "verbose"], null, ct)).StdOut);
        var wantDefault = request.Policy.Firewall?.DefaultIncoming ?? "deny";

        var changes = new List<PlannedChange>();
        foreach (var r in desired.Where(r => !current.Contains(r)))
            changes.Add(new(ChangeKind.RunCommand, "ufw", $"allow {r}", string.Join(Sep, r.AddArgs())));
        foreach (var r in current.Where(r => !desired.Contains(r)))
            changes.Add(new(ChangeKind.RunCommand, "ufw", $"remove {r}", string.Join(Sep, r.DeleteArgs())));
        if (defaultIn != wantDefault)
            changes.Add(new(ChangeKind.RunCommand, "ufw", $"default {wantDefault} incoming", string.Join(Sep, ["default", wantDefault, "incoming"])));
        if (!active)
            changes.Add(new(ChangeKind.StartService, "ufw", "enable ufw", string.Join(Sep, ["--force", "enable"])));
        return new ReconcilePlan(Info.Id, request.Revision, changes, [], changes.Count == 0 ? ConfigState.InSync : ConfigState.Pending);
    }

    public async Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct)
    {
        if (plan.ResultingState == ConfigState.Rejected)
        {
            var message = string.Join(" ", plan.Warnings.Select(w => w.Message));
            return new ReconcileResult(false, ConfigState.Rejected, message, [Event(EventKinds.ConfigRejected, Severity.High, $"ufw: not applied. {message}")]);
        }
        if (plan.IsNoop) return ReconcileResult.Ok(ConfigState.InSync);

        // Validate every new rule before touching anything.
        foreach (var c in plan.Changes.Where(c => c.Description.StartsWith("allow ", StringComparison.Ordinal)))
        {
            var dry = await runner.RunAsync("ufw", ["--dry-run", .. c.Content!.Split(Sep)], null, ct);
            if (!dry.Success) return Rejected($"ufw refused '{c.Description}': {dry.CombinedOutput.Trim()}");
        }

        var done = new List<PlannedChange>();
        foreach (var c in plan.Changes)
        {
            var r = await runner.RunAsync("ufw", c.Content!.Split(Sep), null, ct);
            if (r.Success) { done.Add(c); continue; }
            logger.LogWarning("ufw {Change} failed, rolling back {Count} step(s): {Output}", c.Description, done.Count, r.CombinedOutput.Trim());
            foreach (var undo in Enumerable.Reverse(done)) await UndoAsync(undo, ct);
            return Rejected($"ufw failed at '{c.Description}': {r.CombinedOutput.Trim()}. Earlier steps were rolled back.");
        }
        return ReconcileResult.Ok(ConfigState.InSync, Event(EventKinds.ConfigApplied, Severity.Info, $"ufw: {string.Join("; ", plan.Changes.Select(c => c.Description))}"));
    }

    private async Task UndoAsync(PlannedChange c, CancellationToken ct)
    {
        var args = c.Content!.Split(Sep);
        string[]? undo = args[0] switch
        {
            "allow" => ["delete", .. args],
            "delete" => args[1..],
            "--force" => ["disable"],
            _ => null, // a changed default stays; it is reported in the error
        };
        if (undo is not null) await runner.RunAsync("ufw", undo, null, ct);
    }

    private ReconcileResult Rejected(string message) =>
        new(false, ConfigState.Rejected, message, [Event(EventKinds.ConfigRejected, Severity.High, $"ufw: {message}")]);

    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        await Task.CompletedTask;
        yield break;
    }

    /// <summary>Removes the agent's rules, except SSH ones while ufw is active, so uninstalling never locks anyone out.</summary>
    public async Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct)
    {
        if (runner.Which("ufw") is null) return ReconcileResult.Ok(ConfigState.InSync);
        var (active, _) = UfwRules.ParseStatus((await runner.RunAsync("ufw", ["status", "verbose"], null, ct)).StdOut);
        var ssh = await runner.RunAsync("sshd", ["-T"], null, ct);
        var sshPorts = ssh.Success ? NetworkParsers.ParseSshdSettings(ssh.StdOut).Ports : [22];
        foreach (var r in UfwRules.ParseShowAdded((await runner.RunAsync("ufw", ["show", "added"], null, ct)).StdOut))
            if (!(active && sshPorts.Contains(r.Port))) await runner.RunAsync("ufw", r.DeleteArgs(), null, ct);
        return ReconcileResult.Ok(ConfigState.InSync);
    }

    /// <summary>Interface names from <c>ip -j addr</c>; null when they can't be read (then interface rules aren't second-guessed).</summary>
    private async Task<HashSet<string>?> InterfacesAsync(CancellationToken ct)
    {
        if (runner.Which("ip") is null) return null;
        var r = await runner.RunAsync("ip", ["-j", "addr", "show"], null, ct);
        if (!r.Success) return null;
        try { return NetworkParsers.ParseIpAddr(r.StdOut).Select(a => a.Interface).ToHashSet(StringComparer.Ordinal); }
        catch (System.Text.Json.JsonException) { return null; }
    }

    private SecurityEvent Event(string kind, Severity severity, string message) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow().UtcDateTime,
        Capability = Capability.Firewall,
        Severity = severity,
        SourceTool = Info.Id,
        Kind = kind,
        Message = message,
        DedupKey = $"{Info.Id}:{kind}",
    };
}
