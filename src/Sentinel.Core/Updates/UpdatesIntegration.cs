using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Contracts;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Core.Platform;
using Sentinel.Core.Policy;

namespace Sentinel.Core.Updates;

/// <summary>
/// Pending security updates, counted and installed by the distribution's own tools:
/// <list type="bullet">
/// <item>Debian/Ubuntu: <c>apt-get update</c> + an <c>apt-get -s dist-upgrade</c> simulation to count; <c>unattended-upgrade</c>
/// (installed from the distro if missing) to apply, so its allowed-origins, blacklist and dpkg-conffile handling apply.</item>
/// <item>RHEL family: <c>dnf check-update [--security]</c> to count, <c>dnf upgrade --security</c> to apply,
/// <c>needs-restarting -r</c> for reboots.</item>
/// <item>Alpine: <c>apk list --upgradable</c> and <c>apk upgrade</c>. Alpine publishes no security metadata, so every update counts.</item>
/// </list>
/// The agent manages no config files here; whether the OS installs updates by itself is a baseline check.
/// </summary>
public sealed class UpdatesIntegration(
    ICommandRunner runner,
    IFileSystem fs,
    IPackageManager? packages,
    IStateStore state,
    OsInfo os,
    ILogger<UpdatesIntegration> logger,
    TimeProvider time) : IToolIntegration, IScheduledJobProvider
{
    public const string CheckJob = "updates.check";
    public const string ApplyJob = "updates.apply";
    public const string RebootRequiredFile = "/var/run/reboot-required";

    private const string StateLastReport = "updates.lastReport";
    private const string StateLastApply = "updates.lastApply";
    private const string StateKnownSecurity = "updates.knownSecurity";
    private const string StateReboot = "updates.rebootRequired";

    private static readonly CommandOptions Slow = new() { Timeout = TimeSpan.FromMinutes(10), Environment = new Dictionary<string, string> { ["DEBIAN_FRONTEND"] = "noninteractive" } };
    private static readonly CommandOptions Upgrade = new() { Timeout = TimeSpan.FromMinutes(60), Environment = new Dictionary<string, string> { ["DEBIAN_FRONTEND"] = "noninteractive" } };

    private readonly Queue<SecurityEvent> _events = new();
    private readonly SemaphoreSlim _lock = new(1, 1);

    public static readonly ToolDescriptor Info = new(
        "updates",
        "Security updates (unattended-upgrades / dnf / apk)",
        Capability.Updates,
        "GPL-2.0 (unattended-upgrades, dnf, apk-tools)",
        "https://wiki.debian.org/UnattendedUpgrades",
        new Dictionary<DistroFamily, string> { [DistroFamily.Debian] = "unattended-upgrades", [DistroFamily.RedHat] = "dnf", [DistroFamily.Alpine] = "apk-tools" },
        "Counts pending security updates with the distribution's package manager and installs them on schedule or on demand.");

    public ToolDescriptor Descriptor => Info;

    public IReadOnlyList<ScheduledJob> Jobs =>
    [
        new(CheckJob, "Check for updates", "updates.checkSchedule", RunOnFirstStart: true, (_, _, ct) => CheckAsync(ct)),
        new(ApplyJob, "Install security updates", "updates.applySchedule", RunOnFirstStart: false, (_, _, ct) => InstallUpdatesAsync(ct)),
    ];

    public bool IsWanted(PolicyDocument policy) => true;

    public async Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        var manager = Manager;
        if (manager is null)
            return new ToolStatus { ToolId = Info.Id, Availability = Availability.Unavailable, UnavailableReason = $"No supported package manager on {os.PrettyName}." };
        var details = new Dictionary<string, string> { ["manager"] = manager };
        string? version = null;
        if (os.Family == DistroFamily.Debian)
        {
            version = packages is null ? null : await packages.InstalledVersionAsync("unattended-upgrades", ct);
            details["unattended-upgrades"] = version is null ? "not installed" : "installed";
        }
        var last = LastReport();
        if (last?.Updates is { } u)
        {
            details["pending"] = u.Pending.ToString(CultureInfo.InvariantCulture);
            if (u.Security is { } sec) details["security"] = sec.ToString(CultureInfo.InvariantCulture);
            if (u.RebootRequired) details["reboot"] = "required";
        }
        return new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Running = true,
            Version = version,
            Ownership = Ownership.Adopted,
            ConfigState = ConfigState.InSync,
            LastError = last is { Success: false } ? last.Error : null,
            LastSuccessAt = last is { Success: true } ? last.FinishedAtUtc : null,
            Details = details,
        };
    }

    public async Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct)
    {
        // unattended-upgrade is what applies updates on Debian/Ubuntu; it's tiny and preinstalled on Ubuntu.
        if (os.Family == DistroFamily.Debian && packages is not null && request.AllowInstall && runner.Which("unattended-upgrade") is null)
        {
            var r = await packages.InstallAsync("unattended-upgrades", ct);
            if (!r.Success) logger.LogWarning("Installing unattended-upgrades failed: {Error}", r.Error);
        }
        return await DetectAsync(ct);
    }

    public Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct) =>
        Task.FromResult(new ReconcilePlan(Info.Id, request.Revision, [], [], ConfigState.InSync));

    public Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        await Task.CompletedTask;
        while (_events.TryDequeue(out var e)) yield return e;
    }

    public Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    private string? Manager => os.Family switch
    {
        DistroFamily.Debian when runner.Which("apt-get") is not null => "apt",
        DistroFamily.RedHat when runner.Which("dnf") is not null => "dnf",
        DistroFamily.Alpine when runner.Which("apk") is not null => "apk",
        _ => null,
    };

    // ---- check ----

    public async Task<AgentReport> CheckAsync(CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            return await CheckCoreAsync(refresh: true, ct);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<AgentReport> CheckCoreAsync(bool refresh, CancellationToken ct)
    {
        var started = time.GetUtcNow().UtcDateTime;
        UpdatesReport report;
        try
        {
            report = Manager switch
            {
                "apt" => await CheckAptAsync(refresh, ct),
                "dnf" => await CheckDnfAsync(ct),
                "apk" => await CheckApkAsync(refresh, ct),
                _ => throw new UpdateCheckException($"No supported package manager on {os.PrettyName}."),
            };
        }
        catch (UpdateCheckException ex)
        {
            logger.LogWarning("Update check failed: {Error}", ex.Message);
            var failed = new AgentReport(CheckJob, started, time.GetUtcNow().UtcDateTime, false, ex.Message) { Updates = LastReport()?.Updates };
            await SaveReportAsync(failed, ct);
            return failed;
        }
        report = report with { LastApply = LastApply() };
        await RaiseCheckEventsAsync(report, ct);
        var result = new AgentReport(CheckJob, started, time.GetUtcNow().UtcDateTime, true, null) { Updates = report };
        await SaveReportAsync(result, ct);
        logger.LogInformation("Updates: {Pending} pending, {Security} security, reboot {Reboot}", report.Pending, report.Security?.ToString(CultureInfo.InvariantCulture) ?? "unknown", report.RebootRequired);
        return result;
    }

    private async Task<UpdatesReport> CheckAptAsync(bool refresh, CancellationToken ct)
    {
        if (refresh)
        {
            // Wait for a running apt (the daily timer, an admin) instead of failing on its lock.
            var update = await runner.RunAsync("apt-get", ["update", "-q", "-o", "DPkg::Lock::Timeout=300"], Slow, ct);
            if (!update.Success) throw new UpdateCheckException($"apt-get update failed: {Tail(update.CombinedOutput, 400)}");
        }
        var sim = await runner.RunAsync("apt-get", ["-s", "-o", "Debug::NoLocking=1", "dist-upgrade"], Slow, ct);
        if (!sim.Success) throw new UpdateCheckException($"apt-get -s dist-upgrade failed: {Tail(sim.CombinedOutput, 400)}");
        var reboot = fs.FileExists(RebootRequiredFile);
        var rebootPkgs = reboot && await fs.ReadAllTextAsync(RebootRequiredFile + ".pkgs", ct) is { } pkgs
            ? pkgs.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct().ToList()
            : [];
        return new UpdatesReport("apt", UpdateParsers.ParseAptSimulation(sim.StdOut), reboot, rebootPkgs, null);
    }

    private async Task<UpdatesReport> CheckDnfAsync(CancellationToken ct)
    {
        // check-update exits 100 when updates exist, 0 when none, 1 on error.
        var all = await runner.RunAsync("dnf", ["-q", "check-update"], Slow, ct);
        if (all.ExitCode is not (0 or 100)) throw new UpdateCheckException($"dnf check-update failed: {Tail(all.CombinedOutput, 400)}");
        var sec = await runner.RunAsync("dnf", ["-q", "check-update", "--security"], Slow, ct);
        if (sec.ExitCode is not (0 or 100)) throw new UpdateCheckException($"dnf check-update --security failed: {Tail(sec.CombinedOutput, 400)}");
        var security = UpdateParsers.ParseDnfCheckUpdate(sec.StdOut).Select(x => x.Name).ToHashSet(StringComparer.Ordinal);
        var list = UpdateParsers.ParseDnfCheckUpdate(all.StdOut)
            .Select(x => new PendingUpdate(x.Name, null, x.Candidate, x.Repo, security.Contains(x.Name))).ToList();
        var reboot = false;
        if (runner.Which("needs-restarting") is not null)
            reboot = (await runner.RunAsync("needs-restarting", ["-r"], ct: ct)).ExitCode == 1; // documented: 1 = reboot needed
        return new UpdatesReport("dnf", list, reboot, [], null);
    }

    private async Task<UpdatesReport> CheckApkAsync(bool refresh, CancellationToken ct)
    {
        if (refresh)
        {
            var update = await runner.RunAsync("apk", ["update", "-q"], Slow, ct);
            if (!update.Success) throw new UpdateCheckException($"apk update failed: {Tail(update.CombinedOutput, 400)}");
        }
        var list = await runner.RunAsync("apk", ["list", "--upgradable"], Slow, ct);
        if (!list.Success) throw new UpdateCheckException($"apk list failed: {Tail(list.CombinedOutput, 400)}");
        return new UpdatesReport("apk", UpdateParsers.ParseApkUpgradable(list.StdOut), false, [], null);
    }

    private async Task RaiseCheckEventsAsync(UpdatesReport report, CancellationToken ct)
    {
        var relevant = report.Packages.Where(p => p.Security != false).ToList();
        var known = (state.Get(StateKnownSecurity) ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        var fresh = relevant.Where(p => !known.Contains($"{p.Name}={p.Candidate}")).ToList();
        if (fresh.Count > 0)
        {
            var names = string.Join(", ", relevant.Select(p => p.Name).Take(8)) + (relevant.Count > 8 ? $" and {relevant.Count - 8} more" : "");
            var message = report.Security is null
                ? $"{relevant.Count} update{(relevant.Count == 1 ? "" : "s")} pending ({names}). This distribution doesn't mark security updates."
                : $"{relevant.Count} security update{(relevant.Count == 1 ? "" : "s")} pending: {names}";
            _events.Enqueue(Event(EventKinds.UpdatesPending, report.Security is null ? Severity.Low : Severity.Medium, message, null));
        }
        await state.SetAsync(StateKnownSecurity, string.Join(' ', relevant.Select(p => $"{p.Name}={p.Candidate}")), ct);

        var wasReboot = state.Get(StateReboot) == "true";
        if (report.RebootRequired && !wasReboot)
            _events.Enqueue(Event(EventKinds.RebootRequired, Severity.Medium,
                "A reboot is required to finish installing updates" + (report.RebootPackages.Count > 0 ? $" ({string.Join(", ", report.RebootPackages.Take(6))})" : "") + ". The running kernel or libraries are still the old, vulnerable ones.", null));
        await state.SetAsync(StateReboot, report.RebootRequired ? "true" : "false", ct);
    }

    // ---- apply ----

    public async Task<AgentReport> InstallUpdatesAsync(CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var started = time.GetUtcNow().UtcDateTime;
            var before = LastReport()?.Updates;
            CommandResult r;
            List<string>? reported = null;
            switch (Manager)
            {
                case "apt":
                    var refresh = await runner.RunAsync("apt-get", ["update", "-q", "-o", "DPkg::Lock::Timeout=300"], Slow, ct);
                    if (!refresh.Success) { r = refresh; break; }
                    if (runner.Which("unattended-upgrade") is not null)
                    {
                        r = await runner.RunAsync("unattended-upgrade", ["-v"], Upgrade, ct);
                        reported = UpdateParsers.ParseUnattendedUpgrade(r.StdOut);
                    }
                    else
                    {
                        // Fallback without unattended-upgrades: only the security candidates, keeping locally modified config files.
                        var sim = await runner.RunAsync("apt-get", ["-s", "-o", "Debug::NoLocking=1", "dist-upgrade"], Slow, ct);
                        var sec = UpdateParsers.ParseAptSimulation(sim.StdOut).Where(p => p.Security == true).Select(p => p.Name).ToList();
                        r = sec.Count == 0 ? new CommandResult(0, "No security updates to install.", "") :
                            await runner.RunAsync("apt-get", ["install", "-y", "-q", "--only-upgrade", "-o", "DPkg::Lock::Timeout=300",
                                "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", .. sec], Upgrade, ct);
                        reported = sec;
                    }
                    break;
                case "dnf":
                    r = await runner.RunAsync("dnf", ["-y", "-q", "upgrade", "--security"], Upgrade, ct);
                    break;
                case "apk":
                    r = await runner.RunAsync("apk", ["upgrade", "-q"], Upgrade, ct);
                    break;
                default:
                    r = new CommandResult(127, "", $"No supported package manager on {os.PrettyName}.");
                    break;
            }

            var after = await CheckCoreAsync(refresh: false, ct);
            var remaining = after.Updates?.Packages.Select(p => p.Name).ToHashSet(StringComparer.Ordinal) ?? [];
            // What the tool said it installed, else what disappeared from the pending list (also covers partial failures).
            var upgraded = r.Success && reported is { Count: > 0 } ? reported
                : before?.Packages.Select(p => p.Name).Where(n => !remaining.Contains(n)).ToList() ?? [];
            var apply = new UpdateApplyResult(time.GetUtcNow().UtcDateTime, r.Success, upgraded, r.Success ? null : Tail(r.CombinedOutput, 500), Tail(r.CombinedOutput, 3000));
            await state.SetAsync(StateLastApply, JsonSerializer.Serialize(apply, AgentJsonContext.Default.UpdateApplyResult), ct);

            if (r.Success && upgraded.Count > 0)
                _events.Enqueue(Event(EventKinds.UpdatesApplied, Severity.Info, $"Installed {upgraded.Count} update{(upgraded.Count == 1 ? "" : "s")}: {string.Join(", ", upgraded.Take(10))}{(upgraded.Count > 10 ? " …" : "")}", null));
            else if (!r.Success)
                _events.Enqueue(Event(EventKinds.UpdatesFailed, Severity.High, $"Installing security updates failed: {apply.Error}", apply.LogTail));
            logger.LogInformation("Updates applied: success={Success}, {Count} package(s)", r.Success, upgraded.Count);

            var report = (after.Updates ?? before ?? new UpdatesReport(Manager ?? "?", [], false, [], null)) with { LastApply = apply };
            var result = new AgentReport(ApplyJob, started, time.GetUtcNow().UtcDateTime, r.Success, apply.Error) { Updates = report };
            await SaveReportAsync(result with { JobId = CheckJob, Success = after.Success, Error = after.Error }, ct);
            return result;
        }
        finally
        {
            _lock.Release();
        }
    }

    // ---- state ----

    private AgentReport? LastReport() =>
        state.Get(StateLastReport) is { } json ? JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentReport) : null;

    private UpdateApplyResult? LastApply() =>
        state.Get(StateLastApply) is { } json ? JsonSerializer.Deserialize(json, AgentJsonContext.Default.UpdateApplyResult) : null;

    private Task SaveReportAsync(AgentReport report, CancellationToken ct) =>
        state.SetAsync(StateLastReport, JsonSerializer.Serialize(report, AgentJsonContext.Default.AgentReport), ct);

    private static string Tail(string s, int max)
    {
        s = s.Trim();
        return s.Length <= max ? s : "…" + s[^max..];
    }

    private SecurityEvent Event(string kind, Severity severity, string message, string? raw) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow().UtcDateTime,
        Capability = Capability.Updates,
        Severity = severity,
        SourceTool = Info.Id,
        Kind = kind,
        Message = message,
        Raw = raw,
        DedupKey = $"{Info.Id}:{kind}",
    };

    private sealed class UpdateCheckException(string message) : Exception(message);
}
