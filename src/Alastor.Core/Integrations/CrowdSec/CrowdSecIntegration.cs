using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Extensions.Logging;
using Alastor.Core.Events;
using Alastor.Core.Net;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Core.Integrations.CrowdSec;

public sealed record CrowdSecOptions
{
    public string ConfigDir { get; init; } = "/etc/crowdsec";
    public string SystemdDir { get; init; } = "/etc/systemd/system";
    public string ServiceName { get; init; } = "crowdsec";
    public string BouncerService { get; init; } = "crowdsec-firewall-bouncer";

    /// <summary>A parser-stage whitelist: CrowdSec drops events from these sources before any scenario sees them.</summary>
    public string AllowlistFile => Path.Combine(ConfigDir, "parsers", "s02-enrich", "alastor-allowlist.yaml");

    public string CentralApiCredentials => Path.Combine(ConfigDir, "online_api_credentials.yaml");
    public string DropInFile => Path.Combine(SystemdDir, ServiceName + ".service.d", "alastor.conf");
    public string ConfigFile => Path.Combine(ConfigDir, "config.yaml");
}

/// <summary>
/// CrowdSec as the opt-in banning engine (<c>banning.engine: crowdsec</c>), with the firewall bouncer enforcing its
/// decisions. Both come from the distro repositories (Debian and Ubuntu ship them); elsewhere a CrowdSec installed from
/// the vendor's repository is adopted.
/// <list type="bullet">
/// <item>Bans and events: <c>cscli decisions list -o json</c> and <c>cscli alerts list -o json</c>, never its logs.</item>
/// <item>Manual bans: <c>cscli decisions add</c> / <c>delete</c>.</item>
/// <item>Allowlist: owns one parser whitelist file, validated with <c>crowdsec -t</c> before a reload.</item>
/// <item>Privacy: CrowdSec's Central API (signal sharing and the community blocklist) stays off unless
/// <c>banning.crowdsecCentralApi</c> is true. Before installing, the agent writes the Central API credentials file
/// itself, which makes the Debian package skip its registration, and a systemd drop-in starts the daemon with
/// <c>-no-capi</c>.</item>
/// </list>
/// fail2ban jail settings don't apply here: CrowdSec's scenarios and profile (4 h bans by default) decide what gets banned.
/// </summary>
public sealed class CrowdSecIntegration(
    ICommandRunner runner,
    IFileSystem fs,
    IPackageManager? packages,
    IServiceManager services,
    IStateStore state,
    ILogger<CrowdSecIntegration> logger,
    TimeProvider time,
    CrowdSecOptions? options = null) : IToolIntegration, IBanProvider
{
    private const string Cscli = "cscli";
    private const string StateInstalledByAgent = "crowdsec.installedByAgent";
    private const string StateAppliedRevision = "crowdsec.appliedRevision";
    private const string StateConfigState = "crowdsec.configState";
    private const string StateLastReload = "crowdsec.lastReloadUtc";
    private const string StateLastAlertId = "crowdsec.lastAlertId";
    public const string ManualReasonPrefix = "alastor";
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private readonly CrowdSecOptions _opt = options ?? new CrowdSecOptions();
    private DateTime _lastPoll = DateTime.MinValue;

    public static readonly ToolDescriptor Info = new(
        "crowdsec",
        "CrowdSec",
        Capability.Banning,
        "MIT",
        "https://github.com/crowdsecurity/crowdsec",
        new Dictionary<DistroFamily, string>
        {
            [DistroFamily.Debian] = "crowdsec crowdsec-firewall-bouncer",
        },
        "Behaviour-based detection with shareable scenarios; its firewall bouncer enforces the decisions.");

    public ToolDescriptor Descriptor => Info;

    public bool IsWanted(PolicyDocument policy) =>
        policy.Banning is { } b && b.Enabled != false && b.Engine == "crowdsec";

    private static bool CentralApiWanted(PolicyDocument policy) => policy.Banning?.CrowdsecCentralApi == true;

    public async Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        if (runner.Which(Cscli) is null)
        {
            if (packages is null)
                return Status(Availability.Unavailable, "No supported package manager (apt, dnf, apk) found on this host.");
            if (packages.Name != "apt" || !await packages.IsAvailableAsync("crowdsec", ct))
                return Status(Availability.Unavailable,
                    $"CrowdSec isn't in this host's {packages.Name} repositories. Install it from CrowdSec's own repository (https://doc.crowdsec.net) and the agent adopts it.");
            return Status(Availability.Available, null);
        }

        var version = await runner.RunAsync(Cscli, ["version"], null, ct);
        var running = await services.IsActiveAsync(_opt.ServiceName, ct);
        var bouncerInstalled = runner.Which(_opt.BouncerService) is not null;
        var bouncerRunning = bouncerInstalled && await services.IsActiveAsync(_opt.BouncerService, ct);

        var allow = ManagedFile.Inspect(await fs.ReadAllTextAsync(_opt.AllowlistFile, ct));
        var configState = allow.State switch
        {
            ManagedFileState.Drifted => ConfigState.Drifted,
            ManagedFileState.Foreign => ConfigState.Conflict,
            _ => Enum.TryParse<ConfigState>(state.Get(StateConfigState), out var last) ? last : ConfigState.Pending,
        };

        var warnings = new List<string>();
        if (!bouncerInstalled) warnings.Add("No firewall bouncer is installed: CrowdSec records decisions, but nothing blocks the addresses.");
        else if (!bouncerRunning) warnings.Add("The CrowdSec firewall bouncer isn't running: decisions aren't enforced.");

        var dropIn = ManagedFile.Inspect(await fs.ReadAllTextAsync(_opt.DropInFile, ct));
        var details = new Dictionary<string, string>
        {
            ["bouncer"] = bouncerRunning ? "running" : bouncerInstalled ? "stopped" : "missing",
            ["centralApi"] = dropIn.State == ManagedFileState.Owned ? "off" : "on",
        };

        return new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Version = CrowdSecParsers.ParseVersion(version.StdOut + "\n" + version.StdErr),
            Running = running,
            Ownership = state.Get(StateInstalledByAgent) == "true" ? Ownership.Managed : Ownership.Adopted,
            ConfigState = configState,
            AppliedRevision = state.Get(StateAppliedRevision),
            LastSuccessAt = DateTime.TryParse(state.Get(StateLastReload), null, DateTimeStyles.RoundtripKind, out var t) ? t : null,
            LastError = running ? null : "CrowdSec is installed but its service isn't running.",
            Warnings = warnings,
            Details = details,
        };
    }

    public async Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct)
    {
        var status = await DetectAsync(ct);
        if (status.Installed || status.Availability == Availability.Unavailable) return status;
        if (!request.AllowInstall)
            return status with
            {
                Availability = Availability.Unavailable,
                UnavailableReason = "CrowdSec is not installed and agent.autoInstall is false. Install crowdsec and crowdsec-firewall-bouncer, or enable auto-install.",
            };

        // The Debian package registers with CrowdSec's Central API on install unless this file already has content.
        if (!CentralApiWanted(request.Policy) && !fs.FileExists(_opt.CentralApiCredentials))
            await fs.WriteAllTextAtomicAsync(_opt.CentralApiCredentials, ManagedFile.Render(CentralApiPlaceholder, request.Revision), Mode600, ct);

        logger.LogInformation("Installing CrowdSec and its firewall bouncer from distro repositories via {PackageManager}", packages!.Name);
        foreach (var pkg in new[] { "crowdsec", "crowdsec-firewall-bouncer" })
        {
            var result = await packages.InstallAsync(pkg, ct);
            if (!result.Success)
                return status with { Availability = Availability.Unavailable, UnavailableReason = $"Installing {pkg} failed: {result.Error}" };
        }
        await state.SetAsync(StateInstalledByAgent, "true", ct);
        return await DetectAsync(ct);
    }

    public async Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct)
    {
        var changes = new List<PlannedChange>();
        var warnings = new List<PlanWarning>();
        var allowInspect = ManagedFile.Inspect(await fs.ReadAllTextAsync(_opt.AllowlistFile, ct));
        var dropInInspect = ManagedFile.Inspect(await fs.ReadAllTextAsync(_opt.DropInFile, ct));
        var capiInspect = ManagedFile.Inspect(await fs.ReadAllTextAsync(_opt.CentralApiCredentials, ct));
        var resultState = ConfigState.InSync;
        var running = await services.IsActiveAsync(_opt.ServiceName, ct);
        ManualDuration = Duration.TryParseSeconds(request.Policy.Banning?.ManualBantime, out var manual) ? CrowdSecParsers.FormatDuration(manual) : "87600h";

        if (!IsWanted(request.Policy))
        {
            // CrowdSec stays installed but is no longer managed: remove our allowlist. The -no-capi drop-in stays,
            // so the daemon doesn't start sharing data just because the engine was switched back to fail2ban.
            if (allowInspect.State == ManagedFileState.Owned || (allowInspect.State == ManagedFileState.Drifted && request.Reclaim))
            {
                changes.Add(new(ChangeKind.DeleteFile, _opt.AllowlistFile, "Banning engine is not CrowdSec: remove the managed allowlist"));
                if (running) changes.Add(new(ChangeKind.Reload, _opt.ServiceName, "Reload CrowdSec"));
            }
            return new ReconcilePlan(Info.Id, request.Revision, changes, warnings, ConfigState.InSync);
        }

        void PlanFile(string path, ManagedFileInspection inspect, string? body, string what)
        {
            if (body is null)
            {
                if (inspect.State == ManagedFileState.Owned || (inspect.State == ManagedFileState.Drifted && request.Reclaim))
                    changes.Add(new(ChangeKind.DeleteFile, path, $"Remove {what}"));
                return;
            }
            switch (inspect.State)
            {
                case ManagedFileState.Missing:
                    changes.Add(new(ChangeKind.WriteFile, path, $"Create {what}", ManagedFile.Render(body, request.Revision)));
                    break;
                case ManagedFileState.Owned when Normalize(inspect.Body) != Normalize(body):
                    changes.Add(new(ChangeKind.WriteFile, path, $"Update {what}", ManagedFile.Render(body, request.Revision)));
                    break;
                case ManagedFileState.Drifted when request.Reclaim:
                    changes.Add(new(ChangeKind.WriteFile, path, $"Reclaim hand-edited {what}", ManagedFile.Render(body, request.Revision)));
                    break;
                case ManagedFileState.Drifted:
                    warnings.Add(new(EventKinds.ConfigDrift, $"{path} was edited by hand. Not overwriting it; use \"Reclaim\" in the dashboard to restore policy control."));
                    resultState = ConfigState.Drifted;
                    break;
                case ManagedFileState.Foreign:
                    warnings.Add(new(EventKinds.ConfigConflict, $"{path} exists but was not written by Alastor. Not touching it."));
                    resultState = ConfigState.Conflict;
                    break;
            }
        }

        PlanFile(_opt.AllowlistFile, allowInspect, RenderAllowlist(request.Policy.Banning?.Allowlist ?? []), "CrowdSec allowlist");

        var capi = CentralApiWanted(request.Policy);
        var crowdsecPath = runner.Which("crowdsec") ?? "/usr/bin/crowdsec";
        if (!(dropInInspect.State == ManagedFileState.Foreign && !capi))
            PlanFile(_opt.DropInFile, dropInInspect, capi ? null : RenderDropIn(crowdsecPath, _opt.ConfigFile), "systemd drop-in that keeps the Central API off");
        if (capi && capiInspect.State == ManagedFileState.Owned)
            changes.Add(new(ChangeKind.DeleteFile, _opt.CentralApiCredentials, "Register with CrowdSec's Central API (banning.crowdsecCentralApi: true)"));
        else if (!capi && dropInInspect.State == ManagedFileState.Foreign)
        {
            warnings.Add(new(EventKinds.ConfigConflict, $"{_opt.DropInFile} is not managed by Alastor, so the agent can't guarantee CrowdSec's Central API is off."));
            if (resultState == ConfigState.InSync) resultState = ConfigState.Conflict;
        }

        var unitChanged = changes.Any(c => c.Target == _opt.DropInFile || c.Target == _opt.CentralApiCredentials);
        if (!running) changes.Add(new(ChangeKind.StartService, _opt.ServiceName, "Enable and start CrowdSec"));
        else if (unitChanged) changes.Add(new(ChangeKind.StartService, _opt.ServiceName, "Restart CrowdSec"));
        else if (changes.Count > 0) changes.Add(new(ChangeKind.Reload, _opt.ServiceName, "Reload CrowdSec"));

        if (runner.Which(_opt.BouncerService) is not null && !await services.IsActiveAsync(_opt.BouncerService, ct))
            changes.Add(new(ChangeKind.StartService, _opt.BouncerService, "Enable and start the CrowdSec firewall bouncer"));
        else if (runner.Which(_opt.BouncerService) is null)
            warnings.Add(new(EventKinds.ToolUnavailable, "crowdsec-firewall-bouncer is not installed, so CrowdSec's decisions aren't enforced. Install it from the same repository as CrowdSec."));

        return new ReconcilePlan(Info.Id, request.Revision, changes, warnings, resultState);
    }

    public async Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct)
    {
        var events = plan.Warnings.Select(w => LifecycleEvent(w.Kind, Severity.Medium, w.Message, plan.Revision)).ToList();
        if (plan.IsNoop)
        {
            await state.SetAsync(StateAppliedRevision, plan.Revision, ct);
            await state.SetAsync(StateConfigState, plan.ResultingState.ToString(), ct);
            return new ReconcileResult(true, plan.ResultingState, null, events);
        }

        var backups = new Dictionary<string, string?>();
        foreach (var c in plan.Changes.Where(c => c.Kind is ChangeKind.WriteFile or ChangeKind.DeleteFile))
            backups[c.Target] = await fs.ReadAllTextAsync(c.Target, ct);
        var unitTouched = backups.ContainsKey(_opt.DropInFile);

        async Task RollbackAsync()
        {
            foreach (var (path, content) in backups)
            {
                if (content is null) fs.DeleteFile(path);
                else await fs.WriteAllTextAtomicAsync(path, content, path == _opt.CentralApiCredentials ? Mode600 : Mode644, ct);
            }
            if (unitTouched) await runner.RunAsync("systemctl", ["daemon-reload"], null, ct);
        }

        try
        {
            foreach (var c in plan.Changes)
            {
                if (c.Kind == ChangeKind.WriteFile) await fs.WriteAllTextAtomicAsync(c.Target, c.Content!, Mode644, ct);
                else if (c.Kind == ChangeKind.DeleteFile) fs.DeleteFile(c.Target);
            }
            if (backups.ContainsKey(_opt.CentralApiCredentials) && !fs.FileExists(_opt.CentralApiCredentials))
            {
                var reg = await runner.RunAsync(Cscli, ["capi", "register"], null, ct);
                if (!reg.Success) throw new InvalidOperationException($"cscli capi register failed: {reg.CombinedOutput.Trim()}");
            }
            if (unitTouched && !(await runner.RunAsync("systemctl", ["daemon-reload"], null, ct)).Success)
                throw new InvalidOperationException("systemctl daemon-reload failed");

            if (backups.Count > 0)
            {
                var test = await runner.RunAsync("crowdsec", ["-c", _opt.ConfigFile, "-t"], null, ct);
                if (!test.Success)
                {
                    await RollbackAsync();
                    var msg = $"CrowdSec rejected the new configuration and it was rolled back: {LastLines(test.CombinedOutput)}";
                    events.Add(LifecycleEvent(EventKinds.ConfigRejected, Severity.High, msg, plan.Revision));
                    await state.SetAsync(StateConfigState, nameof(ConfigState.Rejected), ct);
                    return new ReconcileResult(false, ConfigState.Rejected, msg, events);
                }
            }

            foreach (var c in plan.Changes)
            {
                // The bouncer enforces decisions but isn't part of CrowdSec's configuration: if it can't start (no
                // nftables, no CAP_NET_ADMIN), report that instead of rolling back a valid allowlist.
                if (c.Target == _opt.BouncerService)
                {
                    if (!await services.EnableAndStartAsync(c.Target, ct))
                        events.Add(LifecycleEvent(EventKinds.ToolError, Severity.High,
                            $"The CrowdSec firewall bouncer didn't start, so decisions aren't enforced. See: journalctl -u {_opt.BouncerService}", plan.Revision));
                    continue;
                }
                var ok = c.Kind switch
                {
                    ChangeKind.Reload => await services.ReloadAsync(c.Target, ct),
                    ChangeKind.StartService when c.Description.StartsWith("Restart", StringComparison.Ordinal) => await services.RestartAsync(c.Target, ct),
                    ChangeKind.StartService => await services.EnableAndStartAsync(c.Target, ct),
                    _ => true,
                };
                if (!ok) throw new InvalidOperationException($"'{c.Description}' failed");
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            logger.LogError(ex, "Applying CrowdSec configuration failed. Rolling back.");
            await RollbackAsync();
            if (backups.Count > 0 && await services.IsActiveAsync(_opt.ServiceName, ct)) await services.RestartAsync(_opt.ServiceName, ct);
            var msg = $"Applying CrowdSec configuration failed and was rolled back: {ex.Message}";
            events.Add(LifecycleEvent(EventKinds.ConfigRejected, Severity.High, msg, plan.Revision));
            await state.SetAsync(StateConfigState, nameof(ConfigState.Rejected), ct);
            return new ReconcileResult(false, ConfigState.Rejected, msg, events);
        }

        await state.SetAsync(StateAppliedRevision, plan.Revision, ct);
        await state.SetAsync(StateConfigState, plan.ResultingState.ToString(), ct);
        await state.SetAsync(StateLastReload, time.GetUtcNow().UtcDateTime.ToString("O"), ct);
        events.Add(LifecycleEvent(EventKinds.ConfigApplied, Severity.Info,
            $"Applied banning policy {plan.Revision}: {string.Join(", ", plan.Changes.Select(c => c.Description))}", plan.Revision));
        return new ReconcileResult(true, plan.ResultingState, null, events);
    }

    /// <summary>New alerts since the last call, read from the Local API with cscli (at most every 30 s).</summary>
    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        if (now - _lastPoll < PollInterval) yield break;
        _lastPoll = now;
        var r = await runner.RunAsync(Cscli, ["alerts", "list", "-o", "json", "--since", "24h", "--limit", "200"], null, ct);
        if (!r.Success) yield break;
        IReadOnlyList<CrowdSecAlert> alerts;
        try
        {
            alerts = CrowdSecParsers.ParseAlerts(r.StdOut);
        }
        catch (System.Text.Json.JsonException ex)
        {
            logger.LogWarning("Unreadable cscli alerts output: {Error}", ex.Message);
            yield break;
        }
        var last = long.TryParse(state.Get(StateLastAlertId), out var l) ? l : (long?)null;
        var max = alerts.Count == 0 ? last ?? 0 : Math.Max(alerts.Max(a => a.Id), last ?? 0);
        if (max != last) await state.SetAsync(StateLastAlertId, max.ToString(CultureInfo.InvariantCulture), ct);
        // First run: remember where we are instead of replaying a day of alerts.
        if (last is null) yield break;
        foreach (var e in Normalize(alerts.Where(a => a.Id > last).OrderBy(a => a.Id))) yield return e;
    }

    public static IEnumerable<SecurityEvent> Normalize(IEnumerable<CrowdSecAlert> alerts)
    {
        foreach (var a in alerts)
        {
            // Community blocklist pulls arrive as one alert with thousands of decisions; they aren't attacks on this host.
            var local = a.Decisions.Where(d => d.Origin is "crowdsec" or "cscli").ToList();
            if (a.Decisions.Count > 0 && local.Count == 0) continue;
            var subject = a.SourceValue;
            var manual = local.Any(d => d.Origin == "cscli");
            var ban = local.FirstOrDefault(d => d.Type == "ban" && !d.Simulated);
            var meta = new Dictionary<string, string>
            {
                ["scenario"] = a.Scenario,
                ["alertId"] = a.Id.ToString(CultureInfo.InvariantCulture),
                ["events"] = a.EventsCount.ToString(CultureInfo.InvariantCulture),
                ["manual"] = manual ? "true" : "false",
            };
            if (a.SourceScope is { } scope) meta["scope"] = scope;
            // The time left when cscli was asked; round it so "4h2m9.8s" reads as the 4h the profile set.
            if (ban?.Remaining is { } left)
                meta["duration"] = Duration.Format(left.TotalHours >= 1 ? (long)Math.Round(left.TotalHours) * 3600 : (long)Math.Max(1, Math.Round(left.TotalMinutes)) * 60);

            string kind, message;
            Severity severity;
            if (ban is not null && manual)
                (kind, severity, message) = (EventKinds.BanAdded, Severity.Info, $"Banned {subject} (manual ban: {a.Scenario})");
            else if (ban is not null)
                (kind, severity, message) = (EventKinds.BanAdded, Severity.Low, $"Banned {subject}: {a.Scenario} ({a.EventsCount} event{(a.EventsCount == 1 ? "" : "s")})");
            else
                (kind, severity, message) = (EventKinds.AuthFailures, Severity.Info,
                    $"{a.Scenario} triggered for {subject}{(a.Simulated || local.Any(d => d.Simulated) ? " (simulation mode, not banned)" : "")}");

            yield return new SecurityEvent
            {
                Id = SecurityEvent.StableId(Info.Id, a.Id.ToString(CultureInfo.InvariantCulture), a.CreatedAt.ToString("O")),
                OccurredAt = a.CreatedAt,
                Capability = Capability.Banning,
                Severity = severity,
                SourceTool = Info.Id,
                Kind = kind,
                Subject = subject,
                Message = message,
                Raw = a.Message,
                Metadata = meta,
                DedupKey = $"{Info.Id}:{kind}:{a.Scenario}:{subject}",
            };
        }
    }

    public async Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct)
    {
        var allow = ManagedFile.Inspect(await fs.ReadAllTextAsync(_opt.AllowlistFile, ct));
        if (allow.State == ManagedFileState.Owned)
        {
            fs.DeleteFile(_opt.AllowlistFile);
            if (await services.IsActiveAsync(_opt.ServiceName, ct)) await services.ReloadAsync(_opt.ServiceName, ct);
        }
        // The drop-in and the Central API placeholder stay: removing them would turn on data sharing the admin never asked for.
        await state.SetAsync(StateAppliedRevision, null, ct);
        return ReconcileResult.Ok(ConfigState.Unknown);
    }

    // ---- IBanProvider ----

    public async Task<IReadOnlyList<BanEntry>> ListBansAsync(CancellationToken ct)
    {
        var r = await runner.RunAsync(Cscli, ["decisions", "list", "-o", "json"], null, ct);
        if (!r.Success) return [];
        var now = time.GetUtcNow().UtcDateTime;
        IReadOnlyList<CrowdSecAlert> alerts;
        try
        {
            alerts = CrowdSecParsers.ParseAlerts(r.StdOut);
        }
        catch (System.Text.Json.JsonException)
        {
            return [];
        }
        return alerts
            .SelectMany(a => a.Decisions.Select(d => (a, d)))
            .Where(x => x.d.Type == "ban" && !x.d.Simulated && x.d.Scope is "Ip" or "Range")
            .Select(x => new BanEntry(x.d.Value, x.d.Origin == "cscli" ? "manual" : x.d.Scenario, x.a.CreatedAt,
                x.d.Remaining is { } left ? now + left : null, x.d.Origin == "cscli"))
            .ToList();
    }

    /// <summary>Uses <c>banning.manualBantime</c> from the last policy seen (CrowdSec needs a duration; "permanent" is ten years).</summary>
    public string ManualDuration { get; set; } = "87600h";

    public async Task<CommandOutcome> BanAsync(IpTarget target, string? reason, CancellationToken ct)
    {
        var why = string.IsNullOrWhiteSpace(reason) ? $"{ManualReasonPrefix}: manual ban" : $"{ManualReasonPrefix}: {reason.Trim()}";
        var r = await runner.RunAsync(Cscli,
            ["decisions", "add", target.IsSingleAddress ? "--ip" : "--range", target.ToString(), "--duration", ManualDuration, "--reason", why, "--type", "ban"], null, ct);
        return r.Success ? new(true, $"Banned {target} for {ManualDuration}") : new(false, r.CombinedOutput.Trim());
    }

    public async Task<CommandOutcome> UnbanAsync(IpTarget target, CancellationToken ct)
    {
        var r = await runner.RunAsync(Cscli, ["decisions", "delete", target.IsSingleAddress ? "--ip" : "--range", target.ToString()], null, ct);
        if (!r.Success) return new(false, r.CombinedOutput.Trim());
        var n = CrowdSecParsers.ParseDeletedCount(r.CombinedOutput);
        return new(true, n == 0 ? $"{target} was not banned" : $"Unbanned {target}");
    }

    // ---- rendering ----

    internal const string CentralApiPlaceholder =
        "# CrowdSec's Central API is off (banning.crowdsecCentralApi is false), so this host never registers with or\n" +
        "# sends signals to api.crowdsec.net. The Debian package skips registration while this file has content.\n";

    /// <summary>A CrowdSec parser whitelist (s02-enrich). Null when the allowlist is empty: there is nothing to write.</summary>
    public static string? RenderAllowlist(IEnumerable<string> allowlist)
    {
        var targets = allowlist.Select(e => IpTarget.TryParse(e, out var t) ? t : null).OfType<IpTarget>().Distinct().ToList();
        if (targets.Count == 0) return null;
        var sb = new StringBuilder();
        sb.Append("name: alastor/allowlist\n");
        sb.Append("description: \"Addresses from the Alastor banning.allowlist; never banned\"\n");
        sb.Append("whitelist:\n");
        sb.Append("  reason: \"Alastor allowlist\"\n");
        var ips = targets.Where(t => t.IsSingleAddress).ToList();
        var cidrs = targets.Where(t => !t.IsSingleAddress).ToList();
        if (ips.Count > 0)
        {
            sb.Append("  ip:\n");
            foreach (var t in ips) sb.Append("    - \"").Append(t).Append("\"\n");
        }
        if (cidrs.Count > 0)
        {
            sb.Append("  cidr:\n");
            foreach (var t in cidrs) sb.Append("    - \"").Append(t).Append("\"\n");
        }
        return sb.ToString();
    }

    public static string RenderDropIn(string crowdsecPath, string configFile) =>
        "# Keeps CrowdSec off its Central API (banning.crowdsecCentralApi: false): no signal sharing, no community blocklist.\n" +
        "[Service]\n" +
        "ExecStartPre=\n" +
        $"ExecStartPre={crowdsecPath} -c {configFile} -t\n" +
        "ExecStart=\n" +
        $"ExecStart={crowdsecPath} -c {configFile} -no-capi\n";

    // ---- helpers ----

    private static readonly UnixFileMode Mode644 =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    private static readonly UnixFileMode Mode600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private static string Normalize(string? s) => (s ?? "").ReplaceLineEndings("\n").Trim();

    private static string LastLines(string output) =>
        string.Join("; ", output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).TakeLast(3));

    private ToolStatus Status(Availability availability, string? reason) => new()
    {
        ToolId = Info.Id,
        Availability = availability,
        UnavailableReason = reason,
        Ownership = Ownership.NotInstalled,
    };

    private SecurityEvent LifecycleEvent(string kind, Severity severity, string message, string revision) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow().UtcDateTime,
        Capability = Capability.Banning,
        Severity = severity,
        SourceTool = Info.Id,
        Kind = kind,
        Message = message,
        Metadata = new Dictionary<string, string> { ["revision"] = revision },
        DedupKey = $"{Info.Id}:{kind}:{SecurityEvent.StableId(message):N}",
    };
}
