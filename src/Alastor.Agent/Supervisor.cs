using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using System.Net;
using Alastor.Core.Access;
using Alastor.Core.Baseline;
using Alastor.Core.Blocklists;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Net;
using Alastor.Core.Platform;
using Alastor.Core.Policy;
using Alastor.Core.Software;
using Alastor.Core.Storage;
using System.Text.Json;

namespace Alastor.Agent;

/// <summary>
/// The agent's main loop. Every heartbeat interval, or right away when the server sends a SignalR "wake":
///   1. heartbeat: metrics + per-tool status. The response says which policy revision is desired and whether commands are waiting.
///   2. reconcile: when the revision changed (or every 5 min, to catch drift), plan + apply each integration.
///   3. commands: ban / unban / reconcile / reclaim / refresh-bans / jobs / packages / reboot.
/// A second, faster loop drains tool events every 5 s and pushes ban-list snapshots when they change.
/// All IO is async. A failing tool is reported, never fatal to the loop.
/// </summary>
public sealed class Supervisor(
    ServerClient server,
    IEnumerable<IToolIntegration> integrations,
    HostMetricsCollector metrics,
    IStateStore state,
    ICommandRunner runner,
    OsInfo os,
    AgentConfig config,
    TimeProvider time,
    ILogger<Supervisor> logger) : BackgroundService
{
    private const int MaxSpooledEvents = 20_000;

    private readonly IReadOnlyList<IToolIntegration> _tools = integrations.ToList();
    private readonly Channel<string> _wake = Channel.CreateBounded<string>(new BoundedChannelOptions(16) { FullMode = BoundedChannelFullMode.DropOldest });
    private readonly ConcurrentQueue<SecurityEvent> _outbox = new();
    private readonly SemaphoreSlim _reconcileLock = new(1, 1);
    private readonly Dictionary<string, ToolStatus> _lastStatus = [];
    private readonly Dictionary<string, HashSet<string>> _lastWarnings = [];
    private readonly Dictionary<string, (string Hash, DateTime At)> _lastBanSnapshot = [];
    private PolicyDocument? _policy;

    /// <summary>Loop timings from the effective policy (agent.*); defaults until the first desired state arrives.</summary>
    private AgentTimings Timings => AgentTimings.From(_policy, TimeSpan.FromSeconds(config.HeartbeatIntervalSeconds));
    private PolicyApplyReport? _lastReport;
    private DateTime _lastReconcile = DateTime.MinValue;
    private DateTime _lastServerContact;
    private DateTime? _lastBaselineRun;
    private bool _baselineDirty = true;
    private BaselineReport? _pendingBaseline;
    private DateTime? _lastBlocklistFetch;
    private readonly Channel<string> _jobRequests = Channel.CreateBounded<string>(new BoundedChannelOptions(16) { FullMode = BoundedChannelFullMode.DropOldest });
    private readonly ConcurrentQueue<AgentReport> _pendingReports = new();
    private readonly ConcurrentDictionary<string, bool> _runningJobs = new();

    private const string StateRebootCommand = "agent.rebootCommand";
    private const string StateRebootPending = "agent.rebootPending";

    /// <summary>Set on the first start after a dashboard reboot: the update check runs again so "reboot required" clears.</summary>
    private bool _recheckAfterReboot;

    /// <summary>Called by the SignalR listener. Wakes the main loop without waiting for the next interval.</summary>
    public void Wake(string reason) => _wake.Writer.TryWrite(reason);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _lastServerContact = time.GetUtcNow().UtcDateTime;
        if (state.Get(StateRebootPending) is not null)
        {
            _recheckAfterReboot = true;
            await state.SetAsync(StateRebootPending, null, ct);
        }
        var pump = Task.Run(() => EventPumpAsync(ct), ct);
        var jobs = Task.Run(() => JobLoopAsync(ct), ct);
        string? forced = "startup";
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await TickAsync(forced, ct);
            }
            catch (HttpRequestException ex)
            {
                logger.LogWarning("Server unreachable: {Message}", ex.Message);
                await CheckServerLossAsync(ct);
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested)
            {
                logger.LogWarning("Server request timed out");
                await CheckServerLossAsync(ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Supervisor tick failed");
            }
            forced = await WaitForWakeAsync(Timings.HeartbeatInterval, ct);
        }
        await pump;
        await jobs;
    }

    private async Task<string?> WaitForWakeAsync(TimeSpan interval, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(interval);
        try
        {
            var reason = await _wake.Reader.ReadAsync(timeout.Token);
            // Coalesce a burst of wakes, e.g. ten ban commands queued at once.
            await Task.Delay(TimeSpan.FromMilliseconds(250), ct);
            while (_wake.Reader.TryRead(out var more)) reason = more == "command" || reason == "command" ? "command" : more;
            return reason;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
    }

    private async Task TickAsync(string? wakeReason, CancellationToken ct)
    {
        var statuses = await DetectAllAsync(ct);
        var hb = await server.HeartbeatAsync(new HeartbeatRequest(
            AgentInfo.Version,
            Environment.MachineName,
            os.PrettyName,
            await HostMetricsCollector.KernelVersionAsync(ct),
            await metrics.CollectAsync(ct),
            statuses,
            _lastReport,
            HostMetricsCollector.IpAddresses()), ct);
        _lastServerContact = time.GetUtcNow().UtcDateTime;
        if (hb.HeartbeatIntervalSeconds is >= 10 and <= 3600) config.HeartbeatIntervalSeconds = hb.HeartbeatIntervalSeconds;

        var now = time.GetUtcNow().UtcDateTime;
        var revisionChanged = _lastReport?.Revision != hb.DesiredRevision;
        if (revisionChanged || wakeReason == "policy" || now - _lastReconcile > Timings.DriftCheckInterval)
            await ReconcileAsync(reclaim: false, ct);

        if (hb.PendingCommands > 0 || wakeReason == "command")
            await ProcessCommandsAsync(ct);

        // A newer blocklist on the server (lists refreshed) is applied like a policy change, just for that tool.
        if (_policy is not null && await RefreshBlocklistAsync(_policy, force: false, ct))
            await ReconcileAsync(reclaim: false, ct);

        await RunBaselineIfDueAsync(force: false, ct);
    }

    /// <summary>
    /// Runs the baseline checks on startup, after every policy change (apply/ignore changes the results), and on
    /// baseline.checkSchedule. A report that couldn't be delivered is retried on the next tick.
    /// </summary>
    private async Task RunBaselineIfDueAsync(bool force, CancellationToken ct)
    {
        if (_policy is null) return;
        var provider = _tools.OfType<IBaselineProvider>().FirstOrDefault();
        if (provider is null) return;
        var now = time.GetUtcNow().UtcDateTime;
        var schedule = ScheduleDefaults.For(_policy, "baseline.checkSchedule");
        // A disabled schedule ("off") is never due by itself, but startup, policy changes and "Re-check now" still run.
        var due = force || _baselineDirty || _lastBaselineRun is null ||
                  schedule.IsDue(_lastBaselineRun, _lastBaselineRun.Value, now, TimeZoneInfo.Local, Schedule.HostSpread(Environment.MachineName, Timings.ScheduleSpread));
        if (due)
        {
            try
            {
                _pendingBaseline = await provider.RunChecksAsync(_policy, _lastReport?.Revision, ct);
                _lastBaselineRun = now;
                _baselineDirty = false;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Baseline checks failed");
                _lastBaselineRun = now;
            }
        }
        if (_pendingBaseline is { } report)
        {
            await server.SendBaselineAsync(report, ct);
            _pendingBaseline = null;
        }
    }

    /// <summary>
    /// Asks the server for this host's merged blocklist when the policy enables blocklists and blocklists.refreshSchedule
    /// is due (or <paramref name="force"/>). Conditional on the ETag, so an unchanged list costs one 304. Returns true when a new set arrived.
    /// </summary>
    private async Task<bool> RefreshBlocklistAsync(PolicyDocument policy, bool force, CancellationToken ct)
    {
        var consumer = _tools.OfType<IBlocklistConsumer>().FirstOrDefault();
        if (consumer is null || policy.Blocklists?.Enabled != true) return false;
        var now = time.GetUtcNow().UtcDateTime;
        var schedule = ScheduleDefaults.For(policy, "blocklists.refreshSchedule");
        if (!force && _lastBlocklistFetch is { } last && !schedule.IsDue(last, last, now, TimeZoneInfo.Local, TimeSpan.Zero)) return false;
        var payload = await server.GetBlocklistAsync(consumer.DesiredEtag, ct);
        _lastBlocklistFetch = now;
        if (payload is null) return false;
        consumer.SetDesired(payload, await ServerAddressesAsync(ct));
        logger.LogInformation("Blocklist {Etag}: {V4} IPv4 and {V6} IPv6 networks", payload.Etag, payload.V4.Count, payload.V6.Count);
        return true;
    }

    /// <summary>The server's own addresses. The blocklist never blocks them, whatever a list says.</summary>
    private async Task<IReadOnlyList<IPAddress>> ServerAddressesAsync(CancellationToken ct)
    {
        var host = new Uri(config.ServerUrl).Host;
        if (IPAddress.TryParse(host.Trim('[', ']'), out var literal)) return [literal];
        try
        {
            return await Dns.GetHostAddressesAsync(host, ct);
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            logger.LogWarning("Resolving {Host} failed ({Message}); the blocklist is loaded without a server exception", host, ex.Message);
            return [];
        }
    }

    private async Task<List<ToolStatus>> DetectAllAsync(CancellationToken ct)
    {
        var result = new List<ToolStatus>();
        foreach (var tool in _tools)
        {
            ToolStatus status;
            try
            {
                status = await tool.DetectAsync(ct);
                if (_policy is not null && !tool.IsWanted(_policy))
                    status = status with { Availability = status.Installed ? status.Availability : Availability.Disabled, UnavailableReason = status.Installed ? status.UnavailableReason : "Disabled by policy" };
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Detecting {Tool} failed", tool.Descriptor.Id);
                status = new ToolStatus { ToolId = tool.Descriptor.Id, LastError = ex.Message };
            }
            if (_lastWarnings.TryGetValue(tool.Descriptor.Id, out var w) && w.Count > 0) status = status with { Warnings = w.ToList() };
            TrackTransitions(tool, status);
            result.Add(status);
        }
        return result;
    }

    /// <summary>Generic tool-health events derived from status changes, identical for every integration.</summary>
    private void TrackTransitions(IToolIntegration tool, ToolStatus status)
    {
        var id = tool.Descriptor.Id;
        _lastStatus.TryGetValue(id, out var prev);
        _lastStatus[id] = status;
        var wanted = _policy is not null && tool.IsWanted(_policy);
        if (prev is { Running: true } && status is { Installed: true, Running: false } && wanted)
            Enqueue(Lifecycle(tool, EventKinds.ToolDown, Severity.High, $"{tool.Descriptor.DisplayName} stopped running", status.LastError));
        if (status.Availability == Availability.Unavailable && wanted && prev?.UnavailableReason != status.UnavailableReason)
            Enqueue(Lifecycle(tool, EventKinds.ToolUnavailable, Severity.Medium, $"{tool.Descriptor.DisplayName} unavailable: {status.UnavailableReason}", null));
    }

    private async Task ReconcileAsync(bool reclaim, CancellationToken ct)
    {
        await _reconcileLock.WaitAsync(ct);
        try
        {
            var desired = await server.GetDesiredStateAsync(ct);
            _policy = desired.Policy;
            var request = new ReconcileRequest(desired.Policy, desired.Revision) { Reclaim = reclaim };
            try
            {
                await RefreshBlocklistAsync(desired.Policy, force: _lastReport?.Revision != desired.Revision || _lastBlocklistFetch is null, ct);
            }
            catch (HttpRequestException ex)
            {
                logger.LogWarning("Fetching the blocklist failed, keeping the current one: {Message}", ex.Message);
            }
            var reports = new List<ToolApplyReport>();

            foreach (var tool in _tools)
            {
                var id = tool.Descriptor.Id;
                try
                {
                    var wanted = tool.IsWanted(desired.Policy);
                    var status = wanted ? await tool.EnsureInstalledAsync(request, ct) : await tool.DetectAsync(ct);
                    if (wanted && _lastStatus.GetValueOrDefault(id) is { Installed: false } && status.Installed)
                        Enqueue(Lifecycle(tool, status.Ownership == Ownership.Managed ? EventKinds.ToolInstalled : EventKinds.ToolAdopted, Severity.Info,
                            $"{tool.Descriptor.DisplayName} {status.Version} {(status.Ownership == Ownership.Managed ? "installed from distro repositories" : "adopted")}", null));
                    if (!status.Installed)
                    {
                        reports.Add(new ToolApplyReport(id, !wanted, wanted ? ConfigState.Unknown : ConfigState.InSync,
                            wanted ? status.UnavailableReason : null, [], []));
                        continue;
                    }

                    var plan = await tool.PlanAsync(request, ct);
                    var result = await tool.ApplyAsync(plan, ct);
                    var warnings = plan.Warnings.Select(w => w.Message).ToHashSet();
                    var previous = _lastWarnings.GetValueOrDefault(id) ?? [];
                    // Raise warning events only when the warning set changes, not on every drift check.
                    foreach (var e in result.Events)
                        if (!(warnings.Contains(e.Message) && previous.Contains(e.Message))) Enqueue(e);
                    _lastWarnings[id] = warnings;
                    reports.Add(new ToolApplyReport(id, result.Success, result.State, result.Error, warnings.ToList(),
                        plan.Changes.Select(c => c.Description).ToList()));
                    if (!plan.IsNoop && result.Success) logger.LogInformation("{Tool}: applied revision {Revision} ({Changes})", id, desired.Revision, string.Join(", ", plan.Changes.Select(c => c.Description)));
                    else if (!plan.IsNoop) logger.LogWarning("{Tool}: revision {Revision} not applied: {Error}", id, desired.Revision, result.Error);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogError(ex, "Reconciling {Tool} failed", id);
                    reports.Add(new ToolApplyReport(id, false, ConfigState.Unknown, ex.Message, [], []));
                }
            }

            if (_lastReport?.Revision != desired.Revision || reclaim || reports.Any(r => r.Changes.Count > 0)) _baselineDirty = true;
            _lastReport = new PolicyApplyReport(desired.Revision, reports.All(r => r.Success), time.GetUtcNow().UtcDateTime, reports);
            _lastReconcile = time.GetUtcNow().UtcDateTime;
            // Report the outcome (and fresh tool states) right away instead of waiting a full heartbeat interval.
            Wake("report");
            await state.SetAsync("agent.appliedRevision", desired.Revision, ct);
        }
        finally
        {
            _reconcileLock.Release();
        }
    }

    private async Task ProcessCommandsAsync(CancellationToken ct)
    {
        var commands = await server.GetCommandsAsync(ct);
        var bansTouched = false;
        foreach (var cmd in commands)
        {
            CommandOutcome outcome;
            try
            {
                outcome = await ExecuteAsync(cmd, ct);
                bansTouched |= cmd.Type is AgentCommandTypes.Ban or AgentCommandTypes.Unban or AgentCommandTypes.RefreshBans;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Command {Type} {Id} failed", cmd.Type, cmd.Id);
                outcome = new CommandOutcome(false, ex.Message);
            }
            logger.LogInformation("Command {Type} {Payload}: {Result}", cmd.Type, string.Join(",", cmd.Payload.Values), outcome.Message);
            await server.ReportCommandAsync(cmd.Id, new AgentCommandResult(outcome.Success, outcome.Message) { Detail = outcome.Detail }, ct);
        }
        if (bansTouched) await PushBanSnapshotsAsync(force: true, ct);
    }

    private async Task<CommandOutcome> ExecuteAsync(AgentCommand cmd, CancellationToken ct)
    {
        switch (cmd.Type)
        {
            case AgentCommandTypes.Ban or AgentCommandTypes.Unban:
                if (!IpTarget.TryParse(cmd.Payload.GetValueOrDefault("target"), out var target))
                    return new(false, "Invalid target");
                var provider = ActiveBanProvider();
                if (provider is null) return new(false, "No banning engine is active on this host (check the banning policy and tool status).");
                return cmd.Type == AgentCommandTypes.Ban
                    ? await provider.BanAsync(target.Value, cmd.Payload.GetValueOrDefault("reason"), ct)
                    : await provider.UnbanAsync(target.Value, ct);
            case AgentCommandTypes.Reconcile:
                await ReconcileAsync(reclaim: false, ct);
                return new(_lastReport?.Success ?? false, $"Reconciled revision {_lastReport?.Revision}");
            case AgentCommandTypes.Reclaim:
                await ReconcileAsync(reclaim: true, ct);
                return new(_lastReport?.Success ?? false, $"Reclaimed managed files at revision {_lastReport?.Revision}");
            case AgentCommandTypes.RefreshBans:
                return new(true, "Ban list refreshed");
            case AgentCommandTypes.RunJob:
                var jobId = cmd.Payload.GetValueOrDefault("job") ?? "";
                var job = AllJobs().FirstOrDefault(j => j.Id == jobId);
                if (job is null) return new(false, $"Unknown job '{jobId}' (agent {AgentInfo.Version})");
                if (_runningJobs.ContainsKey(jobId)) return new(true, $"{job.DisplayName} is already running");
                _jobRequests.Writer.TryWrite(jobId);
                return new(true, $"{job.DisplayName} started; the result follows as a report");
            case AgentCommandTypes.BaselineCheck:
                await RunBaselineIfDueAsync(force: true, ct);
                return new(true, "Baseline checks ran");
            case AgentCommandTypes.PackagePlan or AgentCommandTypes.PackageAction:
                return await PackageCommandAsync(cmd, ct);
            case AgentCommandTypes.StorageCleanup:
                return StorageCleanup(cmd, ct);
            case AgentCommandTypes.SshKey:
                return await SshKeyAsync(cmd, ct);
            case AgentCommandTypes.Reboot:
                return await RebootAsync(cmd, ct);
            default:
                return new(false, $"Unknown command '{cmd.Type}' (agent {AgentInfo.Version})");
        }
    }

    /// <summary>
    /// A dry run answers inline (it takes seconds). An upgrade or uninstall can take minutes, so like a job it runs off the
    /// heartbeat loop and its outcome follows as a software report; afterwards the update check and CVE scan run again.
    /// </summary>
    private async Task<CommandOutcome> PackageCommandAsync(AgentCommand cmd, CancellationToken ct)
    {
        var software = _tools.OfType<SoftwareIntegration>().FirstOrDefault();
        if (software is null) return new(false, $"This agent has no software inventory (agent {AgentInfo.Version})");
        var op = cmd.Payload.GetValueOrDefault("op") ?? "";
        var package = cmd.Payload.GetValueOrDefault("package") ?? "";
        if (!PackageOps.IsValid(op) || !PackageOps.IsValidName(package)) return new(false, "Invalid operation or package name");
        if (cmd.Type == AgentCommandTypes.PackagePlan)
        {
            var plan = await software.PreviewAsync(op, package, ct);
            var message = !plan.Success ? plan.Error ?? "Dry run failed"
                : plan.Blocked.Count > 0 ? $"Blocked: would remove protected {string.Join(", ", plan.Blocked)}"
                : plan.Changes.Count == 0 ? "Nothing to do"
                : $"Would change {plan.Changes.Count} package{(plan.Changes.Count == 1 ? "" : "s")}";
            return new(plan.Success, message) { Detail = JsonSerializer.Serialize(plan, AgentJsonContext.Default.PackagePlan) };
        }
        if (!_runningJobs.TryAdd(SoftwareIntegration.ActionJob, true)) return new(false, "Another package upgrade or uninstall is still running");
        _ = Task.Run(async () =>
        {
            try
            {
                AgentReport report;
                try { report = await software.RunActionAsync(op, package, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogError(ex, "Package {Op} {Package} failed", op, package);
                    var now = time.GetUtcNow().UtcDateTime;
                    report = new AgentReport(SoftwareIntegration.ActionJob, now, now, false, ex.Message);
                }
                _pendingReports.Enqueue(report);
                _jobRequests.Writer.TryWrite(""); // deliver now
                if (report.Success)
                    foreach (var job in AllJobs().Where(j => j.Id is Alastor.Core.Updates.UpdatesIntegration.CheckJob or Alastor.Core.Vulnerabilities.VulnerabilityIntegration.ScanJob))
                        _jobRequests.Writer.TryWrite(job.Id);
                Wake("report");
            }
            finally
            {
                _runningJobs.TryRemove(SoftwareIntegration.ActionJob, out _);
            }
        }, ct);
        return new(true, $"{(op == PackageOps.Upgrade ? "Upgrading" : "Uninstalling")} {package} started; the result follows as a report");
    }

    /// <summary>
    /// A cleanup can take minutes (docker image prune, apt autoremove), so like a package action it runs off the heartbeat
    /// loop and its outcome follows as a storage report; afterwards a fresh scan shows where the space went.
    /// </summary>
    private CommandOutcome StorageCleanup(AgentCommand cmd, CancellationToken ct)
    {
        var storage = _tools.OfType<StorageIntegration>().FirstOrDefault();
        if (storage is null) return new(false, $"This agent has no storage cleanup (agent {AgentInfo.Version})");
        var id = cmd.Payload.GetValueOrDefault("cleanup") ?? "";
        if (StorageCleanups.Find(id) is not { } cleanup) return new(false, $"Unknown cleanup '{id}' (agent {AgentInfo.Version})");
        if (!_runningJobs.TryAdd(StorageIntegration.CleanupJob, true)) return new(false, "Another cleanup is still running");
        _ = Task.Run(async () =>
        {
            try
            {
                AgentReport report;
                try { report = await storage.RunCleanupAsync(id, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogError(ex, "Storage cleanup {Cleanup} failed", id);
                    var now = time.GetUtcNow().UtcDateTime;
                    report = new AgentReport(StorageIntegration.CleanupJob, now, now, false, ex.Message);
                }
                _pendingReports.Enqueue(report);
                _jobRequests.Writer.TryWrite(""); // deliver now
                if (report.Success) _jobRequests.Writer.TryWrite(StorageIntegration.ScanJob);
                Wake("report");
            }
            finally
            {
                _runningJobs.TryRemove(StorageIntegration.CleanupJob, out _);
            }
        }, ct);
        return new(true, $"{cleanup.Title}: cleanup started; the result follows as a report");
    }

    /// <summary>A key change takes a second, so it answers inline; a fresh key scan follows as a report so the dashboard shows the result.</summary>
    private async Task<CommandOutcome> SshKeyAsync(AgentCommand cmd, CancellationToken ct)
    {
        var keys = _tools.OfType<SshKeysIntegration>().FirstOrDefault();
        if (keys is null) return new(false, $"This agent can't manage SSH keys (agent {AgentInfo.Version})");
        var user = cmd.Payload.GetValueOrDefault("user") ?? "";
        var result = cmd.Payload.GetValueOrDefault("op") switch
        {
            "add" => await keys.AddAsync(user, cmd.Payload.GetValueOrDefault("key") ?? "", ct),
            "remove" => await keys.RemoveAsync(user, cmd.Payload.GetValueOrDefault("fingerprint") ?? "", ct),
            _ => new SshKeysIntegration.KeyChangeResult(false, false, "Invalid operation"),
        };
        _jobRequests.Writer.TryWrite(SshKeysIntegration.ScanJob);
        return new(result.Success, result.Message);
    }

    /// <summary>
    /// Schedules the reboot a minute out instead of rebooting now: the acknowledgement reaches the server first, logged-in
    /// users get a warning, and it can be cancelled on the host with <c>shutdown -c</c>. A redelivered copy of the same
    /// command (the acknowledgement got lost) does not reboot again.
    /// </summary>
    private async Task<CommandOutcome> RebootAsync(AgentCommand cmd, CancellationToken ct)
    {
        var id = cmd.Id.ToString();
        if (state.Get(StateRebootCommand) == id) return new(true, "Reboot already ran for this command");
        if (runner.Which("shutdown") is null) return new(false, "shutdown is not available on this host (container or minimal image?)");
        await state.SetAsync(StateRebootCommand, id, ct);
        await state.SetAsync(StateRebootPending, "true", ct);
        var r = await runner.RunAsync("shutdown", ["-r", "+1", "Alastor: reboot requested from the dashboard"], null, ct);
        if (!r.Success)
        {
            await state.SetAsync(StateRebootPending, null, ct);
            return new(false, $"shutdown failed: {r.CombinedOutput}");
        }
        return new(true, "Reboot scheduled in 1 minute (cancel on the host with shutdown -c)");
    }

    private IBanProvider? ActiveBanProvider() =>
        _tools.Where(t => _policy is not null && t.IsWanted(_policy)).OfType<IBanProvider>().FirstOrDefault();

    // ---- scheduled jobs (update checks, scans, audits) ----

    private IEnumerable<ScheduledJob> AllJobs() => _tools.OfType<IScheduledJobProvider>().SelectMany(p => p.Jobs);

    /// <summary>
    /// Runs scheduled jobs off the heartbeat loop: each on its policy schedule (per-host spread), once on first start
    /// if it asks for that, and right away when the dashboard asks. Reports that can't be delivered are retried.
    /// </summary>
    private async Task JobLoopAsync(CancellationToken ct)
    {
        var started = time.GetUtcNow().UtcDateTime;
        while (!ct.IsCancellationRequested)
        {
            string? forced = null;
            using (var wait = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                wait.CancelAfter(TimeSpan.FromSeconds(30));
                try { forced = await _jobRequests.Reader.ReadAsync(wait.Token); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            }
            try
            {
                if (_policy is { } policy)
                {
                    var now = time.GetUtcNow().UtcDateTime;
                    var spread = Schedule.HostSpread(Environment.MachineName, Timings.ScheduleSpread);
                    foreach (var job in AllJobs())
                    {
                        var lastRun = DateTime.TryParse(state.Get($"job.{job.Id}.lastRunUtc"), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var l) ? l : (DateTime?)null;
                        var schedule = job.ScheduleKey.Length == 0 ? Schedule.Parse("off") : ScheduleDefaults.For(policy, job.ScheduleKey);
                        var due = forced == job.Id
                                  || (_recheckAfterReboot && job.Id == Alastor.Core.Updates.UpdatesIntegration.CheckJob)
                                  || (lastRun is null && job.RunOnFirstStart && !schedule.IsDisabled)
                                  || schedule.IsDue(lastRun, lastRun ?? started, now, TimeZoneInfo.Local, spread);
                        if (!due || !_runningJobs.TryAdd(job.Id, true)) continue;
                        if (job.Id == Alastor.Core.Updates.UpdatesIntegration.CheckJob) _recheckAfterReboot = false;
                        // Each job runs on its own: a CVE scan waiting for the server's database mirror must not hold up an update check.
                        var isForced = forced == job.Id;
                        _ = Task.Run(() => RunJobAsync(job, policy, isForced, ct), ct);
                    }
                }
                while (_pendingReports.TryPeek(out var report))
                {
                    await server.SendReportAsync(report, ct);
                    _pendingReports.TryDequeue(out _);
                }
            }
            catch (HttpRequestException ex)
            {
                logger.LogDebug("Report delivery deferred: {Message}", ex.Message);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Job loop failed");
            }
        }
    }

    /// <summary>Runs one job the caller has already claimed in <see cref="_runningJobs"/>.</summary>
    private async Task RunJobAsync(ScheduledJob job, PolicyDocument policy, bool forced, CancellationToken ct)
    {
        try
        {
            logger.LogInformation("Running {Job}{Forced}", job.Id, forced ? " (requested from the dashboard)" : "");
            AgentReport report;
            try
            {
                report = await job.RunAsync(policy, forced, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Job {Job} failed", job.Id);
                var now = time.GetUtcNow().UtcDateTime;
                report = new AgentReport(job.Id, now, now, false, ex.Message);
            }
            // Recorded even on failure, so a broken scanner isn't retried every 30 seconds; the error is in the report.
            await state.SetAsync($"job.{job.Id}.lastRunUtc", time.GetUtcNow().UtcDateTime.ToString("O"), ct);
            _pendingReports.Enqueue(report);
            while (_pendingReports.Count > 20 && _pendingReports.TryDequeue(out _)) { }
            _jobRequests.Writer.TryWrite(""); // deliver the report now instead of at the next 30 s tick
            Wake("report"); // fresh tool details (pending counts) with the next heartbeat
        }
        finally
        {
            _runningJobs.TryRemove(job.Id, out _);
        }
    }

    // ---- fast loop: events + ban snapshots ----

    private async Task EventPumpAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            // Re-read every round, so a policy change to agent.eventFlushInterval takes effect without a restart.
            await Task.Delay(Timings.EventFlushInterval, time, ct);
            try
            {
                foreach (var tool in _tools)
                {
                    if (_lastStatus.GetValueOrDefault(tool.Descriptor.Id) is not { Installed: true }) continue;
                    await foreach (var e in tool.CollectEventsAsync(ct)) Enqueue(e);
                }
                await FlushOutboxAsync(ct);
                await PushBanSnapshotsAsync(force: false, ct);
            }
            catch (HttpRequestException ex)
            {
                logger.LogDebug("Event push deferred: {Message}", ex.Message);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Event pump failed");
            }
        }
    }

    private void Enqueue(SecurityEvent e)
    {
        _outbox.Enqueue(e);
        // The outbox is bounded so a long outage cannot exhaust memory: the oldest events are dropped first.
        while (_outbox.Count > MaxSpooledEvents && _outbox.TryDequeue(out _)) { }
    }

    private async Task FlushOutboxAsync(CancellationToken ct)
    {
        while (!_outbox.IsEmpty)
        {
            var batch = new List<SecurityEvent>(500);
            while (batch.Count < 500 && _outbox.TryPeek(out var e))
            {
                batch.Add(e);
                _outbox.TryDequeue(out _);
            }
            try
            {
                await server.SendEventsAsync(new EventBatch(batch), ct);
            }
            catch
            {
                // Put the batch back. Event ids are stable, so re-sending is idempotent on the server.
                var rest = _outbox.ToArray();
                _outbox.Clear();
                foreach (var e in batch.Concat(rest)) _outbox.Enqueue(e);
                throw;
            }
        }
    }

    private async Task PushBanSnapshotsAsync(bool force, CancellationToken ct)
    {
        foreach (var tool in _tools)
        {
            if (tool is not IBanProvider bans || _lastStatus.GetValueOrDefault(tool.Descriptor.Id) is not { Running: true }) continue;
            var list = await bans.ListBansAsync(ct);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                string.Join('\n', list.Select(b => $"{b.Scope}|{b.Target}|{b.ExpiresAt:O}").Order()))));
            var now = time.GetUtcNow().UtcDateTime;
            if (!force && _lastBanSnapshot.TryGetValue(tool.Descriptor.Id, out var last) && last.Hash == hash && now - last.At < Timings.BanSnapshotInterval) continue;
            await server.SendBanSnapshotAsync(new BanSnapshot(tool.Descriptor.Id, list), ct);
            _lastBanSnapshot[tool.Descriptor.Id] = (hash, now);
        }
    }

    private async Task CheckServerLossAsync(CancellationToken ct)
    {
        var grace = Timings.OfflineGracePeriod;
        var since = time.GetUtcNow().UtcDateTime - _lastServerContact;
        if (since <= grace) return;
        // Server-pushed firewall state (the blocklist) is released: a stale list nobody can update shouldn't keep
        // dropping traffic forever. fail2ban keeps protecting the host locally: its config needs no server.
        foreach (var consumer in _tools.OfType<IBlocklistConsumer>())
        {
            try
            {
                if (!await consumer.ReleaseAfterServerLossAsync(since, ct)) continue;
                logger.LogWarning("No server contact for {Since}, beyond the {Grace} grace period: blocklist released", since, grace);
                // Reconcile right after the server is back, instead of waiting for the next drift check.
                _lastReconcile = DateTime.MinValue;
                _lastBlocklistFetch = null;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Releasing the blocklist failed");
            }
        }
    }

    private SecurityEvent Lifecycle(IToolIntegration tool, string kind, Severity severity, string message, string? raw) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow().UtcDateTime,
        Capability = tool.Descriptor.Capability,
        Severity = severity,
        SourceTool = tool.Descriptor.Id,
        Kind = kind,
        Message = message,
        Raw = raw,
        DedupKey = $"{tool.Descriptor.Id}:{kind}",
    };
}
