using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Sentinel.Core.Contracts;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Core.Net;
using Sentinel.Core.Platform;
using Sentinel.Core.Policy;

namespace Sentinel.Agent;

/// <summary>
/// The agent's main loop. Every heartbeat interval, or right away when the server sends a SignalR "wake":
///   1. heartbeat: metrics + per-tool status. The response says which policy revision is desired and whether commands are waiting.
///   2. reconcile: when the revision changed (or every 5 min, to catch drift), plan + apply each integration.
///   3. commands: ban / unban / reconcile / reclaim / refresh-bans.
/// A second, faster loop drains tool events every 5 s and pushes ban-list snapshots when they change.
/// All IO is async. A failing tool is reported, never fatal to the loop.
/// </summary>
public sealed class Supervisor(
    ServerClient server,
    IEnumerable<IToolIntegration> integrations,
    HostMetricsCollector metrics,
    IStateStore state,
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

    /// <summary>Called by the SignalR listener. Wakes the main loop without waiting for the next interval.</summary>
    public void Wake(string reason) => _wake.Writer.TryWrite(reason);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _lastServerContact = time.GetUtcNow().UtcDateTime;
        var pump = Task.Run(() => EventPumpAsync(ct), ct);
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
                    if (!plan.IsNoop) logger.LogInformation("{Tool}: applied revision {Revision} ({Changes})", id, desired.Revision, string.Join(", ", plan.Changes.Select(c => c.Description)));
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogError(ex, "Reconciling {Tool} failed", id);
                    reports.Add(new ToolApplyReport(id, false, ConfigState.Unknown, ex.Message, [], []));
                }
            }

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
            await server.ReportCommandAsync(cmd.Id, new AgentCommandResult(outcome.Success, outcome.Message), ct);
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
            default:
                return new(false, $"Unknown command '{cmd.Type}' (agent {AgentInfo.Version})");
        }
    }

    private IBanProvider? ActiveBanProvider() =>
        _tools.Where(t => _policy is not null && t.IsWanted(_policy)).OfType<IBanProvider>().FirstOrDefault();

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

    private Task CheckServerLossAsync(CancellationToken ct)
    {
        var grace = Timings.OfflineGracePeriod;
        var since = time.GetUtcNow().UtcDateTime - _lastServerContact;
        if (since > grace)
        {
            // Server-pushed firewall state (blocklist ipsets, deliverable 5) is released here. fail2ban keeps
            // protecting the host locally: its config is self-contained and needs no server.
            logger.LogWarning("No server contact for {Since}, beyond the {Grace} grace period. Server-pushed firewall state would be released now.", since, grace);
        }
        return Task.CompletedTask;
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
