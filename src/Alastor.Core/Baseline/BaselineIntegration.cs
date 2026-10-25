using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Core.Baseline;

/// <summary>Optional capability: integrations that produce a security baseline report.</summary>
public interface IBaselineProvider
{
    Task<BaselineReport> RunChecksAsync(PolicyDocument policy, string? revision, CancellationToken ct);
}

public sealed record BaselineOptions
{
    public string SshdDropIn { get; init; } = BaselineMitigations.SshdDropIn;
    public string SysctlDropIn { get; init; } = BaselineMitigations.SysctlDropIn;
}

/// <summary>
/// The security baseline. Unlike other integrations it bundles no third-party tool: it reads the system's own
/// tools (see <see cref="BaselineProbe"/>) and, for checks the policy sets to <c>apply</c>, owns two drop-ins:
/// <list type="bullet">
/// <item><c>/etc/ssh/sshd_config.d/01-alastor.conf</c>, validated with <c>sshd -t</c> before sshd reloads.</item>
/// <item><c>/etc/sysctl.d/99-zz-alastor.conf</c>, loaded with <c>sysctl -p</c>. The runtime values it replaced are
/// recorded, so removing a fix restores them instead of waiting for a reboot.</item>
/// </list>
/// SSH changes that could lock the operator out are refused (see <see cref="BaselineMitigations.CheckLockout"/>).
/// </summary>
public sealed class BaselineIntegration(
    ICommandRunner runner,
    IFileSystem fs,
    IServiceManager services,
    IStateStore state,
    OsInfo os,
    ILogger<BaselineIntegration> logger,
    TimeProvider time,
    BaselineOptions? options = null) : IToolIntegration, IBaselineProvider
{
    private const string StateConfigState = "baseline.configState";
    private const string StateAppliedRevision = "baseline.appliedRevision";
    private const string StateLastResults = "baseline.lastResults";
    private const string StateLastRun = "baseline.lastRunUtc";
    private const string StateLastScore = "baseline.lastScore";
    private const string StateSysctlPrevious = "baseline.sysctlPrevious";
    private const string StateSysctlRefused = "baseline.sysctlRefused";
    private static readonly UnixFileMode Mode644 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    private readonly BaselineOptions _opt = options ?? new BaselineOptions();
    private readonly BaselineProbe _probe = new(runner, fs, os);
    private readonly Queue<SecurityEvent> _events = new();

    public static readonly ToolDescriptor Info = new(
        "baseline",
        "Security baseline",
        Capability.Hardening,
        "MIT (part of Alastor)",
        "https://github.com/nor0x/Alastor",
        new Dictionary<DistroFamily, string>(),
        "The most common server hardening checks (SSH, firewall, updates, kernel, accounts), with fixes the agent can apply.");

    public ToolDescriptor Descriptor => Info;

    /// <summary>The checks always run; the drop-ins only exist while the policy applies a fix.</summary>
    public bool IsWanted(PolicyDocument policy) => true;

    public async Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        var inspections = new[] { await InspectAsync(_opt.SshdDropIn, ct), await InspectAsync(_opt.SysctlDropIn, ct) };
        var configState =
            inspections.Any(i => i.State == ManagedFileState.Drifted) ? ConfigState.Drifted :
            inspections.Any(i => i.State == ManagedFileState.Foreign) ? ConfigState.Conflict :
            Enum.TryParse<ConfigState>(state.Get(StateConfigState), out var last) ? last : ConfigState.InSync;
        var details = new Dictionary<string, string>();
        if (state.Get(StateLastScore) is { } score) details["score"] = score;
        if (LastResults() is { } results)
            details["failing"] = results.Count(r => r.Value == nameof(CheckStatus.Fail)).ToString(System.Globalization.CultureInfo.InvariantCulture);
        return new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Running = true,
            Version = "built-in",
            Ownership = Ownership.Managed,
            ConfigState = configState,
            AppliedRevision = state.Get(StateAppliedRevision),
            LastSuccessAt = DateTime.TryParse(state.Get(StateLastRun), null, System.Globalization.DateTimeStyles.RoundtripKind, out var t) ? t : null,
            Details = details,
        };
    }

    public Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct) => DetectAsync(ct);

    public async Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct)
    {
        var changes = new List<PlannedChange>();
        var warnings = new List<PlanWarning>();
        var resultState = ConfigState.InSync;
        var facts = await _probe.GatherAsync(ct);
        var requested = BaselineMitigations.WithValue(request.Policy, BaselineMitigationValues.Apply).ToList();

        var sshIds = new List<string>();
        foreach (var id in requested.Where(BaselineMitigations.SshSettings.ContainsKey))
        {
            if (facts.Sshd is null)
            {
                if (facts.SshdError is not null) warnings.Add(new(EventKinds.ConfigRejected, $"Baseline fix '{id}' skipped: sshd -T failed ({facts.SshdError})."));
                continue;
            }
            if (!facts.SshdIncludesDropIns)
            {
                warnings.Add(new(EventKinds.ConfigConflict, $"Baseline fix '{id}' skipped: {BaselineProbe.SshdConfig} doesn't include sshd_config.d/*.conf, so a drop-in would have no effect."));
                continue;
            }
            var lockout = BaselineMitigations.CheckLockout(id, facts);
            if (!lockout.Safe)
            {
                warnings.Add(new(EventKinds.ConfigRejected, $"Baseline fix '{id}' not applied: {lockout.Reason}"));
                continue;
            }
            sshIds.Add(id);
        }

        void PlanFile(string path, ManagedFileInspection inspect, string? body, string what, string reload)
        {
            if (body is null)
            {
                if (inspect.State == ManagedFileState.Owned || (inspect.State == ManagedFileState.Drifted && request.Reclaim))
                    changes.Add(new(ChangeKind.DeleteFile, path, $"Remove {what} (no fix applied any more)"));
                else if (inspect.State == ManagedFileState.Drifted)
                    warnings.Add(new(EventKinds.ConfigDrift, $"{path} was edited by hand and is no longer needed. Not deleting it; use \"Reclaim\" to remove it."));
                else return;
            }
            else
            {
                switch (inspect.State)
                {
                    case ManagedFileState.Missing:
                        changes.Add(new(ChangeKind.WriteFile, path, $"Create {what}", ManagedFile.Render(body, request.Revision)));
                        break;
                    case ManagedFileState.Owned when inspect.Body?.Trim() != body.Trim():
                        changes.Add(new(ChangeKind.WriteFile, path, $"Update {what}", ManagedFile.Render(body, request.Revision)));
                        break;
                    case ManagedFileState.Drifted when request.Reclaim:
                        changes.Add(new(ChangeKind.WriteFile, path, $"Reclaim hand-edited {what}", ManagedFile.Render(body, request.Revision)));
                        break;
                    case ManagedFileState.Drifted:
                        warnings.Add(new(EventKinds.ConfigDrift, $"{path} was edited by hand. Not overwriting it; use \"Reclaim\" in the dashboard to restore policy control."));
                        resultState = ConfigState.Drifted;
                        return;
                    case ManagedFileState.Foreign:
                        warnings.Add(new(EventKinds.ConfigConflict, $"{path} exists but was not written by Alastor. Not touching it."));
                        resultState = ConfigState.Conflict;
                        return;
                    default:
                        return;
                }
            }
            if (changes.Count > 0 && changes[^1].Target == path) changes.Add(new(ChangeKind.Reload, reload, $"Reload {reload}"));
        }

        PlanFile(_opt.SshdDropIn, await InspectAsync(_opt.SshdDropIn, ct), BaselineMitigations.RenderSshd(sshIds, facts.Sshd), "SSH hardening drop-in", "sshd");
        PlanFile(_opt.SysctlDropIn, await InspectAsync(_opt.SysctlDropIn, ct),
            BaselineMitigations.RenderSysctl(requested, facts.Sysctl), "kernel hardening drop-in", "sysctl");

        return new ReconcilePlan(Info.Id, request.Revision, changes, warnings, resultState);
    }

    public async Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct)
    {
        var events = plan.Warnings.Select(w => Event(w.Kind, Severity.Medium, w.Message, null)).ToList();
        if (plan.IsNoop)
        {
            await state.SetAsync(StateAppliedRevision, plan.Revision, ct);
            await state.SetAsync(StateConfigState, plan.ResultingState.ToString(), ct);
            return new ReconcileResult(true, plan.ResultingState, null, events);
        }

        var backups = new Dictionary<string, string?>();
        foreach (var c in plan.Changes.Where(c => c.Kind is ChangeKind.WriteFile or ChangeKind.DeleteFile))
            backups[c.Target] = await fs.ReadAllTextAsync(c.Target, ct);

        async Task RollbackAsync()
        {
            foreach (var (path, content) in backups)
            {
                if (content is null) fs.DeleteFile(path);
                else await fs.WriteAllTextAtomicAsync(path, content, Mode644, ct);
            }
        }

        async Task<ReconcileResult> FailAsync(string message)
        {
            await RollbackAsync();
            events.Add(Event(EventKinds.ConfigRejected, Severity.High, message, null));
            await state.SetAsync(StateConfigState, nameof(ConfigState.Rejected), ct);
            return new ReconcileResult(false, ConfigState.Rejected, message, events);
        }

        try
        {
            var sysctlChange = plan.Changes.FirstOrDefault(c => c.Target == _opt.SysctlDropIn && c.Kind is ChangeKind.WriteFile or ChangeKind.DeleteFile);
            var sysctlBefore = SysctlKeys(backups.GetValueOrDefault(_opt.SysctlDropIn));
            var sysctlAfter = sysctlChange?.Kind == ChangeKind.WriteFile ? SysctlKeys(sysctlChange.Content) : [];
            if (sysctlChange is not null) await RememberSysctlAsync(sysctlAfter.Except(sysctlBefore).ToList(), ct);

            foreach (var c in plan.Changes)
            {
                if (c.Kind == ChangeKind.WriteFile) await fs.WriteAllTextAtomicAsync(c.Target, c.Content!, Mode644, ct);
                else if (c.Kind == ChangeKind.DeleteFile) fs.DeleteFile(c.Target);
            }

            if (backups.ContainsKey(_opt.SshdDropIn))
            {
                var test = await runner.RunAsync("sshd", ["-t"], null, ct);
                if (!test.Success) return await FailAsync($"sshd rejected the SSH hardening drop-in and it was rolled back: {test.CombinedOutput.Trim()}");
            }

            foreach (var c in plan.Changes.Where(c => c.Kind == ChangeKind.Reload))
            {
                if (c.Target == "sshd") await ReloadSshdAsync(ct);
                else if (c.Target == "sysctl")
                {
                    if (sysctlChange?.Kind == ChangeKind.WriteFile)
                    {
                        var r = await runner.RunAsync("sysctl", ["-p", _opt.SysctlDropIn], null, ct);
                        if (!r.Success)
                        {
                            await RestoreSysctlAsync(sysctlAfter.Except(sysctlBefore).ToList(), ct);
                            return await FailAsync($"Loading the kernel hardening drop-in failed and it was rolled back: {r.CombinedOutput.Trim()}");
                        }
                        // `sysctl -p` exits 0 even when it skips a key ("ignoring: Read-only file system"), so read the values back.
                        var refused = await RefusedSysctlAsync(sysctlChange.Content!, ct);
                        await state.SetAsync(StateSysctlRefused, refused.Count > 0 ? string.Join(' ', refused) : null, ct);
                        if (refused.Count > 0)
                            events.Add(Event(EventKinds.ConfigRejected, Severity.Medium,
                                $"The kernel kept its own value for {refused.Count} baseline setting(s): {string.Join(", ", refused)}. {SysctlRefusedHint}", null));
                    }
                    else await state.SetAsync(StateSysctlRefused, null, ct);
                    await RestoreSysctlAsync(sysctlBefore.Except(sysctlAfter).ToList(), ct);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogError(ex, "Applying baseline fixes failed. Rolling back.");
            return await FailAsync($"Applying baseline fixes failed and was rolled back: {ex.Message}");
        }

        await state.SetAsync(StateAppliedRevision, plan.Revision, ct);
        await state.SetAsync(StateConfigState, plan.ResultingState.ToString(), ct);
        events.Add(Event(EventKinds.ConfigApplied, Severity.Info,
            $"Applied baseline fixes {plan.Revision}: {string.Join(", ", plan.Changes.Where(c => c.Kind != ChangeKind.Reload).Select(c => c.Description))}", null));
        return new ReconcileResult(true, plan.ResultingState, null, events);
    }

    public async Task<BaselineReport> RunChecksAsync(PolicyDocument policy, string? revision, CancellationToken ct)
    {
        var facts = await _probe.GatherAsync(ct);
        var results = BaselineEvaluator.Evaluate(facts, policy);
        if (state.Get(StateSysctlRefused) is { Length: > 0 } refusedKeys)
        {
            var refused = refusedKeys.Split(' ');
            results = results.Select(r => r.Enforced && r.Status == CheckStatus.Fail && BaselineMitigations.SysctlSettings.TryGetValue(r.CheckId, out var keys) && keys.Keys.Any(refused.Contains)
                ? r with { Detail = $"The agent applied the fix, but the kernel refused it. {SysctlRefusedHint}" }
                : r).ToList();
        }
        var now = time.GetUtcNow().UtcDateTime;
        var previous = LastResults();
        var score = BaselineScore.Compute(results);

        if (previous is null)
        {
            var failing = results.Where(r => r.Status == CheckStatus.Fail && !r.Accepted).ToList();
            var worst = failing.Select(r => BaselineCatalog.Find(r.CheckId)!.Severity).DefaultIfEmpty(Severity.Info).Max();
            Enqueue(Event(EventKinds.BaselineSummary, worst >= Severity.High ? Severity.Medium : Severity.Info,
                failing.Count == 0
                    ? $"Security baseline: all applicable checks pass (score {score?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "n/a"})"
                    : $"Security baseline: {failing.Count} of {results.Count(r => r.Status is CheckStatus.Pass or CheckStatus.Fail)} checks fail (score {score}). Worst: {string.Join(", ", failing.OrderByDescending(r => BaselineCatalog.Find(r.CheckId)!.Severity).Take(3).Select(r => BaselineCatalog.Find(r.CheckId)!.Title))}",
                null, now));
        }
        else
        {
            foreach (var r in results.Where(r => !r.Accepted))
            {
                var check = BaselineCatalog.Find(r.CheckId)!;
                var before = previous.GetValueOrDefault(r.CheckId);
                if (r.Status == CheckStatus.Fail && before == nameof(CheckStatus.Pass))
                    Enqueue(Event(EventKinds.BaselineFailed, check.Severity, $"Baseline check failed: {check.Title} ({r.Actual})", r.CheckId, now));
                else if (r.Status == CheckStatus.Pass && before == nameof(CheckStatus.Fail))
                    Enqueue(Event(EventKinds.BaselineResolved, Severity.Info, $"Baseline check now passes: {check.Title}", r.CheckId, now));
            }
        }

        await state.SetAsync(StateLastResults, JsonSerializer.Serialize(results.ToDictionary(r => r.CheckId, r => r.Status.ToString()), BaselineJsonContext.Default.DictionaryStringString), ct);
        await state.SetAsync(StateLastRun, now.ToString("O"), ct);
        await state.SetAsync(StateLastScore, score?.ToString(System.Globalization.CultureInfo.InvariantCulture), ct);
        return new BaselineReport(now, revision, results);
    }

    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        await Task.CompletedTask;
        List<SecurityEvent> drained;
        lock (_events)
        {
            drained = [.. _events];
            _events.Clear();
        }
        foreach (var e in drained) yield return e;
    }

    public async Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct)
    {
        var sshd = await InspectAsync(_opt.SshdDropIn, ct);
        var sysctl = await InspectAsync(_opt.SysctlDropIn, ct);
        if (sshd.State == ManagedFileState.Owned)
        {
            fs.DeleteFile(_opt.SshdDropIn);
            if ((await runner.RunAsync("sshd", ["-t"], null, ct)).Success) await ReloadSshdAsync(ct);
        }
        if (sysctl.State == ManagedFileState.Owned)
        {
            var keys = SysctlKeys(sysctl.Body);
            fs.DeleteFile(_opt.SysctlDropIn);
            await RestoreSysctlAsync(keys, ct);
        }
        await state.SetAsync(StateSysctlRefused, null, ct);
        await state.SetAsync(StateAppliedRevision, null, ct);
        return ReconcileResult.Ok(ConfigState.Unknown);
    }

    // ---- helpers ----

    private async Task<ManagedFileInspection> InspectAsync(string path, CancellationToken ct) =>
        ManagedFile.Inspect(await fs.ReadAllTextAsync(path, ct));

    private Dictionary<string, string>? LastResults() =>
        state.Get(StateLastResults) is { } json ? JsonSerializer.Deserialize(json, BaselineJsonContext.Default.DictionaryStringString) : null;

    /// <summary>Reload sshd if it runs as a daemon. Socket-activated sshd (Ubuntu 22.10+) reads the config on the next connection anyway.</summary>
    private async Task ReloadSshdAsync(CancellationToken ct)
    {
        foreach (var unit in new[] { "ssh", "sshd" })
        {
            if (!await services.IsActiveAsync(unit, ct)) continue;
            if (!await services.ReloadAsync(unit, ct)) logger.LogWarning("Reloading {Unit} failed; the new settings apply on its next restart", unit);
            return;
        }
    }

    private const string SysctlRefusedHint =
        "/proc/sys is read-only on this host, which is normal for containers and LXC/OpenVZ VPS plans: the hosting provider controls these kernel settings. The drop-in stays in place and applies if the host boots its own kernel.";

    /// <summary>Keys from the drop-in whose runtime value differs from it after loading.</summary>
    private async Task<List<string>> RefusedSysctlAsync(string content, CancellationToken ct)
    {
        var desired = BaselineParsers.ParseSysctl(content);
        if (desired.Count == 0) return [];
        var actual = BaselineParsers.ParseSysctl((await runner.RunAsync("sysctl", ["-e", .. desired.Keys], null, ct)).StdOut);
        return desired.Where(kv => actual.TryGetValue(kv.Key, out var v) && v != kv.Value).Select(kv => kv.Key).ToList();
    }

    private static List<string> SysctlKeys(string? content) =>
        content is null ? [] : BaselineParsers.ParseSysctl(content).Keys.ToList();

    /// <summary>Records the current runtime value of keys we're about to set, unless an earlier apply already did.</summary>
    private async Task RememberSysctlAsync(List<string> keys, CancellationToken ct)
    {
        if (keys.Count == 0) return;
        var saved = SavedSysctl();
        var current = BaselineParsers.ParseSysctl((await runner.RunAsync("sysctl", ["-e", .. keys], null, ct)).StdOut);
        foreach (var k in keys) if (!saved.ContainsKey(k) && current.TryGetValue(k, out var v)) saved[k] = v;
        await state.SetAsync(StateSysctlPrevious, JsonSerializer.Serialize(saved, BaselineJsonContext.Default.DictionaryStringString), ct);
    }

    /// <summary>Puts keys we no longer manage back to the value they had before the first apply.</summary>
    private async Task RestoreSysctlAsync(List<string> keys, CancellationToken ct)
    {
        if (keys.Count == 0) return;
        var saved = SavedSysctl();
        foreach (var k in keys)
        {
            if (!saved.Remove(k, out var v)) continue;
            var r = await runner.RunAsync("sysctl", ["-w", $"{k}={v}"], null, ct);
            if (!r.Success) logger.LogWarning("Restoring {Key}={Value} failed: {Error}", k, v, r.CombinedOutput.Trim());
        }
        await state.SetAsync(StateSysctlPrevious, JsonSerializer.Serialize(saved, BaselineJsonContext.Default.DictionaryStringString), ct);
    }

    private Dictionary<string, string> SavedSysctl() =>
        state.Get(StateSysctlPrevious) is { } json ? JsonSerializer.Deserialize(json, BaselineJsonContext.Default.DictionaryStringString) ?? [] : [];

    private void Enqueue(SecurityEvent e)
    {
        lock (_events) _events.Enqueue(e);
    }

    private SecurityEvent Event(string kind, Severity severity, string message, string? subject, DateTime? at = null)
    {
        var when = at ?? time.GetUtcNow().UtcDateTime;
        return new SecurityEvent
        {
            Id = SecurityEvent.StableId(Info.Id, kind, subject, message, when.ToString("O")),
            OccurredAt = when,
            Capability = Capability.Hardening,
            Severity = severity,
            SourceTool = Info.Id,
            Kind = kind,
            Subject = subject,
            Message = message,
            DedupKey = $"{Info.Id}:{kind}:{subject}",
        };
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class BaselineJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
