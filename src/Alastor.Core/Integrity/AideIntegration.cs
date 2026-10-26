using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Core.Integrity;

/// <summary>
/// Opt-in file-integrity checks with AIDE on <c>integrity.checkSchedule</c>. The agent runs AIDE with its own config and
/// database under its state directory, so the distribution's aide.conf and its daily job are never involved. The first
/// run records the baseline; later runs report what was added, removed or changed. Report only: after reviewing (an
/// update replaced binaries, an admin edited /etc), "Accept changes" in the dashboard re-records the baseline
/// (<c>aide --update</c>). Runs at the lowest CPU priority.
/// </summary>
public sealed class AideIntegration(
    ICommandRunner runner,
    IPackageManager? packages,
    IServiceManager services,
    IStateStore state,
    string stateDir,
    ILogger<AideIntegration> logger,
    TimeProvider time) : IToolIntegration, IScheduledJobProvider
{
    public const string CheckJob = "integrity.check";
    public const string AcceptJob = "integrity.accept";
    public const int MaxChanges = 2000;

    /// <summary>Folder under the state directory with the generated aide.conf and the baseline database.</summary>
    public const string DbDirName = "aide";
    public static readonly IReadOnlyList<string> DefaultPaths =
        ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/etc", "/root/.ssh", "/usr/lib/systemd/system"];

    private const string StateInstalledByAgent = "aide.installedByAgent";
    private const string StateKnown = "aide.known";
    private static readonly CommandOptions Slow = new() { Timeout = TimeSpan.FromHours(2) };
    private readonly Queue<SecurityEvent> _events = new();
    private readonly SemaphoreSlim _lock = new(1, 1);

    public static readonly ToolDescriptor Info = new(
        "aide",
        "AIDE",
        Capability.Integrity,
        "GPL-2.0-or-later",
        "https://aide.github.io/",
        new Dictionary<DistroFamily, string> { [DistroFamily.Debian] = "aide", [DistroFamily.RedHat] = "aide", [DistroFamily.Alpine] = "aide" },
        "File integrity: binaries, /etc and SSH keys compared with an accepted baseline.");

    public ToolDescriptor Descriptor => Info;

    public IReadOnlyList<ScheduledJob> Jobs =>
    [
        new(CheckJob, "Check file integrity", "integrity.checkSchedule", RunOnFirstStart: false, (policy, _, ct) => RunAsync(policy, accept: false, ct)),
        new(AcceptJob, "Accept file changes", "", RunOnFirstStart: false, (policy, _, ct) => RunAsync(policy, accept: true, ct)),
    ];

    public bool IsWanted(PolicyDocument policy) => !ScheduleDefaults.For(policy, "integrity.checkSchedule").IsDisabled;

    private string DbDir => Path.Combine(stateDir, DbDirName);
    private string ConfigPath => Path.Combine(DbDir, "aide.conf");
    private string DbPath => Path.Combine(DbDir, "aide.db");

    public async Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        if (runner.Which("aide") is null)
        {
            var available = packages is not null && await packages.IsAvailableAsync("aide", ct);
            return new ToolStatus
            {
                ToolId = Info.Id,
                Availability = available ? Availability.Available : Availability.Unavailable,
                UnavailableReason = available ? null : "AIDE isn't available from this host's package repositories.",
            };
        }
        var version = AideParser.ParseVersion((await runner.RunAsync("aide", ["--version"], new CommandOptions { Timeout = TimeSpan.FromSeconds(20) }, ct)).CombinedOutput);
        return new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Running = true,
            Version = version?.ToString(),
            Ownership = state.Get(StateInstalledByAgent) == "true" ? Ownership.Managed : Ownership.Adopted,
            ConfigState = ConfigState.InSync,
            Details = new Dictionary<string, string> { ["baseline"] = File.Exists(DbPath) ? "recorded" : "not yet" },
        };
    }

    public async Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct)
    {
        var status = await DetectAsync(ct);
        if (status.Installed || status.Availability == Availability.Unavailable || packages is null) return status;
        if (!request.AllowInstall)
            return status with { Availability = Availability.Unavailable, UnavailableReason = "AIDE is not installed and agent.autoInstall is false. Install the aide package, or enable auto-install." };
        var result = await packages.InstallAsync("aide", ct);
        if (!result.Success) return status with { Availability = Availability.Unavailable, UnavailableReason = $"Installing AIDE failed: {result.Error}" };
        await state.SetAsync(StateInstalledByAgent, "true", ct);
        // Debian's aide-common checks the whole system daily with its own config and mails root; the agent does this instead.
        await services.DisableAndStopAsync("dailyaidecheck.timer", ct);
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

    /// <summary>The baseline and config live in the agent's state directory; remove them with the agent.</summary>
    public Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct)
    {
        try
        {
            if (Directory.Exists(DbDir)) Directory.Delete(DbDir, recursive: true);
            return Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Task.FromResult(new ReconcileResult(false, ConfigState.InSync, ex.Message, []));
        }
    }

    public async Task<AgentReport> RunAsync(PolicyDocument policy, bool accept, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        var started = time.GetUtcNow().UtcDateTime;
        var job = accept ? AcceptJob : CheckJob;
        try
        {
            if (runner.Which("aide") is null) return Failed(job, started, "AIDE is not installed.");
            var version = AideParser.ParseVersion((await runner.RunAsync("aide", ["--version"], new CommandOptions { Timeout = TimeSpan.FromSeconds(20) }, ct)).CombinedOutput);
            var paths = policy.Integrity?.Paths ?? DefaultPaths.ToList();
            Directory.CreateDirectory(DbDir);
            await File.WriteAllTextAsync(ConfigPath, AideConfig.Render(DbDir, version, paths, policy.Integrity?.Exclude ?? []), ct);

            var mode = !File.Exists(DbPath) ? "init" : accept ? "accept" : "check";
            var r = await Aide(mode switch { "init" => "--init", "accept" => "--update", _ => "--check" }, ct);
            if (!AideParser.IsSuccess(r.ExitCode))
                return Failed(job, started, $"aide {mode} failed (exit {r.ExitCode}): {Tail(r.CombinedOutput, 600)}");
            if (mode != "check")
            {
                var fresh = DbPath + ".new";
                if (!File.Exists(fresh)) return Failed(job, started, $"aide {mode} didn't write {fresh}.");
                File.Move(fresh, DbPath, overwrite: true);
                await state.SetAsync(StateKnown, "", ct);
            }

            var (entries, changes) = mode == "check" ? AideParser.Parse(r.StdOut) : (AideParser.Parse(r.StdOut).Entries, []);
            var report = new IntegrityReport(version?.ToString(), mode, entries, changes.Take(MaxChanges).ToList(), paths, changes.Count > MaxChanges);
            if (mode == "check") await RaiseEventsAsync(report, ct);
            logger.LogInformation("AIDE {Mode}: {Entries} entries, {Changes} changes", mode, entries, changes.Count);
            return new AgentReport(job, started, time.GetUtcNow().UtcDateTime, true, null) { Integrity = report };
        }
        finally
        {
            _lock.Release();
        }
    }

    private Task<CommandResult> Aide(string action, CancellationToken ct) =>
        runner.Which("nice") is { } nice
            ? runner.RunAsync(nice, ["-n", "19", runner.Which("aide")!, action, $"--config={ConfigPath}"], Slow, ct)
            : runner.RunAsync("aide", [action, $"--config={ConfigPath}"], Slow, ct);

    private async Task RaiseEventsAsync(IntegrityReport report, CancellationToken ct)
    {
        static string Key(IntegrityChange c) => $"{c.Path}|{c.Change}|{c.Flags}";
        var known = (state.Get(StateKnown) ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        var fresh = report.Changes.Where(c => !known.Contains(Key(c))).ToList();
        if (fresh.Count > 0)
        {
            var critical = fresh.Where(c => c.Critical).ToList();
            var shown = critical.Concat(fresh.Except(critical)).Take(6)
                .Select(c => $"{c.Path} ({c.Change}{(c.Attributes.Count > 0 ? ": " + string.Join(", ", c.Attributes) : "")})");
            _events.Enqueue(new SecurityEvent
            {
                Id = Guid.NewGuid(),
                OccurredAt = time.GetUtcNow().UtcDateTime,
                Capability = Capability.Integrity,
                Severity = critical.Count > 0 ? Severity.High : Severity.Medium,
                SourceTool = Info.Id,
                Kind = EventKinds.IntegrityChanged,
                Subject = (critical.FirstOrDefault() ?? fresh[0]).Path,
                Message = $"{fresh.Count} file{(fresh.Count == 1 ? "" : "s")} changed since the accepted baseline{(critical.Count > 0 ? $", {critical.Count} in binaries, SSH or account files" : "")}: " +
                          string.Join("; ", shown) + (fresh.Count > 6 ? " …" : ""),
                DedupKey = $"{Info.Id}:{EventKinds.IntegrityChanged}",
            });
        }
        await state.SetAsync(StateKnown, string.Join('\n', report.Changes.Select(Key)), ct);
    }

    private AgentReport Failed(string job, DateTime started, string error)
    {
        logger.LogWarning("AIDE run failed: {Error}", error);
        return new AgentReport(job, started, time.GetUtcNow().UtcDateTime, false, error);
    }

    private static string Tail(string s, int max) => s.Length <= max ? s.Trim() : "…" + s[^max..].Trim();
}
