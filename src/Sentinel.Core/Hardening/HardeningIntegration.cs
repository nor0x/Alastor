using System.Globalization;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Contracts;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Core.Platform;
using Sentinel.Core.Policy;

namespace Sentinel.Core.Hardening;

/// <summary>
/// Lynis hardening audits: <c>lynis audit system --cronjob</c> on <c>hardening.auditSchedule</c>, reading its own report
/// file (hardening index, warnings, suggestions). Lynis is in every supported distribution's repositories (EPEL on the
/// RHEL family), so it is installed like fail2ban when <c>agent.autoInstall</c> allows. The agent passes its own profile
/// that turns off Lynis's upgrade check (a DNS lookup to cisofy.com): agents talk only to the SentinelVPS server.
/// Lynis only reports; fixes for the most important findings are the baseline's one-click mitigations.
/// </summary>
public sealed class HardeningIntegration(
    ICommandRunner runner,
    IFileSystem fs,
    IPackageManager? packages,
    IStateStore state,
    string stateDir,
    ILogger<HardeningIntegration> logger,
    TimeProvider time) : IToolIntegration, IScheduledJobProvider
{
    public const string AuditJob = "hardening.audit";

    private const string StateInstalledByAgent = "lynis.installedByAgent";
    private const string StateInstallTried = "lynis.installTriedUtc";
    private const string StateLastIndex = "lynis.lastIndex";
    private const string StateKnownWarnings = "lynis.knownWarnings";
    private const string StateSummary = "lynis.summary";

    /// <summary>A drop of at least this many points between audits raises an event.</summary>
    public const int RegressionThreshold = 5;

    private readonly Queue<SecurityEvent> _events = new();
    private readonly SemaphoreSlim _lock = new(1, 1);

    public static readonly ToolDescriptor Info = new(
        "lynis",
        "Lynis",
        Capability.Hardening,
        "GPL-3.0",
        "https://cisofy.com/lynis/",
        new Dictionary<DistroFamily, string> { [DistroFamily.Debian] = "lynis", [DistroFamily.RedHat] = "lynis", [DistroFamily.Alpine] = "lynis" },
        "Security auditing: a hardening index and a checklist of warnings and suggestions.");

    public ToolDescriptor Descriptor => Info;

    private string Dir => Path.Combine(stateDir, "lynis");
    public string ProfilePath => Path.Combine(Dir, "sentinel-vps.prf");
    private string ReportPath => Path.Combine(Dir, "report.dat");
    private string LogPath => Path.Combine(Dir, "lynis.log");

    public IReadOnlyList<ScheduledJob> Jobs =>
    [
        new(AuditJob, "Run a Lynis audit", "hardening.auditSchedule", RunOnFirstStart: true, (_, _, ct) => AuditAsync(ct)),
    ];

    public bool IsWanted(PolicyDocument policy) => !ScheduleDefaults.For(policy, "hardening.auditSchedule").IsDisabled;

    public async Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        var details = new Dictionary<string, string>();
        if (state.Get(StateSummary) is { } summary) details["lastAudit"] = summary;
        if (runner.Which("lynis") is null)
            return new ToolStatus
            {
                ToolId = Info.Id,
                Availability = packages is null ? Availability.Unavailable : Availability.Available,
                UnavailableReason = packages is null ? "No supported package manager to install Lynis." : null,
                Ownership = Ownership.NotInstalled,
                Details = details,
            };
        var v = await runner.RunAsync("lynis", ["--version"], new CommandOptions { Timeout = TimeSpan.FromSeconds(20) }, ct);
        return new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            // Lynis has no daemon: "running" means it's ready to audit.
            Running = true,
            Version = v.Success ? v.StdOut.Trim() : null,
            Ownership = state.Get(StateInstalledByAgent) == "true" ? Ownership.Managed : Ownership.Adopted,
            ConfigState = ConfigState.InSync,
            Details = details,
        };
    }

    public async Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct)
    {
        var status = await DetectAsync(ct);
        if (status.Installed || packages is null || !IsWanted(request.Policy)) return status;
        if (!request.AllowInstall)
            return status with { Availability = Availability.Unavailable, UnavailableReason = "Lynis is not installed and agent.autoInstall is false. Install the lynis package, or enable auto-install." };

        // At most one attempt a day: a missing EPEL repository won't appear by retrying every reconcile.
        var last = DateTime.TryParse(state.Get(StateInstallTried), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var l) ? l : DateTime.MinValue;
        var now = time.GetUtcNow().UtcDateTime;
        if (now - last < TimeSpan.FromDays(1))
            return status with { Availability = Availability.Unavailable, UnavailableReason = state.Get("lynis.installError") ?? "Installing Lynis failed; retrying tomorrow." };
        await state.SetAsync(StateInstallTried, now.ToString("O"), ct);
        logger.LogInformation("Installing Lynis from distro repositories via {PackageManager}", packages.Name);
        var r = await packages.InstallAsync("lynis", ct);
        if (!r.Success)
        {
            var reason = $"Installing lynis failed: {r.Error}" + (packages.Name == "dnf" ? " (on the RHEL family, Lynis comes from EPEL: dnf install epel-release)" : "");
            await state.SetAsync("lynis.installError", reason, ct);
            return status with { Availability = Availability.Unavailable, UnavailableReason = reason };
        }
        await state.SetAsync(StateInstalledByAgent, "true", ct);
        await state.SetAsync("lynis.installError", null, ct);
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

    /// <summary>Only our profile and report live under the state directory; the lynis package stays installed.</summary>
    public Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct)
    {
        foreach (var f in new[] { ProfilePath, ReportPath, LogPath })
            if (fs.FileExists(f)) fs.DeleteFile(f);
        return Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));
    }

    // ---- audit ----

    public async Task<AgentReport> AuditAsync(CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        var started = time.GetUtcNow().UtcDateTime;
        try
        {
            if (runner.Which("lynis") is null)
                return Failed(started, "Lynis isn't installed.");
            fs.CreateDirectory(Dir);
            // Lynis refuses profiles that others can write to.
            await fs.WriteAllTextAtomicAsync(ProfilePath,
                "# Written by SentinelVPS. Agents talk only to their server, so Lynis's upgrade check (a DNS query to cisofy.com) is off.\nskip-upgrade-test=yes\n",
                UnixFileMode.UserRead | UnixFileMode.UserWrite, ct);
            if (fs.FileExists(ReportPath)) fs.DeleteFile(ReportPath);

            List<string> args = ["audit", "system", "--cronjob", "--quiet", "--no-colors", "--profile", ProfilePath, "--report-file", ReportPath, "--log-file", LogPath];
            // Some tests read every file under /etc or every package; at low priority they don't slow the host's services.
            var options = new CommandOptions { Timeout = TimeSpan.FromMinutes(60) };
            var r = runner.Which("nice") is { } nice
                ? await runner.RunAsync(nice, ["-n", "15", runner.Which("lynis")!, .. args], options, ct)
                : await runner.RunAsync("lynis", args, options, ct);

            var content = await fs.ReadAllTextAsync(ReportPath, ct);
            var report = content is null ? null : LynisReportParser.Parse(content);
            if (report?.HardeningIndex is null)
                return Failed(started, $"lynis exited with {r.ExitCode} and wrote no hardening index: {Tail(r.CombinedOutput, 500)}");

            RaiseEvents(report);
            await state.SetAsync(StateLastIndex, report.HardeningIndex.Value.ToString(CultureInfo.InvariantCulture), ct);
            await state.SetAsync(StateKnownWarnings, string.Join('\n', report.Items.Where(i => i.Kind == LynisItemKind.Warning).Select(Key)), ct);
            var warnings = report.Items.Count(i => i.Kind == LynisItemKind.Warning);
            await state.SetAsync(StateSummary, $"index {report.HardeningIndex}, {warnings} warnings, {report.Items.Count - warnings} suggestions at {time.GetUtcNow().UtcDateTime:O}", ct);
            logger.LogInformation("Lynis audit: hardening index {Index}, {Warnings} warnings, {Suggestions} suggestions", report.HardeningIndex, warnings, report.Items.Count - warnings);
            return new AgentReport(AuditJob, started, time.GetUtcNow().UtcDateTime, true, null) { Hardening = report };
        }
        finally
        {
            _lock.Release();
        }
    }

    private void RaiseEvents(HardeningReport report)
    {
        var known = (state.Get(StateKnownWarnings) ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        var fresh = report.Items.Where(i => i.Kind == LynisItemKind.Warning && !known.Contains(Key(i))).ToList();
        if (fresh.Count > 0)
            _events.Enqueue(Event(EventKinds.HardeningWarning, Severity.Medium,
                $"Lynis reports {fresh.Count} new warning{(fresh.Count == 1 ? "" : "s")}: {string.Join("; ", fresh.Take(4).Select(i => $"{i.Text} [{i.TestId}]"))}{(fresh.Count > 4 ? " …" : "")}"));

        if (int.TryParse(state.Get(StateLastIndex), NumberStyles.Integer, CultureInfo.InvariantCulture, out var previous)
            && report.HardeningIndex is { } now && previous - now >= RegressionThreshold)
            _events.Enqueue(Event(EventKinds.HardeningRegressed, Severity.Medium,
                $"The Lynis hardening index dropped from {previous} to {now}. A recent change weakened this host's configuration."));
    }

    private static string Key(LynisItem i) => $"{i.TestId}|{i.Text}|{i.Details}";

    private SecurityEvent Event(string kind, Severity severity, string message) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow().UtcDateTime,
        Capability = Capability.Hardening,
        Severity = severity,
        SourceTool = Info.Id,
        Kind = kind,
        Message = message,
        DedupKey = $"{Info.Id}:{kind}",
    };

    private AgentReport Failed(DateTime started, string error)
    {
        logger.LogWarning("Lynis audit failed: {Error}", error);
        return new AgentReport(AuditJob, started, time.GetUtcNow().UtcDateTime, false, error);
    }

    private static string Tail(string s, int max)
    {
        s = s.Trim();
        return s.Length <= max ? s : "…" + s[^max..];
    }
}
