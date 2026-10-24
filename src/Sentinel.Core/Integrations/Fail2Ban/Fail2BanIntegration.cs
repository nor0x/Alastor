using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Events;
using Sentinel.Core.Net;
using Sentinel.Core.Platform;
using Sentinel.Core.Policy;

namespace Sentinel.Core.Integrations.Fail2Ban;

public sealed record Fail2BanOptions
{
    public string ConfigDir { get; init; } = "/etc/fail2ban";
    public string JailFileName { get; init; } = "sentinel-vps.local";
    public string ServiceName { get; init; } = "fail2ban";

    public string JailFile => Path.Combine(ConfigDir, "jail.d", JailFileName);
    public string ManualFilterFile => Path.Combine(ConfigDir, "filter.d", PolicyYaml.ManualJailName + ".conf");
}

/// <summary>
/// The fail2ban integration, the reference implementation of <see cref="IToolIntegration"/>.
/// <list type="bullet">
/// <item>Config: owns exactly two files, <c>jail.d/sentinel-vps.local</c> and <c>filter.d/sentinel-manual.conf</c>.</item>
/// <item>Validation: <c>fail2ban-client -t</c> before every reload; rolls back on rejection.</item>
/// <item>Bans: <c>fail2ban-client get &lt;jail&gt; banip --with-time</c>; manual bans go to the <c>sentinel-manual</c> jail.</item>
/// <item>Events: tails the log file reported by <c>fail2ban-client get logtarget</c>.</item>
/// </list>
/// </summary>
public sealed partial class Fail2BanIntegration(
    ICommandRunner runner,
    IFileSystem fs,
    IPackageManager? packages,
    IServiceManager services,
    IStateStore state,
    ILogger<Fail2BanIntegration> logger,
    TimeProvider time,
    Fail2BanOptions? options = null,
    TimeZoneInfo? localZone = null) : IToolIntegration, IBanProvider
{
    private const string Client = "fail2ban-client";
    private const string StateInstalledByAgent = "fail2ban.installedByAgent";
    private const string StateAppliedRevision = "fail2ban.appliedRevision";
    private const string StateLastReload = "fail2ban.lastReloadUtc";
    private const string StateConfigState = "fail2ban.configState";
    private readonly Fail2BanOptions _opt = options ?? new Fail2BanOptions();
    private readonly TimeZoneInfo _tz = localZone ?? TimeZoneInfo.Local;
    private readonly LogTailer _tailer = new(fs, state, "fail2ban.log");
    private string? _logTarget;
    private DateTime _logTargetCheckedAt;

    public static readonly ToolDescriptor Info = new(
        "fail2ban",
        "fail2ban",
        Capability.Banning,
        "GPL-2.0-or-later",
        "https://github.com/fail2ban/fail2ban",
        new Dictionary<DistroFamily, string>
        {
            [DistroFamily.Debian] = "fail2ban",
            [DistroFamily.RedHat] = "fail2ban",
            [DistroFamily.Alpine] = "fail2ban",
        },
        "Scans logs for brute-force patterns and bans offending IPs via the firewall.");

    public ToolDescriptor Descriptor => Info;

    public bool IsWanted(PolicyDocument policy) =>
        policy.Banning is { } b && b.Enabled != false && (b.Engine ?? "fail2ban") == "fail2ban";

    public async Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        var installed = runner.Which(Client) is not null;
        if (!installed)
        {
            if (packages is null)
                return Status(Availability.Unavailable, "No supported package manager (apt, dnf, apk) found on this host.");
            var available = await packages.IsAvailableAsync(Info.Packages.GetValueOrDefault(DistroFamily.Debian, "fail2ban"), ct);
            return available
                ? Status(Availability.Available, null)
                : Status(Availability.Unavailable, packages.Name == "dnf"
                    ? "fail2ban is not in the enabled repositories. Enable EPEL first: dnf install epel-release"
                    : $"fail2ban is not available from this host's {packages.Name} repositories.");
        }

        var versionResult = await runner.RunAsync(Client, ["--version"], null, ct);
        var ping = await runner.RunAsync(Client, ["ping"], null, ct);
        var running = ping.Success && ping.StdOut.Contains("pong", StringComparison.Ordinal);

        var jailFile = ManagedFile.Inspect(await fs.ReadAllTextAsync(_opt.JailFile, ct));
        // File inspection catches hand edits right away. Otherwise report the outcome of the last apply (InSync, Conflict, Rejected).
        var configState = jailFile.State switch
        {
            ManagedFileState.Drifted => ConfigState.Drifted,
            ManagedFileState.Foreign => ConfigState.Conflict,
            ManagedFileState.Missing => ConfigState.Pending,
            _ => Enum.TryParse<ConfigState>(state.Get(StateConfigState), out var last) ? last : ConfigState.InSync,
        };

        var details = new Dictionary<string, string>();
        if (running)
        {
            var status = await runner.RunAsync(Client, ["status"], null, ct);
            details["jails"] = string.Join(", ", Fail2BanParsers.ParseJailList(status.StdOut));
        }

        return new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Version = Fail2BanParsers.ParseVersion(versionResult.StdOut + versionResult.StdErr),
            Running = running,
            Ownership = state.Get(StateInstalledByAgent) == "true" ? Ownership.Managed : Ownership.Adopted,
            ConfigState = configState,
            AppliedRevision = state.Get(StateAppliedRevision),
            LastSuccessAt = DateTime.TryParse(state.Get(StateLastReload), null, System.Globalization.DateTimeStyles.RoundtripKind, out var t) ? t : null,
            LastError = running ? null : "fail2ban is installed but its server is not responding to 'fail2ban-client ping'.",
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
                UnavailableReason = "fail2ban is not installed and agent.autoInstall is false. Install it manually or enable auto-install in the policy.",
            };

        logger.LogInformation("Installing fail2ban from distro repositories via {PackageManager}", packages!.Name);
        var result = await packages.InstallAsync("fail2ban", ct);
        if (!result.Success)
            return status with { Availability = Availability.Unavailable, UnavailableReason = $"Installing fail2ban failed: {result.Error}" };
        await state.SetAsync(StateInstalledByAgent, "true", ct);
        await services.EnableAndStartAsync(_opt.ServiceName, ct);
        return await DetectAsync(ct);
    }

    public async Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct)
    {
        var changes = new List<PlannedChange>();
        var warnings = new List<PlanWarning>();
        var jailInspect = ManagedFile.Inspect(await fs.ReadAllTextAsync(_opt.JailFile, ct));
        var filterInspect = ManagedFile.Inspect(await fs.ReadAllTextAsync(_opt.ManualFilterFile, ct));

        if (!IsWanted(request.Policy))
        {
            // Banning off, or another engine selected: remove only what we own.
            foreach (var (path, inspect) in new[] { (_opt.JailFile, jailInspect), (_opt.ManualFilterFile, filterInspect) })
            {
                if (inspect.State == ManagedFileState.Owned || (inspect.State == ManagedFileState.Drifted && request.Reclaim))
                    changes.Add(new(ChangeKind.DeleteFile, path, "Banning disabled by policy: remove managed fail2ban config"));
                else if (inspect.State is ManagedFileState.Drifted or ManagedFileState.Foreign)
                    warnings.Add(new(EventKinds.ConfigDrift, $"{path} is not (or no longer) owned by SentinelVPS. Left in place."));
            }
            if (changes.Count > 0 && await IsRunningAsync(ct)) changes.Add(new(ChangeKind.Reload, Client, "Reload fail2ban"));
            return new ReconcilePlan(Info.Id, request.Revision, changes, warnings, ConfigState.InSync);
        }

        var banning = request.Policy.Banning!;
        var skip = new HashSet<string>(StringComparer.Ordinal);
        var conflicts = await FindAdminOwnedJailsAsync(ct);
        foreach (var (name, jail) in banning.Jails ?? [])
        {
            if (conflicts.TryGetValue(name, out var file) && jail.Takeover != true)
            {
                skip.Add(name);
                warnings.Add(new(EventKinds.ConfigConflict, $"Jail '{name}' is configured by hand in {file}. Leaving it unmanaged. Set banning.jails.{name}.takeover: true to let SentinelVPS manage it."));
                continue;
            }
            if (jail.Enabled == true)
            {
                var filter = jail.Filter ?? name;
                if (!fs.FileExists(Path.Combine(_opt.ConfigDir, "filter.d", filter + ".conf")) &&
                    !fs.FileExists(Path.Combine(_opt.ConfigDir, "filter.d", filter + ".local")))
                {
                    skip.Add(name);
                    warnings.Add(new(EventKinds.ConfigRejected, $"Jail '{name}' skipped: filter '{filter}' does not exist in {_opt.ConfigDir}/filter.d."));
                    continue;
                }
                foreach (var logpath in (jail.Logpath ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!logpath.Contains('*') && !fs.FileExists(logpath))
                    {
                        skip.Add(name);
                        warnings.Add(new(EventKinds.ConfigRejected, $"Jail '{name}' skipped: log file {logpath} does not exist (fail2ban refuses to start with a missing log)."));
                        break;
                    }
                }
            }
        }

        var resultState = skip.Count > 0 && conflicts.Keys.Any(skip.Contains) ? ConfigState.Conflict : ConfigState.InSync;
        var desiredJail = Fail2BanConfigRenderer.RenderJails(banning, skip);
        var desiredFilter = Fail2BanConfigRenderer.ManualFilterBody;

        void PlanFile(string path, ManagedFileInspection inspect, string body, string what)
        {
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
                    warnings.Add(new(EventKinds.ConfigConflict, $"{path} exists but was not written by SentinelVPS. Not touching it."));
                    resultState = ConfigState.Conflict;
                    break;
            }
        }

        PlanFile(_opt.ManualFilterFile, filterInspect, desiredFilter, "manual-ban filter");
        PlanFile(_opt.JailFile, jailInspect, desiredJail, "jail configuration");

        var running = await IsRunningAsync(ct);
        if (!running) changes.Add(new(ChangeKind.StartService, _opt.ServiceName, "Enable and start fail2ban"));
        else if (changes.Count > 0) changes.Add(new(ChangeKind.Reload, Client, "Reload fail2ban"));

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

        // Back up current contents so any failure restores the previous state exactly.
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

        try
        {
            foreach (var c in plan.Changes)
            {
                if (c.Kind == ChangeKind.WriteFile) await fs.WriteAllTextAtomicAsync(c.Target, c.Content!, Mode644, ct);
                else if (c.Kind == ChangeKind.DeleteFile) fs.DeleteFile(c.Target);
            }

            if (backups.Count > 0)
            {
                var test = await runner.RunAsync(Client, ["-t"], null, ct);
                if (!test.Success)
                {
                    await RollbackAsync();
                    var errors = Fail2BanParsers.ParseTestErrors(test.CombinedOutput);
                    var msg = $"fail2ban rejected the new configuration and it was rolled back: {string.Join("; ", errors.DefaultIfEmpty(test.CombinedOutput.Trim()))}";
                    events.Add(LifecycleEvent(EventKinds.ConfigRejected, Severity.High, msg, plan.Revision));
                    await state.SetAsync(StateConfigState, nameof(ConfigState.Rejected), ct);
                    return new ReconcileResult(false, ConfigState.Rejected, msg, events);
                }
            }

            foreach (var c in plan.Changes)
            {
                var ok = c.Kind switch
                {
                    ChangeKind.Reload => (await runner.RunAsync(Client, ["reload"], null, ct)).Success,
                    ChangeKind.StartService => await services.EnableAndStartAsync(_opt.ServiceName, ct),
                    _ => true,
                };
                if (!ok) throw new InvalidOperationException($"'{c.Description}' failed");
            }

            if (IsWantedPlan(plan) && !await WaitForJailAsync(PolicyYaml.ManualJailName, ct))
                throw new InvalidOperationException("fail2ban did not come up with the sentinel-manual jail after reload");
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            logger.LogError(ex, "Applying fail2ban configuration failed. Rolling back.");
            await RollbackAsync();
            if (backups.Count > 0) await runner.RunAsync(Client, ["reload"], null, ct);
            var msg = $"Applying fail2ban configuration failed and was rolled back: {ex.Message}";
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

    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        var logPath = await GetLogTargetAsync(ct);
        if (logPath is null) yield break;
        var lines = await _tailer.ReadNewLinesAsync(logPath, ct);
        if (lines.Count == 0) yield break;
        var records = lines.Select(l => Fail2BanParsers.ParseLogLine(l, _tz)).OfType<Fail2BanLogRecord>();
        foreach (var e in Fail2BanEventNormalizer.Normalize(records)) yield return e;
    }

    public async Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct)
    {
        var removed = new List<string>();
        foreach (var path in new[] { _opt.JailFile, _opt.ManualFilterFile })
        {
            var inspect = ManagedFile.Inspect(await fs.ReadAllTextAsync(path, ct));
            if (inspect.State == ManagedFileState.Owned)
            {
                fs.DeleteFile(path);
                removed.Add(path);
            }
        }
        if (removed.Count > 0 && await IsRunningAsync(ct)) await runner.RunAsync(Client, ["reload"], null, ct);
        await state.SetAsync(StateAppliedRevision, null, ct);
        return ReconcileResult.Ok(ConfigState.Unknown);
    }

    // ---- IBanProvider ----

    public async Task<IReadOnlyList<BanEntry>> ListBansAsync(CancellationToken ct)
    {
        var status = await runner.RunAsync(Client, ["status"], null, ct);
        if (!status.Success) return [];
        var result = new List<BanEntry>();
        foreach (var jail in Fail2BanParsers.ParseJailList(status.StdOut))
        {
            var r = await runner.RunAsync(Client, ["get", jail, "banip", "--with-time"], null, ct);
            if (!r.Success) continue;
            foreach (var b in Fail2BanParsers.ParseBanList(jail, r.StdOut, _tz))
                result.Add(new BanEntry(b.Target, b.Jail, b.BannedAtUtc, b.ExpiresAtUtc, b.Jail == PolicyYaml.ManualJailName));
        }
        return result;
    }

    public async Task<CommandOutcome> BanAsync(IpTarget target, string? reason, CancellationToken ct)
    {
        if (!await WaitForJailAsync(PolicyYaml.ManualJailName, ct, attempts: 1))
            return new(false, "The sentinel-manual jail is not active yet. The banning policy has not been applied on this host.");
        var r = await runner.RunAsync(Client, ["set", PolicyYaml.ManualJailName, "banip", target.ToString()], null, ct);
        if (!r.Success) return new(false, r.CombinedOutput.Trim());
        return new(true, r.StdOut.Trim() == "0" ? $"{target} was already banned" : $"Banned {target}");
    }

    public async Task<CommandOutcome> UnbanAsync(IpTarget target, CancellationToken ct)
    {
        // "unban" removes the address from every jail, which is what an operator means by "unban".
        var r = await runner.RunAsync(Client, ["unban", target.ToString()], null, ct);
        if (!r.Success) return new(false, r.CombinedOutput.Trim());
        return new(true, r.StdOut.Trim() == "0" ? $"{target} was not banned" : $"Unbanned {target}");
    }

    // ---- helpers ----

    private static readonly UnixFileMode Mode644 =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    private static bool IsWantedPlan(ReconcilePlan plan) =>
        plan.Changes.All(c => c.Kind != ChangeKind.DeleteFile);

    private static string Normalize(string? s) => (s ?? "").ReplaceLineEndings("\n").Trim();

    private async Task<bool> IsRunningAsync(CancellationToken ct)
    {
        var ping = await runner.RunAsync(Client, ["ping"], null, ct);
        return ping.Success && ping.StdOut.Contains("pong", StringComparison.Ordinal);
    }

    private async Task<bool> WaitForJailAsync(string jail, CancellationToken ct, int attempts = 10)
    {
        for (var i = 0; i < attempts; i++)
        {
            var status = await runner.RunAsync(Client, ["status"], null, ct);
            if (status.Success && Fail2BanParsers.ParseJailList(status.StdOut).Contains(jail)) return true;
            if (i < attempts - 1) await Task.Delay(TimeSpan.FromMilliseconds(500), time, ct);
        }
        return false;
    }

    /// <summary>Jails defined in admin-owned <c>.local</c> files (<c>jail.local</c>, <c>jail.d/*.local</c> apart from ours).</summary>
    private async Task<Dictionary<string, string>> FindAdminOwnedJailsAsync(CancellationToken ct)
    {
        var files = new List<string> { Path.Combine(_opt.ConfigDir, "jail.local") };
        files.AddRange(fs.EnumerateFiles(Path.Combine(_opt.ConfigDir, "jail.d"), "*.local").Where(f => f != _opt.JailFile));
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var file in files)
        {
            var text = await fs.ReadAllTextAsync(file, ct);
            if (text is null) continue;
            foreach (Match m in IniSectionRegex().Matches(text))
            {
                var name = m.Groups[1].Value.Trim();
                if (name is not ("DEFAULT" or "INCLUDES")) result.TryAdd(name, file);
            }
        }
        return result;
    }

    private async Task<string?> GetLogTargetAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        if (_logTarget is not null && now - _logTargetCheckedAt < TimeSpan.FromMinutes(5)) return _logTarget;
        var r = await runner.RunAsync(Client, ["get", "logtarget"], null, ct);
        _logTargetCheckedAt = now;
        _logTarget = r.Success ? Fail2BanParsers.ParseLogTarget(r.StdOut) : null;
        return _logTarget;
    }

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

    [GeneratedRegex(@"^\s*\[([^\]\r\n]+)\]", RegexOptions.Multiline)]
    private static partial Regex IniSectionRegex();
}
