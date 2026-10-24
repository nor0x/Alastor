using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Core.Integrations.Fail2Ban;
using Sentinel.Core.Platform;
using Sentinel.Core.Policy;

namespace Sentinel.Tests;

/// <summary>Policy reconciliation for fail2ban: desired policy vs. the actual files and daemon state.</summary>
public class Fail2BanReconcileTests
{
    private const string JailFile = "/etc/fail2ban/jail.d/sentinel-vps.local";
    private const string FilterFile = "/etc/fail2ban/filter.d/sentinel-manual.conf";

    private readonly FakeFileSystem _fs = new();
    private readonly FakeCommandRunner _runner = new();
    private readonly InMemoryStateStore _state = new();
    private bool _testPasses = true;
    private string _jails = "sshd";

    public Fail2BanReconcileTests()
    {
        _fs.Files["/etc/fail2ban/filter.d/sshd.conf"] = "[Definition]\n";
        _fs.Files["/etc/fail2ban/filter.d/nginx-http-auth.conf"] = "[Definition]\n";
        _fs.Files["/etc/fail2ban/jail.d/defaults-debian.conf"] = "[sshd]\nbackend = systemd\nenabled = true\n";
        _runner.On("fail2ban-client ping", "Server replied: pong")
            .On("fail2ban-client --version", "Fail2Ban v1.1.0")
            .On("fail2ban-client -t", () => _testPasses
                ? new CommandResult(0, Fixture.Read("fail2ban/client-test-ok.txt"), "")
                : new CommandResult(255, "", Fixture.Read("fail2ban/client-test-failed.txt")))
            .On("fail2ban-client reload", () =>
            {
                _jails = "sentinel-manual, sshd";
                return new CommandResult(0, "OK", "");
            })
            .On("fail2ban-client status", () => new CommandResult(0, $"Status\n|- Number of jail:\t2\n`- Jail list:\t{_jails}\n", ""));
    }

    private Fail2BanIntegration Integration() => new(_runner, _fs, null, new SystemdServiceManager(_runner), _state,
        NullLogger<Fail2BanIntegration>.Instance, TimeProvider.System, localZone: TimeZoneInfo.Utc);

    private static ReconcileRequest Request(string yaml, bool reclaim = false)
    {
        var doc = PolicyYaml.Parse(yaml).Document!;
        return new ReconcileRequest(doc, PolicyYaml.Revision(doc)) { Reclaim = reclaim };
    }

    private const string Policy = """
        banning:
          allowlist: [10.0.0.0/8]
          defaults: {bantime: 1h, findtime: 10m, maxretry: 5, banaction: nftables}
          jails:
            sshd: {enabled: true, maxretry: 3}
        """;

    [Fact]
    public async Task Fresh_host_plans_both_files_and_a_reload()
    {
        var plan = await Integration().PlanAsync(Request(Policy), default);
        Assert.Equal([ChangeKind.WriteFile, ChangeKind.WriteFile, ChangeKind.Reload], plan.Changes.Select(c => c.Kind));
        var jail = plan.Changes.Single(c => c.Target == JailFile).Content!;
        Assert.Contains("[sshd]\nenabled = true\nbantime = 3600\nfindtime = 600\nmaxretry = 3\nbanaction = nftables\nignoreip = 127.0.0.1/8 ::1 10.0.0.0/8\n", jail);
        Assert.Contains("[sentinel-manual]", jail);
        Assert.DoesNotContain("[DEFAULT]", jail); // never touch admin-wide defaults
        Assert.Equal(ConfigState.InSync, plan.ResultingState);
    }

    [Fact]
    public async Task Apply_then_plan_again_is_a_noop()
    {
        var f2b = Integration();
        var result = await f2b.ApplyAsync(await f2b.PlanAsync(Request(Policy), default), default);
        Assert.True(result.Success);
        Assert.Contains(result.Events, e => e.Kind == EventKinds.ConfigApplied);
        Assert.Contains("fail2ban-client -t", _runner.Calls);
        Assert.True(_runner.Calls.IndexOf("fail2ban-client -t") < _runner.Calls.IndexOf("fail2ban-client reload"), "validate before reload");

        _runner.Calls.Clear();
        var again = await f2b.PlanAsync(Request(Policy), default);
        Assert.True(again.IsNoop);
    }

    [Fact]
    public async Task Changing_a_threshold_updates_only_the_jail_file()
    {
        var f2b = Integration();
        await f2b.ApplyAsync(await f2b.PlanAsync(Request(Policy), default), default);
        var plan = await f2b.PlanAsync(Request(Policy.Replace("maxretry: 3", "maxretry: 4")), default);
        Assert.Equal([(ChangeKind.WriteFile, JailFile), (ChangeKind.Reload, "fail2ban-client")], plan.Changes.Select(c => (c.Kind, c.Target)));
    }

    [Fact]
    public async Task Hand_edited_managed_file_is_reported_as_drift_and_left_alone_until_reclaimed()
    {
        var f2b = Integration();
        await f2b.ApplyAsync(await f2b.PlanAsync(Request(Policy), default), default);
        _fs.Files[JailFile] = _fs.Files[JailFile].Replace("maxretry = 3", "maxretry = 99");

        var plan = await f2b.PlanAsync(Request(Policy.Replace("maxretry: 3", "maxretry: 4")), default);
        Assert.DoesNotContain(plan.Changes, c => c.Target == JailFile);
        Assert.Equal(ConfigState.Drifted, plan.ResultingState);
        Assert.Contains(plan.Warnings, w => w.Kind == EventKinds.ConfigDrift);
        Assert.Equal(ConfigState.Drifted, (await f2b.DetectAsync(default)).ConfigState);

        var reclaim = await f2b.PlanAsync(Request(Policy, reclaim: true), default);
        Assert.Contains(reclaim.Changes, c => c.Kind == ChangeKind.WriteFile && c.Target == JailFile);
    }

    [Fact]
    public async Task Foreign_file_at_our_path_is_never_overwritten()
    {
        _fs.Files[JailFile] = "[sshd]\nmaxretry = 2\n";
        var plan = await Integration().PlanAsync(Request(Policy), default);
        Assert.DoesNotContain(plan.Changes, c => c.Target == JailFile);
        Assert.Equal(ConfigState.Conflict, plan.ResultingState);
    }

    [Fact]
    public async Task Jail_configured_by_admin_in_jail_local_is_skipped_unless_takeover()
    {
        _fs.Files["/etc/fail2ban/jail.local"] = "[DEFAULT]\nbantime = 1d\n\n[sshd]\nmaxretry = 10\n";
        var plan = await Integration().PlanAsync(Request(Policy), default);
        var jail = plan.Changes.Single(c => c.Target == JailFile).Content!;
        Assert.DoesNotContain("[sshd]", jail);
        Assert.Contains(plan.Warnings, w => w.Kind == EventKinds.ConfigConflict && w.Message.Contains("jail.local"));
        Assert.Equal(ConfigState.Conflict, plan.ResultingState);

        var takeover = await Integration().PlanAsync(Request(Policy.Replace("maxretry: 3}", "maxretry: 3, takeover: true}")), default);
        Assert.Contains("[sshd]", takeover.Changes.Single(c => c.Target == JailFile).Content!);
    }

    [Fact]
    public async Task Distro_conf_files_are_overridden_without_conflict()
    {
        // defaults-debian.conf is distro config (.conf), not an admin .local override.
        var plan = await Integration().PlanAsync(Request(Policy), default);
        Assert.Empty(plan.Warnings);
    }

    [Fact]
    public async Task Jails_with_missing_filter_or_log_are_skipped_so_fail2ban_keeps_running()
    {
        var yaml = Policy + "\n    nope: {enabled: true}\n    nginx-http-auth: {enabled: true, logpath: /var/log/nginx/error.log}\n";
        var plan = await Integration().PlanAsync(Request(yaml), default);
        var jail = plan.Changes.Single(c => c.Target == JailFile).Content!;
        Assert.DoesNotContain("[nope]", jail);
        Assert.DoesNotContain("[nginx-http-auth]", jail);
        Assert.Equal(2, plan.Warnings.Count(w => w.Kind == EventKinds.ConfigRejected));
    }

    [Fact]
    public async Task Disabled_jail_is_rendered_as_enabled_false()
    {
        var plan = await Integration().PlanAsync(Request("banning:\n  jails:\n    sshd: {enabled: false}\n"), default);
        Assert.Contains("[sshd]\nenabled = false\n", plan.Changes.Single(c => c.Target == JailFile).Content!);
    }

    [Fact]
    public async Task Rejected_config_is_rolled_back_to_the_previous_files()
    {
        var f2b = Integration();
        await f2b.ApplyAsync(await f2b.PlanAsync(Request(Policy), default), default);
        var before = _fs.Files[JailFile];
        _runner.Calls.Clear();

        _testPasses = false;
        var result = await f2b.ApplyAsync(await f2b.PlanAsync(Request(Policy.Replace("nftables", "nope")), default), default);

        Assert.False(result.Success);
        Assert.Equal(ConfigState.Rejected, result.State);
        Assert.Equal(before, _fs.Files[JailFile]);
        Assert.DoesNotContain("fail2ban-client reload", _runner.Calls);
        var e = Assert.Single(result.Events, x => x.Kind == EventKinds.ConfigRejected);
        Assert.Equal(Severity.High, e.Severity);
        Assert.Contains("Unable to read the filter 'nope'", e.Message);
        Assert.Equal(ConfigState.Rejected, (await f2b.DetectAsync(default)).ConfigState);
    }

    [Fact]
    public async Task Rejected_first_apply_removes_the_new_files_entirely()
    {
        _testPasses = false;
        var f2b = Integration();
        await f2b.ApplyAsync(await f2b.PlanAsync(Request(Policy), default), default);
        Assert.False(_fs.FileExists(JailFile));
        Assert.False(_fs.FileExists(FilterFile));
    }

    [Fact]
    public async Task Disabling_banning_removes_only_owned_files()
    {
        var f2b = Integration();
        await f2b.ApplyAsync(await f2b.PlanAsync(Request(Policy), default), default);
        var plan = await f2b.PlanAsync(Request("banning:\n  enabled: false\n"), default);
        Assert.Equal([ChangeKind.DeleteFile, ChangeKind.DeleteFile, ChangeKind.Reload], plan.Changes.Select(c => c.Kind));

        _fs.Files[JailFile] = "hand written";
        var foreign = await f2b.PlanAsync(Request("banning:\n  enabled: false\n"), default);
        Assert.DoesNotContain(foreign.Changes, c => c.Target == JailFile);
    }

    [Fact]
    public async Task Not_running_daemon_is_started_instead_of_reloaded()
    {
        _runner.On("fail2ban-client ping", "", exitCode: 255, stderr: "Failed to access socket path");
        var plan = await Integration().PlanAsync(Request(Policy), default);
        Assert.Equal(ChangeKind.StartService, plan.Changes[^1].Kind);
    }

    [Fact]
    public async Task Detect_reports_unavailable_with_reason_when_tool_missing_and_no_package_manager()
    {
        _runner.Installed.Clear();
        var status = await Integration().DetectAsync(default);
        Assert.False(status.Installed);
        Assert.Equal(Availability.Unavailable, status.Availability);
        Assert.Contains("package manager", status.UnavailableReason);
    }

    [Fact]
    public async Task Existing_install_is_adopted_not_reinstalled()
    {
        var status = await Integration().EnsureInstalledAsync(Request(Policy), default);
        Assert.True(status.Installed);
        Assert.Equal(Ownership.Adopted, status.Ownership);
        Assert.Equal("1.1.0", status.Version);
        Assert.DoesNotContain(_runner.Calls, c => c.StartsWith("apt", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Ban_list_comes_from_fail2ban_client_per_jail()
    {
        _jails = "sentinel-manual, sshd";
        var all = Fixture.Read("fail2ban/client-banip-with-time.txt").Split('\n');
        _runner.On("fail2ban-client get sshd banip --with-time", string.Join('\n', all.Take(4)))
               .On("fail2ban-client get sentinel-manual banip --with-time", all[4]);
        var bans = await Integration().ListBansAsync(default);
        Assert.Equal(5, bans.Count);
        var manual = Assert.Single(bans, b => b.Manual);
        Assert.Equal("2001:db8::/48", manual.Target);
        Assert.Null(manual.ExpiresAt);
    }
}
