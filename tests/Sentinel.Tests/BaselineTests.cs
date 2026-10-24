using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core.Baseline;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Core.Platform;
using Sentinel.Core.Policy;

namespace Sentinel.Tests;

/// <summary>Parsers on captured output, the evaluator, lockout guards, and the drop-in lifecycle.</summary>
public class BaselineParserTests
{
    [Fact]
    public void Sshd_T_gives_the_effective_values()
    {
        var sshd = BaselineParsers.ParseSshdT(Fixture.Read("baseline/sshd-T.ubuntu-default.txt"));
        Assert.Equal("prohibit-password", sshd["permitrootlogin"]);
        Assert.Equal("yes", sshd["passwordauthentication"]);
        Assert.Equal("no", sshd["kbdinteractiveauthentication"]);
        Assert.Equal("120", sshd["logingracetime"]);
        Assert.Equal("[::]:22", sshd["listenaddress"]); // repeated keywords keep the first
        Assert.False(sshd.ContainsKey("challengeresponseauthentication")); // OpenSSH 10 prints only the new name
    }

    [Fact]
    public void Sysctl_lines_parse_to_key_values()
    {
        var s = BaselineParsers.ParseSysctl(Fixture.Read("baseline/sysctl.container.txt"));
        Assert.Equal(BaselineProbe.SysctlKeys.Length, s.Count);
        Assert.Equal("2", s["kernel.randomize_va_space"]);
        Assert.Equal("1", s["net.ipv4.conf.default.accept_redirects"]);
    }

    [Theory]
    [InlineData("baseline/ufw-status.active.txt", true)]
    [InlineData("baseline/ufw-status.inactive.txt", false)]
    [InlineData("baseline/ufw-status.no-permission.txt", null)]
    public void Ufw_status(string fixture, bool? expected) => Assert.Equal(expected, BaselineParsers.ParseUfwStatus(Fixture.Read(fixture)));

    [Theory]
    [InlineData("baseline/nft-ruleset.drop-policy.json", true)]
    [InlineData("baseline/nft-ruleset.trailing-drop.json", true)]
    [InlineData("baseline/nft-ruleset.debian-stock.json", false)]
    public void Nft_input_chain_filtering(string fixture, bool expected) => Assert.Equal(expected, BaselineParsers.NftFiltersInput(Fixture.Read(fixture)));

    [Theory]
    [InlineData("baseline/iptables-S-INPUT.drop.txt", true)]
    [InlineData("baseline/iptables-S-INPUT.accept.txt", false)]
    public void Iptables_input_policy(string fixture, bool expected) => Assert.Equal(expected, BaselineParsers.IptablesInputDrops(Fixture.Read(fixture)));

    [Fact]
    public void Apt_config_dump()
    {
        var cfg = BaselineParsers.ParseAptConfig(Fixture.Read("baseline/apt-config-periodic.txt"));
        Assert.Equal("1", cfg["APT::Periodic::Unattended-Upgrade"]);
        Assert.Equal("0", cfg["APT::Periodic::Enable"]);
        Assert.Equal("", cfg["APT::Periodic"]);
    }

    [Fact]
    public void Accounts_and_password_status()
    {
        var accounts = BaselineParsers.ParseGetentPasswd(Fixture.Read("baseline/getent-passwd.txt"));
        Assert.Contains(accounts, a => a is { Name: "root", Uid: 0, Home: "/root" });
        Assert.Single(accounts, a => a.Uid == 0);
        Assert.Empty(BaselineParsers.ParsePasswdStatusNoPassword(Fixture.Read("baseline/passwd-S-a.txt")));
        Assert.Equal(["eve"], BaselineParsers.ParsePasswdStatusNoPassword("root L 2026-09-01 0 99999 7 -1\neve NP 2026-10-01 0 99999 7 -1\n"));
        Assert.Equal(["alice", "bob"], BaselineParsers.ParseGetentGroupMembers("sudo:x:27:alice,bob\nadmin:x:118:alice\n"));
    }

    [Fact]
    public void Timedatectl_show()
    {
        Assert.Equal("yes", BaselineParsers.ParseKeyValues(Fixture.Read("baseline/timedatectl-show.txt"))["NTPSynchronized"]);
    }

    [Theory]
    [InlineData(".ssh/authorized_keys", "/home/alice/.ssh/authorized_keys")]
    [InlineData("/etc/ssh/keys/%u", "/etc/ssh/keys/alice")]
    [InlineData("%h/.ssh/keys%%", "/home/alice/.ssh/keys%")]
    public void Authorized_keys_paths_expand_like_sshd(string pattern, string expected) =>
        Assert.Equal(expected, BaselineParsers.ExpandAuthorizedKeysPath(pattern, new AccountInfo("alice", 1000, "/home/alice", "/bin/bash")));

    [Theory]
    [InlineData("ssh-ed25519 AAAAC3Nza alice@laptop\n", true)]
    [InlineData("# ssh-ed25519 AAAAC3Nza old key\n\n", false)]
    [InlineData("from=\"10.0.0.0/8\" ecdsa-sha2-nistp256 AAAAE2 ci\n", true)]
    [InlineData("", false)]
    public void Authorized_key_detection(string content, bool expected) => Assert.Equal(expected, BaselineParsers.HasAuthorizedKey(content));
}

/// <summary>A fake Ubuntu host built from the captured fixtures, then probed and evaluated end to end.</summary>
public class BaselineIntegrationTests
{
    private readonly FakeFileSystem _fs = new();
    private readonly FakeCommandRunner _runner = new();
    private readonly InMemoryStateStore _state = new();
    private readonly OsInfo _os = new("ubuntu", "26.04", "Ubuntu 26.04 LTS", DistroFamily.Debian, "x64");
    private string _sshdT = Fixture.Read("baseline/sshd-T.ubuntu-default.txt");
    private bool _sshdTestPasses = true;
    private readonly Dictionary<string, string> _sysctl;

    public BaselineIntegrationTests()
    {
        _sysctl = BaselineParsers.ParseSysctl(Fixture.Read("baseline/sysctl.container.txt"));
        foreach (var tool in new[] { "sshd", "sysctl", "ufw", "timedatectl", "systemctl" }) _runner.Installed.Add(tool);
        _runner.Installed.Remove("fail2ban-client");
        _fs.Files[BaselineProbe.SshdConfig] = "Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\n";
        _fs.Files["/root/.ssh/authorized_keys"] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG admin@laptop\n";
        _fs.Files["/etc/shadow"] = "";
        _fs.Files["/etc/passwd"] = "";
        _fs.Modes["/etc/shadow"] = (UnixFileMode)Convert.ToInt32("640", 8);

        _runner.On("sshd -T", () => new CommandResult(0, _sshdT, ""))
            .On("sshd -t", () => new CommandResult(_sshdTestPasses ? 0 : 255, "", _sshdTestPasses ? "" : "/etc/ssh/sshd_config.d/01-sentinel-vps.conf line 3: Bad configuration option"))
            .On($"sysctl -e {string.Join(' ', BaselineProbe.SysctlKeys)}", () => new CommandResult(0, Render(_sysctl), ""))
            .On("ufw status", Fixture.Read("baseline/ufw-status.inactive.txt"))
            .On("dpkg-query -W -f=${Status} unattended-upgrades", "install ok installed")
            .On("apt-config dump APT::Periodic", Fixture.Read("baseline/apt-config-periodic.txt"))
            .On("systemctl is-enabled apt-daily-upgrade.timer", "enabled")
            .On("getent passwd", Fixture.Read("baseline/getent-passwd.txt"))
            .On("getent group sudo wheel admin", "", exitCode: 2)
            .On("passwd -S -a", Fixture.Read("baseline/passwd-S-a.txt"))
            .On("timedatectl show", Fixture.Read("baseline/timedatectl-show.txt"))
            .On("systemctl is-active --quiet ssh", "", exitCode: 3) // socket-activated: ssh.service isn't running
            .On("systemctl is-active --quiet sshd", "", exitCode: 3);
    }

    private static string Render(Dictionary<string, string> values) => string.Concat(values.Select(kv => $"{kv.Key} = {kv.Value}\n"));

    /// <summary>Lets `sysctl -e k1 k2…` (remember) and `sysctl -w k=v` (restore) work for any key subset.</summary>
    private void SysctlFor(IEnumerable<string> keys) =>
        _runner.On($"sysctl -e {string.Join(' ', keys)}", () => new CommandResult(0, Render(keys.Where(_sysctl.ContainsKey).ToDictionary(k => k, k => _sysctl[k])), ""));

    private BaselineIntegration Integration() => new(_runner, _fs, new SystemdServiceManager(_runner), _state, _os,
        NullLogger<BaselineIntegration>.Instance, TimeProvider.System);

    private static PolicyDocument Policy(string yaml) => PolicyYaml.Parse(yaml).Document!;

    private static ReconcileRequest Request(string yaml, bool reclaim = false)
    {
        var doc = Policy(yaml);
        return new ReconcileRequest(doc, PolicyYaml.Revision(doc)) { Reclaim = reclaim };
    }

    private async Task<Dictionary<string, BaselineResult>> RunAsync(string yaml = "{}") =>
        (await Integration().RunChecksAsync(Policy(yaml), "r1", default)).Results.ToDictionary(r => r.CheckId);

    [Fact]
    public async Task Stock_ubuntu_fails_the_expected_checks()
    {
        var r = await RunAsync();
        Assert.Equal(BaselineCatalog.All.Count, r.Count);

        Assert.Equal(CheckStatus.Pass, r["ssh-root-login"].Status);
        Assert.Equal(CheckStatus.Fail, r["ssh-password-auth"].Status);
        Assert.Equal("PasswordAuthentication yes, KbdInteractiveAuthentication no", r["ssh-password-auth"].Actual);
        Assert.Equal(CheckStatus.Fail, r["ssh-max-auth-tries"].Status);
        Assert.Equal(CheckStatus.Fail, r["ssh-login-grace"].Status);
        Assert.Equal(CheckStatus.Fail, r["ssh-x11-forwarding"].Status);
        Assert.Equal(CheckStatus.Pass, r["ssh-empty-passwords"].Status);
        Assert.Equal(CheckStatus.Fail, r["ssh-brute-force-protection"].Status);
        Assert.Equal(CheckStatus.Fail, r["firewall-active"].Status);
        Assert.Equal(CheckStatus.Fail, r["updates-automatic"].Status); // APT::Periodic::Enable "0" in the fixture
        Assert.Contains("APT::Periodic::Enable", r["updates-automatic"].Actual);
        Assert.Equal(CheckStatus.Pass, r["updates-reboot-required"].Status);
        Assert.Equal(CheckStatus.Fail, r["net-redirects"].Status);
        Assert.Contains("net.ipv4.conf.default.accept_redirects = 1", r["net-redirects"].Actual);
        Assert.DoesNotContain("net.ipv4.conf.all.accept_redirects", r["net-redirects"].Actual); // only failing keys are listed
        Assert.Equal(CheckStatus.Pass, r["net-rp-filter"].Status); // loose mode (2) is accepted
        Assert.Equal(CheckStatus.Pass, r["kernel-aslr"].Status);
        Assert.Equal(CheckStatus.Pass, r["accounts-uid0"].Status);
        Assert.Equal(CheckStatus.Pass, r["accounts-empty-password"].Status);
        Assert.Equal(CheckStatus.Pass, r["files-sensitive-permissions"].Status);
        Assert.Equal(CheckStatus.Pass, r["time-sync"].Status);
    }

    [Fact]
    public async Task Failed_checks_carry_host_specific_commands()
    {
        _sshdT = _sshdT.Replace("port 22\n", "port 2222\n");
        var r = await RunAsync();
        Assert.Contains(r["firewall-active"].Commands, c => c.Contains("ufw allow 2222/tcp"));
        Assert.Contains("sshd_config.d/", Assert.Single(r["ssh-x11-forwarding"].Commands));
        Assert.Contains("systemctl reload ssh", r["ssh-x11-forwarding"].Commands[0]); // Debian names the unit "ssh"
        Assert.Contains(r["updates-automatic"].Commands, c => c.Contains("APT::Periodic::Enable"));
        Assert.Empty(r["ssh-root-login"].Commands); // passing checks carry no commands
    }

    [Fact]
    public async Task Missing_ssh_server_makes_ssh_checks_not_applicable()
    {
        _runner.Installed.Remove("sshd");
        var r = await RunAsync();
        Assert.All(BaselineMitigations.SshSettings.Keys, id => Assert.Equal(CheckStatus.NotApplicable, r[id].Status));
        Assert.Equal(CheckStatus.NotApplicable, r["ssh-brute-force-protection"].Status);
    }

    [Fact]
    public async Task Unreadable_firewall_is_unknown_not_failing()
    {
        _runner.On("ufw status", "", exitCode: 1, stderr: Fixture.Read("baseline/ufw-status.no-permission.txt"));
        _runner.Installed.Add("nft");
        _runner.On("nft -j list ruleset", "", exitCode: 1, stderr: Fixture.Read("baseline/nft-ruleset.no-permission.txt"));
        var fw = (await RunAsync())["firewall-active"];
        Assert.Equal(CheckStatus.Unknown, fw.Status);
        Assert.Contains("Operation not permitted", fw.Detail);
    }

    [Fact]
    public async Task Nft_drop_policy_counts_as_a_firewall()
    {
        _runner.Installed.Add("nft");
        _runner.On("nft -j list ruleset", Fixture.Read("baseline/nft-ruleset.drop-policy.json"));
        Assert.Equal(CheckStatus.Pass, (await RunAsync())["firewall-active"].Status);
    }

    [Fact]
    public async Task Bad_permissions_and_uid0_accounts_fail_with_fixes()
    {
        _fs.Modes["/etc/shadow"] = (UnixFileMode)Convert.ToInt32("644", 8);
        _runner.On("getent passwd", Fixture.Read("baseline/getent-passwd.txt") + "toor:x:0:0::/root:/bin/bash\n");
        var r = await RunAsync();
        Assert.Equal("/etc/shadow 644", r["files-sensitive-permissions"].Actual);
        Assert.Contains("sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow", r["files-sensitive-permissions"].Commands);
        Assert.Equal("UID 0: toor", r["accounts-uid0"].Actual);
    }

    [Fact]
    public async Task Ignore_marks_accepted_and_leaves_the_score()
    {
        var before = await Integration().RunChecksAsync(Policy("{}"), null, default);
        var after = await Integration().RunChecksAsync(Policy("baseline:\n  mitigations:\n    firewall-active: ignore\n"), null, default);
        Assert.True(after.Results.Single(r => r.CheckId == "firewall-active").Accepted);
        Assert.True(BaselineScore.Compute(after.Results) > BaselineScore.Compute(before.Results));
    }

    [Fact]
    public void Score_is_severity_weighted_and_skips_unknown()
    {
        BaselineResult R(string id, CheckStatus s) => new(id, s, "");
        Assert.Equal(100, BaselineScore.Compute([R("ssh-password-auth", CheckStatus.Pass), R("firewall-active", CheckStatus.Unknown)]));
        // High (6) passes, Low (1) fails: 6/7.
        Assert.Equal(86, BaselineScore.Compute([R("ssh-password-auth", CheckStatus.Pass), R("ssh-x11-forwarding", CheckStatus.Fail)]));
        Assert.Null(BaselineScore.Compute([R("firewall-active", CheckStatus.NotApplicable)]));
    }

    [Fact]
    public async Task First_run_summarizes_then_only_transitions_raise_events()
    {
        var baseline = Integration();
        await baseline.RunChecksAsync(Policy("{}"), null, default);
        var first = await Drain(baseline);
        var summary = Assert.Single(first);
        Assert.Equal(EventKinds.BaselineSummary, summary.Kind);
        Assert.Contains("checks fail", summary.Message);

        await baseline.RunChecksAsync(Policy("{}"), null, default);
        Assert.Empty(await Drain(baseline)); // nothing changed

        _sshdT = _sshdT.Replace("x11forwarding yes", "x11forwarding no").Replace("permitrootlogin prohibit-password", "permitrootlogin yes");
        await baseline.RunChecksAsync(Policy("{}"), null, default);
        var events = await Drain(baseline);
        Assert.Contains(events, e => e.Kind == EventKinds.BaselineResolved && e.Subject == "ssh-x11-forwarding");
        var failed = Assert.Single(events, e => e.Kind == EventKinds.BaselineFailed);
        Assert.Equal("ssh-root-login", failed.Subject);
        Assert.Equal(Severity.High, failed.Severity);
    }

    private static async Task<List<SecurityEvent>> Drain(BaselineIntegration b)
    {
        var list = new List<SecurityEvent>();
        await foreach (var e in b.CollectEventsAsync(default)) list.Add(e);
        return list;
    }

    // ---- fixes: drop-ins, lockout guards, rollback ----

    private const string ApplySsh = """
        baseline:
          mitigations:
            ssh-password-auth: apply
            ssh-x11-forwarding: apply
            ssh-max-auth-tries: apply
        """;

    [Fact]
    public async Task Applying_ssh_fixes_writes_a_validated_drop_in()
    {
        var b = Integration();
        var plan = await b.PlanAsync(Request(ApplySsh), default);
        var write = Assert.Single(plan.Changes, c => c.Kind == ChangeKind.WriteFile);
        Assert.Equal(BaselineMitigations.SshdDropIn, write.Target);
        Assert.Contains("PasswordAuthentication no\nKbdInteractiveAuthentication no\n", write.Content);
        Assert.DoesNotContain("ChallengeResponseAuthentication", write.Content); // this sshd doesn't know the old name
        Assert.Contains("MaxAuthTries 3\n", write.Content);
        Assert.Contains("X11Forwarding no\n", write.Content);
        Assert.DoesNotContain(plan.Changes, c => c.Target == BaselineMitigations.SysctlDropIn);

        var result = await b.ApplyAsync(plan, default);
        Assert.True(result.Success, result.Error);
        Assert.Contains("sshd -t", _runner.Calls);
        Assert.True(ManagedFile.Inspect(_fs.Files[BaselineMitigations.SshdDropIn]).State == ManagedFileState.Owned);
        Assert.Empty((await b.PlanAsync(Request(ApplySsh), default)).Changes); // idempotent
    }

    [Fact]
    public async Task Older_sshd_gets_the_old_keyword()
    {
        _sshdT = _sshdT.Replace("kbdinteractiveauthentication no", "challengeresponseauthentication no");
        var plan = await Integration().PlanAsync(Request(ApplySsh), default);
        var content = plan.Changes.Single(c => c.Kind == ChangeKind.WriteFile).Content!;
        Assert.Contains("ChallengeResponseAuthentication no", content);
        Assert.DoesNotContain("KbdInteractiveAuthentication", content);
    }

    [Fact]
    public async Task Password_auth_is_refused_without_an_admin_key()
    {
        _fs.Files.Remove("/root/.ssh/authorized_keys");
        var plan = await Integration().PlanAsync(Request(ApplySsh), default);
        Assert.Contains(plan.Warnings, w => w.Kind == EventKinds.ConfigRejected && w.Message.Contains("lock everyone out"));
        var content = plan.Changes.Single(c => c.Kind == ChangeKind.WriteFile).Content!;
        Assert.DoesNotContain("PasswordAuthentication", content); // the other fixes still go ahead
        Assert.Contains("X11Forwarding no", content);
    }

    [Fact]
    public async Task A_sudo_user_with_a_key_satisfies_the_lockout_guard()
    {
        _fs.Files.Remove("/root/.ssh/authorized_keys");
        _runner.On("getent passwd", Fixture.Read("baseline/getent-passwd.txt") + "alice:x:1000:1000::/home/alice:/bin/bash\n");
        _runner.On("getent group sudo wheel admin", "sudo:x:27:alice\n");
        _fs.Files["/home/alice/.ssh/authorized_keys"] = "ssh-ed25519 AAAAC3Nza alice@laptop\n";
        var plan = await Integration().PlanAsync(Request(ApplySsh), default);
        Assert.Empty(plan.Warnings);
        Assert.Contains("PasswordAuthentication no", plan.Changes.Single(c => c.Kind == ChangeKind.WriteFile).Content);
    }

    [Fact]
    public async Task Rejected_sshd_config_is_rolled_back()
    {
        _sshdTestPasses = false;
        var b = Integration();
        var result = await b.ApplyAsync(await b.PlanAsync(Request(ApplySsh), default), default);
        Assert.False(result.Success);
        Assert.Equal(ConfigState.Rejected, result.State);
        Assert.False(_fs.Files.ContainsKey(BaselineMitigations.SshdDropIn));
        Assert.DoesNotContain(_runner.Calls, c => c.StartsWith("systemctl reload", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Hand_edited_drop_in_is_not_overwritten()
    {
        var b = Integration();
        await b.ApplyAsync(await b.PlanAsync(Request(ApplySsh), default), default);
        _fs.Files[BaselineMitigations.SshdDropIn] += "PermitRootLogin yes\n";
        var plan = await b.PlanAsync(Request(ApplySsh + "\n    ssh-login-grace: apply\n"), default);
        Assert.Empty(plan.Changes);
        Assert.Equal(ConfigState.Drifted, plan.ResultingState);
        var reclaim = await b.PlanAsync(Request(ApplySsh + "\n    ssh-login-grace: apply\n", reclaim: true), default);
        Assert.Contains("LoginGraceTime 30", reclaim.Changes.Single(c => c.Kind == ChangeKind.WriteFile).Content);
    }

    [Fact]
    public async Task Foreign_file_at_the_drop_in_path_is_left_alone()
    {
        _fs.Files[BaselineMitigations.SshdDropIn] = "# mine\nPasswordAuthentication yes\n";
        var plan = await Integration().PlanAsync(Request(ApplySsh), default);
        Assert.Empty(plan.Changes);
        Assert.Equal(ConfigState.Conflict, plan.ResultingState);
    }

    [Fact]
    public async Task Sysctl_fix_remembers_and_restores_previous_values()
    {
        var keys = BaselineMitigations.SysctlSettings["net-redirects"].Keys.ToList();
        SysctlFor(keys);
        var before = keys.ToDictionary(k => k, k => _sysctl[k]);
        _runner.On("sysctl -p " + BaselineMitigations.SysctlDropIn, () =>
        {
            foreach (var (k, v) in BaselineParsers.ParseSysctl(_fs.Files[BaselineMitigations.SysctlDropIn])) _sysctl[k] = v;
            return new CommandResult(0, "", "");
        });
        foreach (var k in keys) _runner.On($"sysctl -w {k}={before[k]}", "");

        var b = Integration();
        var apply = "baseline:\n  mitigations:\n    net-redirects: apply\n";
        var plan = await b.PlanAsync(Request(apply), default);
        var content = plan.Changes.Single(c => c.Kind == ChangeKind.WriteFile).Content!;
        Assert.Contains("net.ipv4.conf.default.send_redirects = 0", content);
        var applied = await b.ApplyAsync(plan, default);
        Assert.True(applied.Success);
        Assert.DoesNotContain(applied.Events, e => e.Kind == EventKinds.ConfigRejected);
        Assert.Contains("sysctl -p " + BaselineMitigations.SysctlDropIn, _runner.Calls);
        Assert.Equal("0", _sysctl["net.ipv4.conf.default.accept_redirects"]);

        // Dropping the fix deletes the file and puts the old runtime values back.
        var remove = await b.PlanAsync(Request("{}"), default);
        Assert.Equal(ChangeKind.DeleteFile, remove.Changes[0].Kind);
        Assert.True((await b.ApplyAsync(remove, default)).Success);
        Assert.False(_fs.Files.ContainsKey(BaselineMitigations.SysctlDropIn));
        Assert.Contains("sysctl -w net.ipv4.conf.default.accept_redirects=1", _runner.Calls);
        Assert.Contains("sysctl -w net.ipv4.conf.all.accept_redirects=0", _runner.Calls);
    }

    [Fact]
    public async Task Read_only_proc_sys_is_reported_not_silently_passed()
    {
        // Containers and LXC/OpenVZ VPS: `sysctl -p` prints "ignoring: Read-only file system" and still exits 0.
        var keys = BaselineMitigations.SysctlSettings["net-redirects"].Keys.ToList();
        SysctlFor(keys);
        _runner.On("sysctl -p " + BaselineMitigations.SysctlDropIn, "", stderr: "sysctl: setting key \"net.ipv4.conf.all.accept_redirects\", ignoring: Read-only file system\n");
        var apply = "baseline:\n  mitigations:\n    net-redirects: apply\n";
        var b = Integration();
        var result = await b.ApplyAsync(await b.PlanAsync(Request(apply), default), default);
        Assert.True(result.Success); // the drop-in is right; the kernel is the problem
        var warning = Assert.Single(result.Events, e => e.Kind == EventKinds.ConfigRejected);
        Assert.Contains("net.ipv4.conf.default.accept_redirects", warning.Message);
        Assert.DoesNotContain("net.ipv4.conf.all.accept_redirects", warning.Message); // already 0, so not refused

        var check = (await b.RunChecksAsync(Policy(apply), null, default)).Results.Single(r => r.CheckId == "net-redirects");
        Assert.Equal(CheckStatus.Fail, check.Status);
        Assert.Contains("read-only", check.Detail);
    }

    [Fact]
    public async Task Sysctl_keys_the_kernel_lacks_are_left_out()
    {
        foreach (var k in _sysctl.Keys.Where(k => k.StartsWith("net.ipv6.", StringComparison.Ordinal)).ToList()) _sysctl.Remove(k);
        var plan = await Integration().PlanAsync(Request("baseline:\n  mitigations:\n    net-redirects: apply\n"), default);
        Assert.DoesNotContain("ipv6", plan.Changes.Single(c => c.Kind == ChangeKind.WriteFile).Content);
    }

    [Fact]
    public async Task Uninstall_removes_owned_drop_ins()
    {
        var b = Integration();
        await b.ApplyAsync(await b.PlanAsync(Request(ApplySsh), default), default);
        await b.RemoveManagedStateAsync(default);
        Assert.False(_fs.Files.ContainsKey(BaselineMitigations.SshdDropIn));
    }

    [Fact]
    public async Task Enforced_fix_that_still_fails_explains_why()
    {
        var r = await RunAsync("baseline:\n  mitigations:\n    ssh-x11-forwarding: apply\n");
        Assert.True(r["ssh-x11-forwarding"].Enforced);
        Assert.Contains("still fails", r["ssh-x11-forwarding"].Detail);
    }
}

public class BaselinePolicyTests
{
    [Theory]
    [InlineData("baseline:\n  mitigations:\n    ssh-telnet: apply\n", "Unknown baseline check")]
    [InlineData("baseline:\n  mitigations:\n    ssh-x11-forwarding: yes-please\n", "baseline.mitigations.ssh-x11-forwarding")]
    [InlineData("baseline:\n  mitigations:\n    firewall-active: apply\n", "can't be applied automatically")]
    [InlineData("baseline:\n  mitigations:\n    ssh-brute-force-protection: apply\n", "banning.jails.sshd.enabled")]
    [InlineData("baseline:\n  checkSchedule: every 3 fortnights\n", "baseline.checkSchedule")]
    public void Invalid_baseline_policy_is_rejected(string yaml, string expected)
    {
        var r = PolicyYaml.Parse(yaml);
        Assert.False(r.IsValid);
        Assert.Contains(r.Issues, i => i.Level == IssueLevel.Error && (i.Message.Contains(expected) || i.Path == expected));
    }

    [Fact]
    public void Ignore_and_report_are_valid_for_manual_checks()
    {
        Assert.True(PolicyYaml.Parse("baseline:\n  mitigations:\n    firewall-active: ignore\n    updates-automatic: report\n").IsValid);
    }

    [Fact]
    public void Mitigations_merge_key_by_key_and_report_overrides_a_lower_layer()
    {
        var global = PolicyYaml.Parse("baseline:\n  checkSchedule: every 6h\n  mitigations:\n    ssh-x11-forwarding: apply\n    kernel-aslr: apply\n").Document!;
        var host = PolicyYaml.Parse("baseline:\n  mitigations:\n    kernel-aslr: report\n    firewall-active: ignore\n").Document!;
        var merged = PolicyMerger.MergeLayers([global, host]);
        Assert.Equal("every 6h", merged.Baseline!.CheckSchedule);
        Assert.Equal(["ssh-x11-forwarding"], BaselineMitigations.WithValue(merged, BaselineMitigationValues.Apply));
        Assert.Equal(["firewall-active"], BaselineMitigations.WithValue(merged, BaselineMitigationValues.Ignore));
    }

    [Fact]
    public void Revision_ignores_mitigation_order()
    {
        var a = PolicyYaml.Parse("baseline:\n  mitigations:\n    kernel-aslr: apply\n    ssh-x11-forwarding: apply\n").Document!;
        var b = PolicyYaml.Parse("baseline:\n  mitigations:\n    ssh-x11-forwarding: apply\n    kernel-aslr: apply\n").Document!;
        Assert.Equal(PolicyYaml.Revision(a), PolicyYaml.Revision(b));
    }

    [Fact]
    public void Every_policy_fix_has_settings_and_every_check_is_evaluated()
    {
        foreach (var c in BaselineCatalog.All.Where(c => c.Fix == FixKind.Policy && c.PolicyPath[0] == "baseline"))
            Assert.True(BaselineMitigations.SshSettings.ContainsKey(c.Id) || BaselineMitigations.SysctlSettings.ContainsKey(c.Id), c.Id);
        Assert.Equal(BaselineCatalog.All.Count, BaselineCatalog.All.Select(c => c.Id).Distinct().Count());
        var results = BaselineEvaluator.Evaluate(new BaselineFacts(), new PolicyDocument());
        Assert.DoesNotContain(results, r => r.Actual == "Not evaluated");
    }
}
