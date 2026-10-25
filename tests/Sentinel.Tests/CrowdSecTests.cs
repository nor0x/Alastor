using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Core.Integrations.CrowdSec;
using Sentinel.Core.Integrations.Fail2Ban;
using Sentinel.Core.Net;
using Sentinel.Core.Platform;
using Sentinel.Core.Policy;

namespace Sentinel.Tests;

/// <summary>CrowdSec as the opt-in banning engine: cscli's JSON output, the owned allowlist and the Central API switch.</summary>
public class CrowdSecTests
{
    private const string Allowlist = "/etc/crowdsec/parsers/s02-enrich/sentinel-vps-allowlist.yaml";
    private const string DropIn = "/etc/systemd/system/crowdsec.service.d/sentinel-vps.conf";
    private const string Capi = "/etc/crowdsec/online_api_credentials.yaml";

    private readonly FakeFileSystem _fs = new();
    private readonly FakeCommandRunner _runner = new();
    private readonly InMemoryStateStore _state = new();
    private bool _active = true;
    private bool _configOk = true;

    public CrowdSecTests()
    {
        _runner.Installed.UnionWith(["cscli", "crowdsec", "crowdsec-firewall-bouncer", "systemctl"]);
        _runner.On("cscli version", "", stderr: Fixture.Read("crowdsec/version.txt"))
            .On("systemctl is-active --quiet crowdsec", () => new CommandResult(_active ? 0 : 3, "", ""))
            .On("systemctl is-active --quiet crowdsec-firewall-bouncer", "")
            .On("systemctl daemon-reload", "")
            .On("systemctl reload crowdsec", "")
            .On("systemctl restart crowdsec", "")
            .On("systemctl enable --now crowdsec", () => { _active = true; return new CommandResult(0, "", ""); })
            .On("crowdsec -c /etc/crowdsec/config.yaml -t", () => _configOk
                ? new CommandResult(0, "", "")
                : new CommandResult(1, "", "level=fatal msg=\"failed to load parser: yaml: line 4: did not find expected key\""));
    }

    private CrowdSecIntegration Integration(TimeProvider? time = null) => new(_runner, _fs, null, new SystemdServiceManager(_runner), _state,
        NullLogger<CrowdSecIntegration>.Instance, time ?? TimeProvider.System);

    private static ReconcileRequest Request(string yaml, bool reclaim = false)
    {
        var doc = PolicyYaml.Parse(yaml).Document!;
        return new ReconcileRequest(doc, PolicyYaml.Revision(doc)) { Reclaim = reclaim };
    }

    private const string Policy = """
        banning:
          engine: crowdsec
          allowlist: [10.0.0.0/8, 203.0.113.9, "2001:db8::/32"]
        """;

    // ---- parsers (real cscli output) ----

    [Fact]
    public void Parses_decisions_list_from_cscli()
    {
        var alerts = CrowdSecParsers.ParseAlerts(Fixture.Read("crowdsec/decisions-list.json"));
        var decisions = alerts.SelectMany(a => a.Decisions).ToList();
        Assert.Equal(3, decisions.Count);
        var bf = decisions.Single(d => d.Scenario == "crowdsecurity/ssh-bf");
        Assert.Equal(("Ip", "198.51.100.23", "crowdsec", "ban"), (bf.Scope, bf.Value, bf.Origin, bf.Type));
        Assert.InRange(bf.Remaining!.Value.TotalHours, 3.9, 4.1);
        var range = decisions.Single(d => d.Scope == "Range");
        Assert.Equal(("192.0.2.0/24", "cscli"), (range.Value, range.Origin));
        Assert.InRange(range.Remaining!.Value.TotalHours, 23.9, 24);
    }

    [Fact]
    public void Parses_alerts_with_events_and_null_for_empty()
    {
        var alerts = CrowdSecParsers.ParseAlerts(Fixture.Read("crowdsec/alerts-list.json"));
        var bf = alerts.Single(a => a.Scenario == "crowdsecurity/ssh-bf");
        Assert.Equal(6, bf.EventsCount);
        Assert.Equal("198.51.100.23", bf.SourceValue);
        Assert.Equal(new DateTime(2026, 10, 25, 13, 2, 49, DateTimeKind.Utc), bf.CreatedAt);
        Assert.Empty(CrowdSecParsers.ParseAlerts(Fixture.Read("crowdsec/decisions-empty.json")));
    }

    [Theory]
    [InlineData("3h59m51.825539104s", 14391.825539104)]
    [InlineData("4h0m0s", 14400)]
    [InlineData("1.5ms", 0.0015)]
    [InlineData("-2.25s", -2.25)]
    public void Reads_go_durations(string value, double seconds) =>
        Assert.Equal(seconds, CrowdSecParsers.ParseGoDuration(value)!.Value.TotalSeconds, 6);

    [Fact]
    public void Reads_version_and_deleted_count()
    {
        Assert.Equal("1.4.6-10.1-debian", CrowdSecParsers.ParseVersion(Fixture.Read("crowdsec/version.txt")));
        Assert.Equal(1, CrowdSecParsers.ParseDeletedCount(Fixture.Read("crowdsec/decisions-delete.txt")));
        Assert.Equal(0, CrowdSecParsers.ParseDeletedCount(Fixture.Read("crowdsec/decisions-delete-none.txt")));
    }

    [Theory]
    [InlineData(-1, "87600h")]
    [InlineData(3600, "1h")]
    [InlineData(5400, "90m")]
    [InlineData(45, "45s")]
    public void Formats_manual_ban_durations(long seconds, string expected) => Assert.Equal(expected, CrowdSecParsers.FormatDuration(seconds));

    // ---- events ----

    [Fact]
    public void Normalizes_alerts_into_ban_events()
    {
        var events = CrowdSecIntegration.Normalize(CrowdSecParsers.ParseAlerts(Fixture.Read("crowdsec/alerts-list.json"))).ToList();
        Assert.Equal(3, events.Count);
        var bf = events.Single(e => e.Subject == "198.51.100.23");
        Assert.Equal((EventKinds.BanAdded, Severity.Low, "crowdsec"), (bf.Kind, bf.Severity, bf.SourceTool));
        Assert.Equal("Banned 198.51.100.23: crowdsecurity/ssh-bf (6 events)", bf.Message);
        Assert.Equal("4h", bf.Metadata!["duration"]);
        var manual = events.Single(e => e.Subject == "203.0.113.77");
        Assert.Equal((Severity.Info, "true"), (manual.Severity, manual.Metadata!["manual"]));
        // Stable ids: the same alert collected twice is one event.
        Assert.Equal(bf.Id, CrowdSecIntegration.Normalize(CrowdSecParsers.ParseAlerts(Fixture.Read("crowdsec/alerts-list.json"))).Single(e => e.Subject == "198.51.100.23").Id);
    }

    [Fact]
    public void Community_blocklist_pulls_are_not_attacks()
    {
        var alert = new CrowdSecAlert(9, "update : +15000/-0 IPs", "", null, null, 0, DateTime.UtcNow, false,
            [new CrowdSecDecision(1, "ban", "Ip", "198.51.100.1", "CAPI", "crowdsecurity/ssh-bf", TimeSpan.FromDays(1), false)]);
        Assert.Empty(CrowdSecIntegration.Normalize([alert]));
    }

    [Fact]
    public async Task First_poll_remembers_the_position_and_later_polls_emit_only_new_alerts()
    {
        var json = Fixture.Read("crowdsec/alerts-list.json");
        _runner.On("cscli alerts list -o json --since 24h --limit 200", () => new CommandResult(0, json, ""));
        var time = new ManualTime(DateTimeOffset.UtcNow);
        var cs = Integration(time);
        Assert.Empty(await cs.CollectEventsAsync(default).ToListAsync());
        Assert.Equal("3", _state.Get("crowdsec.lastAlertId"));

        // A fourth alert arrives; polling is throttled to every 30 s.
        json = json.TrimEnd().TrimEnd(']') + """, {"id": 4, "scenario": "crowdsecurity/ssh-slow-bf", "message": "m", "events_count": 11, "created_at": "2026-10-25T14:00:00Z", "simulated": false, "source": {"scope": "Ip", "value": "198.51.100.40"}, "decisions": [{"id": 9, "type": "ban", "scope": "Ip", "value": "198.51.100.40", "origin": "crowdsec", "scenario": "crowdsecurity/ssh-slow-bf", "duration": "3h59m0s", "simulated": false}]}]""";
        Assert.Empty(await cs.CollectEventsAsync(default).ToListAsync());
        time.Advance(TimeSpan.FromSeconds(31));
        var e = Assert.Single(await cs.CollectEventsAsync(default).ToListAsync());
        Assert.Equal(("198.51.100.40", EventKinds.BanAdded), (e.Subject, e.Kind));
    }

    // ---- bans ----

    [Fact]
    public async Task Lists_bans_with_expiry_and_manual_flag()
    {
        _runner.On("cscli decisions list -o json", Fixture.Read("crowdsec/decisions-list.json"));
        var bans = await Integration().ListBansAsync(default);
        Assert.Equal(3, bans.Count);
        var bf = bans.Single(b => b.Target == "198.51.100.23");
        Assert.Equal(("crowdsecurity/ssh-bf", false), (bf.Scope, bf.Manual));
        Assert.InRange((bf.ExpiresAt!.Value - DateTime.UtcNow).TotalHours, 3.9, 4.1);
        Assert.True(bans.Single(b => b.Target == "192.0.2.0/24").Manual);
    }

    [Fact]
    public async Task Manual_ban_uses_the_policy_bantime_and_range_flag()
    {
        _runner.On("cscli decisions add --range 192.0.2.0/24 --duration 24h --reason sentinel-vps: scanner --type ban", "", stderr: "level=info msg=\"Decision successfully added\"");
        var cs = Integration();
        await cs.PlanAsync(Request(Policy + "\n  manualBantime: 1d"), default);
        IpTarget.TryParse("192.0.2.0/24", out var t);
        var r = await cs.BanAsync(t!.Value, "scanner", default);
        Assert.True(r.Success, r.Message);

        _runner.On("cscli decisions delete --ip 203.0.113.99", "", stderr: Fixture.Read("crowdsec/decisions-delete-none.txt"));
        IpTarget.TryParse("203.0.113.99", out var u);
        Assert.Equal("203.0.113.99 was not banned", (await cs.UnbanAsync(u!.Value, default)).Message);
    }

    // ---- reconcile ----

    [Fact]
    public async Task Wanted_only_when_the_engine_is_crowdsec()
    {
        var cs = Integration();
        Assert.True(cs.IsWanted(Request(Policy).Policy));
        Assert.False(cs.IsWanted(Request("banning: {engine: fail2ban}").Policy));
        Assert.False(cs.IsWanted(Request("banning: {engine: crowdsec, enabled: false}").Policy));
        Assert.False(new Fail2BanIntegration(_runner, _fs, null, new SystemdServiceManager(_runner), _state, NullLogger<Fail2BanIntegration>.Instance, TimeProvider.System)
            .IsWanted(Request(Policy).Policy));
    }

    [Fact]
    public async Task Fresh_host_writes_allowlist_and_no_capi_drop_in_then_restarts()
    {
        var cs = Integration();
        var plan = await cs.PlanAsync(Request(Policy), default);
        Assert.Equal([Allowlist, DropIn, "crowdsec"], plan.Changes.Select(c => c.Target));
        var allow = plan.Changes[0].Content!;
        Assert.Contains("  ip:\n    - \"203.0.113.9\"\n", allow);
        Assert.Contains("  cidr:\n    - \"10.0.0.0/8\"\n    - \"2001:db8::/32\"\n", allow);
        Assert.Contains("ExecStart=/usr/bin/crowdsec -c /etc/crowdsec/config.yaml -no-capi", plan.Changes[1].Content);

        var result = await cs.ApplyAsync(plan, default);
        Assert.True(result.Success, result.Error);
        Assert.Contains("systemctl daemon-reload", _runner.Calls);
        Assert.Contains("crowdsec -c /etc/crowdsec/config.yaml -t", _runner.Calls);
        Assert.Contains("systemctl restart crowdsec", _runner.Calls);
        Assert.Equal(ManagedFileState.Owned, ManagedFile.Inspect(_fs.Files[Allowlist]).State);

        // Converged: nothing to do on the next pass.
        Assert.True((await cs.PlanAsync(Request(Policy), default)).IsNoop);
    }

    [Fact]
    public async Task Allowlist_change_only_reloads()
    {
        var cs = Integration();
        await cs.ApplyAsync(await cs.PlanAsync(Request(Policy), default), default);
        _runner.Calls.Clear();
        var plan = await cs.PlanAsync(Request(Policy.Replace("203.0.113.9", "203.0.113.10")), default);
        Assert.Equal(["Update CrowdSec allowlist", "Reload CrowdSec"], plan.Changes.Select(c => c.Description));
        Assert.True((await cs.ApplyAsync(plan, default)).Success);
        Assert.DoesNotContain("systemctl daemon-reload", _runner.Calls);
    }

    [Fact]
    public async Task Rejected_config_rolls_back()
    {
        var cs = Integration();
        await cs.ApplyAsync(await cs.PlanAsync(Request(Policy), default), default);
        var before = _fs.Files[Allowlist];
        _configOk = false;
        var result = await cs.ApplyAsync(await cs.PlanAsync(Request(Policy.Replace("203.0.113.9", "203.0.113.10")), default), default);
        Assert.False(result.Success);
        Assert.Equal(ConfigState.Rejected, result.State);
        Assert.Contains("did not find expected key", result.Error);
        Assert.Equal(before, _fs.Files[Allowlist]);
        Assert.DoesNotContain("systemctl reload crowdsec", _runner.Calls);
    }

    [Fact]
    public async Task Hand_edited_allowlist_is_drift_and_foreign_drop_in_is_a_conflict()
    {
        var cs = Integration();
        await cs.ApplyAsync(await cs.PlanAsync(Request(Policy), default), default);
        _fs.Files[Allowlist] += "  # my edit\n";
        _fs.Files[DropIn] = "[Service]\nExecStart=\nExecStart=/usr/bin/crowdsec -c /etc/crowdsec/config.yaml\n";
        var plan = await cs.PlanAsync(Request(Policy), default);
        Assert.Equal(ConfigState.Drifted, plan.ResultingState);
        Assert.Contains(plan.Warnings, w => w.Kind == EventKinds.ConfigDrift && w.Message.Contains(Allowlist));
        Assert.Contains(plan.Warnings, w => w.Kind == EventKinds.ConfigConflict && w.Message.Contains("Central API"));
        Assert.DoesNotContain(plan.Changes, c => c.Kind == ChangeKind.WriteFile);
    }

    [Fact]
    public async Task Central_api_opt_in_removes_the_placeholder_registers_and_removes_the_drop_in()
    {
        var cs = Integration();
        _fs.Files[Capi] = ManagedFile.Render("# off\n", "r0");
        await cs.ApplyAsync(await cs.PlanAsync(Request(Policy), default), default);
        _runner.On("cscli capi register", "", stderr: "level=info msg=\"Successfully registered to Central API (CAPI)\"");
        _runner.Calls.Clear();

        var plan = await cs.PlanAsync(Request(Policy + "\n  crowdsecCentralApi: true"), default);
        Assert.Equal([DropIn, Capi, "crowdsec"], plan.Changes.Select(c => c.Target));
        Assert.True((await cs.ApplyAsync(plan, default)).Success);
        Assert.False(_fs.Files.ContainsKey(DropIn));
        Assert.Contains("cscli capi register", _runner.Calls);
        Assert.Contains("systemctl restart crowdsec", _runner.Calls);
    }

    [Fact]
    public async Task Switching_back_to_fail2ban_removes_the_allowlist_but_keeps_capi_off()
    {
        var cs = Integration();
        await cs.ApplyAsync(await cs.PlanAsync(Request(Policy), default), default);
        var plan = await cs.PlanAsync(Request("banning: {engine: fail2ban}"), default);
        Assert.Equal([Allowlist, "crowdsec"], plan.Changes.Select(c => c.Target));
        await cs.ApplyAsync(plan, default);
        Assert.False(_fs.Files.ContainsKey(Allowlist));
        Assert.True(_fs.Files.ContainsKey(DropIn));
    }

    [Fact]
    public async Task A_bouncer_that_cannot_start_is_reported_without_rolling_back()
    {
        _runner.On("systemctl is-active --quiet crowdsec-firewall-bouncer", "", exitCode: 3)
            .On("systemctl enable --now crowdsec-firewall-bouncer", "", exitCode: 1, stderr: "Job for crowdsec-firewall-bouncer.service failed");
        var cs = Integration();
        var plan = await cs.PlanAsync(Request(Policy), default);
        Assert.Contains(plan.Changes, c => c.Target == "crowdsec-firewall-bouncer");
        var result = await cs.ApplyAsync(plan, default);
        Assert.True(result.Success, result.Error);
        Assert.True(_fs.Files.ContainsKey(Allowlist));
        Assert.Contains(result.Events, e => e.Kind == EventKinds.ToolError && e.Message.Contains("bouncer didn't start"));
    }

    [Fact]
    public async Task Empty_allowlist_writes_no_file()
    {
        var plan = await Integration().PlanAsync(Request("banning: {engine: crowdsec}"), default);
        Assert.DoesNotContain(plan.Changes, c => c.Target == Allowlist);
    }

    [Fact]
    public async Task Detect_reports_a_missing_bouncer()
    {
        _runner.Installed.Remove("crowdsec-firewall-bouncer");
        var s = await Integration().DetectAsync(default);
        Assert.Equal("1.4.6-10.1-debian", s.Version);
        Assert.Contains(s.Warnings, w => w.Contains("No firewall bouncer"));
        var plan = await Integration().PlanAsync(Request(Policy), default);
        Assert.Contains(plan.Warnings, w => w.Message.Contains("crowdsec-firewall-bouncer is not installed"));
    }

    [Fact]
    public async Task Install_seeds_the_capi_file_so_the_package_skips_registration()
    {
        _runner.Installed.Remove("cscli");
        var packages = new RecordingPackages();
        var cs = new CrowdSecIntegration(_runner, _fs, packages, new SystemdServiceManager(_runner), _state, NullLogger<CrowdSecIntegration>.Instance, TimeProvider.System);
        packages.OnInstall = _ => _runner.Installed.Add("cscli");
        await cs.EnsureInstalledAsync(Request(Policy), default);
        Assert.Equal(["crowdsec", "crowdsec-firewall-bouncer"], packages.Installed);
        Assert.Equal(ManagedFileState.Owned, ManagedFile.Inspect(_fs.Files[Capi]).State);
    }

    private sealed class RecordingPackages : IPackageManager
    {
        public List<string> Installed { get; } = [];
        public Action<string>? OnInstall { get; set; }
        public string Name => "apt";
        public Task<bool> IsInstalledAsync(string package, CancellationToken ct) => Task.FromResult(Installed.Contains(package));
        public Task<string?> InstalledVersionAsync(string package, CancellationToken ct) => Task.FromResult<string?>(null);
        public Task<bool> IsAvailableAsync(string package, CancellationToken ct) => Task.FromResult(true);
        public Task<PackageInstallResult> InstallAsync(string package, CancellationToken ct)
        {
            Installed.Add(package);
            OnInstall?.Invoke(package);
            return Task.FromResult(new PackageInstallResult(true, null));
        }
    }

    private sealed class ManualTime(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public void Advance(TimeSpan by) => _now += by;
        public override DateTimeOffset GetUtcNow() => _now;
    }
}
