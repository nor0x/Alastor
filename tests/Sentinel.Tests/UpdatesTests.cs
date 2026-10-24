using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core.Contracts;
using Sentinel.Core.Events;
using Sentinel.Core.Platform;
using Sentinel.Core.Updates;

namespace Sentinel.Tests;

public class UpdateParserTests
{
    [Fact]
    public void Ubuntu_simulation_marks_packages_from_the_security_pocket()
    {
        var list = UpdateParsers.ParseAptSimulation(Fixture.Read("updates/apt-get-s-dist-upgrade.ubuntu.txt"));
        Assert.Equal(["libaudit-common", "libaudit1", "rust-coreutils", "gpgv"], list.Select(p => p.Name));
        var gpgv = list.Single(p => p.Name == "gpgv");
        Assert.True(gpgv.Security); // listed under resolute-updates *and* resolute-security
        Assert.Equal("2.4.8-4ubuntu3", gpgv.Installed);
        Assert.Equal("2.4.8-4ubuntu3.1", gpgv.Candidate);
        Assert.False(list.Single(p => p.Name == "libaudit1").Security);
        Assert.Equal("1:4.1.2-1build1", list.Single(p => p.Name == "libaudit1").Installed);
    }

    [Fact]
    public void Debian_security_label_counts_as_security()
    {
        var list = UpdateParsers.ParseAptSimulation(Fixture.Read("updates/apt-get-s-dist-upgrade.debian12.txt"));
        Assert.Equal(3, list.Count);
        Assert.Equal(["libssl3", "openssl"], list.Where(p => p.Security == true).Select(p => p.Name));
    }

    [Fact]
    public void Dnf_check_update_skips_the_obsoletes_section()
    {
        var all = UpdateParsers.ParseDnfCheckUpdate(Fixture.Read("updates/dnf-check-update.txt"));
        Assert.Equal(["kernel.x86_64", "openssl-libs.x86_64", "tzdata.noarch"], all.Select(x => x.Name));
        Assert.Equal("1:3.2.2-6.el9_5", all[1].Candidate);
        Assert.Equal("appstream", all[2].Repo);
    }

    [Fact]
    public void Apk_upgradable_list_has_names_versions_and_no_security_flag()
    {
        var list = UpdateParsers.ParseApkUpgradable(Fixture.Read("updates/apk-list-upgradable.txt"));
        Assert.Equal(["busybox", "libcrypto3", "ssl_client"], list.Select(p => p.Name));
        Assert.Equal("3.5.0-r0", list[1].Installed);
        Assert.Equal("3.5.1-r0", list[1].Candidate);
        Assert.All(list, p => Assert.Null(p.Security));
        Assert.Null(new UpdatesReport("apk", list, false, [], null).Security);
    }

    [Fact]
    public void Unattended_upgrade_output_lists_what_it_installs()
    {
        Assert.Equal(["gpgv"], UpdateParsers.ParseUnattendedUpgrade(Fixture.Read("updates/uu-dry-run.txt")));
        Assert.Empty(UpdateParsers.ParseUnattendedUpgrade("No packages found that can be upgraded unattended and no pending auto-removals\n"));
    }
}

public class UpdatesIntegrationTests
{
    private readonly FakeCommandRunner _runner = new();
    private readonly FakeFileSystem _fs = new();
    private readonly InMemoryStateStore _state = new();
    private static readonly OsInfo Ubuntu = new("ubuntu", "26.04", "Ubuntu 26.04", DistroFamily.Debian, "x64");
    private static readonly OsInfo Rocky = new("rocky", "9.5", "Rocky Linux 9.5", DistroFamily.RedHat, "x64");
    private string _simulation = Fixture.Read("updates/apt-get-s-dist-upgrade.ubuntu.txt");

    public UpdatesIntegrationTests()
    {
        _runner.Installed.UnionWith(["apt-get", "unattended-upgrade", "dnf"]);
        _runner.On("apt-get update -q -o DPkg::Lock::Timeout=300", "Hit:1 http://archive.ubuntu.com/ubuntu resolute InRelease")
            .On("apt-get -s -o Debug::NoLocking=1 dist-upgrade", () => new CommandResult(0, _simulation, ""))
            .On("unattended-upgrade -v", () =>
            {
                _simulation = string.Join('\n', _simulation.Split('\n').Where(l => !l.Contains("gpgv", StringComparison.Ordinal)));
                return new CommandResult(0, Fixture.Read("updates/uu-dry-run.txt"), "");
            })
            .On("dpkg-query -W -f=${Status}\t${Version} unattended-upgrades", "install ok installed\t2.12");
    }

    private UpdatesIntegration Integration(OsInfo? os = null) =>
        new(_runner, _fs, PackageManagers.For((os ?? Ubuntu).Family, _runner), _state, os ?? Ubuntu, NullLogger<UpdatesIntegration>.Instance, TimeProvider.System);

    private static async Task<List<SecurityEvent>> Drain(UpdatesIntegration u)
    {
        var list = new List<SecurityEvent>();
        await foreach (var e in u.CollectEventsAsync(default)) list.Add(e);
        return list;
    }

    [Fact]
    public async Task Check_counts_security_updates_and_raises_one_event_per_new_set()
    {
        _fs.Files[UpdatesIntegration.RebootRequiredFile] = "*** System restart required ***\n";
        _fs.Files[UpdatesIntegration.RebootRequiredFile + ".pkgs"] = "linux-image-6.17.0-5-generic\nlinux-base\n";
        var u = Integration();
        var report = await u.CheckAsync(default);
        Assert.True(report.Success);
        Assert.Equal(4, report.Updates!.Pending);
        Assert.Equal(1, report.Updates.Security);
        Assert.True(report.Updates.RebootRequired);
        Assert.Equal(["linux-image-6.17.0-5-generic", "linux-base"], report.Updates.RebootPackages);

        var events = await Drain(u);
        Assert.Contains(events, e => e.Kind == EventKinds.UpdatesPending && e.Message == "1 security update pending: gpgv" && e.Severity == Severity.Medium);
        Assert.Contains(events, e => e.Kind == EventKinds.RebootRequired);

        await u.CheckAsync(default);
        Assert.Empty(await Drain(u)); // same packages, same reboot state: nothing new

        var status = await u.DetectAsync(default);
        Assert.Equal("1", status.Details["security"]);
        Assert.Equal("required", status.Details["reboot"]);
    }

    [Fact]
    public async Task Apply_runs_unattended_upgrade_and_rechecks()
    {
        var u = Integration();
        await u.CheckAsync(default);
        await Drain(u);
        var report = await u.InstallUpdatesAsync(default);
        Assert.True(report.Success);
        Assert.Equal(["gpgv"], report.Updates!.LastApply!.Upgraded);
        Assert.Equal(0, report.Updates.Security);
        Assert.Equal(3, report.Updates.Pending);
        Assert.Contains(await Drain(u), e => e.Kind == EventKinds.UpdatesApplied && e.Message == "Installed 1 update: gpgv");

        // The next scheduled check keeps showing the last apply.
        Assert.NotNull((await u.CheckAsync(default)).Updates!.LastApply);
    }

    [Fact]
    public async Task A_failed_apt_update_is_reported_and_keeps_the_last_list()
    {
        var u = Integration();
        await u.CheckAsync(default);
        _runner.On("apt-get update -q -o DPkg::Lock::Timeout=300", "", 100, "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 812 (apt-get)");
        var failed = await u.CheckAsync(default);
        Assert.False(failed.Success);
        Assert.Contains("Could not get lock", failed.Error);
        Assert.Equal(4, failed.Updates!.Pending);
        Assert.Contains("Could not get lock", (await u.DetectAsync(default)).LastError);
    }

    [Fact]
    public async Task Rhel_uses_dnf_security_metadata_and_needs_restarting()
    {
        _runner.Installed.Add("needs-restarting");
        _runner.On("dnf -q check-update", Fixture.Read("updates/dnf-check-update.txt"), exitCode: 100)
            .On("dnf -q check-update --security", Fixture.Read("updates/dnf-check-update-security.txt"), exitCode: 100)
            .On("needs-restarting -r", "Core libraries or services have been updated since boot-up:\n  * kernel\n", exitCode: 1)
            .On("rpm -q --qf %{VERSION}-%{RELEASE} unattended-upgrades", "", 1);
        var report = await Integration(Rocky).CheckAsync(default);
        Assert.True(report.Success);
        Assert.Equal("dnf", report.Updates!.Manager);
        Assert.Equal(3, report.Updates.Pending);
        Assert.Equal(2, report.Updates.Security);
        Assert.True(report.Updates.RebootRequired);
    }

    [Fact]
    public async Task Dnf_error_exit_code_fails_the_check()
    {
        _runner.On("dnf -q check-update", "", 1, "Error: Failed to download metadata for repo 'baseos'");
        var report = await Integration(Rocky).CheckAsync(default);
        Assert.False(report.Success);
        Assert.Contains("Failed to download metadata", report.Error);
    }
}

[Collection(ServerHostCollection.Name)]
public sealed class UpdatesApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public UpdatesApiTests(ServerApiTests.Factory factory) => _factory = factory;

    [Fact]
    public async Task Reports_update_the_host_and_apply_now_queues_a_job()
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Sentinel-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "u" })).Content.ReadFromJsonAsync<JsonElement>();
        var enroll = await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "db-01", "Ubuntu 26.04", "ubuntu", "26.04", "x64", "0.1.0", null));
        var resp = (await enroll.Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);

        var packages = UpdateParsers.ParseAptSimulation(Fixture.Read("updates/apt-get-s-dist-upgrade.ubuntu.txt"));
        var now = DateTime.UtcNow;
        var report = new AgentReport(UpdatesIntegration.CheckJob, now.AddSeconds(-20), now, true, null)
        {
            Updates = new UpdatesReport("apt", packages, true, ["linux-base"], null),
        };
        Assert.Equal(HttpStatusCode.NoContent, (await agent.PostAsJsonAsync("/api/agent/reports", report, AgentJsonContext.Default.AgentReport)).StatusCode);

        var host = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{resp.AgentId}", Json);
        Assert.Equal(4, host.GetProperty("summary").GetProperty("pendingUpdates").GetInt32());
        Assert.Equal(1, host.GetProperty("summary").GetProperty("securityUpdates").GetInt32());
        Assert.True(host.GetProperty("summary").GetProperty("rebootRequired").GetBoolean());

        var detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{resp.AgentId}/updates", Json);
        Assert.Equal("gpgv", detail.GetProperty("report").GetProperty("packages")[3].GetProperty("name").GetString());
        Assert.Contains(detail.GetProperty("schedules").EnumerateArray(), s => s.GetProperty("key").GetString() == "updates.applySchedule" && s.GetProperty("value").GetString() == "off");

        var fleet = await admin.GetFromJsonAsync<JsonElement>("/api/updates", Json);
        Assert.Contains(fleet.EnumerateArray(), r => r.GetProperty("name").GetString() == "db-01" && r.GetProperty("security").GetInt32() == 1);

        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsJsonAsync("/api/updates/apply", new { hostIds = new[] { resp.AgentId } })).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsync($"/api/hosts/{resp.AgentId}/actions/check-updates", null)).StatusCode);
        var commands = await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json);
        Assert.Equal(["updates.apply", "updates.check"], commands!.Where(c => c.Type == AgentCommandTypes.RunJob).Select(c => c.Payload["job"]));

        // A failed check keeps the last list and records the error.
        var failed = new AgentReport(UpdatesIntegration.CheckJob, now, now, false, "apt-get update failed: E: Could not get lock") { Updates = report.Updates };
        await agent.PostAsJsonAsync("/api/agent/reports", failed, AgentJsonContext.Default.AgentReport);
        detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{resp.AgentId}/updates", Json);
        Assert.False(detail.GetProperty("lastCheckSucceeded").GetBoolean());
        Assert.Equal(4, detail.GetProperty("report").GetProperty("pending").GetInt32());
    }
}
