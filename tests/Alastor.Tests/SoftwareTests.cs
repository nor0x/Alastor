using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Platform;
using Alastor.Core.Software;
using Alastor.Core.Updates;
using Alastor.Core.Vulnerabilities;
using Alastor.Server.Data;
using Alastor.Server.Services.Osv;

namespace Alastor.Tests;

public class SoftwareParserTests
{
    [Fact]
    public void Dpkg_inventory_reads_manual_essential_and_source_packages()
    {
        var manual = SoftwareParsers.ParseNameList(Fixture.Read("software/apt-mark-showmanual.ubuntu2404.txt"));
        var list = SoftwareParsers.ParseDpkgQuery(Fixture.Read("software/dpkg-query.ubuntu2404.txt"), manual);
        Assert.Equal(527, list.Count);
        Assert.Equal(19, list.Count(p => p.Manual));

        var bash = list.Single(p => p.Name == "bash");
        Assert.True(bash.Manual);
        Assert.True(bash.Protected); // Essential: yes
        Assert.Equal(1900, bash.SizeKb);
        Assert.Equal("5.2.21-2ubuntu4", bash.Version);

        var libssl = list.Single(p => p.Name == "libssl3t64");
        Assert.Equal("openssl", libssl.Source);
        Assert.False(libssl.Manual);
        Assert.False(libssl.Protected);
        Assert.Equal("glibc", list.Single(p => p.Name == "libc6").Source);
        Assert.True(list.Single(p => p.Name == "libc6").Protected); // by name: Ubuntu marks it optional
        Assert.Equal("curl", list.Single(p => p.Name == "curl").Source); // empty Source field = same name
        Assert.True(list.Single(p => p.Name == "sudo").Protected);
    }

    [Fact]
    public void Dpkg_inventory_skips_removed_packages_with_config_left()
    {
        var list = SoftwareParsers.ParseDpkgQuery("nginx\t1.24.0-2\tamd64\trc \t0\toptional\tno\t\ncurl\t8.5.0\tamd64\tii \t521\toptional\tno\t\n", new HashSet<string>());
        Assert.Equal(["curl"], list.Select(p => p.Name));
    }

    [Fact]
    public void Rpm_inventory_skips_signing_keys_and_reads_the_source_rpm()
    {
        var manual = SoftwareParsers.ParseNameList(Fixture.Read("software/dnf-repoquery-userinstalled.dnf4.txt"));
        Assert.Equal(["nginx", "bash", "openssh-server"], manual);
        var list = SoftwareParsers.ParseRpmQuery(Fixture.Read("software/rpm-qa.rocky9.txt"), manual);
        Assert.DoesNotContain(list, p => p.Name == "gpg-pubkey");
        var core = list.Single(p => p.Name == "nginx-core");
        Assert.Equal("2:1.20.1-16.el9_4.1", core.Version);
        Assert.Equal("nginx", core.Source);
        Assert.False(core.Manual);
        Assert.Equal(1621, core.SizeKb);
        Assert.Equal("openssl", list.Single(p => p.Name == "openssl-libs").Source);
        Assert.True(list.Single(p => p.Name == "openssh-server").Protected);
        Assert.True(list.Single(p => p.Name == "nginx").Manual);
    }

    [Fact]
    public void Apk_inventory_reads_origins_and_the_world_file()
    {
        var world = SoftwareParsers.ParseApkWorld(Fixture.Read("software/apk-world.txt"));
        Assert.Equal(["alpine-base", "nginx", "py3-setuptools"], world.Order());
        var list = SoftwareParsers.ParseApkInstalled(Fixture.Read("software/apk-list-installed.txt"), world);
        Assert.Equal(7, list.Count);
        Assert.Equal("3.3.2-r0", list.Single(p => p.Name == "libssl3").Version);
        Assert.Equal("openssl", list.Single(p => p.Name == "libcrypto3").Source);
        Assert.True(list.Single(p => p.Name == "nginx").Manual);
        Assert.True(list.Single(p => p.Name == "musl").Protected);
    }

    [Fact]
    public void Apt_simulations_list_upgrades_and_removals()
    {
        var up = SoftwareParsers.ParseAptPlan(Fixture.Read("software/apt-get-s-upgrade.ubuntu2404.txt"));
        Assert.Equal([("libapparmor1", "upgrade"), ("apparmor", "upgrade")], up.Select(c => (c.Name, c.Action)));
        Assert.Equal("4.0.1really4.0.1-0ubuntu0.24.04.3", up[1].From);
        Assert.Equal("4.0.1really4.0.1-0ubuntu0.24.04.9", up[1].To);

        var rm = SoftwareParsers.ParseAptPlan(Fixture.Read("software/apt-get-s-remove.ubuntu2404.txt"));
        Assert.Equal([new PlannedPackage("ubuntu-wsl", "remove", "1.539.1", null), new PlannedPackage("curl", "remove", "8.5.0-2ubuntu10.6", null)], rm);
        Assert.Empty(SoftwareParsers.ParseAptPlan(Fixture.Read("software/apt-get-s-remove-broken.ubuntu2404.txt")));
    }

    [Fact]
    public void Dnf_transaction_tables_from_dnf4_and_dnf5()
    {
        var rm = SoftwareParsers.ParseDnfPlan(Fixture.Read("software/dnf-assumeno-remove.dnf4.txt"));
        Assert.Equal(["nginx", "nginx-mod-http-perl-and-a-very-long-module-name", "nginx-core", "nginx-filesystem"], rm.Select(c => c.Name));
        Assert.All(rm, c => Assert.Equal("remove", c.Action));
        Assert.Equal("2:1.20.1-16.el9_4.1", rm[1].From); // the wrapped line

        var up = SoftwareParsers.ParseDnfPlan(Fixture.Read("software/dnf-assumeno-upgrade.dnf5.txt"));
        Assert.Equal([new PlannedPackage("openssl-libs", "upgrade", "1:3.2.2-5.fc41", "1:3.2.2-6.fc41"), new PlannedPackage("crypto-policies-scripts", "install", null, "20240828-1.git1.fc41")], up);
    }

    [Fact]
    public void Apk_simulations_list_purges_and_upgrades()
    {
        var rm = SoftwareParsers.ParseApkPlan(Fixture.Read("software/apk-del-simulate.txt"));
        Assert.Equal(["nginx", "pcre2", "libssl3"], rm.Select(c => c.Name));
        Assert.Equal("1.26.2-r0", rm[0].From);
        var up = SoftwareParsers.ParseApkPlan(Fixture.Read("software/apk-upgrade-simulate.txt"));
        Assert.Equal(new PlannedPackage("nginx", "upgrade", "1.26.2-r0", "1.26.2-r1"), up[1]);
    }

    [Theory]
    [InlineData("openssl-3.0.7-27.el9.src.rpm", "openssl")]
    [InlineData("python-dateutil-2.8.1-7.el9.src.rpm", "python-dateutil")]
    [InlineData("(none)", null)]
    public void Source_rpm_names(string srpm, string? expected) => Assert.Equal(expected, SoftwareParsers.SourceFromSrpm(srpm));

    [Theory]
    [InlineData("nginx", true)]
    [InlineData("libstdc++6", true)]
    [InlineData("python3.12", true)]
    [InlineData("libc6:i386", true)]
    [InlineData("-o", false)]
    [InlineData("--allow-remove-essential", false)]
    [InlineData("a b", false)]
    [InlineData("curl;reboot", false)]
    [InlineData("", false)]
    public void Package_names_never_become_options(string name, bool valid) => Assert.Equal(valid, PackageOps.IsValidName(name));

    [Fact]
    public void Commands_are_argument_lists_and_the_shown_command_matches()
    {
        var run = PackageCommands.Run("apt", PackageOps.Remove, "curl")!;
        Assert.Equal("apt-get", run.FileName);
        Assert.Equal("curl", run.Args[^1]);
        Assert.DoesNotContain("--allow-remove-essential", run.Args);
        Assert.StartsWith("sudo apt-get remove curl  #", PackageCommands.Display("apt", PackageOps.Remove, "curl"));
        Assert.Equal("sudo dnf upgrade nginx", PackageCommands.Display("dnf", PackageOps.Upgrade, "nginx"));
        Assert.Null(PackageCommands.Run("zypper", PackageOps.Upgrade, "nginx"));
    }
}

public class SoftwareIntegrationTests
{
    private readonly FakeCommandRunner _runner = new();
    private readonly FakeFileSystem _fs = new();
    private readonly InMemoryStateStore _state = new();
    private static readonly OsInfo Ubuntu = new("ubuntu", "24.04", "Ubuntu 24.04.1 LTS", DistroFamily.Debian, "x64");
    private string _dpkg = Fixture.Read("software/dpkg-query.ubuntu2404.txt");

    private const string AptUpgradeApparmor = "apt-get install -y -q --only-upgrade -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold apparmor";
    private const string SimRemoveCurl = "apt-get -s -o Debug::NoLocking=1 remove curl";

    public SoftwareIntegrationTests()
    {
        _runner.Installed.UnionWith(["dpkg-query", "apt-mark", "apt-get"]);
        _runner.On("dpkg-query -W -f=" + SoftwareParsers.DpkgFormat, () => new CommandResult(0, _dpkg, ""))
            .On("apt-mark showmanual", Fixture.Read("software/apt-mark-showmanual.ubuntu2404.txt"))
            .On("apt-get -s -o Debug::NoLocking=1 install --only-upgrade apparmor", Fixture.Read("software/apt-get-s-upgrade.ubuntu2404.txt"))
            .On(SimRemoveCurl, Fixture.Read("software/apt-get-s-remove.ubuntu2404.txt"))
            .On("apt-get -s -o Debug::NoLocking=1 remove libssl3t64", Fixture.Read("software/apt-get-s-remove-broken.ubuntu2404.txt"), exitCode: 100)
            .On("apt-get update -q -o DPkg::Lock::Timeout=300", "Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease")
            .On(AptUpgradeApparmor, () =>
            {
                _dpkg = _dpkg.Replace("apparmor\t4.0.1really4.0.1-0ubuntu0.24.04.3", "apparmor\t4.0.1really4.0.1-0ubuntu0.24.04.9", StringComparison.Ordinal);
                return new CommandResult(0, "Setting up apparmor (4.0.1really4.0.1-0ubuntu0.24.04.9) ...", "");
            });
    }

    private SoftwareIntegration Integration() => new(_runner, _fs, _state, Ubuntu, NullLogger<SoftwareIntegration>.Instance, TimeProvider.System);

    private static async Task<List<SecurityEvent>> Drain(SoftwareIntegration s)
    {
        var list = new List<SecurityEvent>();
        await foreach (var e in s.CollectEventsAsync(default)) list.Add(e);
        return list;
    }

    [Fact]
    public async Task Inventory_reports_every_package_and_the_tool_status()
    {
        var s = Integration();
        var report = await s.InventoryAsync(default);
        Assert.True(report.Success);
        Assert.Equal("apt", report.Software!.Manager);
        Assert.Equal(527, report.Software.Packages.Count);
        Assert.Equal("19", (await s.DetectAsync(default)).Details["manual"]);
    }

    [Fact]
    public async Task Inventory_failure_is_reported_not_thrown()
    {
        _runner.On("dpkg-query -W -f=" + SoftwareParsers.DpkgFormat, "", 2, "dpkg-query: error: database is locked");
        var report = await Integration().InventoryAsync(default);
        Assert.False(report.Success);
        Assert.Contains("database is locked", report.Error);
    }

    [Fact]
    public async Task Preview_shows_what_an_upgrade_pulls_along()
    {
        var s = Integration();
        await s.InventoryAsync(default);
        var plan = await s.PreviewAsync(PackageOps.Upgrade, "apparmor", default);
        Assert.True(plan.Success);
        Assert.Empty(plan.Blocked);
        Assert.Equal(["libapparmor1", "apparmor"], plan.Changes.Select(c => c.Name));
    }

    [Fact]
    public async Task Removing_a_protected_package_is_blocked_without_asking_apt()
    {
        var s = Integration();
        await s.InventoryAsync(default);
        var plan = await s.PreviewAsync(PackageOps.Remove, "sudo", default);
        Assert.Equal(["sudo"], plan.Blocked);
        Assert.DoesNotContain(_runner.Calls, c => c.Contains("remove sudo", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_removal_that_takes_a_protected_package_along_is_blocked_and_never_run()
    {
        _runner.On(SimRemoveCurl, "Remv openssh-server [1:9.6p1-3ubuntu13.5]\nRemv curl [8.5.0-2ubuntu10.6]\n");
        var s = Integration();
        await s.InventoryAsync(default);
        Assert.Equal(["openssh-server"], (await s.PreviewAsync(PackageOps.Remove, "curl", default)).Blocked);

        var result = await s.RunActionAsync(PackageOps.Remove, "curl", default);
        Assert.False(result.Success);
        Assert.Contains("Refused", result.Software!.LastAction!.Error);
        Assert.DoesNotContain(_runner.Calls, c => c.StartsWith("apt-get remove", StringComparison.Ordinal));
        Assert.Contains(await Drain(s), e => e.Kind == EventKinds.SoftwareFailed);
    }

    [Fact]
    public async Task A_dry_run_apt_refuses_comes_back_as_a_failed_plan()
    {
        var s = Integration();
        await s.InventoryAsync(default);
        var plan = await s.PreviewAsync(PackageOps.Remove, "libssl3t64", default);
        Assert.False(plan.Success);
        Assert.Contains("pkgProblemResolver", plan.Error);
    }

    [Fact]
    public async Task Packages_that_are_not_installed_or_badly_named_are_rejected()
    {
        var s = Integration();
        Assert.Contains("not installed", (await s.PreviewAsync(PackageOps.Upgrade, "nosuchpackage", default)).Error);
        var bad = await s.RunActionAsync(PackageOps.Upgrade, "--fix-broken", default);
        Assert.False(bad.Success);
        Assert.DoesNotContain(_runner.Calls, c => c.Contains("--fix-broken", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Upgrade_runs_apt_then_reports_the_new_inventory_and_versions()
    {
        var s = Integration();
        await s.InventoryAsync(default);
        var result = await s.RunActionAsync(PackageOps.Upgrade, "apparmor", default);
        Assert.True(result.Success);
        Assert.Equal(SoftwareIntegration.ActionJob, result.JobId);
        var action = result.Software!.LastAction!;
        Assert.Equal("4.0.1really4.0.1-0ubuntu0.24.04.3", action.From);
        Assert.Equal("4.0.1really4.0.1-0ubuntu0.24.04.9", action.To);
        Assert.Equal("4.0.1really4.0.1-0ubuntu0.24.04.9", result.Software.Packages.Single(p => p.Name == "apparmor").Version);
        Assert.Contains(AptUpgradeApparmor, _runner.Calls);
        Assert.Contains(await Drain(s), e => e.Kind == EventKinds.SoftwareUpgraded && e.Subject == "apparmor");

        // The next scheduled inventory still carries the outcome.
        Assert.Equal("apparmor", (await s.InventoryAsync(default)).Software!.LastAction!.Package);
    }
}

public class OsvTests
{
    [Fact]
    public void Querybatch_answers_line_up_with_the_queries()
    {
        var results = OsvParsers.ParseQueryBatch(Fixture.Read("software/osv-querybatch.json"));
        Assert.Equal([41, 48, 41, 0], results.Select(r => r.Count));
        Assert.Equal("UBUNTU-CVE-2025-15467", results[0][0].Id);
        Assert.NotNull(results[0][0].Modified);
    }

    [Fact]
    public void Ubuntu_records_use_ubuntus_rating_and_name_the_cve_upstream()
    {
        var a = OsvParsers.ParseVuln(Fixture.Read("software/osv-vuln.ubuntu-cve.json"));
        Assert.Equal("UBUNTU-CVE-2025-15467", a.Id);
        Assert.Contains("CVE-2025-15467", a.Aliases);
        Assert.Equal(Severity.Medium, a.Severity); // Ubuntu says medium; the CVSS vector alone would say critical
        Assert.Equal(9.8, a.Cvss);
        Assert.Equal("3.0.2-0ubuntu1.21", a.Fixed["Ubuntu:22.04:LTS/openssl"]);
    }

    [Fact]
    public void Debian_records_without_an_urgency_fall_back_to_cvss()
    {
        var a = OsvParsers.ParseVuln(Fixture.Read("software/osv-vuln.debian-cve.json"));
        Assert.Equal(8.8, a.Cvss);
        Assert.Equal(Severity.High, a.Severity); // urgency "not yet assigned"
        Assert.Equal("3.0.18-1~deb12u2", a.Fixed["Debian:12/openssl"]);
    }

    [Theory]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1)]
    [InlineData("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5)]
    [InlineData("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0)]
    public void Cvss3_base_scores_match_the_specification(string vector, double score) => Assert.Equal(score, OsvParsers.Cvss3BaseScore(vector));

    [Fact]
    public void Incomplete_vectors_have_no_score() => Assert.Null(OsvParsers.Cvss3BaseScore("CVSS:3.1/AV:N/AC:L"));

    [Theory]
    [InlineData("ubuntu", "24.04", "Ubuntu:24.04:LTS")]
    [InlineData("ubuntu", "24.10", "Ubuntu:24.10")]
    [InlineData("debian", "12", "Debian:12")]
    [InlineData("alpine", "3.20.3", "Alpine:v3.20")]
    [InlineData("almalinux", "9.4", "AlmaLinux:9")]
    [InlineData("rocky", "9.5", "Rocky Linux:9")]
    [InlineData("rhel", "9.4", null)]
    [InlineData("fedora", "41", null)]
    [InlineData("debian", "", null)]
    public void Ecosystems_from_os_release(string id, string version, string? expected) => Assert.Equal(expected, OsvEcosystems.For(id, version));
}

[Collection(ServerHostCollection.Name)]
public sealed class SoftwareApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public SoftwareApiTests(ServerApiTests.Factory factory) => _factory = factory;

    [Fact]
    public async Task Inventory_is_enriched_and_changes_are_previewed_then_queued()
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "sw" })).Content.ReadFromJsonAsync<JsonElement>();
        var enroll = await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "web-01", "Ubuntu 24.04.1 LTS", "ubuntu", "24.04", "x64", "0.1.0", null));
        var resp = (await enroll.Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);
        var id = resp.AgentId;
        var now = DateTime.UtcNow;

        async Task Post(AgentReport r) =>
            Assert.Equal(HttpStatusCode.NoContent, (await agent.PostAsJsonAsync("/api/agent/reports", r, AgentJsonContext.Default.AgentReport)).StatusCode);

        var manual = SoftwareParsers.ParseNameList(Fixture.Read("software/apt-mark-showmanual.ubuntu2404.txt"));
        var packages = SoftwareParsers.ParseDpkgQuery(Fixture.Read("software/dpkg-query.ubuntu2404.txt"), manual);
        await Post(new AgentReport(SoftwareIntegration.InventoryJob, now, now, true, null) { Software = new SoftwareReport("apt", packages, null) });
        await Post(new AgentReport(UpdatesIntegration.CheckJob, now, now, true, null)
        {
            Updates = new UpdatesReport("apt", [new PendingUpdate("apparmor", "4.0.1really4.0.1-0ubuntu0.24.04.3", "4.0.1really4.0.1-0ubuntu0.24.04.9", "noble-updates", false)], false, [], null),
        });
        await Post(new AgentReport(VulnerabilityIntegration.ScanJob, now, now, true, null)
        {
            Vulnerabilities = new VulnScanReport("trivy", "0.60.0", now, "ubuntu 24.04",
                [new VulnFinding("CVE-2025-15467", "libssl3t64", "3.0.13-0ubuntu3.6", "3.0.13-0ubuntu3.7", Severity.Medium, 9.8, FixState.Fixable, "OpenSSL CMS overflow", "deb", null)],
                new Dictionary<string, int>()),
        });

        // What OsvService would have cached for the openssl source package (the worker is off in tests).
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AlastorDbContext>();
            db.OsvPackages.Add(new OsvPackageResult { Ecosystem = "Ubuntu:24.04:LTS", Package = "openssl", Version = "3.0.13-0ubuntu3.6", VulnIds = ["UBUNTU-CVE-2025-15467", "UBUNTU-CVE-2026-0001"], CheckedAt = now });
            var a = OsvParsers.ParseVuln(Fixture.Read("software/osv-vuln.ubuntu-cve.json"));
            db.OsvVulnerabilities.Add(new OsvVulnerability { Id = a.Id, Summary = a.Summary, Severity = a.Severity, Cvss = a.Cvss, Aliases = a.Aliases.ToList(), Fixed = a.Fixed.ToDictionary(), FetchedAt = now });
            await db.SaveChangesAsync();
        }

        var sw = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{id}/software", Json);
        Assert.Equal(527, sw.GetProperty("total").GetInt32());
        Assert.Equal(19, sw.GetProperty("manual").GetInt32());
        Assert.Equal("Ubuntu:24.04:LTS", sw.GetProperty("osvEcosystem").GetString());
        var byName = sw.GetProperty("packages").EnumerateArray().ToDictionary(p => p.GetProperty("name").GetString()!);
        Assert.Equal("4.0.1really4.0.1-0ubuntu0.24.04.9", byName["apparmor"].GetProperty("candidate").GetString());
        // The scan's CVE and OSV's record of the same CVE count once; the unknown OSV id stays as its own entry.
        var libssl = byName["libssl3t64"].GetProperty("vulns").EnumerateArray().ToList();
        Assert.Equal(["CVE-2025-15467", "UBUNTU-CVE-2026-0001"], libssl.Select(v => v.GetProperty("id").GetString()).Order());
        Assert.Equal("scan", libssl.Single(v => v.GetProperty("id").GetString() == "CVE-2025-15467").GetProperty("source").GetString());
        // The openssl binary has no scan finding, so OSV supplies it, with the advisory it came from.
        var openssl = byName["openssl"].GetProperty("vulns").EnumerateArray().First();
        Assert.Equal("osv", openssl.GetProperty("source").GetString());
        Assert.Equal("UBUNTU-CVE-2025-15467", openssl.GetProperty("advisory").GetString());
        Assert.Equal(JsonValueKind.Null, byName["bash"].GetProperty("removeCommand").ValueKind);
        Assert.StartsWith("sudo apt-get remove curl", byName["curl"].GetProperty("removeCommand").GetString());

        // Protected, unknown and malformed packages are refused before anything reaches the agent.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/software/plan", new { op = "remove", package = "bash" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/software/plan", new { op = "upgrade", package = "nginx" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/software/remove", new { package = "-y" })).StatusCode);

        // Dry run: the agent answers with the plan in the command result.
        var planCmd = await (await admin.PostAsJsonAsync($"/api/hosts/{id}/software/plan", new { op = "remove", package = "curl" })).Content.ReadFromJsonAsync<JsonElement>(Json);
        var delivered = await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json);
        var cmd = Assert.Single(delivered!);
        Assert.Equal(AgentCommandTypes.PackagePlan, cmd.Type);
        Assert.Equal("curl", cmd.Payload["package"]);
        var plan = new PackagePlan("remove", "curl", true, null, SoftwareParsers.ParseAptPlan(Fixture.Read("software/apt-get-s-remove.ubuntu2404.txt")), []);
        await agent.PostAsJsonAsync($"/api/agent/commands/{cmd.Id}/result",
            new AgentCommandResult(true, "Would change 2 packages") { Detail = JsonSerializer.Serialize(plan, AgentJsonContext.Default.PackagePlan) }, AgentJsonContext.Default.AgentCommandResult);
        var planResult = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{id}/software/plan/{planCmd.GetProperty("id").GetString()}", Json);
        Assert.Equal("Succeeded", planResult.GetProperty("status").GetString());
        Assert.Equal(2, planResult.GetProperty("plan").GetProperty("changes").GetArrayLength());

        // Then the change itself, audited.
        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsJsonAsync($"/api/hosts/{id}/software/remove", new { package = "curl" })).StatusCode);
        var action = Assert.Single((await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json))!);
        Assert.Equal(AgentCommandTypes.PackageAction, action.Type);
        Assert.Equal("remove", action.Payload["op"]);
        var audit = await admin.GetFromJsonAsync<JsonElement>("/api/audit", Json);
        Assert.Contains(audit.EnumerateArray(), e => e.GetProperty("action").GetString() == "software.remove" && e.GetProperty("details").GetString() == "curl");

        // Fleet views.
        var fleet = await admin.GetFromJsonAsync<JsonElement>("/api/software", Json);
        var apparmor = fleet.EnumerateArray().Single(r => r.GetProperty("name").GetString() == "apparmor");
        Assert.Equal(1, apparmor.GetProperty("outdated").GetInt32());
        Assert.DoesNotContain(fleet.EnumerateArray(), r => r.GetProperty("name").GetString() == "zlib1g"); // a dependency with nothing to report
        var everything = await admin.GetFromJsonAsync<JsonElement>("/api/software?all=true", Json);
        Assert.Contains(everything.EnumerateArray(), r => r.GetProperty("name").GetString() == "zlib1g");
        var hosts = await admin.GetFromJsonAsync<JsonElement>("/api/software/curl/hosts", Json);
        Assert.Equal("web-01", hosts.EnumerateArray().Single().GetProperty("name").GetString());
        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsJsonAsync("/api/software/upgrade", new { package = "apparmor", hostIds = new[] { id } })).StatusCode);

        // A read-only API key sees the inventory but can't change anything.
        var key = await (await admin.PostAsJsonAsync("/api/api-keys", new { name = "sw-reader" })).Content.ReadFromJsonAsync<JsonElement>();
        var reader = _factory.CreateClient();
        reader.DefaultRequestHeaders.Add("X-Api-Key", key.GetProperty("secret").GetString());
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"/api/hosts/{id}/software")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync($"/api/hosts/{id}/software/upgrade", new { package = "apparmor" })).StatusCode);

        // A failed inventory keeps the last list.
        await Post(new AgentReport(SoftwareIntegration.InventoryJob, now, now, false, "dpkg-query: error: database is locked"));
        sw = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{id}/software", Json);
        Assert.False(sw.GetProperty("success").GetBoolean());
        Assert.Equal(527, sw.GetProperty("total").GetInt32());
    }
}
