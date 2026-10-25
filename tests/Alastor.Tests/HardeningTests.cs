using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging.Abstractions;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Hardening;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Tests;

public class LynisReportParserTests
{
    [Fact]
    public void Reads_index_version_and_items_from_a_real_report()
    {
        var r = LynisReportParser.Parse(Fixture.Read("hardening/lynis-report.ubuntu.dat"));
        Assert.Equal("3.1.6", r.LynisVersion);
        Assert.Equal(62, r.HardeningIndex);
        Assert.Equal(243, r.TestsExecuted);

        var warning = Assert.Single(r.Items, i => i.Kind == LynisItemKind.Warning);
        Assert.Equal("NETW-2705", warning.TestId);
        Assert.Equal("Couldn't find 2 responsive nameservers", warning.Text);
        Assert.Null(warning.Details);
        Assert.Null(warning.Solution);
        Assert.Equal(40, r.Items.Count(i => i.Kind == LynisItemKind.Suggestion));

        // One test id can report several distinct items (one per mount point, sysctl key, …).
        Assert.Equal(3, r.Items.Count(i => i.TestId == "FILE-6310"));
        Assert.Equal("/vmlinuz or /boot/vmlinuz", r.Items.First(i => i.TestId == "KRNL-5788").Details);
        // "text:" is Lynis's solution type marker, not part of the hint.
        Assert.Equal("Use chmod to change file permissions", r.Items.First(i => i.TestId == "FILE-7524").Solution);
        Assert.Equal("Install a tool like rkhunter, chkrootkit, OSSEC, Wazuh", r.Items.First(i => i.TestId == "HRDN-7230").Solution);
    }

    [Fact]
    public void Tolerates_partial_and_odd_lines()
    {
        var r = LynisReportParser.Parse("# comment\r\nlynis_version=3.0.9\r\nhardening_index=abc\nwarning[]=SSH-7408|Root login allowed|PermitRootLogin|-|\n" +
                                        "warning[]=SSH-7408|Root login allowed|PermitRootLogin|-|\nsuggestion[]=|no id|-|-|\nsuggestion[]=KRNL-6000\nnot a line\n");
        Assert.Null(r.HardeningIndex);
        var item = Assert.Single(r.Items);
        Assert.Equal("PermitRootLogin", item.Details);
        Assert.Equal("SSH", LynisReportParser.Category("SSH-7408"));
        Assert.Equal("Kernel", LynisReportParser.Category("KRNL-6000"));
        Assert.Equal("ZZZ", LynisReportParser.Category("ZZZ-0001"));
    }

    [Fact]
    public void Policy_validates_and_merges_accepted_test_ids()
    {
        Assert.Contains(PolicyYaml.Parse("hardening:\n  ignore: [SSH-7408, 'rm -rf']\n").Issues, i => i.Path == "hardening.ignore[1]");
        var merged = PolicyMerger.MergeLayers([
            new PolicyDocument { Hardening = new() { Ignore = ["SSH-7408"] } },
            new PolicyDocument { Hardening = new() { Ignore = ["KRNL-6000", "SSH-7408"] } },
        ]);
        Assert.Equal(["KRNL-6000", "SSH-7408"], merged.Hardening!.Ignore!.Order());
    }
}

public sealed class HardeningIntegrationTests
{
    private readonly FakeCommandRunner _runner = new();
    private readonly FakeFileSystem _fs = new();
    private readonly InMemoryStateStore _state = new();
    private string _report = Fixture.Read("hardening/lynis-report.ubuntu.dat");
    private const string StateDir = "/var/lib/alastor-agent";

    public HardeningIntegrationTests()
    {
        _runner.Installed.UnionWith(["lynis", "nice"]);
        _runner.On("lynis --version", "3.1.6\n");
        _runner.Fallback = (file, args) =>
        {
            // nice -n 15 /usr/bin/lynis audit system ... --report-file <file> ...
            if (file != "/usr/bin/nice" || args.Count < 5 || args[2] != "/usr/bin/lynis" || args[3] != "audit") return null;
            _fs.Files[args[args.ToList().IndexOf("--report-file") + 1]] = _report;
            return new CommandResult(0, "", "");
        };
    }

    private HardeningIntegration Integration(IPackageManager? packages = null) =>
        new(_runner, _fs, packages, _state, StateDir, NullLogger<HardeningIntegration>.Instance, TimeProvider.System);

    private static async Task<List<SecurityEvent>> Drain(HardeningIntegration h)
    {
        var list = new List<SecurityEvent>();
        await foreach (var e in h.CollectEventsAsync(default)) list.Add(e);
        return list;
    }

    [Fact]
    public async Task Audit_runs_lynis_with_our_profile_and_reports_its_findings()
    {
        var h = Integration();
        var report = await h.AuditAsync(default);

        Assert.True(report.Success, report.Error);
        Assert.Equal(HardeningIntegration.AuditJob, report.JobId);
        Assert.Equal(62, report.Hardening!.HardeningIndex);
        Assert.Equal(41, report.Hardening.Items.Count);

        var call = Assert.Single(_runner.Calls, c => c.StartsWith("/usr/bin/nice", StringComparison.Ordinal));
        Assert.Contains("audit system --cronjob --quiet --no-colors", call);
        Assert.Contains($"--profile {StateDir}/lynis/alastor.prf", call);
        // Agents talk only to their server: Lynis's upgrade check stays off.
        Assert.Contains("skip-upgrade-test=yes", _fs.Files[h.ProfilePath]);

        var e = Assert.Single(await Drain(h));
        Assert.Equal(EventKinds.HardeningWarning, e.Kind);
        Assert.Contains("NETW-2705", e.Message);

        // The same warnings again: nothing new to say.
        Assert.True((await h.AuditAsync(default)).Success);
        Assert.Empty(await Drain(h));

        var status = await h.DetectAsync(default);
        Assert.True(status.Installed);
        Assert.Equal("3.1.6", status.Version);
        Assert.Equal(Ownership.Adopted, status.Ownership);
    }

    [Fact]
    public async Task A_drop_in_the_index_raises_a_regression_and_failures_are_reported()
    {
        var h = Integration();
        await h.AuditAsync(default);
        await Drain(h);

        _report = _report.Replace("hardening_index=62", "hardening_index=55");
        Assert.True((await h.AuditAsync(default)).Success);
        var e = Assert.Single(await Drain(h));
        Assert.Equal(EventKinds.HardeningRegressed, e.Kind);
        Assert.Contains("from 62 to 55", e.Message);

        _report = "lynis_version=3.1.6\n";
        var failed = await h.AuditAsync(default);
        Assert.False(failed.Success);
        Assert.Contains("no hardening index", failed.Error);
        Assert.Null(failed.Hardening);

        await h.RemoveManagedStateAsync(default);
        Assert.False(_fs.FileExists(h.ProfilePath));
    }

    [Fact]
    public async Task Installs_from_distro_repos_at_most_once_a_day_and_honours_auto_install()
    {
        _runner.Installed.Remove("lynis");
        var packages = new FakePackages { Fail = true };
        var h = Integration(packages);
        var doc = new PolicyDocument { Hardening = new() { AuditSchedule = "0 5 * * 0" } };

        var s = await h.EnsureInstalledAsync(new ReconcileRequest(doc, "r1"), default);
        Assert.Equal(Availability.Unavailable, s.Availability);
        Assert.Contains("lynis", s.UnavailableReason);
        await h.EnsureInstalledAsync(new ReconcileRequest(doc, "r1"), default);
        Assert.Equal(1, packages.Attempts);

        var off = new PolicyDocument { Agent = new() { AutoInstall = false } };
        s = await Integration(new FakePackages()).EnsureInstalledAsync(new ReconcileRequest(off, "r2"), default);
        Assert.Contains("autoInstall", s.UnavailableReason);

        Assert.False((await h.AuditAsync(default)).Success);
        Assert.False(h.IsWanted(new PolicyDocument { Hardening = new() { AuditSchedule = "off" } }));
    }

    private sealed class FakePackages : IPackageManager
    {
        public bool Fail { get; init; }
        public int Attempts { get; private set; }
        public string Name => "apt";
        public Task<bool> IsInstalledAsync(string package, CancellationToken ct) => Task.FromResult(false);
        public Task<string?> InstalledVersionAsync(string package, CancellationToken ct) => Task.FromResult<string?>(null);
        public Task<bool> IsAvailableAsync(string package, CancellationToken ct) => Task.FromResult(true);

        public Task<PackageInstallResult> InstallAsync(string package, CancellationToken ct)
        {
            Attempts++;
            return Task.FromResult(new PackageInstallResult(!Fail, Fail ? "E: Unable to locate package lynis" : null));
        }
    }
}

[Collection(ServerHostCollection.Name)]
public sealed class HardeningApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public HardeningApiTests(ServerApiTests.Factory factory) => _factory = factory;

    private async Task<(HttpClient Admin, HttpClient Agent, Guid HostId)> EnrollAsync(string name)
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "h" })).Content.ReadFromJsonAsync<JsonElement>();
        var enroll = await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, name, "Ubuntu 24.04 LTS", "ubuntu", "24.04", "x64", "0.1.0", null));
        var resp = (await enroll.Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);
        return (admin, agent, resp.AgentId);
    }

    private static AgentReport Audit(string content)
    {
        var now = DateTime.UtcNow;
        return new AgentReport(HardeningIntegration.AuditJob, now.AddMinutes(-3), now, true, null) { Hardening = LynisReportParser.Parse(content) };
    }

    [Fact]
    public async Task Audits_are_stored_accepted_items_excluded_and_resolved_items_listed()
    {
        var (admin, agent, hostId) = await EnrollAsync("audit-01");
        var content = Fixture.Read("hardening/lynis-report.ubuntu.dat");
        Assert.Equal(HttpStatusCode.NoContent, (await agent.PostAsJsonAsync("/api/agent/reports", Audit(content), AgentJsonContext.Default.AgentReport)).StatusCode);

        var detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}/hardening", Json);
        Assert.Equal(62, detail.GetProperty("hardeningIndex").GetInt32());
        Assert.Equal("3.1.6", detail.GetProperty("lynisVersion").GetString());
        Assert.Equal("hardening.auditSchedule", detail.GetProperty("schedule").GetProperty("key").GetString());
        Assert.Empty(detail.GetProperty("resolvedSinceLast").EnumerateArray());
        var items = detail.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(41, items.Count);
        Assert.Equal("Warning", items[0].GetProperty("kind").GetString());
        Assert.Equal("Networking", items[0].GetProperty("category").GetString());

        var summary = (await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}", Json)).GetProperty("summary");
        Assert.Equal(62, summary.GetProperty("hardeningIndex").GetInt32());
        Assert.Equal(1, summary.GetProperty("hardeningWarnings").GetInt32());
        var fleetRow = (await admin.GetFromJsonAsync<JsonElement>("/api/hardening", Json)).GetProperty("hosts").EnumerateArray().First(h => h.GetProperty("name").GetString() == "audit-01");
        // Per test id, warnings excluded: 40 suggestion lines, 34 distinct ids, minus NETW-2705 (also the warning).
        Assert.Equal(33, fleetRow.GetProperty("suggestions").GetInt32());

        // Accepting a test id on the host layer applies without a new audit.
        (await admin.PutAsJsonAsync($"/api/policies/host/{hostId}", new { yaml = "hardening:\n  ignore: [NETW-2705, FILE-6310]\n", comment = "accept" })).EnsureSuccessStatusCode();
        detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}/hardening", Json);
        Assert.All(detail.GetProperty("items").EnumerateArray().Where(i => i.GetProperty("testId").GetString() is "NETW-2705" or "FILE-6310"),
            i => Assert.True(i.GetProperty("accepted").GetBoolean()));
        summary = (await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}", Json)).GetProperty("summary");
        Assert.Equal(0, summary.GetProperty("hardeningWarnings").GetInt32());

        // A fix removed a suggestion: the next audit lists it as resolved.
        var fixedContent = string.Join('\n', content.Split('\n').Where(l => !l.StartsWith("suggestion[]=HRDN-7230", StringComparison.Ordinal)));
        await agent.PostAsJsonAsync("/api/agent/reports", Audit(fixedContent), AgentJsonContext.Default.AgentReport);
        detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}/hardening", Json);
        Assert.Equal(["HRDN-7230"], detail.GetProperty("resolvedSinceLast").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(40, detail.GetProperty("items").GetArrayLength());

        // A failed audit keeps the checklist.
        await agent.PostAsJsonAsync("/api/agent/reports", new AgentReport(HardeningIntegration.AuditJob, DateTime.UtcNow, DateTime.UtcNow, false, "lynis exited with 1"),
            AgentJsonContext.Default.AgentReport);
        detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}/hardening", Json);
        Assert.False(detail.GetProperty("lastAuditSucceeded").GetBoolean());
        Assert.Equal(40, detail.GetProperty("items").GetArrayLength());

        var fleet = await admin.GetFromJsonAsync<JsonElement>("/api/hardening", Json);
        Assert.Contains(fleet.GetProperty("hosts").EnumerateArray(), h => h.GetProperty("name").GetString() == "audit-01" && h.GetProperty("hardeningIndex").GetInt32() == 62);
        var fleetItems = fleet.GetProperty("items").EnumerateArray().ToList();
        Assert.DoesNotContain(fleetItems, i => i.GetProperty("testId").GetString() is "NETW-2705" or "FILE-6310" or "HRDN-7230");
        Assert.Contains(fleetItems, i => i.GetProperty("testId").GetString() == "KRNL-6000" && i.GetProperty("hostCount").GetInt32() >= 1);

        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsync($"/api/hosts/{hostId}/actions/run-audit", null)).StatusCode);
        var commands = await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json);
        Assert.Contains(commands!, c => c.Type == AgentCommandTypes.RunJob && c.Payload["job"] == HardeningIntegration.AuditJob);
    }
}
