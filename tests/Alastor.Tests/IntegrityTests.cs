using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging.Abstractions;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrity;
using Alastor.Core.Malware;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Tests;

public sealed class AideParserTests
{
    [Fact]
    public void Json_and_plain_reports_read_the_same_changes()
    {
        var (entries, json) = AideParser.Parse(Fixture.Read("integrity/aide-check.json"));
        Assert.Equal(7, entries);
        var (plainEntries, plain) = AideParser.Parse(Fixture.Read("integrity/aide-check.txt"));
        Assert.Equal(7, plainEntries);
        foreach (var changes in new[] { json, plain })
        {
            Assert.Equal(4, changes.Count);
            Assert.Equal(("added", "f+++++++++++++++++"), (changes.Single(c => c.Path == "/bin/backdoor").Change, changes.Single(c => c.Path == "/bin/backdoor").Flags));
            Assert.Equal("removed", changes.Single(c => c.Path == "/etc/passwd").Change);
            var ls = changes.Single(c => c.Path == "/bin/ls");
            Assert.Equal(("changed", "f > ... ....H"), (ls.Change, ls.Flags));
            Assert.Equal(["size", "sha256"], ls.Attributes);
            Assert.Equal(["perm"], changes.Single(c => c.Path == "/bin/sudo").Attributes);
            Assert.True(ls.Critical);
            Assert.True(changes.Single(c => c.Path == "/etc/passwd").Critical);
        }
        Assert.Empty(AideParser.Parse(Fixture.Read("integrity/aide-clean.json")).Changes);
        Assert.Equal((7, 0), (AideParser.Parse(Fixture.Read("integrity/aide-clean.txt")).Entries, AideParser.Parse(Fixture.Read("integrity/aide-clean.txt")).Changes.Count));
        Assert.False(new IntegrityChange("/etc/motd", "changed", "f", []).Critical);
    }

    [Fact]
    public void Versions_exit_codes_and_config()
    {
        Assert.Equal(new Version(0, 18, 6), AideParser.ParseVersion("AIDE 0.18.6\n\nCompile-time options:"));
        Assert.Equal(new Version(0, 16), AideParser.ParseVersion("Aide 0.16\n"));
        Assert.True(AideParser.IsSuccess(7));
        Assert.False(AideParser.IsSuccess(17));

        var conf = AideConfig.Render("/var/lib/alastor-agent/aide", new Version(0, 18, 6), ["/usr/bin", "/etc/"], ["/etc/letsencrypt"]);
        Assert.Contains("database_in=file:/var/lib/alastor-agent/aide/aide.db\n", conf);
        Assert.True(conf.IndexOf("report_format=json", StringComparison.Ordinal) < conf.IndexOf("report_url=stdout", StringComparison.Ordinal));
        Assert.Contains("\n/etc AlastorChecks\n", conf);
        Assert.Contains("\n!/etc/letsencrypt\n", conf);
        Assert.Contains("\n!/etc/ld\\.so\\.cache\n", conf);
        Assert.Contains("\n!/etc/.*alastor\n", conf);
        Assert.DoesNotContain("report_format", AideConfig.Render("/x", new Version(0, 17, 4), ["/etc"], []));
    }
}

public sealed class AideIntegrationTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "alastor-aide-" + Guid.NewGuid().ToString("N"));
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    [Fact]
    public async Task First_run_records_the_baseline_then_checks_alert_once_and_accept_resets()
    {
        var runner = new FakeCommandRunner();
        runner.Installed.Clear();
        runner.Installed.Add("aide");
        var db = Path.Combine(_dir, "aide", "aide.db");
        var cfg = $"--config={Path.Combine(_dir, "aide", "aide.conf")}";
        runner.On("aide --version", "AIDE 0.18.6\n");
        runner.On($"aide --init {cfg}", () => { File.WriteAllText(db + ".new", "db"); return new CommandResult(0, "AIDE successfully initialized database.\n\nNumber of entries:\t7\n", ""); });
        runner.On($"aide --check {cfg}", Fixture.Read("integrity/aide-check.json"), exitCode: 7);
        runner.On($"aide --update {cfg}", () => { File.WriteAllText(db + ".new", "db2"); return new CommandResult(7, Fixture.Read("integrity/aide-check.json"), ""); });
        var state = new InMemoryStateStore();
        var aide = new AideIntegration(runner, null, new NoServices(), state, _dir, NullLogger<AideIntegration>.Instance, TimeProvider.System);
        var policy = new PolicyDocument { Integrity = new() { CheckSchedule = "0 4 * * *" } };
        Assert.True(aide.IsWanted(policy));

        var init = await aide.RunAsync(policy, accept: false, default);
        Assert.True(init.Success, init.Error);
        Assert.Equal(("init", 7, 0), (init.Integrity!.Mode, init.Integrity.Entries, init.Integrity.Changes.Count));
        Assert.True(File.Exists(db));
        Assert.Contains("report_format=json", File.ReadAllText(Path.Combine(_dir, "aide", "aide.conf")));

        var check = await aide.RunAsync(policy, accept: false, default);
        Assert.Equal(("check", 4), (check.Integrity!.Mode, check.Integrity.Changes.Count));
        var events = new List<SecurityEvent>();
        await foreach (var e in aide.CollectEventsAsync(default)) events.Add(e);
        var ev = Assert.Single(events);
        Assert.Equal((EventKinds.IntegrityChanged, Severity.High, Capability.Integrity), (ev.Kind, ev.Severity, ev.Capability));
        Assert.Contains("4 files changed since the accepted baseline, 4 in binaries, SSH or account files", ev.Message);

        await aide.RunAsync(policy, accept: false, default);
        await foreach (var e in aide.CollectEventsAsync(default)) Assert.Fail("repeated changes must not alert again");

        var accepted = await aide.RunAsync(policy, accept: true, default);
        Assert.Equal(("accept", 0), (accepted.Integrity!.Mode, accepted.Integrity.Changes.Count));
        Assert.Equal("db2", File.ReadAllText(db));
        Assert.Equal("", state.Get("aide.known"));
        Assert.Equal("", aide.Jobs.Single(j => j.Id == AideIntegration.AcceptJob).ScheduleKey); // on demand only

        runner.On($"aide --check {cfg}", "", 17, "Configuration error");
        var failed = await aide.RunAsync(policy, accept: false, default);
        Assert.False(failed.Success);
        Assert.Contains("exit 17", failed.Error);
    }

    private sealed class NoServices : IServiceManager
    {
        public Task<bool> IsActiveAsync(string unit, CancellationToken ct) => Task.FromResult(false);
        public Task<bool> EnableAndStartAsync(string unit, CancellationToken ct) => Task.FromResult(true);
        public Task<bool> RestartAsync(string unit, CancellationToken ct) => Task.FromResult(true);
        public Task<bool> ReloadAsync(string unit, CancellationToken ct) => Task.FromResult(true);
        public Task<bool> DisableAndStopAsync(string unit, CancellationToken ct) => Task.FromResult(true);
    }
}

public sealed class RkhunterTests
{
    [Fact]
    public void Warnings_keep_their_details_and_get_a_severity()
    {
        var warnings = RkhunterParser.Parse(Fixture.Read("integrity/rkhunter-check.container.txt"));
        Assert.Equal(6, warnings.Count);
        Assert.Equal(Severity.Low, warnings.Single(w => w.Title.StartsWith("The modules file", StringComparison.Ordinal)).Severity);
        var ssh = warnings.Single(w => w.Title.Contains("PermitRootLogin", StringComparison.Ordinal));
        Assert.Equal(["The default value may be 'yes', to allow root access."], ssh.Details);
        var dev = warnings.Single(w => w.Title.StartsWith("Suspicious file types", StringComparison.Ordinal));
        Assert.Equal((Severity.Medium, 2), (dev.Severity, dev.Details.Count));
        Assert.Equal(Severity.Medium, warnings.Single(w => w.Title.StartsWith("Hidden directory", StringComparison.Ordinal)).Severity);

        var changed = RkhunterParser.Parse(Fixture.Read("integrity/rkhunter-check.changed.txt"))[0];
        Assert.Equal(("The file properties have changed:", Severity.High), (changed.Title, changed.Severity));
        Assert.Equal("File: /usr/bin/whoami", changed.Details[0]);
        Assert.Equal(Severity.Critical, RkhunterParser.Classify("Possible rootkit files found"));

        Assert.True(dev.IsIgnored(["/dev/shm/lttng-ust"]));
        Assert.False(dev.IsIgnored(["/etc/.java"]));
    }

    [Fact]
    public async Task First_run_records_properties_then_checks_and_accept_rerecords()
    {
        var runner = new FakeCommandRunner();
        runner.Installed.Clear();
        runner.Installed.Add("rkhunter");
        runner.On("rkhunter --version", "Rootkit Hunter 1.4.6\n\nThis software was developed by the Rootkit Hunter project team.\n");
        runner.On("rkhunter --propupd --nocolors", "[ Rootkit Hunter version 1.4.6 ]\nFile updated: searched for 177 files, found 121\n");
        runner.On("rkhunter --check --sk --nocolors --rwo", Fixture.Read("integrity/rkhunter-check.changed.txt"), exitCode: 1);
        var state = new InMemoryStateStore();
        var rk = new RkhunterIntegration(runner, null, state, NullLogger<RkhunterIntegration>.Instance, TimeProvider.System);
        var policy = new PolicyDocument { Malware = new() { RootkitSchedule = "0 4 * * 0", RootkitIgnore = ["/etc/.java"] } };

        var report = await rk.RunAsync(policy, accept: false, default);
        Assert.True(report.Success, report.Error);
        Assert.Equal(["rkhunter --version", "rkhunter --propupd --nocolors", "rkhunter --check --sk --nocolors --rwo"], runner.Calls);
        Assert.Equal(("1.4.6", 7), (report.Rootkit!.Version, report.Rootkit.Warnings.Count));
        var events = new List<SecurityEvent>();
        await foreach (var e in rk.CollectEventsAsync(default)) events.Add(e);
        // Medium and up, minus the ignored hidden directory: the changed binary and the /dev files.
        Assert.Equal(2, events.Count);
        Assert.Contains(events, e => e.Severity == Severity.High && e.Subject == "/usr/bin/whoami");

        runner.Calls.Clear();
        await rk.RunAsync(policy, accept: false, default);
        Assert.DoesNotContain("rkhunter --propupd --nocolors", runner.Calls);
        await foreach (var e in rk.CollectEventsAsync(default)) Assert.Fail("known warnings must not alert again");

        var accepted = await rk.RunAsync(policy, accept: true, default);
        Assert.Equal(("accept", 0), (accepted.Rootkit!.Mode, accepted.Rootkit.Warnings.Count));
    }
}

[Collection(ServerHostCollection.Name)]
public sealed class IntegrityApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public IntegrityApiTests(ServerApiTests.Factory factory) => _factory = factory;

    [Fact]
    public async Task Integrity_and_rootkit_reports_drive_issues_the_matrix_and_ignore()
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "n" })).Content.ReadFromJsonAsync<JsonElement>();
        var resp = (await (await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "integrity-01", "Debian 13", "debian", "13", "x64", "0.1.0", null))).Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);
        var now = DateTime.UtcNow;

        var (_, changes) = AideParser.Parse(Fixture.Read("integrity/aide-check.json"));
        var aide = new AgentReport(AideIntegration.CheckJob, now, now, true, null) { Integrity = new IntegrityReport("0.18.6", "check", 7, changes, ["/bin", "/etc"]) };
        Assert.Equal(HttpStatusCode.NoContent, (await agent.PostAsJsonAsync("/api/agent/reports", aide, AgentJsonContext.Default.AgentReport)).StatusCode);
        var rk = new AgentReport(RkhunterIntegration.ScanJob, now, now, true, null) { Rootkit = new RootkitReport("1.4.6", "check", RkhunterParser.Parse(Fixture.Read("integrity/rkhunter-check.changed.txt"))) };
        Assert.Equal(HttpStatusCode.NoContent, (await agent.PostAsJsonAsync("/api/agent/reports", rk, AgentJsonContext.Default.AgentReport)).StatusCode);

        var detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{resp.AgentId}/integrity", Json);
        Assert.Equal(4, detail.GetProperty("aide").GetProperty("report").GetProperty("changes").GetArrayLength());
        Assert.Equal("off", detail.GetProperty("aide").GetProperty("run").GetProperty("schedule").GetProperty("value").GetString());
        Assert.Equal(7, detail.GetProperty("rootkit").GetProperty("warnings").GetArrayLength());

        var issues = (await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={resp.AgentId}"))!.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal("High", issues.Single(i => i.GetProperty("rule").GetString() == "integrity.changed").GetProperty("severity").GetString());
        var rootkit = issues.Single(i => i.GetProperty("rule").GetString() == "rootkit.warning");
        Assert.Equal(("3 rkhunter warnings", "High"), (rootkit.GetProperty("title").GetString(), rootkit.GetProperty("severity").GetString()));

        var cell = (await admin.GetFromJsonAsync<JsonElement>("/api/stats/matrix")).GetProperty("rows").EnumerateArray()
            .Single(r => r.GetProperty("hostId").GetGuid() == resp.AgentId).GetProperty("cells").GetProperty("integrity");
        Assert.Equal("bad", cell.GetProperty("status").GetString());

        // Ignoring the known ones on this host leaves only the changed binary.
        (await admin.PutAsJsonAsync($"/api/policies/host/{resp.AgentId}", new { yaml = "malware:\n  rootkitIgnore: [/dev/shm/lttng-ust, /etc/.java]\n" })).EnsureSuccessStatusCode();
        issues = (await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={resp.AgentId}&rule=rootkit.warning"))!.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal("1 rkhunter warning", Assert.Single(issues).GetProperty("title").GetString());
        detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{resp.AgentId}/integrity", Json);
        Assert.Equal(2, detail.GetProperty("rootkit").GetProperty("warnings").EnumerateArray().Count(w => w.GetProperty("ignored").GetBoolean()));

        // Accepting the baseline is an on-demand job the dashboard queues.
        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsync($"/api/hosts/{resp.AgentId}/actions/accept-integrity", null)).StatusCode);
    }
}
