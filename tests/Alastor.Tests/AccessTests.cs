using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging.Abstractions;
using Alastor.Core.Access;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Platform;
using Alastor.Core.Policy;
using Alastor.Core.Updates;
using Alastor.Server.Data;
using Alastor.Server.Services.Issues;
using Alastor.Server.Services.Posture;

namespace Alastor.Tests;

public sealed class NeedrestartTests
{
    [Fact]
    public void Batch_output_lists_services_and_the_kernel_state()
    {
        var clean = UpdateParsers.ParseNeedrestart(Fixture.Read("updates/needrestart-b.clean.txt"));
        Assert.Empty(clean.Services);
        Assert.Equal(0, clean.KernelStatus);
        Assert.False(clean.KernelUpgradePending);
        Assert.Equal("6.18.44-fc-v153", clean.RunningKernel);

        var pending = UpdateParsers.ParseNeedrestart(Fixture.Read("updates/needrestart-b.pending.txt"));
        Assert.Equal(["nginx.service", "ssh.service", "systemd-journald.service"], pending.Services);
        Assert.True(pending.KernelUpgradePending);
        Assert.Equal(("6.8.0-45-generic", "6.8.0-47-generic"), (pending.RunningKernel, pending.ExpectedKernel));

        Assert.Equal(["httpd.service", "php-fpm.service", "sshd.service"], UpdateParsers.ParseNeedsRestartingServices(Fixture.Read("updates/needs-restarting-s.txt")));
    }

    private static UpdatesIntegration Ubuntu(FakeCommandRunner runner, InMemoryStateStore state) =>
        new(runner, new FakeFileSystem(), PackageManagers.For(DistroFamily.Debian, runner), state,
            new OsInfo("ubuntu", "24.04", "Ubuntu 24.04", DistroFamily.Debian, "x64"), NullLogger<UpdatesIntegration>.Instance, TimeProvider.System);

    [Fact]
    public async Task Apt_checks_run_needrestart_in_list_mode_and_alert_on_new_services()
    {
        var output = Fixture.Read("updates/needrestart-b.pending.txt");
        var runner = new FakeCommandRunner();
        runner.Installed.UnionWith(["apt-get", "needrestart"]);
        runner.On("apt-get update -q -o DPkg::Lock::Timeout=300", "")
            .On("apt-get -s -o Debug::NoLocking=1 dist-upgrade", Fixture.Read("updates/apt-get-s-dist-upgrade.ubuntu.txt"))
            .On("needrestart -b -r l", () => new CommandResult(0, output, "readline() on closed filehandle HENV at /usr/sbin/needrestart line 79."));
        var state = new InMemoryStateStore();
        var u = Ubuntu(runner, state);

        var report = (await u.CheckAsync(default)).Updates!;
        Assert.Equal(["nginx.service", "ssh.service", "systemd-journald.service"], report.RestartServices);
        Assert.Equal("needrestart", report.RestartTool);
        Assert.True(report.RebootRequired); // kernel 6.8.0-47 is installed but not running
        Assert.Equal("6.8.0-47-generic", report.ExpectedKernel);
        var events = new List<SecurityEvent>();
        await foreach (var e in u.CollectEventsAsync(default)) events.Add(e);
        var restart = Assert.Single(events, e => e.Kind == EventKinds.RestartRequired);
        Assert.Contains("nginx.service", restart.Message);

        // Same services next time: no new alert. One fewer: none either.
        output = output.Replace("NEEDRESTART-SVC: nginx.service\n", "");
        await u.CheckAsync(default);
        await foreach (var e in u.CollectEventsAsync(default)) Assert.NotEqual(EventKinds.RestartRequired, e.Kind);

        // Without needrestart the report says "can't tell", not "nothing to restart".
        runner.Installed.Remove("needrestart");
        Assert.Null((await u.CheckAsync(default)).Updates!.RestartServices);
    }

    [Fact]
    public void Restart_issue_and_matrix_cell()
    {
        var h = new ManagedHost { Name = "web-01", Hostname = "web-01", SecretHash = "x", IsOnline = true, PendingUpdates = 0, SecurityUpdates = 0, ServicesNeedingRestart = ["nginx.service", "ssh.service"] };
        var issue = Assert.Single(IssueRules.Evaluate(h, new([], [])));
        Assert.Equal(("updates.restart", "2 services run code updates replaced"), (issue.Rule, issue.Title));
        Assert.Contains("sudo systemctl restart nginx.service ssh.service", issue.Detail);
        Assert.Equal(("warn", "2 to restart"), (PostureMatrix.Row(h, new(false, 0))["updates"].Status, PostureMatrix.Row(h, new(false, 0))["updates"].Label));
    }
}

public sealed class LoginParserTests
{
    [Fact]
    public void Sshd_accept_messages()
    {
        var at = new DateTime(2026, 10, 25, 9, 0, 0, DateTimeKind.Utc);
        var lines = Fixture.Read("logins/sshd-E.log").Split('\n');
        var key = LoginParsers.ParseMessage(lines.Single(l => l.StartsWith("Accepted publickey", StringComparison.Ordinal)), at, "c1")!;
        Assert.Equal(("alastortest", "127.0.0.1", 39750, "publickey"), (key.User, key.Address, key.Port, key.Method));
        Assert.Equal("ED25519 SHA256:CUyavIDXWKw6a7MAF+K2UrUb96wV0chzcsj3Lw8Uy/Q", key.Key);
        var pw = LoginParsers.ParseMessage(lines.Single(l => l.StartsWith("Accepted password", StringComparison.Ordinal)), at, "c2")!;
        Assert.Equal(("password", null), (pw.Method, pw.Key));
        Assert.Null(LoginParsers.ParseMessage("Disconnected from user alastortest 127.0.0.1 port 39750", at, "c3"));
        Assert.Null(LoginParsers.ParseMessage("Failed password for root from 203.0.113.9 port 4242 ssh2", at, "c4"));
    }

    [Fact]
    public void Journal_json_keeps_the_last_cursor_and_skips_byte_array_messages()
    {
        var (logins, cursor) = LoginParsers.ParseJournal(Fixture.Read("logins/journal-sshd.json"));
        Assert.Equal(3, logins.Count);
        Assert.Equal(("root", "203.0.113.5", new DateTime(2026, 10, 25, 9, 14, 3, 512, 345, DateTimeKind.Utc)), (logins[0].User, logins[0].Address, logins[0].AtUtc));
        Assert.Equal(("alice", "198.51.100.7", "password"), (logins[1].User, logins[1].Address, logins[1].Method)); // sshd-session identifier
        Assert.Equal(("deploy", "2001:db8::5", "keyboard-interactive/pam"), (logins[2].User, logins[2].Address, logins[2].Method));
        Assert.StartsWith("s=8f1c6e1f3b2a4d5e9a7b6c5d4e3f2a1b;i=1a53;", cursor);
        Assert.NotEqual(logins[0].Cursor, logins[1].Cursor);
    }

    [Fact]
    public void Syslog_files_in_both_timestamp_styles()
    {
        var now = new DateTime(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc);
        var auth = Fixture.Read("logins/auth.log").Split('\n').Select(l => LoginParsers.ParseSyslogLine(l, now)).OfType<LoginRecord>().ToList();
        Assert.Equal(["root", "alice"], auth.Select(l => l.User));
        Assert.Equal(new DateTime(2026, 10, 25, 9, 17, 41, 12, 345, DateTimeKind.Utc), auth[1].AtUtc);
        var secure = Fixture.Read("logins/secure").Split('\n').Select(l => LoginParsers.ParseSyslogLine(l, now)).OfType<LoginRecord>().Single();
        Assert.Equal(("root", "203.0.113.5", "RSA SHA256:7Xo2nY0w0p4cS3Pz3E6uU7k9vYw2a5zB1nCq8dEfGhI"), (secure.User, secure.Address, secure.Key));
        Assert.Equal(10, secure.AtUtc.Month);
    }
}

public sealed class LoginIntegrationTests
{
    private sealed class Clock(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static async Task<List<SecurityEvent>> Drain(LoginIntegration n)
    {
        var list = new List<SecurityEvent>();
        await foreach (var e in n.CollectEventsAsync(default)) list.Add(e);
        return list;
    }

    [Fact]
    public async Task Reads_the_journal_from_now_on_resumes_after_its_cursor_and_polls_at_most_every_30s()
    {
        var clock = new Clock(new DateTimeOffset(2026, 10, 25, 9, 0, 0, TimeSpan.Zero));
        var runner = new FakeCommandRunner();
        runner.Installed.Clear();
        runner.Installed.Add("journalctl");
        var state = new InMemoryStateStore();
        var n = new LoginIntegration(runner, new FakeFileSystem(), state, NullLogger<LoginIntegration>.Instance, clock);

        Assert.Empty(await Drain(n)); // first poll only records "since now"
        Assert.Empty(runner.Calls);
        runner.On("journalctl -o json --no-pager -q -t sshd -t sshd-session -n 1000 --since=@1792918800", Fixture.Read("logins/journal-sshd.json"));
        Assert.Empty(await Drain(n)); // throttled
        clock.Now = clock.Now.AddSeconds(31);
        var events = await Drain(n);
        Assert.Equal(3, events.Count);
        var root = events[0];
        Assert.Equal((EventKinds.Login, Capability.Access, Severity.Info, "203.0.113.5"), (root.Kind, root.Capability, root.Severity, root.Subject));
        Assert.Equal("root", root.Metadata["user"]);
        Assert.Equal("ED25519 SHA256:CUyavIDXWKw6a7MAF+K2UrUb96wV0chzcsj3Lw8Uy/Q", root.Metadata["key"]);

        var cursor = state.Get("logins.cursor")!;
        runner.On($"journalctl -o json --no-pager -q -t sshd -t sshd-session -n 1000 --after-cursor={cursor}", "");
        clock.Now = clock.Now.AddSeconds(31);
        Assert.Empty(await Drain(n));
        Assert.EndsWith($"--after-cursor={cursor}", runner.Calls[^1]);
        Assert.Equal("journald", (await n.DetectAsync(default)).Details["source"]);
    }

    [Fact]
    public async Task Falls_back_to_auth_log_and_can_be_turned_off()
    {
        var clock = new Clock(new DateTimeOffset(2026, 10, 25, 12, 0, 0, TimeSpan.Zero));
        var runner = new FakeCommandRunner();
        runner.Installed.Clear();
        var fs = new FakeFileSystem();
        fs.Files["/var/log/auth.log"] = "";
        var n = new LoginIntegration(runner, fs, new InMemoryStateStore(), NullLogger<LoginIntegration>.Instance, clock);
        Assert.Empty(await Drain(n)); // the tailer starts at the end of the file
        fs.Files["/var/log/auth.log"] = Fixture.Read("logins/auth.log");
        clock.Now = clock.Now.AddMinutes(1);
        Assert.Equal(["root", "alice"], (await Drain(n)).Select(e => e.Metadata["user"]));

        await n.PlanAsync(new Alastor.Core.Integrations.ReconcileRequest(new PolicyDocument { Logins = new() { Monitor = false } }, "r"), default);
        Assert.False(n.IsWanted(new PolicyDocument { Logins = new() { Monitor = false } }));
        Assert.Equal(Alastor.Core.Integrations.Availability.Disabled, (await n.DetectAsync(default)).Availability);
    }
}

[Collection(ServerHostCollection.Name)]
public sealed class LoginApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public LoginApiTests(ServerApiTests.Factory factory) => _factory = factory;

    private static SecurityEvent Login(string user, string address, DateTime at) => new()
    {
        Id = SecurityEvent.StableId("login", user, address, at.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        OccurredAt = at, Capability = Capability.Access, Severity = Severity.Info, SourceTool = "logins", Kind = EventKinds.Login,
        Subject = address, Message = $"{user} logged in over SSH from {address} (publickey)",
        Metadata = new Dictionary<string, string> { ["user"] = user, ["method"] = "publickey", ["port"] = "22", ["key"] = "" },
    };

    [Fact]
    public async Task First_logins_are_learned_then_new_sources_alert_once_and_trusted_ones_never()
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "n" })).Content.ReadFromJsonAsync<JsonElement>();
        var resp = (await (await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "logins-01", "Debian 13", "debian", "13", "x64", "0.1.0", null))).Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);
        (await admin.PutAsJsonAsync($"/api/policies/host/{resp.AgentId}", new { yaml = "logins:\n  trustedSources: [192.0.2.0/24]\n" })).EnsureSuccessStatusCode();

        async Task<List<JsonElement>> NewSourceAlerts() =>
            (await admin.GetFromJsonAsync<JsonElement>($"/api/events?hostId={resp.AgentId}&kind={EventKinds.LoginNewSource}"))!.GetProperty("items").EnumerateArray().ToList();
        var t0 = DateTime.UtcNow.AddMinutes(-30);

        // The host's first batch is learned silently.
        (await agent.PostAsJsonAsync("/api/agent/events", new EventBatch([Login("alice", "198.51.100.7", t0), Login("root", "198.51.100.7", t0.AddSeconds(5))]), Json)).EnsureSuccessStatusCode();
        Assert.Empty(await NewSourceAlerts());

        // A known pair: nothing. A new address for alice: High. A new address for root: Critical. A trusted address: nothing.
        var batch = new EventBatch([Login("alice", "198.51.100.7", t0.AddMinutes(1)), Login("alice", "203.0.113.50", t0.AddMinutes(2)),
            Login("root", "203.0.113.51", t0.AddMinutes(3)), Login("bob", "192.0.2.10", t0.AddMinutes(4))]);
        (await agent.PostAsJsonAsync("/api/agent/events", batch, Json)).EnsureSuccessStatusCode();
        (await agent.PostAsJsonAsync("/api/agent/events", batch, Json)).EnsureSuccessStatusCode(); // re-delivery
        var alerts = await NewSourceAlerts();
        Assert.Equal(2, alerts.Count);
        Assert.Contains(alerts, a => a.GetProperty("subject").GetString() == "203.0.113.50" && a.GetProperty("severity").GetString() == "High");
        Assert.Contains(alerts, a => a.GetProperty("subject").GetString() == "203.0.113.51" && a.GetProperty("severity").GetString() == "Critical");

        var logins = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{resp.AgentId}/logins", Json);
        var sources = logins.GetProperty("sources").EnumerateArray().ToList();
        Assert.Equal(5, sources.Count);
        var alice = sources.Single(s => s.GetProperty("user").GetString() == "alice" && s.GetProperty("address").GetString() == "198.51.100.7");
        Assert.Equal(2, alice.GetProperty("logins").GetInt32());
        Assert.False(sources.Single(s => s.GetProperty("user").GetString() == "bob").GetProperty("alerted").GetBoolean());
        Assert.Equal(["192.0.2.0/24"], logins.GetProperty("trustedSources").EnumerateArray().Select(x => x.GetString()!).ToArray());
        Assert.True(logins.GetProperty("recent").GetArrayLength() >= 6);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/api/hosts/{Guid.NewGuid()}/logins")).StatusCode);
    }
}
