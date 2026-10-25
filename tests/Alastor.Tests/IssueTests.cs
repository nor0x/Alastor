using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Alastor.Core.Baseline;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Network;
using Alastor.Core.Updates;
using Alastor.Server.Data;
using Alastor.Server.Services.Issues;

namespace Alastor.Tests;

public sealed class IssueRuleTests
{
    private static readonly IssueRules.Facts NoFacts = new([], []);

    private static ManagedHost Host(Action<ManagedHost>? set = null)
    {
        var h = new ManagedHost { Name = "web-01", Hostname = "web-01", SecretHash = "x", IsOnline = true, PolicyApplySuccess = true };
        set?.Invoke(h);
        return h;
    }

    [Fact]
    public void A_healthy_host_has_no_issues()
    {
        var now = DateTime.UtcNow;
        Assert.Empty(IssueRules.Evaluate(Host(h =>
        {
            h.NetworkCheckedAt = now;
            h.SshExposure = SshExposureLevel.Restricted;
            h.VulnScannedAt = now;
            h.VulnCritical = 0;
            h.PendingUpdates = 2;
            h.SecurityUpdates = 0;
            h.MalwareScannedAt = now;
            h.MalwareFindings = 0;
            h.Tools.Add(new HostToolStatus { ToolId = "fail2ban", Installed = true, Running = true });
        }), NoFacts));
    }

    [Fact]
    public void Each_rule_opens_with_its_subject_severity_and_tab()
    {
        var now = DateTime.UtcNow;
        var h = Host(x =>
        {
            x.IsOnline = false;
            x.LastSeenAt = now.AddHours(-1);
            x.PolicyApplySuccess = false;
            x.NetworkCheckedAt = now;
            x.SshExposure = SshExposureLevel.Public;
            x.SshPasswordAuth = true;
            x.VulnScannedAt = now;
            x.VulnCritical = 2;
            x.VulnFixable = 1;
            x.MalwareScannedAt = now;
            x.MalwareFindings = 1;
            x.PendingUpdates = 3;
            x.SecurityUpdates = null; // Alpine: every pending update counts
            x.RebootRequired = true;
            x.Tools.Add(new HostToolStatus { ToolId = "fail2ban", Installed = true, Running = false });
        });
        var open = IssueRules.Evaluate(h, new(["CVE-2024-3094"], ["ssh-password-auth", "ssh-max-auth-tries"]));
        var byRule = open.ToLookup(c => c.Rule);

        Assert.Equal(Severity.High, byRule["host.offline"].Single().Severity);
        Assert.Equal("policy", byRule["policy.failed"].Single().Tab);
        Assert.Equal(("fail2ban", "fail2ban: not running"), (byRule["tool.problem"].Single().Subject, byRule["tool.problem"].Single().Title));
        Assert.Single(byRule["ssh.public"]);
        Assert.Empty(byRule["ssh.password-public"]); // the failing ssh-password-auth check already covers it
        Assert.Equal(("CVE-2024-3094", Severity.Critical), (byRule["cve.exploited"].Single().Subject, byRule["cve.exploited"].Single().Severity));
        Assert.Equal("2 critical CVEs", byRule["cve.critical"].Single().Title);
        Assert.Equal(Severity.Critical, byRule["malware.found"].Single().Severity);
        // The low-severity check stays on the score only.
        Assert.Equal("ssh-password-auth", byRule["baseline.failed"].Single().Subject);
        Assert.Equal("3 pending updates", byRule["updates.security"].Single().Title);
        Assert.Equal(Severity.Low, byRule["updates.reboot"].Single().Severity);
        Assert.All(open, c => Assert.True(IssueRules.Rules.ContainsKey(c.Rule)));
    }

    [Fact]
    public void Password_logins_on_a_public_host_are_an_issue_even_when_the_baseline_check_is_accepted()
    {
        var h = Host(x => { x.NetworkCheckedAt = DateTime.UtcNow; x.SshExposure = SshExposureLevel.Public; x.SshPasswordAuth = true; });
        Assert.Contains(IssueRules.Evaluate(h, NoFacts), c => c.Rule == "ssh.password-public");
    }

    [Fact]
    public void Accepted_ssh_exposure_is_not_an_issue()
    {
        var h = Host(x => { x.NetworkCheckedAt = DateTime.UtcNow; x.SshExposure = SshExposureLevel.Public; x.SshExposureAccepted = true; x.SshPasswordAuth = true; });
        Assert.Empty(IssueRules.Evaluate(h, NoFacts));
    }
}

[Collection(ServerHostCollection.Name)]
public sealed class IssueApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public IssueApiTests(ServerApiTests.Factory factory) => _factory = factory;

    [Fact]
    public async Task Issues_open_from_reports_can_be_acknowledged_and_resolve_and_reopen_on_their_own()
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "n" })).Content.ReadFromJsonAsync<JsonElement>();
        var enroll = await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "issues-01", "Ubuntu 24.04 LTS", "ubuntu", "24.04", "x64", "0.1.0", null));
        var resp = (await enroll.Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var hostId = resp.AgentId;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);

        BaselineReport Baseline(CheckStatus status) => new(DateTime.UtcNow, "rev-1", [new("ssh-password-auth", status, "PasswordAuthentication yes")]);
        Assert.Equal(HttpStatusCode.NoContent, (await agent.PostAsJsonAsync("/api/agent/baseline", Baseline(CheckStatus.Fail), Json)).StatusCode);
        var now = DateTime.UtcNow;
        var updates = new AgentReport("updates.check", now, now, true, null)
        {
            Updates = new UpdatesReport("apt", [new PendingUpdate("openssl", "3.0.1", "3.0.2", "noble-security", true)], false, [], null),
        };
        (await agent.PostAsJsonAsync("/api/agent/reports", updates, AgentJsonContext.Default.AgentReport)).EnsureSuccessStatusCode();

        async Task<List<JsonElement>> Issues(string state = "open") =>
            (await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={hostId}&state={state}"))!.GetProperty("items").EnumerateArray().ToList();
        var open = await Issues();
        Assert.Equal(["baseline.failed", "updates.security"], open.Select(i => i.GetProperty("rule").GetString()!).Order().ToArray());
        var check = open.Single(i => i.GetProperty("rule").GetString() == "baseline.failed");
        Assert.Equal("ssh-password-auth", check.GetProperty("subject").GetString());
        Assert.Equal("High", check.GetProperty("severity").GetString());
        Assert.Equal("issues-01", check.GetProperty("hostName").GetString());
        var checkId = check.GetProperty("id").GetInt64();

        // Acknowledge: still open, no longer counted in the badge, audited.
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsJsonAsync($"/api/issues/{checkId}/ack", new { note = "rolling out keys this week" })).StatusCode);
        var list = await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={hostId}");
        Assert.Equal((2, 1, 1), (list.GetProperty("summary").GetProperty("open").GetInt32(), list.GetProperty("summary").GetProperty("acknowledged").GetInt32(),
            list.GetProperty("summary").GetProperty("unacknowledged").GetInt32()));
        Assert.Equal("Medium", list.GetProperty("summary").GetProperty("topSeverity").GetString());
        Assert.Equal("rolling out keys this week", (await Issues("acknowledged")).Single().GetProperty("ackNote").GetString());
        var audit = await admin.GetFromJsonAsync<JsonElement>("/api/audit");
        Assert.Contains(audit.EnumerateArray(), a => a.GetProperty("action").GetString() == "issue.acknowledge");

        // The check passes: the issue resolves on its own, with an Info event on the timeline.
        await agent.PostAsJsonAsync("/api/agent/baseline", Baseline(CheckStatus.Pass), Json);
        Assert.Equal("updates.security", Assert.Single(await Issues()).GetProperty("rule").GetString());
        Assert.Contains(await Issues("resolved"), i => i.GetProperty("id").GetInt64() == checkId);
        var events = await admin.GetFromJsonAsync<JsonElement>($"/api/events?hostId={hostId}&kind={IssueService.ResolvedKind}");
        var resolved = Assert.Single(events.GetProperty("items").EnumerateArray());
        Assert.Equal("Info", resolved.GetProperty("severity").GetString());
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync($"/api/issues/{checkId}/ack", new { })).StatusCode);

        // It fails again: same row, a second occurrence, and the acknowledgement is gone.
        await agent.PostAsJsonAsync("/api/agent/baseline", Baseline(CheckStatus.Fail), Json);
        var again = (await Issues("unacknowledged")).Single(i => i.GetProperty("rule").GetString() == "baseline.failed");
        Assert.Equal(checkId, again.GetProperty("id").GetInt64());
        Assert.Equal(2, again.GetProperty("occurrences").GetInt32());
        Assert.Equal(JsonValueKind.Null, again.GetProperty("acknowledgedAt").ValueKind);

        var summary = await admin.GetFromJsonAsync<JsonElement>("/api/issues/summary");
        Assert.True(summary.GetProperty("unacknowledged").GetInt32() >= 2);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().GetAsync("/api/issues")).StatusCode);
    }

    [Fact]
    public async Task A_tool_going_down_in_a_heartbeat_opens_an_issue()
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "n" })).Content.ReadFromJsonAsync<JsonElement>();
        var resp = (await (await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "issues-02", "Debian 13", "debian", "13", "x64", "0.1.0", null))).Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);

        HeartbeatRequest Hb(bool running) => new("0.1.0", "issues-02", "Debian 13", "6.12.0",
            new HostMetrics(1, 1_000, 500, 1_000, 500, 0, 0, 0, 60),
            [new ToolStatus { ToolId = "fail2ban", Installed = true, Running = running, Ownership = Ownership.Adopted, ConfigState = ConfigState.InSync }],
            null, []);
        (await agent.PostAsJsonAsync("/api/agent/heartbeat", Hb(true), Json)).EnsureSuccessStatusCode();
        var list = await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={resp.AgentId}");
        Assert.Empty(list.GetProperty("items").EnumerateArray());

        (await agent.PostAsJsonAsync("/api/agent/heartbeat", Hb(false), Json)).EnsureSuccessStatusCode();
        list = await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={resp.AgentId}");
        var issue = Assert.Single(list.GetProperty("items").EnumerateArray());
        Assert.Equal(("tool.problem", "fail2ban"), (issue.GetProperty("rule").GetString(), issue.GetProperty("subject").GetString()));

        (await agent.PostAsJsonAsync("/api/agent/heartbeat", Hb(true), Json)).EnsureSuccessStatusCode();
        list = await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={resp.AgentId}");
        Assert.Empty(list.GetProperty("items").EnumerateArray());
    }
}
