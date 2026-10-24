using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Sentinel.Core.Baseline;
using Sentinel.Core.Contracts;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;

namespace Sentinel.Tests;

/// <summary>End-to-end over HTTP against the real server with a temporary SQLite database.</summary>
[Collection(ServerHostCollection.Name)]
public sealed class ServerApiTests : IClassFixture<ServerApiTests.Factory>
{
    public sealed class Factory : WebApplicationFactory<Program>
    {
        public string DataDir { get; } = Path.Combine(Path.GetTempPath(), "sentinel-test-" + Guid.NewGuid().ToString("N"));

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("DataDir", DataDir);
            builder.UseSetting("AdminPassword", "test-password-123");
            builder.UseSetting("SecureCookies", "false");
            builder.UseSetting("ThreatFeedEnabled", "false"); // no internet in tests; ThreatFeedTests drives the feed itself
            builder.UseSetting("AuthRateLimitPerMinute", "1000"); // every test signs in and enrolls; the default 10/min is for real clients
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try { Directory.Delete(DataDir, true); } catch (IOException) { }
        }
    }

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };
    private readonly Factory _factory;

    public ServerApiTests(Factory factory) => _factory = factory;

    private async Task<HttpClient> AdminAsync()
    {
        var c = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        var r = await c.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" });
        r.EnsureSuccessStatusCode();
        c.DefaultRequestHeaders.Add("X-Sentinel-Request", "1");
        return c;
    }

    private async Task<(Guid HostId, HttpClient Agent)> EnrollAsync(HttpClient admin)
    {
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "t" })).Content.ReadFromJsonAsync<JsonElement>();
        var secret = token.GetProperty("secret").GetString()!;
        var anon = _factory.CreateClient();
        var enroll = await anon.PostAsJsonAsync("/api/agent/enroll", new EnrollRequest(secret, "web-01", "Ubuntu 26.04", "ubuntu", "26.04", "x64", "0.1.0", null));
        enroll.EnsureSuccessStatusCode();
        var resp = (await enroll.Content.ReadFromJsonAsync<EnrollResponse>(Json))!;

        var again = await anon.PostAsJsonAsync("/api/agent/enroll", new EnrollRequest(secret, "evil", "x", "x", "x", "x", "x", null));
        Assert.Equal(HttpStatusCode.Unauthorized, again.StatusCode); // single-use

        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);
        return (resp.AgentId, agent);
    }

    [Fact]
    public async Task Unauthenticated_requests_are_rejected()
    {
        var c = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/api/hosts")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/api/agent/desired-state")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/about")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "wrong" })).StatusCode);
    }

    [Fact]
    public async Task Cookie_requests_without_csrf_header_are_refused()
    {
        var admin = await AdminAsync();
        admin.DefaultRequestHeaders.Remove("X-Sentinel-Request");
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.PostAsJsonAsync("/api/groups", new { name = "x" })).StatusCode);
    }

    [Fact]
    public async Task Enroll_heartbeat_desired_state_and_events_roundtrip()
    {
        var admin = await AdminAsync();
        var (hostId, agent) = await EnrollAsync(admin);

        var desired = (await agent.GetFromJsonAsync<DesiredStateResponse>("/api/agent/desired-state", Json))!;
        Assert.True(desired.Policy.Banning!.Jails!["sshd"].Enabled);

        var hb = await agent.PostAsJsonAsync("/api/agent/heartbeat", new HeartbeatRequest("0.1.0", "web-01", "Ubuntu 26.04", "6.8.0",
            new HostMetrics(12.5, 1_000_000_000, 400_000_000, 20_000_000_000, 5_000_000_000, 0.1, 0.2, 0.3, 3600),
            [new ToolStatus { ToolId = "fail2ban", Installed = true, Running = true, Version = "1.1.0", Ownership = Ownership.Adopted, ConfigState = ConfigState.InSync }],
            new PolicyApplyReport(desired.Revision, true, DateTime.UtcNow, []),
            ["192.0.2.50"]), Json);
        hb.EnsureSuccessStatusCode();
        var hbResp = (await hb.Content.ReadFromJsonAsync<HeartbeatResponse>(Json))!;
        Assert.Equal(desired.Revision, hbResp.DesiredRevision);

        var ev = new SecurityEvent
        {
            Id = Guid.NewGuid(), OccurredAt = DateTime.UtcNow, Capability = Capability.Banning, Severity = Severity.Low,
            SourceTool = "fail2ban", Kind = EventKinds.BanAdded, Subject = "203.0.113.9", Message = "Banned 203.0.113.9 in jail sshd",
        };
        var first = await (await agent.PostAsJsonAsync("/api/agent/events", new EventBatch([ev]), Json)).Content.ReadFromJsonAsync<EventBatchResult>(Json);
        var second = await (await agent.PostAsJsonAsync("/api/agent/events", new EventBatch([ev]), Json)).Content.ReadFromJsonAsync<EventBatchResult>(Json);
        Assert.Equal(1, first!.Accepted);
        Assert.Equal(1, second!.Duplicates); // idempotent re-delivery

        var host = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}");
        Assert.Equal("in-sync", host.GetProperty("summary").GetProperty("policySync").GetString());
        Assert.Equal(40.0, host.GetProperty("summary").GetProperty("memoryPercent").GetDouble());
        var tools = host.GetProperty("tools").EnumerateArray().ToList();
        Assert.Contains(tools, t => t.GetProperty("toolId").GetString() == "fail2ban" && t.GetProperty("running").GetBoolean());
        Assert.Contains(tools, t => t.GetProperty("toolId").GetString() == "trivy" && !t.GetProperty("implemented").GetBoolean());

        var events = await admin.GetFromJsonAsync<JsonElement>($"/api/events?hostId={hostId}&ip=203.0.113.9");
        Assert.Single(events.GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Manual_ban_becomes_an_agent_command_and_allowlisted_targets_are_refused()
    {
        var admin = await AdminAsync();
        var (hostId, agent) = await EnrollAsync(admin);

        var ban = await admin.PostAsJsonAsync("/api/bans", new { target = "198.51.100.7", hostIds = new[] { hostId }, reason = "scanner" });
        Assert.Equal(HttpStatusCode.Accepted, ban.StatusCode);

        var cmds = (await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json))!;
        var cmd = Assert.Single(cmds);
        Assert.Equal(AgentCommandTypes.Ban, cmd.Type);
        Assert.Equal("198.51.100.7", cmd.Payload["target"]);
        Assert.Empty((await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json))!); // delivered once
        (await agent.PostAsJsonAsync($"/api/agent/commands/{cmd.Id}/result", new AgentCommandResult(true, "Banned"), Json)).EnsureSuccessStatusCode();

        (await admin.PostAsJsonAsync("/api/allowlist", new { target = "192.0.2.0/24", note = "office" })).EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync("/api/bans", new { target = "192.0.2.10" })).StatusCode);

        // The allowlist flows into every host's effective policy (fail2ban ignoreip).
        var desired = (await agent.GetFromJsonAsync<DesiredStateResponse>("/api/agent/desired-state", Json))!;
        Assert.Contains("192.0.2.0/24", desired.Policy.Banning!.Allowlist!);
    }

    [Fact]
    public async Task Policy_save_validates_versions_and_reverts()
    {
        var admin = await AdminAsync();
        var bad = await admin.PutAsJsonAsync("/api/policies/global", new { yaml = "banning:\n  defaults:\n    maxretry: 0\n" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, bad.StatusCode);

        var preview = await (await admin.PostAsJsonAsync("/api/policies/preview", new { scope = "Global", yaml = "banning:\n  jails:\n    sshd: {enabled: true, maxretry: 4}\n" }))
            .Content.ReadFromJsonAsync<JsonElement>();
        Assert.Contains("maxretry = 4", preview.GetProperty("fail2BanConfig").GetString());

        var layer = await admin.GetFromJsonAsync<JsonElement>("/api/policies/global");
        var original = layer.GetProperty("yaml").GetString()!;
        var v1 = layer.GetProperty("layer").GetProperty("currentVersion").GetInt32();
        (await admin.PutAsJsonAsync("/api/policies/global", new { yaml = original.Replace("maxretry: 5", "maxretry: 6"), comment = "stricter" })).EnsureSuccessStatusCode();
        var layerId = layer.GetProperty("layer").GetProperty("id").GetGuid();
        (await admin.PostAsync($"/api/policies/layers/{layerId}/revert/{v1}", null)).EnsureSuccessStatusCode();
        var after = await admin.GetFromJsonAsync<JsonElement>("/api/policies/global");
        Assert.Equal(original, after.GetProperty("yaml").GetString());
        Assert.Equal(v1 + 2, after.GetProperty("layer").GetProperty("currentVersion").GetInt32());
    }

    [Fact]
    public async Task Preview_judges_warnings_on_the_merged_policy()
    {
        var admin = await AdminAsync();
        await admin.PostAsJsonAsync("/api/allowlist", new { target = "203.0.113.0/24", note = "vpn" }); // 201, or 409 if another test added it

        // The layer itself lists no allowlist, but the Bans page does, so "allowlist is empty" would be wrong.
        var preview = await (await admin.PostAsJsonAsync("/api/policies/preview", new { scope = "Global", yaml = "banning:\n  jails:\n    sshd: {enabled: true}\n" }))
            .Content.ReadFromJsonAsync<JsonElement>();
        var paths = preview.GetProperty("issues").EnumerateArray().Select(i => i.GetProperty("path").GetString()).ToList();
        Assert.DoesNotContain("banning.allowlist", paths);

        // A warning that still holds after merging is kept.
        var risky = await (await admin.PostAsJsonAsync("/api/policies/preview", new { scope = "Global", yaml = "banning:\n  jails:\n    sshd: {enabled: true, maxretry: 2}\n" }))
            .Content.ReadFromJsonAsync<JsonElement>();
        Assert.Contains(risky.GetProperty("issues").EnumerateArray(), i => i.GetProperty("path").GetString() == "banning.jails.sshd.maxretry");
    }

    [Fact]
    public async Task Server_settings_are_admin_only_and_never_return_secrets()
    {
        var admin = await AdminAsync();
        var settings = await admin.GetFromJsonAsync<JsonElement>("/api/system/settings");
        var byKey = settings.EnumerateArray().ToDictionary(s => s.GetProperty("key").GetString()!, s => s.GetProperty("value").GetString()!);
        Assert.Equal("SENTINEL_HEARTBEATINTERVAL", settings.EnumerateArray().First(s => s.GetProperty("key").GetString() == "HeartbeatInterval").GetProperty("envVar").GetString());
        Assert.DoesNotContain("AdminPassword", byKey.Keys);
        Assert.DoesNotContain("ConnectionString", byKey.Keys);
        Assert.Equal("(not set)", byKey["NvdApiKey"]);

        var created = await (await admin.PostAsJsonAsync("/api/api-keys", new { name = "settings-probe" })).Content.ReadFromJsonAsync<JsonElement>();
        var reader = _factory.CreateClient();
        reader.DefaultRequestHeaders.Add("X-Api-Key", created.GetProperty("secret").GetString());
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync("/api/system/settings")).StatusCode);
    }

    [Fact]
    public async Task Read_only_api_key_can_read_but_not_write()
    {
        var admin = await AdminAsync();
        var created = await (await admin.PostAsJsonAsync("/api/api-keys", new { name = "grafana" })).Content.ReadFromJsonAsync<JsonElement>();
        var key = created.GetProperty("secret").GetString()!;
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Add("X-Api-Key", key);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/hosts")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/overview")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.PostAsJsonAsync("/api/bans", new { target = "203.0.113.1" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/api/api-keys")).StatusCode);
    }

    [Fact]
    public async Task Baseline_report_is_scored_on_the_server_and_merged_with_the_catalog()
    {
        var admin = await AdminAsync();
        var (hostId, agent) = await EnrollAsync(admin);

        BaselineReport Report(CheckStatus firewall) => new(DateTime.UtcNow, "rev-1",
        [
            new("ssh-password-auth", CheckStatus.Pass, "PasswordAuthentication no"),
            new("firewall-active", firewall, "No active firewall") { Commands = ["sudo ufw --force enable"] },
            new("time-sync", CheckStatus.Unknown, "?"),
            new("not-a-check", CheckStatus.Fail, "ignored"),
        ]);

        Assert.Equal(HttpStatusCode.NoContent, (await agent.PostAsJsonAsync("/api/agent/baseline", Report(CheckStatus.Fail), Json)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await admin.PostAsJsonAsync("/api/agent/baseline", Report(CheckStatus.Fail), Json)).StatusCode);

        var host = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}/baseline", Json);
        Assert.Equal(50, host.GetProperty("score").GetInt32()); // High pass + High fail; unknown left out
        var checks = host.GetProperty("checks").EnumerateArray().ToList();
        Assert.Equal(BaselineCatalog.All.Count, checks.Count); // every catalog check, reported or not
        var fw = checks.Single(c => c.GetProperty("id").GetString() == "firewall-active");
        Assert.Equal("Fail", fw.GetProperty("status").GetString());
        Assert.Equal("Manual", fw.GetProperty("fix").GetString());
        Assert.Equal("sudo ufw --force enable", fw.GetProperty("commands")[0].GetString());
        Assert.NotEqual(JsonValueKind.Null, fw.GetProperty("failingSince").ValueKind);
        Assert.Equal(JsonValueKind.Null, checks.Single(c => c.GetProperty("id").GetString() == "kernel-aslr").GetProperty("status").ValueKind);

        var summary = (await admin.GetFromJsonAsync<JsonElement>("/api/hosts", Json)).EnumerateArray().Single(h => h.GetProperty("id").GetGuid() == hostId);
        Assert.Equal(50, summary.GetProperty("baselineScore").GetInt32());
        Assert.Equal(1, summary.GetProperty("baselineFailing").GetInt32());

        var fleet = await admin.GetFromJsonAsync<JsonElement>("/api/baseline", Json);
        var fleetFw = fleet.GetProperty("checks").EnumerateArray().Single(c => c.GetProperty("check").GetProperty("id").GetString() == "firewall-active");
        Assert.Contains(fleetFw.GetProperty("failingHosts").EnumerateArray(), h => h.GetProperty("id").GetGuid() == hostId);
        var overview = await admin.GetFromJsonAsync<JsonElement>("/api/overview", Json);
        Assert.True(overview.GetProperty("hostsFailingBaselineHigh").GetInt32() >= 1);

        // The check now passes: failingSince clears and the score goes to 100.
        await agent.PostAsJsonAsync("/api/agent/baseline", Report(CheckStatus.Pass), Json);
        host = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}/baseline", Json);
        Assert.Equal(100, host.GetProperty("score").GetInt32());
        Assert.Equal(JsonValueKind.Null, host.GetProperty("checks").EnumerateArray().Single(c => c.GetProperty("id").GetString() == "firewall-active").GetProperty("failingSince").ValueKind);

        var recheck = await admin.PostAsync($"/api/hosts/{hostId}/actions/recheck", null);
        Assert.Equal(HttpStatusCode.Accepted, recheck.StatusCode);
        var cmds = await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json);
        Assert.Contains(cmds!, c => c.Type == AgentCommandTypes.BaselineCheck);
    }
}
