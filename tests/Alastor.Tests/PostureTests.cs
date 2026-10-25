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
using Alastor.Server.Endpoints;
using Alastor.Server.Services.Posture;

namespace Alastor.Tests;

public sealed class PostureTests
{
    private static ManagedHost Host(Action<ManagedHost>? set = null)
    {
        var h = new ManagedHost { Name = "web-01", Hostname = "web-01", SecretHash = "x", IsOnline = true, AppliedRevision = "r1", PolicyApplySuccess = true };
        set?.Invoke(h);
        return h;
    }

    private static readonly PostureMatrix.Extra None = new(false, 0);

    [Fact]
    public void Matrix_marks_unreported_areas_unknown_and_malware_off()
    {
        var row = PostureMatrix.Row(Host(), None);
        Assert.Equal(PostureMatrix.Ok, row["agent"].Status);
        foreach (var key in new[] { "baseline", "hardening", "network", "updates", "vulnerabilities", "banning" })
            Assert.Equal(PostureMatrix.Unknown, row[key].Status);
        Assert.Equal(PostureMatrix.Off, row["malware"].Status);
        Assert.Equal(PostureMatrix.Columns.Select(c => c.Key).Order(), row.Keys.Order());
    }

    [Fact]
    public void Matrix_judges_each_area()
    {
        var now = DateTime.UtcNow;
        var h = Host(x =>
        {
            x.BaselineScore = 72;
            x.HardeningIndex = 58;
            x.NetworkCheckedAt = now;
            x.SshExposure = SshExposureLevel.Public;
            x.PendingUpdates = 4;
            x.SecurityUpdates = 0;
            x.RebootRequired = true;
            x.VulnScannedAt = now;
            x.VulnCritical = 0;
            x.VulnHigh = 3;
            x.MalwareScannedAt = now;
            x.MalwareFindings = 0;
            x.Tools.Add(new HostToolStatus { ToolId = "fail2ban", Installed = true, Running = false });
        });
        var row = PostureMatrix.Row(h, None);
        Assert.Equal(PostureMatrix.Warn, row["baseline"].Status);
        Assert.Equal(PostureMatrix.Bad, row["hardening"].Status);
        Assert.Equal(("bad", "public SSH"), (row["network"].Status, row["network"].Label));
        Assert.Equal(("warn", "reboot required"), (row["updates"].Status, row["updates"].Label));
        Assert.Equal(("warn", "3 high"), (row["vulnerabilities"].Status, row["vulnerabilities"].Label));
        Assert.Equal(PostureMatrix.Ok, row["malware"].Status);
        Assert.Equal(("bad", "fail2ban down"), (row["banning"].Status, row["banning"].Label));
        Assert.Equal(PostureMatrix.Warn, row["agent"].Status); // the stopped tool

        // Known-exploited CVEs and failing high-severity checks outrank everything else in their column.
        row = PostureMatrix.Row(h, new PostureMatrix.Extra(true, 2));
        Assert.Equal(("bad", "2 exploited"), (row["vulnerabilities"].Status, row["vulnerabilities"].Label));
        Assert.Equal(PostureMatrix.Bad, row["baseline"].Status);

        h.SshExposureAccepted = true;
        h.IsOnline = false;
        row = PostureMatrix.Row(h, None);
        Assert.Equal(PostureMatrix.Ok, row["network"].Status);
        Assert.Equal(("bad", "offline"), (row["agent"].Status, row["agent"].Label));
    }

    [Fact]
    public void Matrix_prefers_crowdsec_when_it_is_the_engine()
    {
        var h = Host(x =>
        {
            x.Tools.Add(new HostToolStatus { ToolId = "fail2ban", Availability = Availability.Disabled });
            x.Tools.Add(new HostToolStatus { ToolId = "crowdsec", Installed = true, Running = true });
        });
        Assert.Equal(("ok", "crowdsec"), (PostureMatrix.Row(h, None)["banning"].Status, PostureMatrix.Row(h, None)["banning"].Label));
    }

    [Fact]
    public void Snapshot_leaves_unreported_measures_null()
    {
        var now = DateTime.UtcNow;
        var s = PostureService.From(Host(), 0, DateOnly.FromDateTime(now), now);
        Assert.Null(s.VulnCritical);
        Assert.Null(s.VulnKev);
        Assert.Null(s.SecurityUpdates);
        Assert.Null(s.PublicSsh);
        Assert.Null(s.MalwareFindings);

        // Alpine has no security flag: every pending update counts.
        s = PostureService.From(Host(x => { x.PendingUpdates = 5; x.VulnScannedAt = now; x.VulnHigh = 2; }), 1, DateOnly.FromDateTime(now), now);
        Assert.Equal(5, s.SecurityUpdates);
        Assert.Equal((0, 2, 1), (s.VulnCritical, s.VulnHigh, s.VulnKev));
    }

    [Fact]
    public void Aggregate_averages_and_sums_only_hosts_that_reported()
    {
        var day = new DateOnly(2026, 10, 1);
        var point = StatsEndpoints.Aggregate(day,
        [
            new HostPostureSnapshot { Day = day, Online = true, BaselineScore = 80, VulnCritical = 1, VulnHigh = 0, SecurityUpdates = 0, PublicSsh = true },
            new HostPostureSnapshot { Day = day, Online = false, BaselineScore = 61, VulnCritical = 0, VulnHigh = 0, SecurityUpdates = 3, RebootRequired = true },
            new HostPostureSnapshot { Day = day, Online = true },
        ]);
        Assert.Equal((3, 2), (point.Hosts, point.Online));
        Assert.Equal(70.5, point.BaselineScore);
        Assert.Null(point.HardeningIndex);
        Assert.Equal(1, point.VulnCritical);
        Assert.Equal(1, point.HostsWithHighCves);
        Assert.Equal((3, 1), (point.SecurityUpdates, point.HostsNeedingUpdates));
        Assert.Equal(1, point.RebootRequired);
        Assert.Equal(1, point.PublicSsh);
        Assert.Null(point.MalwareFindings);
    }
}

[Collection(ServerHostCollection.Name)]
public sealed class StatsApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public StatsApiTests(ServerApiTests.Factory factory) => _factory = factory;

    private async Task<(HttpClient Admin, Guid HostId, HttpClient Agent)> SetupAsync()
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "n" })).Content.ReadFromJsonAsync<JsonElement>();
        var enroll = await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "stats-01", "Ubuntu 24.04 LTS", "ubuntu", "24.04", "x64", "0.1.0", null));
        var resp = (await enroll.Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);
        return (admin, resp.AgentId, agent);
    }

    [Fact]
    public async Task Reports_write_todays_posture_snapshot()
    {
        var (admin, hostId, agent) = await SetupAsync();
        var posture = await admin.GetFromJsonAsync<JsonElement>($"/api/stats/posture?hostId={hostId}");
        Assert.Equal(0, posture.GetArrayLength()); // enrollment alone writes nothing

        var baseline = new BaselineReport(DateTime.UtcNow, "rev-1", [new("ssh-password-auth", CheckStatus.Fail, "PasswordAuthentication yes")]);
        Assert.Equal(HttpStatusCode.NoContent, (await agent.PostAsJsonAsync("/api/agent/baseline", baseline, Json)).StatusCode);
        var now = DateTime.UtcNow;
        var updates = new AgentReport("updates.check", now, now, true, null)
        {
            Updates = new UpdatesReport("apt", [new PendingUpdate("openssl", "3.0.1", "3.0.2", "noble-security", true)], true, ["linux-image"], null),
        };
        Assert.Equal(HttpStatusCode.NoContent, (await agent.PostAsJsonAsync("/api/agent/reports", updates, AgentJsonContext.Default.AgentReport)).StatusCode);

        posture = await admin.GetFromJsonAsync<JsonElement>($"/api/stats/posture?hostId={hostId}&days=7");
        var today = Assert.Single(posture.EnumerateArray());
        Assert.Equal(DateOnly.FromDateTime(DateTime.UtcNow).ToString("yyyy-MM-dd"), today.GetProperty("day").GetString());
        Assert.Equal(0, today.GetProperty("baselineScore").GetDouble());
        Assert.Equal(1, today.GetProperty("securityUpdates").GetInt32());
        Assert.Equal(1, today.GetProperty("rebootRequired").GetInt32());
        Assert.Equal(JsonValueKind.Null, today.GetProperty("vulnCritical").ValueKind);

        var matrix = await admin.GetFromJsonAsync<JsonElement>("/api/stats/matrix");
        Assert.Contains(matrix.GetProperty("columns").EnumerateArray(), c => c.GetProperty("key").GetString() == "vulnerabilities");
        var row = matrix.GetProperty("rows").EnumerateArray().Single(r => r.GetProperty("hostId").GetGuid() == hostId);
        Assert.Equal("bad", row.GetProperty("cells").GetProperty("baseline").GetProperty("status").GetString()); // ssh-password-auth is high severity
        Assert.Equal("1 security", row.GetProperty("cells").GetProperty("updates").GetProperty("label").GetString());
    }

    [Fact]
    public async Task Event_and_ban_stats_bucket_by_day_and_hour()
    {
        var (admin, hostId, agent) = await SetupAsync();
        var now = DateTime.UtcNow;
        SecurityEvent Ev(DateTime at, Severity sev, string kind) => new()
        {
            Id = Guid.NewGuid(), OccurredAt = at, Capability = Capability.Banning, Severity = sev, SourceTool = "fail2ban",
            Kind = kind, Subject = "203.0.113.77", Message = kind,
        };
        var batch = new EventBatch([Ev(now, Severity.Low, EventKinds.BanAdded), Ev(now, Severity.High, EventKinds.AuthFailures), Ev(now.AddDays(-2), Severity.Medium, EventKinds.BanAdded)]);
        (await agent.PostAsJsonAsync("/api/agent/events", batch, Json)).EnsureSuccessStatusCode();

        var stats = await admin.GetFromJsonAsync<JsonElement>($"/api/stats/events?hostId={hostId}&days=7");
        var days = stats.GetProperty("days").EnumerateArray().ToList();
        Assert.Equal(7, days.Count); // every day, zeros included
        var last = days[^1];
        Assert.Equal((1, 1), (last.GetProperty("high").GetInt32(), last.GetProperty("low").GetInt32()));
        Assert.Equal(1, days[^3].GetProperty("medium").GetInt32());
        Assert.Contains(stats.GetProperty("byCapability").EnumerateArray(), c => c.GetProperty("key").GetString() == "Banning" && c.GetProperty("count").GetInt32() >= 3);

        var bans = (await admin.GetFromJsonAsync<JsonElement>($"/api/stats/bans?hostId={hostId}&hours=24")).EnumerateArray().ToList();
        Assert.Equal(24, bans.Count);
        Assert.Equal((1, 1), (bans[^1].GetProperty("bans").GetInt32(), bans[^1].GetProperty("authFailures").GetInt32()));
        Assert.Equal(1, bans.Sum(b => b.GetProperty("bans").GetInt32())); // the 2-day-old ban is outside the window

        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().GetAsync("/api/stats/matrix")).StatusCode);
    }
}
