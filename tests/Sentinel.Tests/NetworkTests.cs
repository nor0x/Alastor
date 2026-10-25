using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core.Contracts;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Core.Network;
using Sentinel.Core.Platform;
using Sentinel.Core.Policy;

namespace Sentinel.Tests;

public class NetworkParserTests
{
    [Fact]
    public void Tailscale_status_running_needs_login_and_prefs()
    {
        var ts = NetworkParsers.ParseTailscaleStatus(Fixture.Read("network/ts-running.json"));
        Assert.True(ts.Running);
        Assert.Equal("1.104.2-tc3430f0d2-g598b63867", ts.Version);
        Assert.Equal(["100.64.0.1", "fd7a:115c:a1e0::1"], ts.Ips);
        Assert.Equal("web-01.tail.example.net", ts.DnsName);
        Assert.Equal(1, ts.PeersTotal);
        Assert.Equal(1, ts.PeersOnline);
        Assert.Null(ts.KeyExpiry);

        var idle = NetworkParsers.ParseTailscaleStatus(Fixture.Read("network/ts-needs-login.json"));
        Assert.False(idle.Running);
        Assert.Equal("NeedsLogin", idle.BackendState);
        Assert.Empty(idle.Ips);
        Assert.Null(idle.DnsName);
        Assert.Equal(["Tailscale is stopped."], idle.Health);

        Assert.True(NetworkParsers.ParseTailscaleRunSsh(Fixture.Read("network/ts-prefs.ssh.json")));
        Assert.False(NetworkParsers.ParseTailscaleRunSsh(Fixture.Read("network/ts-prefs.json")));
        Assert.Null(NetworkParsers.ParseTailscaleRunSsh("not json"));
    }

    [Fact]
    public void Addresses_sockets_and_sshd_settings()
    {
        var container = NetworkParsers.ParseIpAddr(Fixture.Read("network/ip-addr.container.json"));
        Assert.Contains(container, a => a.Interface == "eth0" && a.Address == "172.16.2.2" && a.Kind == AddressKind.Private);
        Assert.Contains(container, a => a.Address == "::1" && a.Kind == AddressKind.Loopback);

        var vps = NetworkParsers.ParseIpAddr(Fixture.Read("network/ip-addr.vps.json"));
        Assert.Equal(AddressKind.Public, vps.Single(a => a.Address == "203.0.113.10").Kind);
        Assert.Equal(AddressKind.Public, vps.Single(a => a.Address == "2001:db8:1::10").Kind);
        Assert.Equal(AddressKind.Tailnet, vps.Single(a => a.Address == "100.64.0.1").Kind);
        Assert.Equal(AddressKind.Tailnet, vps.Single(a => a.Address == "fd7a:115c:a1e0::1").Kind);
        Assert.Equal(AddressKind.LinkLocal, vps.Single(a => a.Address == "fe80::ff:fe00:1").Kind);

        var v4 = NetworkParsers.ParseProcNetTcp(Fixture.Read("network/proc-net-tcp.txt"));
        Assert.Contains(new TcpListenSocket("0.0.0.0", 22), v4);
        Assert.Contains(new TcpListenSocket("127.0.0.1", 58124), v4);
        Assert.Contains(new TcpListenSocket("127.0.0.11", 38765), v4);
        var v6 = NetworkParsers.ParseProcNetTcp(Fixture.Read("network/proc-net-tcp6.txt"));
        Assert.Contains(new TcpListenSocket("::", 22), v6);
        Assert.Equal("::1", NetworkParsers.ParseProcNetTcp("hdr\n 0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A x\n")[0].Address);

        var (ports, password, root) = NetworkParsers.ParseSshdSettings(Fixture.Read("network/sshd-T.default.txt"));
        Assert.Equal([22], ports);
        Assert.True(password);
        Assert.Equal("prohibit-password", root);
        Assert.Equal([22, 2222], NetworkParsers.ParseSshdSettings("port 22\nport 2222\npasswordauthentication no\n").Ports);
    }

    [Theory]
    [InlineData("network/ufw-verbose.open.txt", FirewallSshVerdict.OpenToAnywhere, "rate-limited")]
    [InlineData("network/ufw-verbose.tailnet.txt", FirewallSshVerdict.Restricted, "on tailscale0")]
    [InlineData("network/ufw-verbose.admin-ip.txt", FirewallSshVerdict.Restricted, "from 198.51.100.7")]
    [InlineData("baseline/ufw-status.active.txt", FirewallSshVerdict.OpenToAnywhere, "from anywhere")]
    public void Ufw_rules_for_the_ssh_port(string fixture, FirewallSshVerdict verdict, string detail)
    {
        var fw = NetworkParsers.ParseUfwSsh(Fixture.Read(fixture), [22])!;
        Assert.Equal("ufw", fw.Tool);
        Assert.Equal(verdict, fw.Verdict);
        Assert.Contains(detail, fw.Detail);
    }

    [Fact]
    public void Ufw_inactive_defaults_and_custom_ports()
    {
        Assert.Null(NetworkParsers.ParseUfwSsh(Fixture.Read("baseline/ufw-status.inactive.txt"), [22]));
        // The admin-ip ruleset doesn't mention port 2222: denied by default.
        Assert.Equal(FirewallSshVerdict.Blocked, NetworkParsers.ParseUfwSsh(Fixture.Read("network/ufw-verbose.admin-ip.txt"), [2222])!.Verdict);
        var allowAll = "Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n";
        Assert.Equal(FirewallSshVerdict.OpenToAnywhere, NetworkParsers.ParseUfwSsh(allowAll, [22])!.Verdict);
        var denyFirst = allowAll.Replace("allow (incoming)", "deny (incoming)") + "22/tcp                     DENY IN     Anywhere\n22/tcp                     ALLOW IN    Anywhere\n";
        Assert.Equal(FirewallSshVerdict.Blocked, NetworkParsers.ParseUfwSsh(denyFirst, [22])!.Verdict);
        var range = allowAll.Replace("allow (incoming)", "deny (incoming)") + "2000:3000/tcp              ALLOW IN    Anywhere\n";
        Assert.Equal(FirewallSshVerdict.OpenToAnywhere, NetworkParsers.ParseUfwSsh(range, [2222])!.Verdict);
    }

    [Theory]
    [InlineData("baseline/nft-ruleset.drop-policy.json", FirewallSshVerdict.OpenToAnywhere)]
    [InlineData("baseline/nft-ruleset.debian-stock.json", FirewallSshVerdict.NoFirewall)]
    [InlineData("network/nft-ruleset.tailnet-only.json", FirewallSshVerdict.Restricted)]
    [InlineData("network/nft-ruleset.ufw-jump.json", FirewallSshVerdict.OpenToAnywhere)]
    public void Nftables_rules_for_the_ssh_port(string fixture, FirewallSshVerdict verdict)
    {
        var fw = NetworkParsers.ParseNftSsh(Fixture.Read(fixture), [22]);
        Assert.Equal(verdict, fw.Verdict);
        if (verdict == FirewallSshVerdict.Restricted)
        {
            Assert.Contains("on tailscale0", fw.Detail);
            Assert.Contains("from 198.51.100.0/24", fw.Detail);
        }
    }

    [Fact]
    public void Nftables_trailing_drop_and_other_ports()
    {
        // Policy accept with a trailing unconditional drop: 22 is accepted before it, 2222 isn't.
        Assert.Equal(FirewallSshVerdict.OpenToAnywhere, NetworkParsers.ParseNftSsh(Fixture.Read("baseline/nft-ruleset.trailing-drop.json"), [22]).Verdict);
        Assert.Equal(FirewallSshVerdict.Blocked, NetworkParsers.ParseNftSsh(Fixture.Read("baseline/nft-ruleset.trailing-drop.json"), [2222]).Verdict);
        // The ufw ruleset accepts 22 and 443 only.
        Assert.Equal(FirewallSshVerdict.Blocked, NetworkParsers.ParseNftSsh(Fixture.Read("network/nft-ruleset.ufw-jump.json"), [2222]).Verdict);
        Assert.Equal(FirewallSshVerdict.NoFirewall, NetworkParsers.ParseNftSsh("{\"nftables\":[{\"metainfo\":{\"version\":\"1.1.3\"}}]}", [22]).Verdict);
    }
}

public class ExposureAssessorTests
{
    private static readonly IReadOnlyList<HostAddress> Vps = NetworkParsers.ParseIpAddr(Fixture.Read("network/ip-addr.vps.json"));
    private static readonly IReadOnlyList<HostAddress> Container = NetworkParsers.ParseIpAddr(Fixture.Read("network/ip-addr.container.json"));
    private static readonly FirewallAssessment Open = new("ufw", FirewallSshVerdict.OpenToAnywhere, "ufw allows SSH (port 22) from anywhere.");
    private static readonly FirewallAssessment TailnetOnlyFw = new("ufw", FirewallSshVerdict.Restricted, "ufw allows SSH (port 22) only on tailscale0.");

    private static SshFacts Ssh(bool password = false, params TcpListenSocket[] listeners) =>
        new([22], password, "prohibit-password", listeners.Length > 0 ? listeners : [new("0.0.0.0", 22), new("::", 22)]);

    [Fact]
    public void Public_address_with_an_open_firewall_is_public()
    {
        var e = ExposureAssessor.Assess(Ssh(password: true), Vps, Open, null, null, accepted: false);
        Assert.Equal(SshExposureLevel.Public, e.Level);
        Assert.Contains("203.0.113.10", e.ReachableOn);
        Assert.Contains("2001:db8:1::10", e.ReachableOn);
        Assert.Contains(e.Reasons, r => r.Contains("Password logins are enabled"));
        Assert.Contains(e.Reasons, r => r.Contains("provider firewall"));
    }

    [Fact]
    public void Firewall_restrictions_tailnet_binds_and_loopback()
    {
        Assert.Equal(SshExposureLevel.Restricted, ExposureAssessor.Assess(Ssh(), Vps, TailnetOnlyFw, null, null, false).Level);
        Assert.Equal(SshExposureLevel.TailnetOnly, ExposureAssessor.Assess(Ssh(false, new TcpListenSocket("100.64.0.1", 22)), Vps, Open, null, null, false).Level);
        Assert.Equal(SshExposureLevel.LocalOnly, ExposureAssessor.Assess(Ssh(false, new TcpListenSocket("127.0.0.1", 22)), Vps, Open, null, null, false).Level);
        Assert.Equal(SshExposureLevel.NotListening, ExposureAssessor.Assess(new SshFacts([22], false, "no", []), Vps, Open, null, null, false).Level);
        Assert.Equal(SshExposureLevel.NoSsh, ExposureAssessor.Assess(null, Vps, Open, null, null, false).Level);
    }

    [Fact]
    public void Private_only_hosts_use_the_address_the_server_sees()
    {
        Assert.Equal(SshExposureLevel.PrivateOnly, ExposureAssessor.Assess(Ssh(), Container, Open, null, null, false).Level);
        Assert.Equal(SshExposureLevel.PrivateOnly, ExposureAssessor.Assess(Ssh(), Container, Open, null, "10.1.2.3", false).Level);
        var nat = ExposureAssessor.Assess(Ssh(), Container, Open, null, "198.51.100.20", false);
        Assert.Equal(SshExposureLevel.PossiblyPublic, nat.Level);
        Assert.Contains(nat.Reasons, r => r.Contains("1:1 NAT"));
        // A tailnet IP from Tailscale (userspace mode: no tailscale0 interface) still counts as reachable on the tailnet.
        var ts = NetworkParsers.ParseTailscaleStatus(Fixture.Read("network/ts-running.json"));
        Assert.Contains("100.64.0.1", ExposureAssessor.Assess(Ssh(), Container, Open, ts, null, false).ReachableOn);
    }
}

public sealed class NetworkIntegrationTests
{
    private readonly FakeCommandRunner _runner = new();
    private readonly FakeFileSystem _fs = new();
    private readonly InMemoryStateStore _state = new();
    private readonly FakeTime _time = new(new DateTimeOffset(2026, 10, 25, 8, 0, 0, TimeSpan.Zero));

    public NetworkIntegrationTests()
    {
        _runner.Installed.Clear();
        _runner.Installed.UnionWith(["ip", "sshd", "ufw"]);
        _runner.On("ip -j addr show", Fixture.Read("network/ip-addr.vps.json"));
        _runner.On("sshd -T", Fixture.Read("network/sshd-T.default.txt"));
        _runner.On("ufw status verbose", Fixture.Read("network/ufw-verbose.open.txt"));
        _fs.Files["/proc/net/tcp"] = Fixture.Read("network/proc-net-tcp.txt");
        _fs.Files["/proc/net/tcp6"] = Fixture.Read("network/proc-net-tcp6.txt");
    }

    private NetworkIntegration Integration() => new(_runner, _fs, _state, NullLogger<NetworkIntegration>.Instance, _time);

    private static async Task<List<SecurityEvent>> Drain(NetworkIntegration n)
    {
        var list = new List<SecurityEvent>();
        await foreach (var e in n.CollectEventsAsync(default)) list.Add(e);
        return list;
    }

    [Fact]
    public async Task Public_ssh_with_passwords_alerts_once_and_accepting_silences_it()
    {
        var n = Integration();
        var report = await n.CheckAsync(new PolicyDocument(), default);
        Assert.True(report.Success, report.Error);
        var net = report.Network!;
        Assert.Equal(SshExposureLevel.Public, net.Exposure.Level);
        Assert.Equal(FirewallSshVerdict.OpenToAnywhere, net.Firewall.Verdict);
        Assert.Equal([22], net.Ssh!.Ports);
        Assert.Null(net.Tailscale);

        var e = Assert.Single(await Drain(n));
        Assert.Equal(EventKinds.ExposureDetected, e.Kind);
        Assert.Equal(Severity.High, e.Severity);
        Assert.Contains("203.0.113.10", e.Message);
        Assert.Contains("password logins are enabled", e.Message);

        await n.CheckAsync(new PolicyDocument(), default);
        Assert.Empty(await Drain(n));

        // Restricting SSH to the tailnet, then opening it again: one new alert.
        _runner.On("ufw status verbose", Fixture.Read("network/ufw-verbose.tailnet.txt"));
        Assert.Equal(SshExposureLevel.Restricted, (await n.CheckAsync(new PolicyDocument(), default)).Network!.Exposure.Level);
        _runner.On("ufw status verbose", Fixture.Read("network/ufw-verbose.open.txt"));
        var accepted = new PolicyDocument { Network = new() { AllowPublicSsh = true } };
        var r = await n.CheckAsync(accepted, default);
        Assert.True(r.Network!.Exposure.Accepted);
        Assert.Empty(await Drain(n));
    }

    [Fact]
    public async Task Detects_tailscale_and_warns_before_the_node_key_expires()
    {
        _runner.Installed.Add("tailscale");
        var expiring = Fixture.Read("network/ts-running.json").Replace("\"Online\": true,", "\"Online\": true,\n    \"KeyExpiry\": \"2026-11-01T08:00:00Z\",");
        _runner.On("tailscale status --json", expiring);
        _runner.On("tailscale debug prefs", Fixture.Read("network/ts-prefs.ssh.json"));
        _runner.On("ufw status verbose", Fixture.Read("network/ufw-verbose.tailnet.txt"));
        var n = Integration();

        var status = await n.DetectAsync(default);
        Assert.True(status.Installed);
        Assert.True(status.Running);
        Assert.Equal("1.104.2", status.Version);
        Assert.Equal("100.64.0.1", status.Details["ip"]);

        var report = (await n.CheckAsync(new PolicyDocument(), default)).Network!;
        Assert.True(report.Tailscale!.SshEnabled);
        Assert.Equal(new DateTime(2026, 11, 1, 8, 0, 0, DateTimeKind.Utc), report.Tailscale.KeyExpiry);
        Assert.Equal(SshExposureLevel.Restricted, report.Exposure.Level);
        var e = Assert.Single(await Drain(n));
        Assert.Equal(EventKinds.TailscaleKeyExpiring, e.Kind);
        Assert.Contains("7 day", e.Message);
        await n.CheckAsync(new PolicyDocument(), default);
        Assert.Empty(await Drain(n));
    }

    [Fact]
    public async Task Missing_tools_and_a_stopped_tailscaled_are_reported_not_fatal()
    {
        _runner.Installed.Clear();
        _runner.Installed.Add("tailscale");
        _runner.On("tailscale status --json", "", 1, Fixture.Read("network/ts-status.not-running.txt"));
        var n = Integration();
        var status = await n.DetectAsync(default);
        Assert.False(status.Running);
        Assert.Contains("doesn't appear to be running", status.LastError);

        var report = await n.CheckAsync(new PolicyDocument(), default);
        Assert.True(report.Success);
        Assert.Equal("NotRunning", report.Network!.Tailscale!.BackendState);
        Assert.Equal(SshExposureLevel.NoSsh, report.Network.Exposure.Level);
        Assert.Equal(FirewallSshVerdict.Unknown, report.Network.Firewall.Verdict);

        _runner.Installed.Clear();
        Assert.Equal(Availability.Disabled, (await n.DetectAsync(default)).Availability);
        Assert.False(n.IsWanted(new PolicyDocument { Network = new() { CheckSchedule = "off" } }));
    }

    private sealed class FakeTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

[Collection(ServerHostCollection.Name)]
public sealed class NetworkApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public NetworkApiTests(ServerApiTests.Factory factory) => _factory = factory;

    private async Task<(HttpClient Admin, HttpClient Agent, Guid HostId)> EnrollAsync(string name)
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Sentinel-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "n" })).Content.ReadFromJsonAsync<JsonElement>();
        var enroll = await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, name, "Ubuntu 24.04 LTS", "ubuntu", "24.04", "x64", "0.1.0", null));
        var resp = (await enroll.Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);
        return (admin, agent, resp.AgentId);
    }

    private static AgentReport Check(IReadOnlyList<HostAddress> addresses, FirewallAssessment firewall)
    {
        var ssh = new SshFacts([22], true, "prohibit-password", [new("0.0.0.0", 22), new("::", 22)]);
        var now = DateTime.UtcNow;
        return new AgentReport(NetworkIntegration.CheckJob, now, now, true, null)
        {
            Network = new NetworkReport(null, null, addresses, ssh, firewall, ExposureAssessor.Assess(ssh, addresses, firewall, null, null, false)),
        };
    }

    [Fact]
    public async Task Reports_are_stored_and_accepting_public_ssh_applies_at_once()
    {
        var (admin, agent, hostId) = await EnrollAsync("edge-01");
        var open = new FirewallAssessment("ufw", FirewallSshVerdict.OpenToAnywhere, "ufw allows SSH (port 22) from anywhere.");
        var vps = NetworkParsers.ParseIpAddr(Fixture.Read("network/ip-addr.vps.json"));
        Assert.Equal(HttpStatusCode.NoContent, (await agent.PostAsJsonAsync("/api/agent/reports", Check(vps, open), AgentJsonContext.Default.AgentReport)).StatusCode);

        var detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}/network", Json);
        Assert.Equal("Public", detail.GetProperty("exposure").GetProperty("level").GetString());
        Assert.Equal("network.checkSchedule", detail.GetProperty("schedule").GetProperty("key").GetString());
        Assert.False(detail.GetProperty("allowPublicSsh").GetBoolean());
        var summary = (await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}", Json)).GetProperty("summary");
        Assert.Equal("Public", summary.GetProperty("sshExposure").GetString());
        var overview = await admin.GetFromJsonAsync<JsonElement>("/api/overview", Json);
        Assert.True(overview.GetProperty("hostsWithPublicSsh").GetInt32() >= 1);

        (await admin.PutAsJsonAsync($"/api/policies/host/{hostId}", new { yaml = "network:\n  allowPublicSsh: true\n", comment = "bastion" })).EnsureSuccessStatusCode();
        detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}/network", Json);
        Assert.True(detail.GetProperty("exposure").GetProperty("accepted").GetBoolean());
        summary = (await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}", Json)).GetProperty("summary");
        Assert.True(summary.GetProperty("sshExposureAccepted").GetBoolean());

        var fleet = await admin.GetFromJsonAsync<JsonElement>("/api/network", Json);
        var row = fleet.EnumerateArray().First(r => r.GetProperty("name").GetString() == "edge-01");
        Assert.Equal("OpenToAnywhere", row.GetProperty("firewall").GetString());
        Assert.True(row.GetProperty("passwordAuth").GetBoolean());

        // A failed check keeps the last report.
        await agent.PostAsJsonAsync("/api/agent/reports", new AgentReport(NetworkIntegration.CheckJob, DateTime.UtcNow, DateTime.UtcNow, false, "boom"), AgentJsonContext.Default.AgentReport);
        detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{hostId}/network", Json);
        Assert.False(detail.GetProperty("lastCheckSucceeded").GetBoolean());
        Assert.Equal("Public", detail.GetProperty("exposure").GetProperty("level").GetString());

        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsync($"/api/hosts/{hostId}/actions/check-network", null)).StatusCode);
        var commands = await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json);
        Assert.Contains(commands!, c => c.Type == AgentCommandTypes.RunJob && c.Payload["job"] == NetworkIntegration.CheckJob);
    }
}
