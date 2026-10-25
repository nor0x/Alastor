using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging.Abstractions;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Network;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Tests;

public sealed class ExposureParserTests
{
    [Fact]
    public void Ss_lists_tcp_and_udp_listeners_with_their_process()
    {
        var sockets = NetworkParsers.ParseSs(Fixture.Read("network/ss-tulpn.txt"));
        Assert.Equal(9, sockets.Count);
        Assert.Contains(new ListenSocket("udp", "0.0.0.0", 51820, "python3", 812), sockets);
        Assert.Contains(new ListenSocket("udp", "127.0.0.53", 53, "python3", 812), sockets);
        Assert.Contains(new ListenSocket("tcp", "127.0.0.1", 5432, "python3", 812), sockets);
        Assert.Contains(new ListenSocket("tcp", "0.0.0.0", 8080, "alastor-server", 7059), sockets);
        Assert.Contains(new ListenSocket("tcp", "0.0.0.0", 2024), sockets); // no process column
    }

    [Fact]
    public void Ss_reads_ipv6_wildcards_scopes_and_mapped_addresses()
    {
        var sockets = NetworkParsers.ParseSs(Fixture.Read("network/ss-tulpn.v6.txt"));
        Assert.Contains(new ListenSocket("tcp", "::", 22, "sshd", 812), sockets);
        Assert.Contains(new ListenSocket("tcp", "::", 80, "caddy", 1031), sockets); // *:80
        Assert.Contains(new ListenSocket("udp", "fe80::5054:ff:fe12:3456", 546, "systemd-network", 402), sockets);
        Assert.Contains(new ListenSocket("udp", "::", 51820), sockets);
        Assert.Contains(new ListenSocket("tcp", "127.0.0.1", 3000, "node", 2210), sockets);
        Assert.Contains(new ListenSocket("tcp", "2001:db8::10", 5432, "postgres", 990), sockets); // first of two owners
        Assert.True(sockets.Single(s => s.Port == 80).IsWildcard);
    }

    [Fact]
    public void Proc_net_udp_cgroup_and_systemd_scores()
    {
        var udp = NetworkParsers.ParseProcNet(Fixture.Read("network/proc-net-udp.txt"), "udp");
        Assert.Equal([new ListenSocket("udp", "127.0.0.53", 53), new ListenSocket("udp", "0.0.0.0", 51820)], udp);
        Assert.Contains(new ListenSocket("tcp", "0.0.0.0", 22), NetworkParsers.ParseProcNet(Fixture.Read("network/proc-net-tcp.txt"), "tcp"));

        Assert.Equal("nginx.service", NetworkParsers.ParseCgroupUnit(Fixture.Read("network/cgroup.v2.txt")));
        Assert.Equal("redis-server.service", NetworkParsers.ParseCgroupUnit(Fixture.Read("network/cgroup.v1.txt")));
        Assert.Null(NetworkParsers.ParseCgroupUnit(Fixture.Read("network/cgroup.session.txt")));

        var scores = NetworkParsers.ParseSystemdSecurity(Fixture.Read("network/systemd-analyze-security.json"));
        Assert.Equal((9.6, "UNSAFE"), scores["nginx.service"]);
        Assert.Equal((4.7, "OK"), scores["redis-server.service"]);
        Assert.Equal(9.6, scores["sshd.service"].Exposure); // a number in some versions
    }

    [Fact]
    public void Ufw_and_nftables_judge_any_port_and_protocol()
    {
        var open = Fixture.Read("network/ufw-verbose.open.txt");
        Assert.Equal(FirewallSshVerdict.OpenToAnywhere, NetworkParsers.ParseUfw(open, [443], "tcp", "port 443/tcp")!.Verdict);
        var redis = NetworkParsers.ParseUfw(open, [6379], "tcp", "port 6379/tcp")!;
        Assert.Equal(FirewallSshVerdict.Blocked, redis.Verdict);
        Assert.Contains("port 6379/tcp", redis.Detail);
        Assert.Equal(FirewallSshVerdict.Blocked, NetworkParsers.ParseUfw(open, [443], "udp", "port 443/udp")!.Verdict); // 443/tcp doesn't cover udp
        Assert.Equal(FirewallSshVerdict.OpenToAnywhere, NetworkParsers.ParseUfwSsh(open, [22])!.Verdict); // unchanged for SSH

        var tailnet = Fixture.Read("network/ufw-verbose.tailnet.txt");
        Assert.Equal(FirewallSshVerdict.Restricted, NetworkParsers.ParseUfw(tailnet, [51820], "udp", "port 51820/udp")!.Verdict);

        // App profiles and port numbers without a protocol.
        var profiles = open.Replace("443/tcp                    ALLOW IN    Anywhere\n", "Nginx Full                 ALLOW IN    Anywhere\n53                         ALLOW IN    Anywhere\n");
        Assert.Equal(FirewallSshVerdict.OpenToAnywhere, NetworkParsers.ParseUfw(profiles, [80], "tcp", "port 80/tcp")!.Verdict);
        Assert.Equal(FirewallSshVerdict.OpenToAnywhere, NetworkParsers.ParseUfw(profiles, [53], "udp", "port 53/udp")!.Verdict);

        var nft = Fixture.Read("network/nft-ruleset.tailnet-only.json");
        Assert.Equal(FirewallSshVerdict.Restricted, NetworkParsers.ParseNft(nft, [6379], "tcp", "port 6379/tcp").Verdict); // tailscale0 only
        Assert.Equal(NetworkParsers.ParseNftSsh(nft, [22]).Verdict, NetworkParsers.ParseNft(nft, [22], "tcp", "SSH").Verdict);
    }
}

public sealed class ServiceExposureAssessorTests
{
    private static readonly IReadOnlyList<HostAddress> Vps = NetworkParsers.ParseIpAddr(Fixture.Read("network/ip-addr.vps.json"));

    [Fact]
    public void Services_are_judged_by_bound_address_then_firewall()
    {
        var sockets = NetworkParsers.ParseSs(Fixture.Read("network/ss-tulpn.txt"));
        FirewallAssessment Judge(int port, string proto) => port == 6379
            ? new("ufw", FirewallSshVerdict.Blocked, "ufw denies port 6379/tcp.")
            : new("ufw", FirewallSshVerdict.OpenToAnywhere, $"ufw allows port {port}/{proto} from anywhere.");
        var services = ServiceExposureAssessor.Assess(sockets, Vps, null, Judge,
            new Dictionary<int, string> { [812] = "redis-server.service" },
            new Dictionary<string, (double, string)> { ["redis-server.service"] = (4.7, "OK") });

        var https = services.Single(s => s.Key == "443/tcp");
        Assert.Equal(ServiceReach.Public, https.Reach);
        Assert.Contains("203.0.113.10", https.ReachableOn);
        Assert.Equal(("python3", "redis-server.service", 4.7), (https.Process, https.Unit, https.SystemdExposure));
        Assert.Equal("python3 on 443/tcp", https.Label);
        Assert.Equal(ServiceReach.Restricted, services.Single(s => s.Key == "6379/tcp").Reach);
        Assert.Equal(ServiceReach.Local, services.Single(s => s.Key == "5432/tcp").Reach);
        Assert.Equal(ServiceReach.Local, services.Single(s => s.Key == "53/udp").Reach);
        Assert.Equal(ServiceReach.Public, services.Single(s => s.Key == "51820/udp").Reach);
        Assert.Null(services.Single(s => s.Key == "2024/tcp").Process);

        var unexpected = ServiceExposureAssessor.Unexpected(services, [22], ["443/tcp", "51820"]).Select(s => s.Key).ToList();
        Assert.Equal(["2024/tcp", "8080/tcp"], unexpected);
    }

    [Fact]
    public void Tailnet_and_private_bindings_never_count_as_public()
    {
        var sockets = new List<ListenSocket> { new("tcp", "100.64.0.1", 9100), new("tcp", "10.0.0.5", 9200) };
        var services = ServiceExposureAssessor.Assess(sockets, Vps, null, (_, _) => throw new InvalidOperationException("no firewall lookup for non-public services"));
        Assert.Equal(ServiceReach.Tailnet, services.Single(s => s.Port == 9100).Reach);
        Assert.Equal(ServiceReach.Private, services.Single(s => s.Port == 9200).Reach);
    }

    [Theory]
    [InlineData("443", 443, 443, null)]
    [InlineData("443/tcp", 443, 443, "tcp")]
    [InlineData("51820/UDP", 51820, 51820, "udp")]
    [InlineData("60000-61000/udp", 60000, 61000, "udp")]
    public void Port_specs_parse(string spec, int lo, int hi, string? proto)
    {
        Assert.True(ServiceExposureAssessor.TryParsePortSpec(spec, out var l, out var h, out var p));
        Assert.Equal((lo, hi, proto), (l, h, p));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("70000")]
    [InlineData("443/icmp")]
    [InlineData("2000-1000")]
    [InlineData("https")]
    public void Bad_port_specs_are_refused_by_policy_validation(string spec)
    {
        Assert.False(ServiceExposureAssessor.TryParsePortSpec(spec, out _, out _, out _));
        Assert.Contains(PolicyYaml.Parse($"network: {{allowPublicPorts: [\"{spec}\"]}}").Issues, i => i.Path == "network.allowPublicPorts[0]");
    }

    [Fact]
    public void Allowed_ports_merge_across_layers()
    {
        var merged = PolicyMerger.Merge(new PolicyDocument { Network = new() { AllowPublicPorts = ["80/tcp", "443/tcp"] } },
            new PolicyDocument { Network = new() { AllowPublicPorts = ["51820/udp", "443/TCP"] } });
        Assert.Equal(["80/tcp", "443/tcp", "51820/udp"], merged.Network!.AllowPublicPorts);
    }
}

public sealed class ExposureIntegrationTests
{
    [Fact]
    public async Task The_network_check_inventories_services_and_alerts_once_per_unexpected_port()
    {
        var runner = new FakeCommandRunner();
        runner.Installed.Clear();
        runner.Installed.UnionWith(["ip", "sshd", "ufw", "ss", "systemd-analyze"]);
        runner.On("ip -j addr show", Fixture.Read("network/ip-addr.vps.json"));
        runner.On("sshd -T", Fixture.Read("network/sshd-T.default.txt"));
        runner.On("ufw status verbose", Fixture.Read("network/ufw-verbose.open.txt"));
        runner.On("ss -tulpnH", Fixture.Read("network/ss-tulpn.txt"));
        runner.On("systemd-analyze security --json=short --no-pager redis-server.service", Fixture.Read("network/systemd-analyze-security.json"));
        var fs = new FakeFileSystem();
        fs.Files["/proc/net/tcp"] = Fixture.Read("network/proc-net-tcp.txt");
        fs.Files["/proc/812/cgroup"] = Fixture.Read("network/cgroup.v1.txt");
        var n = new NetworkIntegration(runner, fs, new InMemoryStateStore(), NullLogger<NetworkIntegration>.Instance, TimeProvider.System);
        var policy = new PolicyDocument { Network = new() { AllowPublicPorts = ["443/tcp"] } };

        var report = (await n.CheckAsync(policy, default)).Network!;
        var services = report.Services!;
        Assert.Equal(9, services.Count);
        var redis = services.Single(s => s.Key == "6379/tcp");
        Assert.Equal(("redis-server.service", 4.7, "OK"), (redis.Unit, redis.SystemdExposure, redis.SystemdRating));
        // ufw's default deny covers redis; 51820/udp has no ufw rule either.
        Assert.Equal(ServiceReach.Restricted, redis.Reach);
        Assert.Equal(ServiceReach.Restricted, services.Single(s => s.Key == "51820/udp").Reach);
        Assert.Equal(ServiceReach.Public, services.Single(s => s.Key == "443/tcp").Reach);

        var events = new List<SecurityEvent>();
        await foreach (var e in n.CollectEventsAsync(default)) events.Add(e);
        // 443 is allowed and everything else is firewalled, so only SSH alerts.
        Assert.DoesNotContain(events, e => e.Kind == EventKinds.ServiceExposed);

        // Opening the firewall exposes 8080 and 2024 (and the others): one alert each, then quiet.
        runner.On("ufw status verbose", Fixture.Read("network/ufw-verbose.open.txt").Replace("Default: deny (incoming)", "Default: allow (incoming)"));
        await n.CheckAsync(policy, default);
        events.Clear();
        await foreach (var e in n.CollectEventsAsync(default)) events.Add(e);
        var exposed = events.Where(e => e.Kind == EventKinds.ServiceExposed).Select(e => e.Subject).Order().ToList();
        Assert.Equal(["2024/tcp", "51820/udp", "6379/tcp", "8080/tcp"], exposed);
        Assert.Contains("add 6379/tcp to network.allowPublicPorts", events.Single(e => e.Subject == "6379/tcp").Message);
        await n.CheckAsync(policy, default);
        await foreach (var e in n.CollectEventsAsync(default)) Assert.NotEqual(EventKinds.ServiceExposed, e.Kind);
    }
}

[Collection(ServerHostCollection.Name)]
public sealed class ExposureApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public ExposureApiTests(ServerApiTests.Factory factory) => _factory = factory;

    [Fact]
    public async Task Unexpected_public_services_reach_the_host_issues_matrix_and_fleet_view()
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "n" })).Content.ReadFromJsonAsync<JsonElement>();
        var resp = (await (await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "exposed-01", "Debian 13", "debian", "13", "x64", "0.1.0", null))).Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);

        var vps = NetworkParsers.ParseIpAddr(Fixture.Read("network/ip-addr.vps.json"));
        var fw = new FirewallAssessment("ufw", FirewallSshVerdict.Blocked, "ufw denies SSH (port 22).");
        var ssh = new SshFacts([22], false, "prohibit-password", [new("0.0.0.0", 22)]);
        var open = (int port, string proto) => new FirewallAssessment("ufw", FirewallSshVerdict.OpenToAnywhere, $"ufw allows port {port}/{proto} from anywhere.");
        var services = ServiceExposureAssessor.Assess(
            [new("tcp", "0.0.0.0", 22, "sshd", 1), new("tcp", "0.0.0.0", 443, "caddy", 2), new("tcp", "0.0.0.0", 6379, "redis-server", 3), new("tcp", "127.0.0.1", 5432, "postgres", 4)],
            vps, null, open);
        var now = DateTime.UtcNow;
        var report = new AgentReport(NetworkIntegration.CheckJob, now, now, true, null)
        {
            Network = new NetworkReport(null, null, vps, ssh, fw, ExposureAssessor.Assess(ssh, vps, fw, null, null, false)) { Services = services },
        };
        (await agent.PostAsJsonAsync("/api/agent/reports", report, AgentJsonContext.Default.AgentReport)).EnsureSuccessStatusCode();

        // The default policy allows 80/tcp and 443/tcp, and SSH has its own check: only redis is unexpected.
        var detail = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{resp.AgentId}/network", Json);
        Assert.Equal(["6379/tcp"], detail.GetProperty("unexpectedPublic").EnumerateArray().Select(x => x.GetString()!).ToArray());
        Assert.Contains("443/tcp", detail.GetProperty("allowPublicPorts").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(4, detail.GetProperty("report").GetProperty("services").GetArrayLength());

        var issues = await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={resp.AgentId}&rule=service.public");
        var issue = Assert.Single(issues.GetProperty("items").EnumerateArray());
        Assert.Equal("redis-server on 6379/tcp is reachable from the internet", issue.GetProperty("title").GetString());

        var fleet = (await admin.GetFromJsonAsync<JsonElement>("/api/network", Json)).EnumerateArray().Single(r => r.GetProperty("hostId").GetGuid() == resp.AgentId);
        Assert.Equal(["6379/tcp redis-server"], fleet.GetProperty("publicServices").EnumerateArray().Select(x => x.GetString()!).ToArray());
        Assert.Equal(3, fleet.GetProperty("publicTotal").GetInt32());

        var matrix = await admin.GetFromJsonAsync<JsonElement>("/api/stats/matrix");
        var cell = matrix.GetProperty("rows").EnumerateArray().Single(r => r.GetProperty("hostId").GetGuid() == resp.AgentId).GetProperty("cells").GetProperty("network");
        Assert.Equal(("warn", "6379/tcp public"), (cell.GetProperty("status").GetString(), cell.GetProperty("label").GetString()));

        // Allowing the port on this host clears it at once.
        (await admin.PutAsJsonAsync($"/api/policies/host/{resp.AgentId}", new { yaml = "network:\n  allowPublicPorts: [6379/tcp]\n" })).EnsureSuccessStatusCode();
        issues = await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={resp.AgentId}&rule=service.public");
        Assert.Empty(issues.GetProperty("items").EnumerateArray());
        var overview = await admin.GetFromJsonAsync<JsonElement>("/api/overview");
        Assert.NotEqual(JsonValueKind.Null, overview.GetProperty("hostsWithPublicServices").ValueKind);
    }
}
