using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core.Blocklists;
using Sentinel.Core.Contracts;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Core.Net;
using Sentinel.Core.Platform;
using Sentinel.Core.Policy;
using Sentinel.Server.Services.Blocklists;

namespace Sentinel.Tests;

public class IpRangeSetTests
{
    private static IpRangeSet Set(params string[] targets) => IpRangeSet.From(targets.Select(t => IpTarget.TryParse(t, out var x) ? x!.Value : throw new ArgumentException(t)));
    private static string[] V4(IpRangeSet s) => s.ToCidrs(AddressFamily.InterNetwork).ToArray();
    private static string[] V6(IpRangeSet s) => s.ToCidrs(AddressFamily.InterNetworkV6).ToArray();

    [Fact]
    public void Adjacent_and_overlapping_networks_merge_into_minimal_cidrs()
    {
        Assert.Equal(["10.0.0.0/23"], V4(Set("10.0.0.0/24", "10.0.1.0/24")));
        Assert.Equal(["10.0.0.0/24"], V4(Set("10.0.0.0/24", "10.0.0.128/25", "10.0.0.7")));
        // 1.0.0.1 - 1.0.0.6 isn't one block: it's .1, .2/31, .4/31, .6
        Assert.Equal(["1.0.0.1", "1.0.0.2/31", "1.0.0.4/31", "1.0.0.6"], V4(Set("1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4", "1.0.0.5", "1.0.0.6")));
        Assert.Equal(["2001:db8::/31"], V6(Set("2001:db8::/32", "2001:db9::/32")));
    }

    [Fact]
    public void Subtracting_an_allowlisted_address_splits_the_network()
    {
        var s = Set("198.51.100.0/24").Except(Set("198.51.100.77"));
        Assert.Equal(["198.51.100.0/26", "198.51.100.64/29", "198.51.100.72/30", "198.51.100.76", "198.51.100.78/31", "198.51.100.80/28", "198.51.100.96/27", "198.51.100.128/25"], V4(s));
        Assert.False(s.Contains(IPAddress.Parse("198.51.100.77")));
        Assert.True(s.Contains(IPAddress.Parse("198.51.100.78")));
        Assert.Equal(255UL, s.Ipv4AddressCount);
    }

    [Fact]
    public void Edges_of_the_address_space()
    {
        Assert.Equal(["0.0.0.0/0"], V4(Set("0.0.0.0/1", "128.0.0.0/1")));
        Assert.Equal(["::/0"], V6(Set("::/1", "8000::/1")));
        Assert.Equal(["255.255.255.255"], V4(Set("255.255.255.254/31").Except(Set("255.255.255.254"))));
        Assert.True(Set("0.0.0.0/8").Except(IpRangeSet.Reserved).IsEmpty);
    }

    [Fact]
    public void Reserved_ranges_cover_private_networks_cgnat_and_link_local()
    {
        foreach (var ip in new[] { "10.1.2.3", "100.100.1.1", "172.20.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254", "fd7a:115c:a1e0::1", "fe80::1", "::1" })
            Assert.True(IpRangeSet.Reserved.Contains(IPAddress.Parse(ip)), ip);
        foreach (var ip in new[] { "1.10.16.1", "8.8.8.8", "2a00:1450::1" })
            Assert.False(IpRangeSet.Reserved.Contains(IPAddress.Parse(ip)), ip);
    }
}

public class BlocklistParserTests
{
    [Fact]
    public void Firehol_netset_keeps_networks_and_skips_comments()
    {
        var parsed = BlocklistParser.Parse(BlocklistFormat.Netset, Fixture.Read("blocklists/firehol_level1.netset"));
        Assert.Equal(0, parsed.Invalid);
        Assert.Equal(0, parsed.TooWide); // 224.0.0.0/3 is reserved-only, so it isn't counted as too wide
        Assert.Contains(parsed.Entries, e => e.ToString() == "1.10.16.0/20");
        Assert.Contains(parsed.Entries, e => e.ToString() == "10.0.0.0/8");

        // After taking out reserved ranges, the bogons are gone and the real entries stay.
        var set = IpRangeSet.From(parsed.Entries).Except(IpRangeSet.Reserved);
        Assert.False(set.Contains(IPAddress.Parse("10.0.0.1")));
        Assert.False(set.Contains(IPAddress.Parse("100.64.0.1")));
        Assert.True(set.Contains(IPAddress.Parse("1.10.16.1")));
    }

    [Fact]
    public void Spamhaus_json_reads_cidrs_and_ignores_the_metadata_record()
    {
        var v4 = BlocklistParser.Parse(BlocklistFormat.SpamhausJson, Fixture.Read("blocklists/spamhaus_drop_v4.json"));
        var v6 = BlocklistParser.Parse(BlocklistFormat.SpamhausJson, Fixture.Read("blocklists/spamhaus_drop_v6.json"));
        Assert.Equal(40, v4.Entries.Count);
        Assert.Equal(0, v4.Invalid);
        Assert.Equal("1.10.16.0/20", v4.Entries[0].ToString());
        Assert.Equal(8, v6.Entries.Count);
        Assert.All(v6.Entries, e => Assert.Equal(AddressFamily.InterNetworkV6, e.Network.BaseAddress.AddressFamily));
    }

    [Fact]
    public void Plain_ip_lists_with_ipv6_and_trailing_comments()
    {
        var de = BlocklistParser.Parse(BlocklistFormat.Netset, Fixture.Read("blocklists/blocklist_de_all.txt"));
        Assert.Equal(35, de.Entries.Count);
        Assert.Equal(5, de.Entries.Count(e => e.Network.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6));
        var feodo = BlocklistParser.Parse(BlocklistFormat.Netset, Fixture.Read("blocklists/feodo_recommended.txt"));
        Assert.Equal(["50.16.16.211"], feodo.Entries.Select(e => e.ToString()));
    }

    [Fact]
    public void Garbage_and_overly_wide_entries_are_skipped()
    {
        var parsed = BlocklistParser.Parse(BlocklistFormat.Netset, "1.2.3.4\nnot-an-ip\n1.2.3\n0.0.0.0/0\n5.0.0.0/7 ; too wide\n2a00::/12\n6.6.6.0/24 # fine\n");
        Assert.Equal(["1.2.3.4", "6.6.6.0/24"], parsed.Entries.Select(e => e.ToString()));
        Assert.Equal(2, parsed.Invalid);
        Assert.Equal(3, parsed.TooWide);
    }
}

public class BlocklistPolicyTests
{
    [Fact]
    public void Lists_replace_and_extra_entries_union_across_layers()
    {
        var global = PolicyYaml.Parse("blocklists:\n  enabled: true\n  lists: [spamhaus-drop, firehol-level1]\n  extra: [198.51.100.0/24]\n").Document!;
        var host = PolicyYaml.Parse("blocklists:\n  lists: [abuse-ch-feodo]\n  extra: [203.0.113.9]\n").Document!;
        var merged = PolicyMerger.MergeLayers([global, host]);
        Assert.True(merged.Blocklists!.Enabled);
        Assert.Equal(["abuse-ch-feodo"], merged.Blocklists.Lists);
        Assert.Equal(["198.51.100.0/24", "203.0.113.9"], merged.Blocklists.Extra);
    }

    [Fact]
    public void Validation_names_unknown_lists_bad_entries_and_schedules()
    {
        var issues = PolicyYaml.Parse("blocklists:\n  enabled: true\n  lists: [spamhaus-drop, nope]\n  extra: [1.2.3.4, banana, 5.0.0.0/6, 10.0.0.0/8]\n  refreshSchedule: sometimes\n").Issues;
        Assert.Contains(issues, i => i.Path == "blocklists.lists[1]" && i.Level == IssueLevel.Error);
        Assert.Contains(issues, i => i.Path == "blocklists.extra[1]" && i.Level == IssueLevel.Error);
        Assert.Contains(issues, i => i.Path == "blocklists.extra[2]" && i.Level == IssueLevel.Error);
        Assert.Contains(issues, i => i.Path == "blocklists.extra[3]" && i.Level == IssueLevel.Warning); // private: never blocked
        Assert.Contains(issues, i => i.Path == "blocklists.refreshSchedule");
        Assert.DoesNotContain(issues, i => i.Path == "blocklists.extra[0]");
    }

    [Fact]
    public void Default_policy_enables_spamhaus_drop()
    {
        var doc = PolicyYaml.Parse(Fixture.Read("default.yaml")).Document!;
        Assert.True(doc.Blocklists!.Enabled);
        Assert.Equal([BlocklistCatalog.DefaultList], doc.Blocklists.Lists);
    }
}

/// <summary>The agent side: rendering, plan/apply against recorded nft output, idempotence, removal.</summary>
public class BlocklistIntegrationTests
{
    private readonly FakeCommandRunner _runner = new();
    private readonly FakeFileSystem _fs = new();
    private readonly InMemoryStateStore _state = new();
    private bool _tableExists;
    private int _loads;

    private static readonly BlocklistPayload Payload = new("abc123", DateTime.UtcNow,
        [new BlocklistListInfo("spamhaus-drop", 3, DateTime.UtcNow, null)], ["1.10.16.0/20", "1.19.0.0/16"], ["2001:678:254::/48"]);

    public BlocklistIntegrationTests()
    {
        _runner.Installed.Add("nft");
        _runner.On("nft --version", "nftables v1.1.6 (Commodore Bullmoose #7)")
            .On("nft list table inet sentinel_vps", () => _tableExists ? new CommandResult(0, "table inet sentinel_vps {}", "") : new CommandResult(1, "", "Error: No such file or directory"))
            .On("nft -c -f /var/lib/sentinel/blocklist.nft", "")
            .On("nft -f /var/lib/sentinel/blocklist.nft", () =>
            {
                _tableExists = true;
                _loads++;
                return new CommandResult(0, "", "");
            })
            .On("nft delete table inet sentinel_vps", () =>
            {
                _tableExists = false;
                return new CommandResult(0, "", "");
            })
            .On("nft -j list chain inet sentinel_vps prerouting", Fixture.Read("blocklists/nft-list-chain.json"));
    }

    private BlocklistIntegration Integration() => new(_runner, _fs, null, _state, "/var/lib/sentinel", NullLogger<BlocklistIntegration>.Instance, TimeProvider.System);

    private static ReconcileRequest Request(bool enabled = true)
    {
        var doc = PolicyYaml.Parse($"blocklists:\n  enabled: {(enabled ? "true" : "false")}\n  lists: [spamhaus-drop]\n").Document!;
        return new ReconcileRequest(doc, PolicyYaml.Revision(doc));
    }

    [Fact]
    public void Nft_script_replaces_only_its_own_table_atomically()
    {
        var script = BlocklistIntegration.RenderNft(Payload, [IPAddress.Parse("192.0.2.10")]);
        Assert.StartsWith("# Managed by SentinelVPS", script);
        // Declare, delete, recreate: one transaction, valid whether or not the table exists yet.
        Assert.Contains("table inet sentinel_vps\ndelete table inet sentinel_vps\ntable inet sentinel_vps {\n", script);
        Assert.Contains("\tset allow4 {\n\t\ttype ipv4_addr; flags interval;\n\t\telements = {\n\t\t\t192.0.2.10\n\t\t}\n", script);
        Assert.Contains("\t\t\t1.10.16.0/20,\n\t\t\t1.19.0.0/16\n", script);
        Assert.Contains("type filter hook prerouting priority -300; policy accept;", script);
        Assert.True(script.IndexOf("@allow4 accept", StringComparison.Ordinal) < script.IndexOf("@blocklist4 counter drop", StringComparison.Ordinal));
        Assert.DoesNotContain("flush ruleset", script);
        Assert.Contains("\tset allow6 {\n\t\ttype ipv6_addr; flags interval;\n\t}\n", script); // empty sets have no elements line
    }

    [Fact]
    public void Ipset_script_fills_a_side_set_and_swaps_it_in()
    {
        var script = BlocklistIntegration.RenderIpset(Payload);
        Assert.Equal(
            "create sentinel-vps4 hash:net family inet maxelem 65536\ncreate sentinel-vps4-new hash:net family inet maxelem 65536\nflush sentinel-vps4-new\n" +
            "add sentinel-vps4-new 1.10.16.0/20\nadd sentinel-vps4-new 1.19.0.0/16\nswap sentinel-vps4-new sentinel-vps4\ndestroy sentinel-vps4-new\n",
            script[..script.IndexOf("create sentinel-vps6", StringComparison.Ordinal)]);
    }

    [Fact]
    public async Task Waits_for_the_server_then_loads_validates_and_stays_idempotent()
    {
        var bl = Integration();
        var waiting = await bl.PlanAsync(Request(), default);
        Assert.True(waiting.IsNoop);
        Assert.Equal(ConfigState.Pending, waiting.ResultingState);

        bl.SetDesired(Payload, [IPAddress.Parse("192.0.2.10")]);
        var plan = await bl.PlanAsync(Request(), default);
        Assert.Equal("Load the blocklist (3 networks from spamhaus-drop)", plan.Changes[0].Description);
        var result = await bl.ApplyAsync(plan, default);
        Assert.True(result.Success);
        Assert.Equal(EventKinds.ConfigApplied, Assert.Single(result.Events).Kind);
        Assert.True(_runner.Calls.IndexOf("nft -c -f /var/lib/sentinel/blocklist.nft") < _runner.Calls.IndexOf("nft -f /var/lib/sentinel/blocklist.nft"));
        Assert.Contains("1.19.0.0/16", _fs.Files["/var/lib/sentinel/blocklist.nft"]);

        Assert.True((await bl.PlanAsync(Request(), default)).IsNoop); // same set: nothing to do
        var status = await bl.DetectAsync(default);
        Assert.True(status.Running);
        Assert.Equal("1.1.6", status.Version);
        Assert.Equal("1359", status.Details["dropped"]); // 1342 IPv4 + 17 IPv6 from the counters
        Assert.Equal("2 IPv4, 1 IPv6", status.Details["entries"]);
        Assert.Equal("abc123", status.AppliedRevision);

        // Someone flushed the ruleset: the drift check loads it again.
        _tableExists = false;
        await bl.ApplyAsync(await bl.PlanAsync(Request(), default), default);
        Assert.Equal(2, _loads);
    }

    [Fact]
    public async Task Kernel_refusal_is_reported_with_an_explanation()
    {
        _runner.On("nft -c -f /var/lib/sentinel/blocklist.nft", "", 1, Fixture.Read("blocklists/nft-no-permission.txt"));
        var bl = Integration();
        bl.SetDesired(Payload, []);
        var result = await bl.ApplyAsync(await bl.PlanAsync(Request(), default), default);
        Assert.False(result.Success);
        Assert.Equal(ConfigState.Rejected, result.State);
        Assert.Contains("Containers and some VPS plans", result.Error);
        Assert.Equal(EventKinds.ConfigRejected, Assert.Single(result.Events).Kind);
        Assert.DoesNotContain("nft -f /var/lib/sentinel/blocklist.nft", _runner.Calls);
        Assert.Equal(ConfigState.Rejected, (await bl.DetectAsync(default)).ConfigState);

        // The drift check retries; the same refusal doesn't raise a second event.
        var retry = await bl.ApplyAsync(await bl.PlanAsync(Request(), default), default);
        Assert.False(retry.Success);
        Assert.Empty(retry.Events);
    }

    [Fact]
    public async Task Disabling_or_losing_the_server_removes_the_table()
    {
        var bl = Integration();
        bl.SetDesired(Payload, []);
        await bl.ApplyAsync(await bl.PlanAsync(Request(), default), default);
        Assert.True(_tableExists);

        var off = await bl.PlanAsync(Request(enabled: false), default);
        Assert.Equal(ChangeKind.DeleteFile, off.Changes.Single().Kind);
        Assert.True((await bl.ApplyAsync(off, default)).Success);
        Assert.False(_tableExists);
        Assert.False(_fs.FileExists("/var/lib/sentinel/blocklist.nft"));
        Assert.True((await bl.PlanAsync(Request(enabled: false), default)).IsNoop);

        await bl.ApplyAsync(await bl.PlanAsync(Request(), default), default);
        Assert.True(await bl.ReleaseAfterServerLossAsync(TimeSpan.FromHours(25), default));
        Assert.False(_tableExists);
        Assert.False(await bl.ReleaseAfterServerLossAsync(TimeSpan.FromHours(26), default)); // only once
        var events = new List<SecurityEvent>();
        await foreach (var e in bl.CollectEventsAsync(default)) events.Add(e);
        Assert.Contains(events, e => e.Severity == Severity.Medium && e.Message.Contains("without contact", StringComparison.Ordinal));
        Assert.Null(bl.DesiredEtag); // fetched afresh after reconnecting
    }

    [Fact]
    public void Counters_sum_only_drop_rules()
    {
        Assert.Equal(1359, BlocklistIntegration.SumCounters(Fixture.Read("blocklists/nft-list-chain.json")));
        Assert.Null(BlocklistIntegration.SumCounters("not json"));
    }
}

/// <summary>Server side end to end: lists fetched from (fake) providers, merged per host, served with ETags.</summary>
[Collection(ServerHostCollection.Name)]
public sealed class BlocklistApiTests : IDisposable
{
    private readonly ListHandler _http = new();
    private readonly BlocklistFactory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public BlocklistApiTests() => _factory = new BlocklistFactory(_http);
    public void Dispose() => _factory.Dispose();

    private sealed class BlocklistFactory(ListHandler http) : WebApplicationFactory<Program>
    {
        public readonly string DataDir = Path.Combine(Path.GetTempPath(), "sentinel-bl-test-" + Guid.NewGuid().ToString("N"));

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("DataDir", DataDir);
            builder.UseSetting("AdminPassword", "test-password-123");
            builder.UseSetting("SecureCookies", "false");
            builder.UseSetting("ThreatFeedEnabled", "false");
            builder.UseSetting("BlocklistsEnabled", "false"); // the test drives refreshes itself
            builder.UseSetting("AuthRateLimitPerMinute", "1000");
            builder.ConfigureTestServices(s => s.AddHttpClient(BlocklistService.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => http));
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try { Directory.Delete(DataDir, true); } catch (IOException) { }
        }
    }

    private sealed class ListHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];
        public Dictionary<string, string> Bodies { get; } = new()
        {
            ["https://www.spamhaus.org/drop/drop_v4.json"] = Fixture.Read("blocklists/spamhaus_drop_v4.json"),
            ["https://www.spamhaus.org/drop/drop_v6.json"] = Fixture.Read("blocklists/spamhaus_drop_v6.json"),
            ["https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"] = Fixture.Read("blocklists/feodo_recommended.txt"),
        };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            lock (Requests) Requests.Add(request);
            var url = request.RequestUri!.ToString();
            if (!Bodies.TryGetValue(url, out var body)) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            var etag = $"\"{body.Length}\"";
            if (request.Headers.IfNoneMatch.Any(t => t.Tag == etag)) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotModified));
            var resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
            resp.Headers.ETag = new EntityTagHeaderValue(etag);
            return Task.FromResult(resp);
        }
    }

    private async Task<HttpClient> AdminAsync()
    {
        var c = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await c.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        c.DefaultRequestHeaders.Add("X-Sentinel-Request", "1");
        return c;
    }

    private async Task<HttpClient> EnrollAsync(HttpClient admin)
    {
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "t" })).Content.ReadFromJsonAsync<JsonElement>();
        var enroll = await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "web-01", "Ubuntu 26.04", "ubuntu", "26.04", "x64", "0.1.0", null));
        var resp = (await enroll.Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);
        return agent;
    }

    private async Task SetGlobalAsync(HttpClient admin, string yaml)
    {
        var current = await admin.GetFromJsonAsync<JsonElement>("/api/policies/global");
        var text = current.GetProperty("yaml").GetString()!;
        var start = text.IndexOf("blocklists:", StringComparison.Ordinal);
        var end = text.IndexOf("\n# ----", start, StringComparison.Ordinal);
        (await admin.PutAsJsonAsync("/api/policies/global", new { yaml = text[..start] + yaml + text[end..], comment = "test" })).EnsureSuccessStatusCode();
    }

    private async Task RunDueAsync()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<BlocklistService>().RunDueAsync(default);
    }

    [Fact]
    public async Task Lists_in_use_are_fetched_merged_and_served_with_etags()
    {
        var admin = await AdminAsync();
        var agent = await EnrollAsync(admin);
        await admin.PostAsJsonAsync("/api/allowlist", new { target = "1.19.0.7", note = "partner" });
        await SetGlobalAsync(admin, "blocklists:\n  enabled: true\n  lists: [spamhaus-drop, abuse-ch-feodo]\n  extra: [198.51.100.0/24, 45.9.148.0/24]\n");

        await RunDueAsync();
        Assert.Equal(3, _http.Requests.Count); // two Spamhaus files and Feodo; lists nobody uses are never fetched
        Assert.DoesNotContain(_http.Requests, r => r.RequestUri!.Host.Contains("firehol", StringComparison.Ordinal));

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/agent/blocklist");
        req.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue("gzip"));
        var resp = await agent.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("gzip", resp.Content.Headers.ContentEncoding.Single());
        await using var gz = new GZipStream(await resp.Content.ReadAsStreamAsync(), CompressionMode.Decompress);
        var payload = (await JsonSerializer.DeserializeAsync(gz, AgentJsonContext.Default.BlocklistPayload))!;

        Assert.Equal(["spamhaus-drop", "abuse-ch-feodo"], payload.Lists.Select(l => l.Id));
        Assert.Equal(45, payload.Lists[0].Entries); // 40 + 8 Spamhaus networks, merged where adjacent
        var v4 = IpRangeSet.From(payload.V4.Select(c => IpTarget.TryParse(c, out var t) ? t!.Value : throw new FormatException(c)));
        Assert.True(v4.Contains(IPAddress.Parse("1.10.16.1")));     // Spamhaus
        Assert.True(v4.Contains(IPAddress.Parse("50.16.16.211")));  // Feodo
        Assert.True(v4.Contains(IPAddress.Parse("45.9.148.10")));   // extra
        Assert.False(v4.Contains(IPAddress.Parse("1.19.0.7")));     // allowlisted inside a Spamhaus /16
        Assert.True(v4.Contains(IPAddress.Parse("1.19.0.8")));
        Assert.False(v4.Contains(IPAddress.Parse("198.51.100.1"))); // documentation range: reserved, never blocked
        Assert.Equal(8, payload.V6.Count);

        using var again = new HttpRequestMessage(HttpMethod.Get, "/api/agent/blocklist");
        again.Headers.IfNoneMatch.Add(new EntityTagHeaderValue($"\"{payload.Etag}\""));
        Assert.Equal(HttpStatusCode.NotModified, (await agent.SendAsync(again)).StatusCode);

        // Lookup and overview for the dashboard.
        var hit = await admin.GetFromJsonAsync<JsonElement>("/api/blocklists/lookup?ip=1.10.16.1");
        Assert.Equal("spamhaus-drop", hit.GetProperty("lists")[0].GetString());
        var allowed = await admin.GetFromJsonAsync<JsonElement>("/api/blocklists/lookup?ip=1.19.0.7");
        Assert.True(allowed.GetProperty("allowlisted").GetBoolean());
        var overview = await admin.GetFromJsonAsync<JsonElement>("/api/blocklists");
        var spamhaus = overview.GetProperty("lists").EnumerateArray().Single(l => l.GetProperty("id").GetString() == "spamhaus-drop");
        Assert.Equal("global", spamhaus.GetProperty("usedBy")[0].GetString());
        Assert.Equal(45, spamhaus.GetProperty("entries").GetInt32());
        Assert.True(overview.GetProperty("hosts")[0].GetProperty("wanted").GetBoolean());
    }

    [Fact]
    public async Task Unchanged_lists_cost_a_conditional_request_and_broken_downloads_keep_the_last_good_copy()
    {
        var admin = await AdminAsync();
        await SetGlobalAsync(admin, "blocklists:\n  enabled: true\n  lists: [spamhaus-drop]\n");
        await RunDueAsync();

        await using var scope = _factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<BlocklistService>();
        var source = BlocklistCatalog.Find("spamhaus-drop")!;
        _http.Requests.Clear();
        var state = await service.RefreshAsync(source, default);
        Assert.All(_http.Requests, r => Assert.NotEmpty(r.Headers.IfNoneMatch));
        Assert.Null(state.LastError);
        Assert.Equal(45, state.EntryCount);

        // A truncated download (the provider served an error page with 200) is refused.
        _http.Bodies["https://www.spamhaus.org/drop/drop_v4.json"] = "<html>maintenance</html>";
        _http.Bodies["https://www.spamhaus.org/drop/drop_v6.json"] = "{\"type\":\"metadata\"}";
        state = await service.RefreshAsync(source, default);
        Assert.Contains("keeping the last good copy", state.LastError);
        Assert.Equal(45, state.EntryCount);
        Assert.Equal(1, state.ConsecutiveFailures);

        var refresh = await (await admin.PostAsync("/api/blocklists/spamhaus-drop/refresh", null)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(refresh.GetProperty("success").GetBoolean());
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync("/api/blocklists/nope/refresh", null)).StatusCode);
    }
}
