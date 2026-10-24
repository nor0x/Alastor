using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sentinel.Server.Data;
using Sentinel.Server.Services.ThreatFeed;

namespace Sentinel.Tests;

/// <summary>
/// The threat-feed pipeline end to end inside the real server: fixture responses from a fake HTTP handler, a fixed
/// clock, a fresh SQLite database per test. Covers dedup, KEV flagging, conditional GETs, backoff and the feed API.
/// </summary>
[Collection(ServerHostCollection.Name)]
public sealed class ThreatFeedTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 10, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly FakeFeedHandler _http = new();
    private readonly FixedTime _time = new(Now);
    private readonly FeedFactory _factory;

    public ThreatFeedTests() => _factory = new FeedFactory(_http, _time);

    public void Dispose() => _factory.Dispose();

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class FeedFactory(FakeFeedHandler http, TimeProvider time) : WebApplicationFactory<Program>
    {
        private readonly string _dataDir = Path.Combine(Path.GetTempPath(), "sentinel-feed-test-" + Guid.NewGuid().ToString("N"));

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("DataDir", _dataDir);
            builder.UseSetting("AdminPassword", "test-password-123");
            builder.UseSetting("SecureCookies", "false");
            builder.UseSetting("ThreatFeedEnabled", "false"); // the tests drive ThreatFeedService directly
            builder.ConfigureTestServices(s =>
            {
                s.RemoveAll<TimeProvider>();
                s.AddSingleton(time);
                s.AddHttpClient(ThreatFeedService.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => http);
            });
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try { Directory.Delete(_dataDir, true); } catch (IOException) { }
        }
    }

    /// <summary>Serves the captured fixtures by host. Tests override individual URLs to simulate outages and rate limits.</summary>
    private sealed class FakeFeedHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];
        public Dictionary<string, Func<HttpRequestMessage, HttpResponseMessage>> Overrides { get; } = [];

        private static readonly Dictionary<string, string> Files = new()
        {
            ["services.nvd.nist.gov"] = "nvd.json",
            ["www.cisa.gov"] = "kev.json",
            ["raw.githubusercontent.com"] = "kev.json",
            ["feeds.feedburner.com"] = "thn.xml",
            ["www.bleepingcomputer.com"] = "bleeping.xml",
            ["krebsonsecurity.com"] = "krebs.xml",
            ["www.securityweek.com"] = "securityweek.xml",
            ["www.darkreading.com"] = "darkreading.xml",
        };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            var host = request.RequestUri!.Host;
            if (Overrides.TryGetValue(host, out var o)) return Task.FromResult(o(request));
            const string etag = "\"v1\"";
            if (request.Headers.IfNoneMatch.Any(t => t.Tag == etag)) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotModified));
            var resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Fixture.Read("feeds/" + Files[host])) };
            resp.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue(etag);
            return Task.FromResult(resp);
        }
    }

    private async Task<T> WithServiceAsync<T>(Func<ThreatFeedService, SentinelDbContext, Task<T>> body)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var svc = scope.ServiceProvider.GetRequiredService<ThreatFeedService>();
        svc.NvdPageDelay = TimeSpan.Zero;
        svc.RetryBaseDelay = TimeSpan.Zero;
        return await body(svc, scope.ServiceProvider.GetRequiredService<SentinelDbContext>());
    }

    private Task<int> RunAsync() => WithServiceAsync((svc, _) => svc.RunDueAsync(CancellationToken.None));

    private Task<T> DbAsync<T>(Func<SentinelDbContext, Task<T>> q) => WithServiceAsync((_, db) => q(db));

    /// <summary>Makes every source due again, as if the interval had passed.</summary>
    private void Advance(TimeSpan by) => _time.Now += by;

    [Fact]
    public async Task First_run_fetches_every_source_and_flags_exploited_items()
    {
        var added = await RunAsync();

        var items = await DbAsync(db => db.FeedItems.AsNoTracking().ToListAsync());
        Assert.Equal(added, items.Count);
        // 20 NVD CVEs + 3 articles from each of 5 feeds + KEV additions of the last 30 days (5 of the 6 fixture entries).
        Assert.Equal(20 + 15 + 5, items.Count);
        Assert.Equal(5, items.Select(i => i.Source).Count(s => s is "thehackernews" or "bleepingcomputer" or "krebsonsecurity" or "securityweek" or "darkreading") / 3);

        var collabora = items.Single(i => i.Id == "CVE-2026-110447");
        Assert.Equal(("cisa-kev", FeedItemTypes.Cve, true), (collabora.Source, collabora.Type, collabora.Exploited));
        Assert.Contains("kev", collabora.Tags);
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2026-110447", collabora.Url);
        Assert.DoesNotContain(items, i => i.Id == "CVE-2021-27104"); // in KEV, but added years ago

        // The Hacker News article about that CVE inherits the flag.
        var article = items.Single(i => i.Source == "thehackernews" && i.CveIds.Contains("CVE-2026-110447"));
        Assert.True(article.Exploited);
        Assert.False(items.Single(i => i.Id == "CVE-2026-103515").Exploited);

        var states = await DbAsync(db => db.FeedSources.AsNoTracking().ToListAsync());
        Assert.Equal(FeedSources.All.Count, states.Count);
        Assert.All(states, s =>
        {
            Assert.Equal(0, s.ConsecutiveFailures);
            Assert.Equal(Now.UtcDateTime, s.LastSuccessAt);
            Assert.InRange(s.NextAttemptAt!.Value, Now.UtcDateTime.AddMinutes(17), Now.UtcDateTime.AddMinutes(23)); // 20m ± 10% jitter
        });
        Assert.Equal(Now.UtcDateTime, states.Single(s => s.SourceId == "nvd").Cursor);
        var nvd = _http.Requests.Where(r => r.RequestUri!.Host == "services.nvd.nist.gov").Select(r => r.RequestUri!.Query).ToList();
        Assert.Equal(2, nvd.Count);
        Assert.Contains("pubStartDate=2026-10-17T12:00:00.000Z", nvd[0]); // 7-day publication backfill
        Assert.Contains("kevStartDate=2026-09-24T12:00:00.000Z", nvd[1]); // KEV additions within retention, so they get CVSS
    }

    [Fact]
    public async Task Refetching_deduplicates_uses_conditional_gets_and_continues_the_nvd_cursor()
    {
        await RunAsync();
        var count = await DbAsync(db => db.FeedItems.CountAsync());
        _http.Requests.Clear();

        Assert.Equal(0, await RunAsync()); // nothing is due yet
        Assert.Empty(_http.Requests);

        Advance(TimeSpan.FromMinutes(30));
        Assert.Equal(0, await RunAsync());
        Assert.Equal(count, await DbAsync(db => db.FeedItems.CountAsync()));
        Assert.All(_http.Requests.Where(r => r.RequestUri!.Host != "services.nvd.nist.gov"), r => Assert.Contains(r.Headers.IfNoneMatch, t => t.Tag == "\"v1\""));
        var nvd = _http.Requests.Single(r => r.RequestUri!.Host == "services.nvd.nist.gov").RequestUri!.Query;
        Assert.Contains("lastModStartDate=2026-10-24T11:55:00.000Z", nvd); // cursor minus overlap
        Assert.Contains("lastModEndDate=2026-10-24T12:30:00.000Z", nvd);
    }

    [Fact]
    public async Task A_failing_source_backs_off_without_affecting_the_others()
    {
        _http.Overrides["www.bleepingcomputer.com"] = _ => new HttpResponseMessage(HttpStatusCode.InternalServerError);
        _http.Overrides["krebsonsecurity.com"] = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>maintenance</html>") };

        await RunAsync();

        var states = await DbAsync(db => db.FeedSources.AsNoTracking().ToDictionaryAsync(s => s.SourceId));
        Assert.Equal(1, states["bleepingcomputer"].ConsecutiveFailures);
        Assert.Contains("500", states["bleepingcomputer"].LastError);
        Assert.Equal(Now.UtcDateTime.AddMinutes(1), states["bleepingcomputer"].NextAttemptAt);
        Assert.Contains("Unreadable response", states["krebsonsecurity"].LastError);
        Assert.Null(states["krebsonsecurity"].ETag); // the unusable response must be fetched in full next time
        Assert.Equal(0, states["securityweek"].ConsecutiveFailures);
        Assert.Equal(0, await DbAsync(db => db.FeedItems.CountAsync(i => i.Source == "bleepingcomputer")));
        Assert.Equal(3, await DbAsync(db => db.FeedItems.CountAsync(i => i.Source == "securityweek")));

        // Second failure: the backoff doubles. Then the source recovers.
        Advance(TimeSpan.FromMinutes(1));
        await RunAsync();
        var bc = await DbAsync(db => db.FeedSources.AsNoTracking().SingleAsync(s => s.SourceId == "bleepingcomputer"));
        Assert.Equal((2, Now.UtcDateTime.AddMinutes(3)), (bc.ConsecutiveFailures, bc.NextAttemptAt!.Value));

        _http.Overrides.Remove("www.bleepingcomputer.com");
        Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(3, await RunAsync());
        bc = await DbAsync(db => db.FeedSources.AsNoTracking().SingleAsync(s => s.SourceId == "bleepingcomputer"));
        Assert.Equal((0, null), (bc.ConsecutiveFailures, bc.LastError));
    }

    [Fact]
    public async Task Sources_after_a_failing_one_still_record_their_schedule()
    {
        await RunAsync(); // every state row exists now, so the next run loads them all up front
        Advance(TimeSpan.FromMinutes(30));
        _http.Overrides["www.bleepingcomputer.com"] = _ => new HttpResponseMessage(HttpStatusCode.InternalServerError);

        await RunAsync();

        var states = await DbAsync(db => db.FeedSources.AsNoTracking().ToDictionaryAsync(s => s.SourceId));
        Assert.Equal(1, states["bleepingcomputer"].ConsecutiveFailures);
        // Otherwise they'd be refetched every minute.
        Assert.All(new[] { "krebsonsecurity", "securityweek", "darkreading", "nvd" }, id =>
        {
            Assert.Equal(_time.Now.UtcDateTime, states[id].LastSuccessAt);
            Assert.True(states[id].NextAttemptAt > _time.Now.UtcDateTime.AddMinutes(15));
        });
    }

    [Fact]
    public async Task Rate_limits_are_retried_and_a_long_retry_after_reschedules_the_source()
    {
        // NVD: two 429s with a short Retry-After, then success within the same run.
        var nvdCalls = 0;
        _http.Overrides["services.nvd.nist.gov"] = _ => ++nvdCalls <= 2
            ? new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Headers = { RetryAfter = new(TimeSpan.Zero) } }
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Fixture.Read("feeds/nvd.json")) };
        // Dark Reading: 503 with "come back in 10 minutes", longer than we sleep in-run.
        _http.Overrides["www.darkreading.com"] = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Headers = { RetryAfter = new(TimeSpan.FromMinutes(10)) } };

        await RunAsync();

        Assert.Equal(4, nvdCalls); // 2 rate-limited + publication window + KEV window
        Assert.Equal(20, await DbAsync(db => db.FeedItems.CountAsync(i => i.Source == "nvd")));
        var dr = await DbAsync(db => db.FeedSources.AsNoTracking().SingleAsync(s => s.SourceId == "darkreading"));
        Assert.Equal(1, _http.Requests.Count(r => r.RequestUri!.Host == "www.darkreading.com")); // not hammered
        Assert.Equal(Now.UtcDateTime.AddMinutes(10), dr.NextAttemptAt);
        Assert.Contains("503", dr.LastError);
    }

    [Fact]
    public async Task Kev_falls_back_to_the_github_mirror_and_refuses_a_truncated_catalog()
    {
        _http.Overrides["www.cisa.gov"] = _ => new HttpResponseMessage(HttpStatusCode.Forbidden);
        await RunAsync();
        Assert.Contains(_http.Requests, r => r.RequestUri!.Host == "raw.githubusercontent.com");
        Assert.Equal(6, await DbAsync(db => db.KevEntries.CountAsync()));

        // An almost empty catalog must not clear every exploited flag.
        _http.Overrides["raw.githubusercontent.com"] = _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"vulnerabilities":[{"cveID":"CVE-2026-1","dateAdded":"2026-10-24"}]}"""),
        };
        Advance(TimeSpan.FromHours(1));
        await RunAsync();
        var kev = await DbAsync(db => db.FeedSources.AsNoTracking().SingleAsync(s => s.SourceId == "cisa-kev"));
        Assert.Equal(1, kev.ConsecutiveFailures);
        Assert.Contains("refusing", kev.LastError);
        Assert.True(await DbAsync(db => db.FeedItems.Where(i => i.Id == "CVE-2026-110447").Select(i => i.Exploited).SingleAsync()));
    }

    [Fact]
    public async Task Feed_api_filters_sorts_and_pages()
    {
        await RunAsync();
        var c = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await c.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();

        async Task<JsonElement> Get(string query) => await c.GetFromJsonAsync<JsonElement>("/api/feed" + query, Json);

        var all = await Get("?pageSize=10");
        Assert.Equal(40, all.GetProperty("total").GetInt32());
        Assert.Equal(10, all.GetProperty("items").GetArrayLength());
        var dates = all.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("publishedAt").GetDateTime()).ToList();
        Assert.Equal(dates.OrderDescending(), dates); // newest first

        var page4 = await Get("?pageSize=10&page=4");
        Assert.Equal(10, page4.GetProperty("items").GetArrayLength());
        Assert.Equal(0, (await Get("?pageSize=10&page=5")).GetProperty("items").GetArrayLength());

        var news = await Get("?type=news");
        Assert.Equal(15, news.GetProperty("total").GetInt32());
        var first = news.GetProperty("items")[0];
        Assert.Equal("news", first.GetProperty("type").GetString());
        Assert.False(string.IsNullOrEmpty(first.GetProperty("sourceName").GetString()));

        var critical = await Get("?type=cve&minSeverity=Critical");
        Assert.All(critical.GetProperty("items").EnumerateArray(), i => Assert.Equal("Critical", i.GetProperty("severity").GetString()));
        Assert.True(critical.GetProperty("total").GetInt32() > 0);

        var exploited = await Get("?exploited=true");
        Assert.Equal(6, exploited.GetProperty("total").GetInt32()); // 5 KEV CVEs + 1 article
        Assert.Equal(5, (await Get("?tag=kev")).GetProperty("total").GetInt32());
        Assert.Equal(1, (await Get("?tag=KEV&tag=collabora")).GetProperty("total").GetInt32());

        var search = await Get("?q=COLLABORA");
        Assert.Contains(search.GetProperty("items").EnumerateArray(), i => i.GetProperty("id").GetString() == "CVE-2026-110447");
        Assert.Contains(search.GetProperty("items").EnumerateArray(), i => i.GetProperty("source").GetString() == "thehackernews");

        // Severity sort: scored items first, highest first; unscored (news, KEV-only CVEs) last.
        var bySeverity = (await Get("?sort=severity&pageSize=100")).GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("severity").ValueKind == JsonValueKind.Null ? -1 : (int)Enum.Parse<Sentinel.Core.Events.Severity>(i.GetProperty("severity").GetString()!))
            .ToList();
        Assert.Equal(bySeverity.OrderDescending(), bySeverity);
        Assert.Equal(-1, bySeverity[^1]);

        Assert.Equal(HttpStatusCode.BadRequest, (await c.GetAsync("/api/feed?sort=random")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.GetAsync("/api/feed?type=blog")).StatusCode);

        var sources = await c.GetFromJsonAsync<JsonElement>("/api/feed/sources", Json);
        Assert.Equal(FeedSources.All.Count, sources.GetArrayLength());
        Assert.All(sources.EnumerateArray(), s => Assert.Equal(0, s.GetProperty("consecutiveFailures").GetInt32()));

        var tags = await c.GetFromJsonAsync<JsonElement>("/api/feed/tags", Json);
        Assert.Contains(tags.EnumerateArray(), t => t.GetProperty("tag").GetString() == "kev");

        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().GetAsync("/api/feed")).StatusCode);
    }
}
