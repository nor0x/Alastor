using System.Text;
using System.Text.Json;
using Sentinel.Core.Events;
using Sentinel.Server.Data;
using Sentinel.Server.Services.ThreatFeed;

namespace Sentinel.Tests;

/// <summary>Threat-feed parsers run against responses captured from the live sources on 2026-10-24, stored in Fixtures/feeds.</summary>
public sealed class ThreatFeedParserTests
{
    private static readonly DateTime Now = new(2026, 10, 24, 12, 0, 0, DateTimeKind.Utc);

    private static List<FeedItem> Rss(string file, string sourceId) =>
        RssParser.Parse(RssParser.Load(new MemoryStream(Encoding.UTF8.GetBytes(Fixture.Read($"feeds/{file}")))), FeedSources.Find(sourceId)!, Now);

    [Theory]
    [InlineData("thn.xml", "thehackernews")]
    [InlineData("bleeping.xml", "bleepingcomputer")]
    [InlineData("krebs.xml", "krebsonsecurity")]
    [InlineData("securityweek.xml", "securityweek")]
    [InlineData("darkreading.xml", "darkreading")]
    public void Every_news_source_parses(string file, string sourceId)
    {
        var items = Rss(file, sourceId);
        Assert.Equal(3, items.Count);
        Assert.All(items, i =>
        {
            Assert.Equal(FeedItemTypes.News, i.Type);
            Assert.Equal(sourceId, i.Source);
            Assert.StartsWith($"{sourceId}:", i.Id);
            Assert.StartsWith("https://", i.Url);
            Assert.False(string.IsNullOrWhiteSpace(i.Title));
            Assert.False(string.IsNullOrWhiteSpace(i.Summary));
            Assert.DoesNotContain("<", i.Summary);
            Assert.True(i.Summary.Length <= FeedText.MaxSummary + 1);
            Assert.InRange(i.PublishedAt, Now.AddDays(-30), Now); // a real date, not the "now" fallback
            Assert.NotEqual(Now, i.PublishedAt);
            Assert.Null(i.Severity);
            Assert.Equal(i.SearchText, i.SearchText.ToLowerInvariant());
        });
        Assert.Equal(3, items.Select(i => i.Id).Distinct().Count());
    }

    [Fact]
    public void Ids_are_stable_across_fetches_so_items_deduplicate()
    {
        var first = Rss("bleeping.xml", "bleepingcomputer").Select(i => i.Id);
        var second = Rss("bleeping.xml", "bleepingcomputer").Select(i => i.Id);
        Assert.Equal(first, second);
    }

    [Fact]
    public void Hacker_news_dates_with_compact_offsets_and_mentioned_cves()
    {
        var item = Rss("thn.xml", "thehackernews")[0];
        Assert.Equal(new DateTime(2026, 10, 24, 6, 25, 57, DateTimeKind.Utc), item.PublishedAt); // "Sat, 24 Oct 2026 11:55:57 +0530"
        Assert.Contains("CVE-2026-110447", item.CveIds);
        Assert.Contains("CVE-2026-110447", item.Tags);
        Assert.Contains("|cve-2026-110447|", item.TagIndex);
    }

    [Fact]
    public void Wordpress_footer_is_stripped_and_categories_become_tags()
    {
        var sw = Rss("securityweek.xml", "securityweek")[0];
        Assert.DoesNotContain("appeared first on", sw.Summary);
        Assert.StartsWith("Noteworthy stories", sw.Summary);
        Assert.Contains("Malware & Threats", sw.Tags);

        var bleeping = Rss("bleeping.xml", "bleepingcomputer")[0];
        Assert.DoesNotContain("Security", bleeping.Tags); // feed-wide noise
        Assert.EndsWith("…", bleeping.Summary); // "[...]" becomes an ellipsis

        var krebs = Rss("krebs.xml", "krebsonsecurity")[0];
        Assert.Contains("Time to Patch", krebs.Tags);
    }

    [Fact]
    public void Atom_feeds_parse_too()
    {
        const string atom = """
            <feed xmlns="http://www.w3.org/2005/Atom"><title>x</title>
              <entry><title>Hello &amp;amp; bye</title><id>urn:1</id><link rel="alternate" href="https://example.com/a"/>
                <updated>2026-10-23T08:00:00Z</updated><summary type="html">&lt;p&gt;Body about CVE-2026-0001&lt;/p&gt;</summary>
                <category term="ransomware"/></entry>
              <entry><title>Unsafe</title><id>urn:2</id><link href="javascript:alert(1)"/></entry>
            </feed>
            """;
        var items = RssParser.Parse(RssParser.Load(new MemoryStream(Encoding.UTF8.GetBytes(atom))), FeedSources.Find("krebsonsecurity")!, Now);
        var item = Assert.Single(items); // the javascript: link is dropped
        Assert.Equal("Hello & bye", item.Title);
        Assert.Equal("Body about CVE-2026-0001", item.Summary);
        Assert.Equal(["ransomware", "CVE-2026-0001"], item.Tags);
        Assert.Equal(new DateTime(2026, 10, 23, 8, 0, 0, DateTimeKind.Utc), item.PublishedAt);
    }

    [Fact]
    public void Dtds_and_external_entities_are_not_processed()
    {
        const string xxe = """
            <?xml version="1.0"?><!DOCTYPE rss [<!ENTITY x SYSTEM "file:///etc/passwd">]>
            <rss version="2.0"><channel><item><title>t &x;</title><link>https://example.com/</link></item></channel></rss>
            """;
        // With the DTD ignored, &x; is an undeclared entity: the document is rejected rather than expanded.
        Assert.ThrowsAny<System.Xml.XmlException>(() => RssParser.Load(new MemoryStream(Encoding.UTF8.GetBytes(xxe))));
    }

    [Fact]
    public void Nvd_page_normalizes_cvss_products_and_cwes()
    {
        using var json = JsonDocument.Parse(Fixture.Read("feeds/nvd.json"));
        var page = NvdParser.Parse(json);
        Assert.Equal(20, page.Items.Count);
        Assert.Equal(20, page.TotalResults);

        var gitlab = page.Items.Single(c => c.Id == "CVE-2026-103515");
        Assert.Equal(Severity.Low, gitlab.Severity);
        Assert.Equal(2.7, gitlab.CvssScore);
        Assert.Equal(["GitLab"], gitlab.Products); // vendor "GitLab" + product "GitLab" is not doubled
        Assert.Equal(["CWE-863"], gitlab.Cwes);
        Assert.Equal(new DateTime(2026, 10, 22, 1, 16, 57, 197, DateTimeKind.Utc), gitlab.Published);

        Assert.Equal(Severity.Critical, page.Items.Single(c => c.Id == "CVE-2026-110264").Severity);
        // CVSS 4.0 wins over 3.1 when both are present.
        var mass = page.Items.Single(c => c.Id == "CVE-2026-114574");
        Assert.Equal((Severity.Low, 2.1), (mass.Severity!.Value, mass.CvssScore!.Value));
    }

    [Fact]
    public void Nvd_cve_item_title_summary_and_kev_merge()
    {
        using var json = JsonDocument.Parse(Fixture.Read("feeds/nvd.json"));
        var cve = NvdParser.Parse(json).Items.Single(c => c.Id == "CVE-2026-103515");
        var item = new FeedItem { Id = cve.Id, Source = "nvd", Type = FeedItemTypes.Cve, SourceItemId = cve.Id, Title = "", Url = CveItems.NvdUrl(cve.Id) };
        CveItems.ApplyNvd(item, cve, null, Now);
        Assert.Equal("CVE-2026-103515 in GitLab", item.Title);
        Assert.False(item.Exploited);
        Assert.Equal(cve.Published, item.PublishedAt);

        var kev = new KevEntry { CveId = cve.Id, VulnerabilityName = "GitLab Authorization Bypass", DateAdded = Now.Date, KnownRansomwareUse = true };
        Assert.True(CveItems.ApplyKev(item, kev, Now));
        Assert.True(item.Exploited);
        Assert.Equal(Now.Date, item.PublishedAt); // re-surfaces on the timeline when CISA adds it
        Assert.Equal(["kev", "ransomware", "gitlab", "CWE-863"], item.Tags);
        Assert.False(CveItems.ApplyKev(item, kev, Now)); // idempotent

        Assert.True(CveItems.ApplyKev(item, null, Now)); // removed from the catalog
        Assert.False(item.Exploited);
        Assert.DoesNotContain("kev", item.Tags);
    }

    [Fact]
    public void Kev_catalog_parses()
    {
        using var json = JsonDocument.Parse(Fixture.Read("feeds/kev.json"));
        var entries = KevParser.Parse(json);
        Assert.Equal(6, entries.Count);
        var collabora = entries.Single(e => e.CveId == "CVE-2026-110447");
        Assert.Equal(new DateTime(2026, 10, 23, 0, 0, 0, DateTimeKind.Utc), collabora.DateAdded);
        Assert.Equal("Collabora", collabora.VendorProject);
        Assert.Equal(["CWE-78"], collabora.Cwes);
        Assert.False(collabora.KnownRansomwareUse);
        Assert.True(entries.Single(e => e.CveId == "CVE-2021-27104").KnownRansomwareUse);

        Assert.Throws<FormatException>(() => KevParser.Parse(JsonDocument.Parse("""{"title":"nope"}""")));
    }

    [Theory]
    [InlineData("Sat, 24 Oct 2026 11:55:57 +0530", "2026-10-24T06:25:57Z")]
    [InlineData("Fri, 23 Oct 2026 16:55:05 -0400", "2026-10-23T20:55:05Z")]
    [InlineData("Fri, 23 Oct 2026 20:57:56 GMT", "2026-10-23T20:57:56Z")]
    [InlineData("Fri, 23 Oct 2026 08:00:00 PDT", "2026-10-23T15:00:00Z")]
    [InlineData("23 Oct 2026 08:00 EST", "2026-10-23T13:00:00Z")]
    [InlineData("Mon, 3 Oct 2026 08:00:00 +0000", "2026-10-03T08:00:00Z")] // wrong weekday is ignored
    [InlineData("2026-10-22T01:16:57.197", "2026-10-22T01:16:57.197Z")] // NVD: UTC without a designator
    [InlineData("2026-10-23T10:00:00+02:00", "2026-10-23T08:00:00Z")]
    public void Dates_in_the_wild(string input, string expected) =>
        Assert.Equal(DateTime.Parse(expected, null, System.Globalization.DateTimeStyles.AdjustToUniversal), FeedText.ParseDate(input));

    [Theory]
    [InlineData("<p>A &amp;amp; B</p><script>alert(1)</script>", "A & B")]
    [InlineData("&lt;b&gt;bold&lt;/b&gt;  text", "bold text")]
    [InlineData("It&#8217;s", "It’s")]
    public void Html_becomes_plain_text(string html, string expected) => Assert.Equal(expected, FeedText.PlainText(html));

    [Theory]
    [InlineData("https://a.example/x", "https://a.example/x")]
    [InlineData("javascript:alert(1)", null)]
    [InlineData("data:text/html,x", null)]
    [InlineData("/news/1", "https://www.darkreading.com/news/1")]
    public void Only_http_links_survive(string url, string? expected) =>
        Assert.Equal(expected, FeedText.SafeUrl(url, new Uri("https://www.darkreading.com")));

    [Fact]
    public void Backoff_doubles_and_is_capped()
    {
        Assert.Equal(TimeSpan.FromMinutes(1), ThreatFeedService.Backoff(1));
        Assert.Equal(TimeSpan.FromMinutes(8), ThreatFeedService.Backoff(4));
        Assert.Equal(TimeSpan.FromHours(2), ThreatFeedService.Backoff(30));
    }
}
