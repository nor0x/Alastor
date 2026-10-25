namespace Alastor.Server.Services.ThreatFeed;

public enum FeedSourceKind
{
    Nvd,
    Kev,
    Rss,
}

/// <param name="FallbackUrl">Tried when <paramref name="Url"/> fails, e.g. CISA's official GitHub mirror of the KEV catalog.</param>
public sealed record FeedSource(string Id, string Name, FeedSourceKind Kind, string Url, string Homepage, string? FallbackUrl = null);

/// <summary>The built-in threat-feed sources. All are free and need no account (an NVD API key only raises the rate limit).</summary>
public static class FeedSources
{
    public static readonly FeedSource Nvd = new("nvd", "NVD", FeedSourceKind.Nvd,
        "https://services.nvd.nist.gov/rest/json/cves/2.0", "https://nvd.nist.gov/");

    // cisa.gov sits behind Akamai, which rejects some cloud/VPS address ranges with 403. CISA publishes the same file on GitHub.
    public static readonly FeedSource Kev = new("cisa-kev", "CISA KEV", FeedSourceKind.Kev,
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json");

    /// <summary>Fetch order: KEV first so exploited flags are current when CVEs and news are stored; NVD last because paging is slow.</summary>
    public static readonly IReadOnlyList<FeedSource> All =
    [
        Kev,
        new("thehackernews", "The Hacker News", FeedSourceKind.Rss, "https://feeds.feedburner.com/TheHackersNews", "https://thehackernews.com/"),
        new("bleepingcomputer", "BleepingComputer", FeedSourceKind.Rss, "https://www.bleepingcomputer.com/feed/", "https://www.bleepingcomputer.com/"),
        new("krebsonsecurity", "Krebs on Security", FeedSourceKind.Rss, "https://krebsonsecurity.com/feed/", "https://krebsonsecurity.com/"),
        new("securityweek", "SecurityWeek", FeedSourceKind.Rss, "https://www.securityweek.com/feed/", "https://www.securityweek.com/"),
        new("darkreading", "Dark Reading", FeedSourceKind.Rss, "https://www.darkreading.com/rss.xml", "https://www.darkreading.com/"),
        Nvd,
    ];

    public static FeedSource? Find(string id) => All.FirstOrDefault(s => s.Id == id);
}
