using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Alastor.Core.Events;
using Alastor.Server.Data;

namespace Alastor.Server.Services.ThreatFeed;

// Pure parsing and normalization for the threat feed: no I/O, so every source is unit-tested on captured responses.

public static partial class FeedText
{
    public const int MaxSummary = 600;
    public const int MaxTags = 12;

    [GeneratedRegex(@"<(script|style)\b.*?</\1\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex ScriptOrStyle();

    [GeneratedRegex(@"<[^>]*>", RegexOptions.Singleline)]
    private static partial Regex Tag();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();

    [GeneratedRegex(@"\bCVE-\d{4}-\d{4,}\b", RegexOptions.IgnoreCase)]
    private static partial Regex CveId();

    // WordPress feeds (SecurityWeek, Krebs) append "The post X appeared first on Y." to every description.
    [GeneratedRegex(@"\s*The post .{1,400}? appeared first on .{1,120}?\.\s*$", RegexOptions.Singleline)]
    private static partial Regex WordPressFooter();

    /// <summary>HTML fragment → one line of plain text. Feeds sometimes double-encode entities, so decode until stable (at most twice).</summary>
    public static string PlainText(string? html)
    {
        if (string.IsNullOrWhiteSpace(html)) return "";
        var s = ScriptOrStyle().Replace(html, " ");
        s = Tag().Replace(s, " ");
        for (var i = 0; i < 2 && s.Contains('&'); i++) s = WebUtility.HtmlDecode(s);
        // Decoding can reveal escaped markup (&lt;p&gt;); strip it once more.
        s = Tag().Replace(s, " ");
        return Whitespace().Replace(s, " ").Trim();
    }

    public static string Summary(string? html)
    {
        var s = WordPressFooter().Replace(PlainText(html), "");
        s = s.EndsWith("[...]", StringComparison.Ordinal) || s.EndsWith("[…]", StringComparison.Ordinal) ? s[..s.LastIndexOf('[')].TrimEnd() + "…" : s;
        return Truncate(s, MaxSummary);
    }

    /// <summary>Cuts at a word boundary and appends an ellipsis.</summary>
    public static string Truncate(string s, int max)
    {
        if (s.Length <= max) return s;
        var cut = s.LastIndexOf(' ', max - 1);
        return s[..(cut > max / 2 ? cut : max - 1)].TrimEnd(' ', ',', ';', ':', '-') + "…";
    }

    public static List<string> CveIds(params string?[] texts) =>
        texts.Where(t => t is not null)
            .SelectMany(t => CveId().Matches(t!).Select(m => m.Value.ToUpperInvariant()))
            .Distinct().ToList();

    /// <summary>Only absolute http(s) links reach the browser; anything else (javascript:, data:, relative junk) is dropped.</summary>
    public static string? SafeUrl(string? url, Uri? baseUri = null)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        url = url.Trim();
        // On Unix "/path" parses as an absolute file:// URI, so root-relative links are resolved explicitly.
        if ((url.StartsWith('/') || !Uri.TryCreate(url, UriKind.Absolute, out var uri)) && (baseUri is null || !Uri.TryCreate(baseUri, url, out uri))) return null;
        return uri.Scheme is "http" or "https" ? uri.AbsoluteUri : null;
    }

    public static string ShortHash(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)))[..20];

    /// <summary>Case-insensitive de-duplication that keeps the first spelling.</summary>
    public static List<string> Distinct(IEnumerable<string?> values, int max) =>
        values.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Take(max).ToList();

    /// <summary>Recomputes the derived search columns. Call after any change to title, summary, tags or products.</summary>
    public static void Index(FeedItem item)
    {
        item.Tags = Distinct(item.Tags, MaxTags);
        item.TagIndex = "|" + string.Concat(item.Tags.Select(t => t.ToLowerInvariant() + "|"));
        item.SearchText = string.Join('\n', [item.Title, item.Summary, .. item.Tags, .. item.Products, item.Source]).ToLowerInvariant();
    }

    // RFC 822 dates as found in the wild: "+0530" offsets, named US zones, missing weekday, single-digit days.
    private static readonly Dictionary<string, string> Zones = new(StringComparer.OrdinalIgnoreCase)
    {
        ["GMT"] = "+00:00", ["UT"] = "+00:00", ["UTC"] = "+00:00", ["Z"] = "+00:00",
        ["EST"] = "-05:00", ["EDT"] = "-04:00", ["CST"] = "-06:00", ["CDT"] = "-05:00",
        ["MST"] = "-07:00", ["MDT"] = "-06:00", ["PST"] = "-08:00", ["PDT"] = "-07:00",
    };

    [GeneratedRegex(@"\s([+-])(\d{2}):?(\d{2})$")]
    private static partial Regex NumericZone();

    public static DateTime? ParseDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var s = value.Trim();
        // ISO 8601 (Atom, dc:date, NVD).
        if (char.IsDigit(s[0]) && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var iso))
            return iso.UtcDateTime;
        if (s.Length > 4 && s[3] == ',') s = s[4..].Trim(); // weekday is optional and sometimes wrong
        var space = s.LastIndexOf(' ');
        if (space > 0 && Zones.TryGetValue(s[(space + 1)..], out var offset)) s = s[..space] + " " + offset;
        else s = NumericZone().Replace(s, " $1$2:$3");
        string[] formats = ["d MMM yyyy HH:mm:ss zzz", "d MMM yyyy HH:mm zzz", "d MMM yy HH:mm:ss zzz", "d MMMM yyyy HH:mm:ss zzz"];
        return DateTimeOffset.TryParseExact(s, formats, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var d)
            ? d.UtcDateTime
            : DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var any) ? any.UtcDateTime : null;
    }
}

// ---------------------------------------------------------------- NVD

public sealed record NvdCve(
    string Id,
    DateTime Published,
    bool Rejected,
    string Description,
    Severity? Severity,
    double? CvssScore,
    IReadOnlyList<string> Products,
    IReadOnlyList<string> Vendors,
    IReadOnlyList<string> Cwes,
    DateTime? CisaExploitAdd,
    string? CisaVulnerabilityName);

public sealed record NvdPage(int TotalResults, int StartIndex, int ResultsPerPage, IReadOnlyList<NvdCve> Items);

/// <summary>Parses NVD CVE API 2.0 responses (https://nvd.nist.gov/developers/vulnerabilities).</summary>
public static class NvdParser
{
    // Newest CVSS version first; within a version the NVD's own ("Primary") score wins over a CNA's ("Secondary").
    private static readonly string[] MetricKeys = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"];

    public static NvdPage Parse(JsonDocument doc)
    {
        var root = doc.RootElement;
        var items = new List<NvdCve>();
        if (root.TryGetProperty("vulnerabilities", out var vulns))
            foreach (var v in vulns.EnumerateArray())
                if (v.TryGetProperty("cve", out var cve) && ParseCve(cve) is { } parsed)
                    items.Add(parsed);
        return new NvdPage(Int(root, "totalResults"), Int(root, "startIndex"), Int(root, "resultsPerPage"), items);
    }

    private static NvdCve? ParseCve(JsonElement cve)
    {
        var id = Str(cve, "id");
        if (id is null || FeedText.ParseDate(Str(cve, "published")) is not { } published) return null;

        var description = "";
        if (cve.TryGetProperty("descriptions", out var descs))
        {
            var all = descs.EnumerateArray().ToList();
            var en = all.FirstOrDefault(d => Str(d, "lang") == "en");
            description = Str(en.ValueKind == JsonValueKind.Object ? en : all.FirstOrDefault(), "value") ?? "";
        }

        var (severity, score) = Cvss(cve);

        var vendors = new List<string?>();
        var products = new List<string?>();
        // CVE 5 style "affected" block, which NVD now passes through from the CNA.
        if (cve.TryGetProperty("affected", out var affected))
            foreach (var a in affected.EnumerateArray())
                if (a.TryGetProperty("affectedData", out var data))
                    foreach (var d in data.EnumerateArray())
                    {
                        var vendor = Clean(Str(d, "vendor"));
                        var product = Clean(Str(d, "product"));
                        vendors.Add(vendor);
                        products.Add(Product(vendor, product));
                    }
        // NVD's analyzed CPE configurations.
        if (cve.TryGetProperty("configurations", out var configs))
            foreach (var cfg in configs.EnumerateArray())
                if (cfg.TryGetProperty("nodes", out var nodes))
                    foreach (var node in nodes.EnumerateArray())
                        if (node.TryGetProperty("cpeMatch", out var matches))
                            foreach (var m in matches.EnumerateArray())
                                if (Str(m, "criteria")?.Split(':') is { Length: > 5 } cpe && m.TryGetProperty("vulnerable", out var vul) && vul.GetBoolean())
                                {
                                    var vendor = Clean(cpe[3].Replace('_', ' '));
                                    vendors.Add(vendor);
                                    products.Add(Product(vendor, Clean(cpe[4].Replace('_', ' '))));
                                }

        var cwes = new List<string?>();
        if (cve.TryGetProperty("weaknesses", out var weaknesses))
            foreach (var w in weaknesses.EnumerateArray())
                if (w.TryGetProperty("description", out var wd))
                    foreach (var d in wd.EnumerateArray())
                        if (Str(d, "value") is { } cwe && cwe.StartsWith("CWE-", StringComparison.Ordinal)) // skips NVD-CWE-Other / noinfo
                            cwes.Add(cwe);

        return new NvdCve(
            id,
            published,
            Str(cve, "vulnStatus") == "Rejected",
            description,
            severity,
            score,
            FeedText.Distinct(products, 5),
            FeedText.Distinct(vendors, 3),
            FeedText.Distinct(cwes, 3),
            FeedText.ParseDate(Str(cve, "cisaExploitAdd")),
            Str(cve, "cisaVulnerabilityName"));
    }

    private static (Severity?, double?) Cvss(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var metrics)) return (null, null);
        foreach (var key in MetricKeys)
        {
            if (!metrics.TryGetProperty(key, out var list) || list.GetArrayLength() == 0) continue;
            var all = list.EnumerateArray().ToList();
            var m = all.FirstOrDefault(x => Str(x, "type") == "Primary");
            if (m.ValueKind != JsonValueKind.Object) m = all[0];
            if (!m.TryGetProperty("cvssData", out var data)) continue;
            double? score = data.TryGetProperty("baseScore", out var bs) && bs.TryGetDouble(out var d) ? d : null;
            // v2 keeps baseSeverity next to cvssData rather than inside it.
            var sev = SeverityOf(Str(data, "baseSeverity") ?? Str(m, "baseSeverity")) ?? SeverityOf(score);
            return (sev, score);
        }
        return (null, null);
    }

    public static Severity? SeverityOf(string? cvssSeverity) => cvssSeverity?.ToUpperInvariant() switch
    {
        "CRITICAL" => Severity.Critical,
        "HIGH" => Severity.High,
        "MEDIUM" => Severity.Medium,
        "LOW" => Severity.Low,
        "NONE" => Severity.Info,
        _ => null,
    };

    /// <summary>CVSS v3/v4 qualitative bands, for metrics that carry only a score.</summary>
    public static Severity? SeverityOf(double? score) => score switch
    {
        null => null,
        >= 9.0 => Severity.Critical,
        >= 7.0 => Severity.High,
        >= 4.0 => Severity.Medium,
        > 0 => Severity.Low,
        _ => Severity.Info,
    };

    // CNAs fill unknown vendor/product fields with placeholders; those would become meaningless tags.
    private static readonly HashSet<string> Placeholders = new(StringComparer.OrdinalIgnoreCase) { "*", "-", "n/a", "unknown", "unspecified" };

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) || Placeholders.Contains(s.Trim()) ? null : s.Trim();

    private static string? Product(string? vendor, string? product) =>
        product is null ? vendor
        : vendor is null || product.StartsWith(vendor, StringComparison.OrdinalIgnoreCase) ? product
        : $"{vendor} {product}";

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    private static int Int(JsonElement e, string name) => e.TryGetProperty(name, out var p) && p.TryGetInt32(out var i) ? i : 0;
}

// ---------------------------------------------------------------- CISA KEV

/// <summary>Parses the CISA KEV catalog JSON (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).</summary>
public static class KevParser
{
    public static List<KevEntry> Parse(JsonDocument doc)
    {
        var list = new List<KevEntry>();
        if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulns)) throw new FormatException("Not a KEV catalog: no 'vulnerabilities' array.");
        foreach (var v in vulns.EnumerateArray())
        {
            var id = Str(v, "cveID")?.Trim().ToUpperInvariant();
            if (id is null || FeedText.ParseDate(Str(v, "dateAdded")) is not { } added) continue;
            list.Add(new KevEntry
            {
                CveId = id,
                VendorProject = Str(v, "vendorProject") ?? "",
                Product = Str(v, "product") ?? "",
                VulnerabilityName = Str(v, "vulnerabilityName") ?? "",
                ShortDescription = Str(v, "shortDescription") ?? "",
                DateAdded = added,
                DueDate = FeedText.ParseDate(Str(v, "dueDate")),
                KnownRansomwareUse = string.Equals(Str(v, "knownRansomwareCampaignUse"), "Known", StringComparison.OrdinalIgnoreCase),
                Cwes = v.TryGetProperty("cwes", out var c) && c.ValueKind == JsonValueKind.Array
                    ? c.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
                    : [],
            });
        }
        return list.DistinctBy(e => e.CveId).ToList();
    }

    private static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
}

// ---------------------------------------------------------------- RSS / Atom

/// <summary>Tolerant RSS 2.0, RSS 1.0 (RDF) and Atom parser. DTDs and external entities are never processed.</summary>
public static class RssParser
{
    private static readonly XNamespace Atom = "http://www.w3.org/2005/Atom";
    private static readonly XNamespace Rss1 = "http://purl.org/rss/1.0/";
    private static readonly XNamespace Dc = "http://purl.org/dc/elements/1.1/";
    private static readonly XNamespace Content = "http://purl.org/rss/1.0/modules/content/";

    // Feed-wide categories that say nothing about the article.
    private static readonly HashSet<string> NoiseTags = new(StringComparer.OrdinalIgnoreCase) { "uncategorized", "security", "news", "featured" };

    public static XDocument Load(Stream stream)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Ignore,
            XmlResolver = null,
            MaxCharactersFromEntities = 1024,
            MaxCharactersInDocument = 20_000_000,
            IgnoreComments = true,
        };
        using var reader = XmlReader.Create(stream, settings);
        return XDocument.Load(reader, LoadOptions.SetBaseUri);
    }

    /// <summary>Normalizes a feed into news items. <paramref name="now"/> stands in for a missing or unparseable date.</summary>
    public static List<FeedItem> Parse(XDocument doc, FeedSource source, DateTime now)
    {
        var root = doc.Root ?? throw new FormatException("Empty feed document.");
        var channelLink = root.Element("channel")?.Element("link")?.Value;
        var baseUri = Uri.TryCreate(FeedText.SafeUrl(channelLink) ?? source.Homepage, UriKind.Absolute, out var b) ? b : null;

        var entries = root.Name == Atom + "feed"
            ? root.Elements(Atom + "entry").Select(e => ParseAtom(e, baseUri))
            : root.Descendants().Where(e => e.Name == "item" || e.Name == Rss1 + "item").Select(e => ParseRss(e, baseUri));

        if (root.Name != Atom + "feed" && root.Name.LocalName is not ("rss" or "RDF"))
            throw new FormatException($"Not an RSS or Atom feed (root element <{root.Name.LocalName}>).");

        var items = new List<FeedItem>();
        foreach (var e in entries)
        {
            if (e.Url is null || string.IsNullOrWhiteSpace(e.Title)) continue;
            var sourceItemId = FeedText.Truncate(string.IsNullOrWhiteSpace(e.Guid) ? e.Url : e.Guid.Trim(), 512);
            var cves = FeedText.CveIds(e.Title, e.Body);
            var item = new FeedItem
            {
                Id = $"{source.Id}:{FeedText.ShortHash(sourceItemId)}",
                Source = source.Id,
                Type = FeedItemTypes.News,
                SourceItemId = sourceItemId,
                Title = FeedText.Truncate(FeedText.PlainText(e.Title), 300),
                Url = e.Url,
                PublishedAt = e.Published is { } p && p <= now.AddHours(1) ? p : now, // future dates are publisher clock errors
                FetchedAt = now,
                UpdatedAt = now,
                Summary = FeedText.Summary(e.Body),
                Tags = [.. e.Categories.Select(FeedText.PlainText).Where(c => c.Length is > 0 and <= 40 && !NoiseTags.Contains(c)), .. cves],
                CveIds = cves,
            };
            FeedText.Index(item);
            items.Add(item);
        }
        return items.DistinctBy(i => i.Id).ToList();
    }

    private sealed record Entry(string? Title, string? Url, string? Guid, DateTime? Published, string? Body, IReadOnlyList<string> Categories);

    private static Entry ParseRss(XElement item, Uri? baseUri)
    {
        string? El(XName name) => item.Element(name)?.Value;
        var link = El("link") ?? El(Rss1 + "link") ?? item.Attribute(XName.Get("about", "http://www.w3.org/1999/02/22-rdf-syntax-ns#"))?.Value;
        var guid = item.Element("guid");
        // A permalink guid is a better link than nothing; a non-permalink guid is only an id.
        if (link is null && guid is not null && guid.Attribute("isPermaLink")?.Value != "false") link = guid.Value;
        var description = El("description") ?? El(Rss1 + "description");
        var content = El(Content + "encoded");
        return new Entry(
            El("title") ?? El(Rss1 + "title"),
            FeedText.SafeUrl(link, baseUri),
            guid?.Value,
            FeedText.ParseDate(El("pubDate") ?? El(Dc + "date")),
            string.IsNullOrWhiteSpace(description) ? content : description,
            item.Elements("category").Concat(item.Elements(Dc + "subject")).Select(c => c.Value).ToList());
    }

    private static Entry ParseAtom(XElement entry, Uri? baseUri)
    {
        var links = entry.Elements(Atom + "link").ToList();
        var link = links.FirstOrDefault(l => (string?)l.Attribute("rel") is null or "alternate") ?? links.FirstOrDefault();
        return new Entry(
            entry.Element(Atom + "title")?.Value,
            FeedText.SafeUrl((string?)link?.Attribute("href"), baseUri),
            entry.Element(Atom + "id")?.Value,
            FeedText.ParseDate(entry.Element(Atom + "published")?.Value ?? entry.Element(Atom + "updated")?.Value),
            entry.Element(Atom + "summary")?.Value ?? entry.Element(Atom + "content")?.Value,
            entry.Elements(Atom + "category").Select(c => (string?)c.Attribute("label") ?? (string?)c.Attribute("term") ?? "").ToList());
    }
}

// ---------------------------------------------------------------- CVE items

/// <summary>Builds and merges CVE timeline items from NVD records and KEV entries. Both sources write the same row, keyed by CVE id.</summary>
public static class CveItems
{
    public static string NvdUrl(string cveId) => $"https://nvd.nist.gov/vuln/detail/{cveId}";

    /// <summary>Applies an NVD record to a new or existing item. <paramref name="kev"/> is the item's KEV entry, if any.</summary>
    public static void ApplyNvd(FeedItem item, NvdCve cve, KevEntry? kev, DateTime now)
    {
        item.Title = Title(cve.Id, kev?.VulnerabilityName ?? cve.CisaVulnerabilityName, cve.Products);
        item.Summary = FeedText.Truncate(cve.Description.Trim(), 1200);
        item.Severity = cve.Severity;
        item.CvssScore = cve.CvssScore;
        item.Products = [.. cve.Products];
        item.PublishedAt = TimelineDate(cve.Published, kev?.DateAdded ?? cve.CisaExploitAdd);
        item.Exploited = kev is not null || cve.CisaExploitAdd is not null;
        item.Tags = [.. ExploitTags(item.Exploited, kev), .. cve.Vendors.Select(v => v.ToLowerInvariant()), .. cve.Cwes];
        item.CveIds = [cve.Id];
        item.UpdatedAt = now;
        FeedText.Index(item);
    }

    /// <summary>A CVE CISA flagged before NVD gave us a record: create it from the catalog entry. NVD fills in CVSS later.</summary>
    public static FeedItem FromKev(KevEntry kev, DateTime now)
    {
        var item = new FeedItem
        {
            Id = kev.CveId,
            Source = FeedSources.Kev.Id,
            Type = FeedItemTypes.Cve,
            SourceItemId = kev.CveId,
            Title = Title(kev.CveId, kev.VulnerabilityName, []),
            Url = NvdUrl(kev.CveId),
            PublishedAt = kev.DateAdded,
            FetchedAt = now,
            UpdatedAt = now,
            Summary = kev.ShortDescription,
            Exploited = true,
            Products = FeedText.Distinct([$"{kev.VendorProject} {kev.Product}".Trim()], 5),
            Tags = [.. ExploitTags(true, kev), kev.VendorProject.ToLowerInvariant(), .. kev.Cwes],
            CveIds = [kev.CveId],
        };
        FeedText.Index(item);
        return item;
    }

    /// <summary>Marks an existing CVE item as in (or no longer in) KEV.</summary>
    public static bool ApplyKev(FeedItem item, KevEntry? kev, DateTime now)
    {
        var tags = item.Tags.Where(t => t is not ("kev" or "ransomware")).ToList();
        var exploited = kev is not null;
        var published = kev is null ? item.PublishedAt : TimelineDate(item.PublishedAt, kev.DateAdded);
        List<string> newTags = [.. ExploitTags(exploited, kev), .. tags];
        if (item.Exploited == exploited && item.PublishedAt == published && newTags.SequenceEqual(item.Tags)) return false;
        item.Exploited = exploited;
        item.PublishedAt = published;
        item.Tags = newTags;
        item.UpdatedAt = now;
        FeedText.Index(item);
        return true;
    }

    private static DateTime TimelineDate(DateTime published, DateTime? kevAdded) => kevAdded is { } k && k > published ? k : published;

    private static IEnumerable<string> ExploitTags(bool exploited, KevEntry? kev) =>
        !exploited ? [] : kev?.KnownRansomwareUse == true ? ["kev", "ransomware"] : ["kev"];

    private static string Title(string cveId, string? name, IReadOnlyList<string> products) =>
        !string.IsNullOrWhiteSpace(name) ? $"{cveId}: {name.Trim()}"
        : products.Count > 0 ? $"{cveId} in {string.Join(", ", products.Take(2))}"
        : cveId;
}
