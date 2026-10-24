using System.Globalization;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sentinel.Server.Data;

namespace Sentinel.Server.Services.ThreatFeed;

/// <summary>An HTTP failure from a feed source. <see cref="RetryAfter"/> is the server's own Retry-After, when it sent one.</summary>
public sealed class FeedHttpException(string url, HttpStatusCode status, TimeSpan? retryAfter)
    : HttpRequestException($"{(int)status} {status} from {new Uri(url).Host}", null, status)
{
    public TimeSpan? RetryAfter { get; } = retryAfter;
}

/// <summary>
/// Fetches every due threat-feed source, normalizes the results into <see cref="FeedItem"/>s and upserts them.
/// Each source has its own schedule in <see cref="FeedSourceState"/>: the configured interval after a success,
/// exponential backoff (or the server's Retry-After) after a failure. One source failing never affects the others,
/// and nothing here runs on a request path: the dashboard only ever reads what is already stored.
/// </summary>
public sealed class ThreatFeedService(
    SentinelDbContext db,
    IHttpClientFactory httpFactory,
    IOptions<SentinelOptions> options,
    TimeProvider time,
    DashboardNotifier notifier,
    ILogger<ThreatFeedService> logger)
{
    public const string HttpClientName = "threat-feed";

    /// <summary>How far back the first NVD fetch reaches. Later fetches continue from the stored cursor.</summary>
    public static readonly TimeSpan NvdBackfill = TimeSpan.FromDays(7);

    private const int NvdPageSize = 2000;
    private const int NvdMaxPages = 25;
    private const int MaxRetries = 3;
    private static readonly TimeSpan NvdMaxWindow = TimeSpan.FromDays(119); // the API rejects ranges over 120 days
    private static readonly TimeSpan NvdMaxKevWindow = TimeSpan.FromDays(90);  // and KEV ranges over 90
    private static readonly TimeSpan NvdCursorOverlap = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromHours(2);

    /// <summary>Pause between NVD pages. NVD allows 5 requests per 30 s without a key (50 with one) and asks clients to sleep between requests.</summary>
    public TimeSpan NvdPageDelay { get; set; } = string.IsNullOrEmpty(options.Value.NvdApiKey) ? TimeSpan.FromSeconds(6) : TimeSpan.FromSeconds(1);

    /// <summary>First in-run retry delay after a 429/5xx without Retry-After; tripled per attempt.</summary>
    public TimeSpan RetryBaseDelay { get; set; } = TimeSpan.FromSeconds(5);

    private sealed record FetchResult(int Seen, int New);

    /// <summary>Runs every source whose next attempt is due. Returns the number of new items.</summary>
    public async Task<int> RunDueAsync(CancellationToken ct)
    {
        var states = await db.FeedSources.ToDictionaryAsync(s => s.SourceId, ct);
        var added = 0;
        foreach (var source in FeedSources.All)
        {
            if (!states.TryGetValue(source.Id, out var state))
            {
                state = new FeedSourceState { SourceId = source.Id };
                db.FeedSources.Add(state);
                await db.SaveChangesAsync(ct);
            }
            if (state.NextAttemptAt > time.GetUtcNow().UtcDateTime) continue;
            added += await RunSourceAsync(source, state, ct);
        }
        if (added > 0) await notifier.FeedUpdatedAsync(new { newItems = added }, ct);
        return added;
    }

    public async Task<int> RunSourceAsync(FeedSource source, FeedSourceState state, CancellationToken ct)
    {
        // A failure in an earlier source clears the change tracker, which detaches this row too.
        if (db.Entry(state).State == EntityState.Detached) db.FeedSources.Attach(state);
        var (etag, lastModified) = (state.ETag, state.LastModified);
        state.LastAttemptAt = time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);
        try
        {
            var result = source.Kind switch
            {
                FeedSourceKind.Kev => await FetchKevAsync(source, state, ct),
                FeedSourceKind.Rss => await FetchRssAsync(source, state, ct),
                FeedSourceKind.Nvd => await FetchNvdAsync(source, state, ct),
                _ => throw new NotSupportedException(source.Kind.ToString()),
            };
            var now = time.GetUtcNow().UtcDateTime;
            state.LastSuccessAt = now;
            state.ConsecutiveFailures = 0;
            state.LastError = null;
            state.LastItemCount = result.Seen;
            state.NextAttemptAt = now + Jitter(options.Value.ThreatFeedIntervalValue);
            await db.SaveChangesAsync(ct);
            if (result.New > 0) logger.LogInformation("Threat feed {Source}: {New} new of {Seen} items", source.Id, result.New, result.Seen);
            return result.New;
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // Throw away half-applied changes from this source, keep the bookkeeping row.
            db.ChangeTracker.Clear();
            db.FeedSources.Attach(state);
            // A response that arrived but couldn't be applied must be fetched in full next time, not answered with 304.
            (state.ETag, state.LastModified) = (etag, lastModified);
            state.ConsecutiveFailures++;
            var backoff = ex is FeedHttpException { RetryAfter: { } ra } ? Max(ra, Backoff(state.ConsecutiveFailures)) : Backoff(state.ConsecutiveFailures);
            state.NextAttemptAt = time.GetUtcNow().UtcDateTime + backoff;
            state.LastError = Describe(ex);
            await db.SaveChangesAsync(ct);
            logger.LogWarning("Threat feed {Source} failed ({Failures}x in a row), retrying in {Backoff}: {Error}",
                source.Id, state.ConsecutiveFailures, backoff, state.LastError);
            return 0;
        }
    }

    /// <summary>1, 2, 4, 8 … minutes, capped at <see cref="MaxBackoff"/>.</summary>
    public static TimeSpan Backoff(int failures) =>
        TimeSpan.FromMinutes(Math.Min(Math.Pow(2, Math.Clamp(failures - 1, 0, 16)), MaxBackoff.TotalMinutes));

    // ---------------------------------------------------------------- sources

    private async Task<FetchResult> FetchRssAsync(FeedSource source, FeedSourceState state, CancellationToken ct)
    {
        using var resp = await GetConditionalAsync(source, state, ct);
        if (resp is null) return new FetchResult(state.LastItemCount, 0);

        var now = time.GetUtcNow().UtcDateTime;
        var cutoff = now - options.Value.ThreatFeedRetentionValue;
        await using var stream = await resp.Content.ReadAsStreamAsync(ct);
        var items = RssParser.Parse(RssParser.Load(stream), source, now).Where(i => i.PublishedAt >= cutoff).ToList();

        var kev = await KevIdsAsync(items.SelectMany(i => i.CveIds), ct);
        var ids = items.Select(i => i.Id).ToList();
        var existing = await db.FeedItems.Where(i => ids.Contains(i.Id)).ToDictionaryAsync(i => i.Id, ct);
        var added = 0;
        foreach (var item in items)
        {
            item.Exploited = item.CveIds.Any(kev.Contains);
            if (!existing.TryGetValue(item.Id, out var row))
            {
                db.FeedItems.Add(item);
                added++;
                continue;
            }
            // Keep the original date and fetch time; take the publisher's latest wording.
            if (row.Title == item.Title && row.Summary == item.Summary && row.Url == item.Url && row.Exploited == item.Exploited && row.Tags.SequenceEqual(item.Tags))
                continue;
            row.Title = item.Title;
            row.Summary = item.Summary;
            row.Url = item.Url;
            row.Tags = item.Tags;
            row.CveIds = item.CveIds;
            row.Exploited = item.Exploited;
            row.UpdatedAt = now;
            FeedText.Index(row);
        }
        await db.SaveChangesAsync(ct);
        return new FetchResult(items.Count, added);
    }

    private async Task<FetchResult> FetchKevAsync(FeedSource source, FeedSourceState state, CancellationToken ct)
    {
        using var resp = await GetConditionalAsync(source, state, ct);
        if (resp is null) return new FetchResult(state.LastItemCount, 0);

        await using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var json = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        var entries = KevParser.Parse(json);

        var stored = await db.KevEntries.ToDictionaryAsync(k => k.CveId, ct);
        // A truncated or wrong file must not silently clear every exploited flag.
        if (entries.Count == 0 || entries.Count < stored.Count / 2)
            throw new FormatException($"KEV catalog has {entries.Count} entries, {stored.Count} stored; refusing to apply it.");

        var byId = entries.ToDictionary(e => e.CveId);
        foreach (var e in entries)
        {
            if (!stored.TryGetValue(e.CveId, out var row)) { db.KevEntries.Add(e); continue; }
            row.VendorProject = e.VendorProject;
            row.Product = e.Product;
            row.VulnerabilityName = e.VulnerabilityName;
            row.ShortDescription = e.ShortDescription;
            row.DateAdded = e.DateAdded;
            row.DueDate = e.DueDate;
            row.KnownRansomwareUse = e.KnownRansomwareUse;
            row.Cwes = e.Cwes;
        }
        db.KevEntries.RemoveRange(stored.Values.Where(s => !byId.ContainsKey(s.CveId)));

        var now = time.GetUtcNow().UtcDateTime;
        var ids = byId.Keys.ToList();
        // CVE rows: flag what is in the catalog, unflag what CISA removed.
        var cves = await db.FeedItems.Where(i => i.Type == FeedItemTypes.Cve && (i.Exploited || ids.Contains(i.Id))).ToListAsync(ct);
        foreach (var item in cves) CveItems.ApplyKev(item, byId.GetValueOrDefault(item.Id), now);

        // Recent catalog additions NVD hasn't given us yet still belong on the timeline.
        var cutoff = now - options.Value.ThreatFeedRetentionValue;
        var have = cves.Select(c => c.Id).ToHashSet();
        var added = 0;
        foreach (var e in entries.Where(e => e.DateAdded >= cutoff && !have.Contains(e.CveId)))
        {
            db.FeedItems.Add(CveItems.FromKev(e, now));
            added++;
        }

        // News that mentions a CVE inherits its exploited flag.
        var news = await db.FeedItems.Where(i => i.Type == FeedItemTypes.News && i.TagIndex.Contains("|cve-")).ToListAsync(ct);
        foreach (var item in news) item.Exploited = item.CveIds.Any(byId.ContainsKey);

        await db.SaveChangesAsync(ct);
        return new FetchResult(entries.Count, added);
    }

    private async Task<FetchResult> FetchNvdAsync(FeedSource source, FeedSourceState state, CancellationToken ct)
    {
        var end = time.GetUtcNow().UtcDateTime;
        var kev = await db.KevEntries.AsNoTracking().ToDictionaryAsync(k => k.CveId, ct);
        var requests = 0;
        FetchResult result;
        if (state.Cursor is { } cursor)
        {
            // Everything modified since the last run. This also picks up CVSS scores and KEV flags NVD adds after publication.
            var start = cursor - NvdCursorOverlap;
            result = await FetchNvdWindowAsync(source, "lastMod", end - start > NvdMaxWindow ? end - NvdMaxWindow : start, end, kev, () => requests++, ct);
        }
        else
        {
            // First run: CVEs published in the backfill window, plus CVEs CISA added to KEV within the retention window
            // (often years old, so outside the publication window, and the most important ones to have CVSS for).
            var published = await FetchNvdWindowAsync(source, "pub", end - NvdBackfill, end, kev, () => requests++, ct);
            var kevDays = Min(options.Value.ThreatFeedRetentionValue, NvdMaxKevWindow);
            var exploited = await FetchNvdWindowAsync(source, "kev", end - kevDays, end, kev, () => requests++, ct);
            result = new FetchResult(published.Seen + exploited.Seen, published.New + exploited.New);
        }
        state.Cursor = end;
        return result;
    }

    private async Task<FetchResult> FetchNvdWindowAsync(FeedSource source, string range, DateTime start, DateTime end,
        Dictionary<string, KevEntry> kev, Func<int> countRequest, CancellationToken ct)
    {
        int seen = 0, added = 0, startIndex = 0, total, pages = 0;
        do
        {
            if (countRequest() > 0) await Task.Delay(NvdPageDelay, time, ct); // pause before every NVD request but the first of the run
            var url = $"{source.Url}?{range}StartDate={NvdDate(start)}&{range}EndDate={NvdDate(end)}&startIndex={startIndex}&resultsPerPage={NvdPageSize}";
            using var resp = await GetAsync(url, req =>
            {
                if (!string.IsNullOrEmpty(options.Value.NvdApiKey)) req.Headers.Add("apiKey", options.Value.NvdApiKey);
            }, ct);
            await using var stream = await resp.Content.ReadAsStreamAsync(ct);
            using var json = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            var page = NvdParser.Parse(json);
            added += await UpsertCvesAsync(page.Items, kev, ct);
            seen += page.Items.Count;
            total = page.TotalResults;
            if (page.ResultsPerPage <= 0) break;
            startIndex += page.ResultsPerPage;
        } while (startIndex < total && ++pages < NvdMaxPages);

        if (startIndex < total) logger.LogWarning("NVD returned {Total} CVEs for one {Range} window; stored the first {Seen}", total, range, seen);
        return new FetchResult(seen, added);
    }

    private async Task<int> UpsertCvesAsync(IReadOnlyList<NvdCve> cves, Dictionary<string, KevEntry> kev, CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var cutoff = now - options.Value.ThreatFeedRetentionValue;
        var ids = cves.Select(c => c.Id).ToList();
        var existing = await db.FeedItems.Where(i => ids.Contains(i.Id)).ToDictionaryAsync(i => i.Id, ct);
        var added = 0;
        foreach (var cve in cves.DistinctBy(c => c.Id))
        {
            var k = kev.GetValueOrDefault(cve.Id);
            if (existing.TryGetValue(cve.Id, out var row))
            {
                if (cve.Rejected) db.FeedItems.Remove(row);
                else CveItems.ApplyNvd(row, cve, k, now);
                continue;
            }
            var exploitedAt = k?.DateAdded ?? cve.CisaExploitAdd;
            var timeline = exploitedAt > cve.Published ? exploitedAt.Value : cve.Published;
            if (cve.Rejected || timeline < cutoff) continue;
            var item = new FeedItem
            {
                Id = cve.Id,
                Source = FeedSources.Nvd.Id,
                Type = FeedItemTypes.Cve,
                SourceItemId = cve.Id,
                Title = cve.Id,
                Url = CveItems.NvdUrl(cve.Id),
                FetchedAt = now,
            };
            CveItems.ApplyNvd(item, cve, k, now);
            db.FeedItems.Add(item);
            added++;
        }
        await db.SaveChangesAsync(ct);
        return added;
    }

    private async Task<HashSet<string>> KevIdsAsync(IEnumerable<string> cveIds, CancellationToken ct)
    {
        var ids = cveIds.Distinct().ToList();
        return ids.Count == 0 ? [] : (await db.KevEntries.Where(k => ids.Contains(k.CveId)).Select(k => k.CveId).ToListAsync(ct)).ToHashSet();
    }

    // ---------------------------------------------------------------- HTTP

    /// <summary>GET with If-None-Match / If-Modified-Since, falling back to the source's mirror. Null means 304 Not Modified.</summary>
    private async Task<HttpResponseMessage?> GetConditionalAsync(FeedSource source, FeedSourceState state, CancellationToken ct)
    {
        void Validators(HttpRequestMessage req)
        {
            if (state.ETag is { } etag && System.Net.Http.Headers.EntityTagHeaderValue.TryParse(etag, out var tag)) req.Headers.IfNoneMatch.Add(tag);
            if (state.LastModified is { } lm && DateTimeOffset.TryParse(lm, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var since)) req.Headers.IfModifiedSince = since;
        }

        HttpResponseMessage resp;
        try
        {
            resp = await GetAsync(source.Url, Validators, ct);
        }
        catch (HttpRequestException ex) when (source.FallbackUrl is not null)
        {
            logger.LogDebug("Threat feed {Source}: {Error}; trying mirror", source.Id, ex.Message);
            resp = await GetAsync(source.FallbackUrl, Validators, ct);
        }
        if (resp.StatusCode == HttpStatusCode.NotModified)
        {
            resp.Dispose();
            return null;
        }
        state.ETag = resp.Headers.ETag?.ToString();
        state.LastModified = resp.Content.Headers.LastModified?.ToString("R");
        return resp;
    }

    /// <summary>
    /// GET with a few short in-run retries on 429/5xx (and NVD's rate-limit 403), honouring Retry-After. Longer waits
    /// are not slept here: the exception carries Retry-After and the source's schedule backs off instead.
    /// </summary>
    private async Task<HttpResponseMessage> GetAsync(string url, Action<HttpRequestMessage>? configure, CancellationToken ct)
    {
        var client = httpFactory.CreateClient(HttpClientName);
        var nvd = url.StartsWith(FeedSources.Nvd.Url, StringComparison.Ordinal);
        for (var attempt = 0; ; attempt++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            configure?.Invoke(req);
            var resp = await client.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode || resp.StatusCode == HttpStatusCode.NotModified) return resp;

            var status = resp.StatusCode;
            var retryAfter = RetryAfter(resp);
            resp.Dispose();
            var transient = status is HttpStatusCode.TooManyRequests or HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout
                            || (nvd && status == HttpStatusCode.Forbidden);
            var delay = retryAfter ?? RetryBaseDelay * Math.Pow(3, attempt);
            if (!transient || attempt >= MaxRetries || delay > TimeSpan.FromMinutes(1)) throw new FeedHttpException(url, status, retryAfter);
            logger.LogDebug("{Url}: {Status}, retrying in {Delay}", url, (int)status, delay);
            await Task.Delay(delay, time, ct);
        }
    }

    private TimeSpan? RetryAfter(HttpResponseMessage resp) => resp.Headers.RetryAfter switch
    {
        { Delta: { } d } => d,
        { Date: { } at } => Max(at - time.GetUtcNow(), TimeSpan.Zero),
        _ => null,
    };

    private static string NvdDate(DateTime utc) => utc.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    private static TimeSpan Jitter(TimeSpan interval) => interval * (0.9 + Random.Shared.NextDouble() * 0.2);

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;

    private static string Describe(Exception ex) => FeedText.Truncate(ex switch
    {
        FeedHttpException h => h.Message,
        HttpRequestException h => $"Network error: {h.Message}",
        TaskCanceledException => "Timed out",
        JsonException or System.Xml.XmlException or FormatException => $"Unreadable response: {ex.Message}",
        _ => ex.Message,
    }, 500);
}
