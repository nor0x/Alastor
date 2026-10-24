using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Events;
using Sentinel.Server.Auth;
using Sentinel.Server.Data;
using Sentinel.Server.Services;
using Sentinel.Server.Services.ThreatFeed;

namespace Sentinel.Server.Endpoints;

public static class FeedEndpoints
{
    public sealed record FeedPage(IReadOnlyList<FeedItemDto> Items, int Total, int Page, int PageSize);

    public sealed record TagCount(string Tag, int Count);

    public static void MapFeedEndpoints(this IEndpointRouteBuilder app)
    {
        // Reads only what the background worker stored, so a source that is down never slows this down.
        app.MapGet("/api/feed", async (string? type, Severity? minSeverity, bool? exploited, string[]? tag, string? source, string? q,
            string? sort, string? order, int? page, int? pageSize, SentinelDbContext db, CancellationToken ct) =>
        {
            var query = db.FeedItems.AsNoTracking().AsQueryable();
            if (type is FeedItemTypes.Cve or FeedItemTypes.News) query = query.Where(i => i.Type == type);
            else if (!string.IsNullOrWhiteSpace(type)) return Results.ValidationProblem(new Dictionary<string, string[]> { ["type"] = ["Use 'cve' or 'news'."] });
            if (minSeverity is { } s) query = query.Where(i => i.Severity >= s);
            if (exploited is { } x) query = query.Where(i => i.Exploited == x);
            if (!string.IsNullOrWhiteSpace(source)) query = query.Where(i => i.Source == source);
            foreach (var t in (tag ?? []).Where(t => !string.IsNullOrWhiteSpace(t)).Take(5))
            {
                var needle = "|" + t.Trim().ToLowerInvariant() + "|";
                query = query.Where(i => i.TagIndex.Contains(needle));
            }
            if (!string.IsNullOrWhiteSpace(q))
            {
                var needle = q.Trim().ToLowerInvariant();
                query = query.Where(i => i.SearchText.Contains(needle));
            }

            var asc = string.Equals(order, "asc", StringComparison.OrdinalIgnoreCase);
            var ordered = sort?.ToLowerInvariant() switch
            {
                null or "" or "date" => asc ? query.OrderBy(i => i.PublishedAt) : query.OrderByDescending(i => i.PublishedAt),
                // Unscored items (news, CVEs awaiting analysis) always sort last. SQLite and PostgreSQL disagree on where NULLs go.
                "severity" => asc
                    ? query.OrderByDescending(i => i.Severity != null).ThenBy(i => i.Severity).ThenBy(i => i.CvssScore).ThenByDescending(i => i.PublishedAt)
                    : query.OrderByDescending(i => i.Severity != null).ThenByDescending(i => i.Severity).ThenByDescending(i => i.CvssScore).ThenByDescending(i => i.PublishedAt),
                _ => null,
            };
            if (ordered is null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["sort"] = ["Use 'date' or 'severity'."] });

            var size = Math.Clamp(pageSize ?? 25, 1, 100);
            var number = Math.Max(page ?? 1, 1);
            var total = await query.CountAsync(ct);
            var items = await ordered.ThenBy(i => i.Id).Skip((number - 1) * size).Take(size).ToListAsync(ct);
            return Results.Ok(new FeedPage(items.Select(Dto.FeedItem).ToList(), total, number, size));
        }).WithTags("Threat feed").Produces<FeedPage>().ProducesValidationProblem().RequireAuthorization(AuthPolicies.Reader);

        app.MapGet("/api/feed/sources", async (SentinelDbContext db, CancellationToken ct) =>
        {
            var states = await db.FeedSources.AsNoTracking().ToDictionaryAsync(s => s.SourceId, ct);
            var counts = await db.FeedItems.GroupBy(i => i.Source).Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(g => g.Key, g => g.Count, ct);
            return FeedSources.All.Select(src => Dto.FeedSource(src, states.GetValueOrDefault(src.Id), counts.GetValueOrDefault(src.Id))).ToList();
        }).WithTags("Threat feed").RequireAuthorization(AuthPolicies.Reader);

        // The most common tags of the last week, for the filter bar.
        app.MapGet("/api/feed/tags", async (int? limit, SentinelDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var since = time.GetUtcNow().UtcDateTime.AddDays(-7);
            var tags = await db.FeedItems.AsNoTracking().Where(i => i.PublishedAt >= since).Select(i => i.Tags).ToListAsync(ct);
            return tags.SelectMany(t => t)
                .GroupBy(t => t, StringComparer.OrdinalIgnoreCase)
                .Select(g => new TagCount(g.Key, g.Count()))
                .Where(t => t.Count > 1)
                .OrderByDescending(t => t.Count).ThenBy(t => t.Tag)
                .Take(Math.Clamp(limit ?? 30, 1, 100))
                .ToList();
        }).WithTags("Threat feed").RequireAuthorization(AuthPolicies.Reader);
    }
}
