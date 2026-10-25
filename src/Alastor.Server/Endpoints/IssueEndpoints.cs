using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Events;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;
using Alastor.Server.Services.Issues;

namespace Alastor.Server.Endpoints;

/// <summary>Open problems per host (derived by <see cref="IssueRules"/>), with acknowledge for the ones an operator has seen.</summary>
public static class IssueEndpoints
{
    public sealed record IssueDto(long Id, Guid HostId, string HostName, bool HostOnline, string Rule, string RuleLabel, string Subject, Severity Severity,
        string Title, string? Detail, string Tab, DateTime FirstSeenAt, DateTime LastSeenAt, DateTime? ResolvedAt, int Occurrences,
        DateTime? AcknowledgedAt, string? AcknowledgedBy, string? AckNote);

    /// <summary>Counts of open issues. <see cref="Unacknowledged"/> drives the navigation badge.</summary>
    public sealed record IssueSummary(int Open, int Acknowledged, int Unacknowledged, Severity? TopSeverity, IReadOnlyDictionary<Severity, int> UnacknowledgedBySeverity);

    public sealed record IssueList(IReadOnlyList<IssueDto> Items, IssueSummary Summary);

    public sealed record AckRequest(string? Note);

    public static void MapIssueEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/issues").WithTags("Issues").RequireAuthorization(AuthPolicies.Reader);

        // state: open (default: unacknowledged and acknowledged), unacknowledged, acknowledged, resolved (latest 200), all.
        g.MapGet("", async (string? state, Guid? hostId, Severity? minSeverity, string? rule, AlastorDbContext db, CancellationToken ct) =>
        {
            var q = db.Issues.AsNoTracking().AsQueryable();
            if (hostId is { } h) q = q.Where(i => i.HostId == h);
            if (minSeverity is { } s) q = q.Where(i => i.Severity >= s);
            if (!string.IsNullOrWhiteSpace(rule)) q = q.Where(i => i.Rule == rule);
            var summary = await SummaryAsync(q, ct);
            q = (state ?? "open") switch
            {
                "unacknowledged" => q.Where(i => i.ResolvedAt == null && i.AcknowledgedAt == null),
                "acknowledged" => q.Where(i => i.ResolvedAt == null && i.AcknowledgedAt != null),
                "resolved" => q.Where(i => i.ResolvedAt != null),
                "all" => q,
                _ => q.Where(i => i.ResolvedAt == null),
            };
            var rows = state == "resolved"
                ? await q.OrderByDescending(i => i.ResolvedAt).Take(200).ToListAsync(ct)
                : await q.OrderByDescending(i => i.Severity).ThenByDescending(i => i.FirstSeenAt).Take(1000).ToListAsync(ct);
            var hostIds = rows.Select(r => r.HostId).Distinct().ToList();
            var hosts = await db.Hosts.AsNoTracking().Where(x => hostIds.Contains(x.Id)).Select(x => new { x.Id, x.Name, x.IsOnline }).ToDictionaryAsync(x => x.Id, ct);
            var items = rows.Select(r =>
            {
                var host = hosts.GetValueOrDefault(r.HostId);
                return new IssueDto(r.Id, r.HostId, host?.Name ?? "?", host?.IsOnline ?? false, r.Rule, IssueRules.Rules.GetValueOrDefault(r.Rule, r.Rule), r.Subject,
                    r.Severity, r.Title, r.Detail, r.Tab, r.FirstSeenAt, r.LastSeenAt, r.ResolvedAt, r.Occurrences, r.AcknowledgedAt, r.AcknowledgedBy, r.AckNote);
            }).ToList();
            return new IssueList(items, summary);
        });

        g.MapGet("/summary", async (AlastorDbContext db, CancellationToken ct) => await SummaryAsync(db.Issues.AsNoTracking(), ct));

        g.MapGet("/rules", () => IssueRules.Rules.Select(r => new { key = r.Key, label = r.Value }).ToList());

        g.MapPost("/{id:long}/ack", async (long id, AckRequest? req, ClaimsPrincipal user, AlastorDbContext db, DashboardNotifier notifier, TimeProvider time, CancellationToken ct) =>
        {
            var issue = await db.Issues.FirstOrDefaultAsync(i => i.Id == id, ct);
            if (issue is null) return Results.NotFound();
            if (issue.ResolvedAt is not null) return Results.Conflict(new { error = "The issue is already resolved." });
            var note = req?.Note?.Trim();
            issue.AcknowledgedAt = time.GetUtcNow().UtcDateTime;
            issue.AcknowledgedBy = user.Actor();
            issue.AckNote = string.IsNullOrEmpty(note) ? null : note.Length > 512 ? note[..512] : note;
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "issue.acknowledge", Target = issue.HostId.ToString(), Details = $"{issue.Rule} {issue.Subject}".Trim() + (issue.AckNote is null ? "" : $": {issue.AckNote}") });
            await db.SaveChangesAsync(ct);
            await notifier.IssuesChangedAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);

        g.MapPost("/{id:long}/unack", async (long id, ClaimsPrincipal user, AlastorDbContext db, DashboardNotifier notifier, CancellationToken ct) =>
        {
            var issue = await db.Issues.FirstOrDefaultAsync(i => i.Id == id, ct);
            if (issue is null) return Results.NotFound();
            issue.AcknowledgedAt = null;
            issue.AcknowledgedBy = null;
            issue.AckNote = null;
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "issue.unacknowledge", Target = issue.HostId.ToString(), Details = $"{issue.Rule} {issue.Subject}".Trim() });
            await db.SaveChangesAsync(ct);
            await notifier.IssuesChangedAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);
    }

    private static async Task<IssueSummary> SummaryAsync(IQueryable<HostIssue> q, CancellationToken ct)
    {
        var open = await q.Where(i => i.ResolvedAt == null).Select(i => new { i.Severity, Acked = i.AcknowledgedAt != null }).ToListAsync(ct);
        var unacked = open.Where(i => !i.Acked).ToList();
        return new IssueSummary(open.Count, open.Count(i => i.Acked), unacked.Count,
            unacked.Count == 0 ? null : unacked.Max(i => i.Severity),
            unacked.GroupBy(i => i.Severity).ToDictionary(x => x.Key, x => x.Count()));
    }
}
