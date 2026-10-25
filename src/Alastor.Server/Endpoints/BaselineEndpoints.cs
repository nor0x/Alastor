using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Baseline;
using Alastor.Core.Events;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;

namespace Alastor.Server.Endpoints;

/// <summary>
/// Security baseline: the agent reports check results, the dashboard reads them merged with the catalog
/// (why it matters, how to fix it). Fixes themselves are policy edits, so they go through the policy API.
/// </summary>
public static class BaselineEndpoints
{
    public static void MapBaselineEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/agent/baseline", Report).WithTags("Agent").RequireAuthorization(AuthPolicies.Agent);

        var g = app.MapGroup("/api").WithTags("Baseline").RequireAuthorization(AuthPolicies.Reader);

        g.MapGet("/baseline/catalog", () => BaselineCatalog.All.Select(i => CheckDto(i, null)).ToList());

        g.MapGet("/hosts/{id:guid}/baseline", async (Guid id, AlastorDbContext db, CancellationToken ct) =>
        {
            var h = await db.Hosts.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
            if (h is null) return Results.NotFound();
            var rows = await db.BaselineChecks.AsNoTracking().Where(c => c.HostId == id).ToDictionaryAsync(c => c.CheckId, ct);
            var checks = BaselineCatalog.All.Select(i => CheckDto(i, rows.GetValueOrDefault(i.Id))).ToList();
            return Results.Ok(new HostBaselineDto(h.Id, h.Name, h.GroupId, h.BaselineScore, h.BaselineCheckedAt, h.BaselineRevision, checks));
        });

        g.MapGet("/baseline", async (AlastorDbContext db, CancellationToken ct) =>
        {
            var hosts = await db.Hosts.AsNoTracking().Include(h => h.Group).OrderBy(h => h.Name).ToListAsync(ct);
            var rows = await db.BaselineChecks.AsNoTracking().ToListAsync(ct);
            var byHost = rows.ToLookup(r => r.HostId);
            var byCheck = rows.ToLookup(r => r.CheckId);
            var names = hosts.ToDictionary(h => h.Id, h => h.Name);

            var hostDtos = hosts.Select(h =>
            {
                var failing = byHost[h.Id].Where(IsOpenFailure).Select(r => BaselineCatalog.Find(r.CheckId)).OfType<BaselineCheckInfo>().ToList();
                return new BaselineHostDto(h.Id, h.Name, h.GroupId, h.Group?.Name, h.IsOnline, h.BaselineScore, h.BaselineCheckedAt,
                    failing.Count, failing.Count(i => i.Severity >= Severity.High));
            }).ToList();

            var checks = BaselineCatalog.All.Select(i =>
            {
                var r = byCheck[i.Id].Where(x => names.ContainsKey(x.HostId)).ToList();
                return new BaselineFleetCheckDto(CheckDto(i, null),
                    r.Count(x => x.Status == CheckStatus.Pass),
                    r.Count(IsOpenFailure),
                    r.Count(x => x.Status == CheckStatus.Fail && x.Accepted),
                    r.Count(x => x.Status == CheckStatus.Unknown),
                    r.Count(x => x.Status == CheckStatus.NotApplicable),
                    r.Count(x => x.Enforced),
                    r.Where(IsOpenFailure).Select(x => new BaselineHostRef(x.HostId, names[x.HostId], x.Actual)).OrderBy(x => x.Name).ToList());
            }).ToList();

            var scored = hosts.Where(h => h.BaselineScore is not null).ToList();
            return new BaselineFleetDto(
                scored.Count == 0 ? null : Math.Round(scored.Average(h => h.BaselineScore!.Value), 0),
                scored.Count, hosts.Count, hostDtos, checks);
        });
    }

    /// <summary>Agent upload of one baseline run. Replaces the host's result set; the score is recomputed here, not trusted.</summary>
    private static async Task<IResult> Report(BaselineReport report, ClaimsPrincipal user, AlastorDbContext db, PolicyService policies,
        DashboardNotifier notifier, HostStateService hostState, TimeProvider time, CancellationToken ct)
    {
        var hostId = user.HostId();
        var now = time.GetUtcNow().UtcDateTime;
        var host = await db.Hosts.FirstAsync(h => h.Id == hostId, ct);
        var existing = await db.BaselineChecks.Where(c => c.HostId == hostId).ToDictionaryAsync(c => c.CheckId, ct);
        var incoming = report.Results.Where(r => BaselineCatalog.Find(r.CheckId) is not null).DistinctBy(r => r.CheckId).ToList();

        foreach (var row in existing.Values.Where(r => incoming.All(i => i.CheckId != r.CheckId))) db.BaselineChecks.Remove(row);
        foreach (var r in incoming)
        {
            if (!existing.TryGetValue(r.CheckId, out var row))
                db.BaselineChecks.Add(row = new HostBaselineCheck { HostId = hostId, CheckId = r.CheckId });
            row.FailingSince = r.Status != CheckStatus.Fail ? null : row.Status == CheckStatus.Fail && row.FailingSince is { } since ? since : now;
            row.Status = r.Status;
            row.Actual = Clip(r.Actual, 500);
            row.Detail = r.Detail is null ? null : Clip(r.Detail, 1000);
            row.Commands = r.Commands.Take(12).Select(c => Clip(c, 500)).ToList();
            row.Enforced = r.Enforced;
            row.Accepted = r.Accepted;
            row.UpdatedAt = now;
        }

        host.BaselineScore = BaselineScore.Compute(incoming);
        host.BaselineCheckedAt = report.RanAtUtc > now ? now : report.RanAtUtc;
        host.BaselineRevision = report.PolicyRevision is null ? null : Clip(report.PolicyRevision, 64);
        await db.SaveChangesAsync(ct);

        var effective = await policies.GetEffectiveAsync(hostId, ct);
        await notifier.HostUpdatedAsync(await HostEndpoints.SummaryAsync(db, hostId, effective.Revision, ct), ct);
        await notifier.BaselineUpdatedAsync(hostId, ct);
        await hostState.ChangedAsync(hostId, ct);
        return Results.NoContent();
    }

    /// <summary>A failure that counts: not accepted as a risk.</summary>
    public static bool IsOpenFailure(HostBaselineCheck c) => c.Status == CheckStatus.Fail && !c.Accepted;

    private static BaselineCheckDto CheckDto(BaselineCheckInfo i, HostBaselineCheck? r) =>
        new(i.Id, i.Title, i.Category, i.Severity, i.Why, i.Expected, i.Fix, i.Remediation, i.PolicyPath, i.PolicyValue,
            r?.Status, r?.Actual, r?.Detail, r?.Commands ?? [], r?.Enforced ?? false, r?.Accepted ?? false, r?.UpdatedAt, r?.FailingSince);

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max];
}
