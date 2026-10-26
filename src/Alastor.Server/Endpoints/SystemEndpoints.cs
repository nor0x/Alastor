using System.Security.Claims;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services.Security;
using Alastor.Server.Services.Storage;

namespace Alastor.Server.Endpoints;

/// <summary>The server looking at itself: the security self-check, and the data it keeps (sizes, retention, compaction).</summary>
public static class SystemEndpoints
{
    public sealed record CleanupResultDto(bool Ok, string? Error, long FreedBytes);

    public static void MapSystemEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/system").WithTags("Settings").RequireAuthorization(AuthPolicies.Admin);

        g.MapGet("/security", (SelfCheckService checks, CancellationToken ct) => checks.RunAsync(ct));

        g.MapGet("/data", (ServerDataService data, CancellationToken ct) => data.OverviewAsync(ct));

        g.MapPost("/data/prune", async (ServerDataService data, AlastorDbContext db, ClaimsPrincipal user, CancellationToken ct) =>
        {
            var result = await data.PruneAsync(force: true, ct);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "data.prune", Details = string.Join(", ", result.Removed.Select(r => $"{r.Value} {r.Key}")) });
            await db.SaveChangesAsync(ct);
            return result;
        });

        g.MapPost("/data/compact", async (ServerDataService data, AlastorDbContext db, ClaimsPrincipal user, CancellationToken ct) =>
        {
            var (ok, error, freed) = await data.CompactAsync(ct);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "data.compact", Details = ok ? $"{freed} bytes freed" : error });
            await db.SaveChangesAsync(ct);
            return ok ? Results.Ok(new CleanupResultDto(true, null, freed)) : Results.Conflict(new CleanupResultDto(false, error, 0));
        });

        g.MapPost("/data/cleanup/{id}", async (string id, ServerDataService data, AlastorDbContext db, ClaimsPrincipal user, CancellationToken ct) =>
        {
            var (ok, error, freed) = await data.CleanupAsync(id, ct);
            if (!ok) return Results.NotFound(new CleanupResultDto(false, error, 0));
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "data.cleanup", Target = id, Details = $"{freed} bytes freed" });
            await db.SaveChangesAsync(ct);
            return Results.Ok(new CleanupResultDto(true, null, freed));
        });
    }
}
