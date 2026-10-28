using System.Security.Claims;
using Alastor.Core.Logging;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;
using Alastor.Server.Services.Security;
using Alastor.Server.Services.Storage;

namespace Alastor.Server.Endpoints;

/// <summary>
/// The server looking at itself: the security self-check, the data it keeps (sizes, retention, compaction), and the
/// Alastor services on its own machine.
/// </summary>
public static class SystemEndpoints
{
    public sealed record CleanupResultDto(bool Ok, string? Error, long FreedBytes);

    public const int ServerLogLines = 2000;

    public static void MapSystemEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/system").WithTags("Settings").RequireAuthorization(AuthPolicies.Admin);

        g.MapGet("/security", (SelfCheckService checks, CancellationToken ct) => checks.RunAsync(ct));

        g.MapGet("/data", (ServerDataService data, CancellationToken ct) => data.OverviewAsync(ct));

        // The server's own log since it started, newest first. Older lines are in the journal (journalctl -u alastor-server).
        g.MapGet("/logs", (LogBuffer logs, int? limit) =>
            logs.Latest(Math.Clamp(limit ?? 500, 1, ServerLogLines)).Reverse()
                .Select(l => new HostEndpoints.LogLineDto(l.Seq, l.At, l.Level, l.Source, l.Message)).ToList());

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

        // This machine: the server and agent services here, started and stopped through the installer's control unit.
        g.MapGet("/machine", (LocalMachineService machine, AlastorDbContext db, CancellationToken ct) => machine.GetAsync(db, ct));

        g.MapPost("/machine/{target}/{action}", async (string target, string action, LocalMachineService machine, AlastorDbContext db,
            ClaimsPrincipal user, HttpContext http, CancellationToken ct) =>
        {
            var request = $"{target} {action}";
            if (!LocalMachineService.Requests.Contains(request)) return Results.NotFound();
            if (!machine.Controllable)
                return Results.Conflict(new { error = "Start and stop from the dashboard need the systemd install (install.sh). Use systemctl or docker on the machine." });
            if (!LocalMachineService.IsInstalled(target)) return Results.Conflict(new { error = $"The Alastor {target} is not installed on this machine." });
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = $"machine.{target}.{action}", Target = Environment.MachineName });
            await db.SaveChangesAsync(ct);
            // Stopping or restarting the server ends this process, so the answer goes out first.
            if (target == "server") http.Response.OnCompleted(() => machine.RequestAsync(request));
            else await machine.RequestAsync(request);
            return Results.NoContent();
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
