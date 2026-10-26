using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Contracts;
using Alastor.Core.Policy;
using Alastor.Core.Storage;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;
using Alastor.Server.Services.Storage;
using ScheduleDto = Alastor.Server.Endpoints.ReportEndpoints.ScheduleDto;

namespace Alastor.Server.Endpoints;

/// <summary>
/// Disk usage per host and across the fleet, and cleanups. The dashboard names a cleanup only by its
/// <see cref="StorageCleanups"/> id; the agent measures it again and builds every command itself. Destructive
/// cleanups (unused Docker volumes) need a typed confirmation: the host's name, or <see cref="FleetConfirmation"/> for several hosts.
/// </summary>
public static class StorageEndpoints
{
    public const string FleetConfirmation = "delete";

    public sealed record CleanupRequest(string? Cleanup, string? Confirm);
    public sealed record FleetCleanupRequest(string? Cleanup, List<Guid>? HostIds, string? Confirm);

    public static void MapStorageEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api").WithTags("Storage").RequireAuthorization(AuthPolicies.Reader);

        g.MapGet("/hosts/{id:guid}/storage", async (Guid id, StorageService storage, PolicyService policies, CancellationToken ct) =>
        {
            var eff = await policies.GetEffectiveAsync(id, ct);
            var schedules = ScheduleDefaults.Resolve(eff.Document).Where(s => s.Path == "storage.scanSchedule")
                .Select(s => new ScheduleDto(s.Path, s.Value, s.IsDefault)).ToList();
            return await storage.HostAsync(id, schedules, ct) is { } dto ? Results.Ok(dto) : Results.NotFound();
        });

        g.MapGet("/storage", async (StorageService storage, CancellationToken ct) => await storage.FleetAsync(ct));

        g.MapPost("/hosts/{id:guid}/storage/cleanup", async (Guid id, CleanupRequest req, AlastorDbContext db, StorageService storage, CommandService commands,
            ClaimsPrincipal user, CancellationToken ct) =>
        {
            if (StorageCleanups.Find(req.Cleanup) is not { } cleanup) return Results.Problem($"Unknown cleanup '{req.Cleanup}'.", statusCode: 400);
            var host = await db.Hosts.AsNoTracking().FirstOrDefaultAsync(h => h.Id == id, ct);
            if (host is null) return Results.NotFound();
            if (await CheckAsync(storage, id, cleanup, ct) is { } problem) return Results.Problem(problem, statusCode: 400);
            if (cleanup.Risk == CleanupRisk.Destructive && !string.Equals(req.Confirm?.Trim(), host.Name, StringComparison.OrdinalIgnoreCase))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["confirm"] = [$"Type the host name ({host.Name}) to confirm: this deletes data for good."] });
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "storage.cleanup", Target = id.ToString(), Details = cleanup.Id });
            var cmds = await commands.QueueAsync([id], AgentCommandTypes.StorageCleanup, new() { ["cleanup"] = cleanup.Id }, user.Actor(), ct);
            return Results.Accepted(value: Dto.Command(cmds[0]));
        }).RequireAuthorization(AuthPolicies.Admin);

        // The same cleanup on several hosts: one command per host it applies to. Hosts where it doesn't apply are skipped.
        g.MapPost("/storage/cleanup", async (FleetCleanupRequest req, AlastorDbContext db, StorageService storage, CommandService commands,
            ClaimsPrincipal user, CancellationToken ct) =>
        {
            if (StorageCleanups.Find(req.Cleanup) is not { } cleanup) return Results.Problem($"Unknown cleanup '{req.Cleanup}'.", statusCode: 400);
            if (cleanup.Risk == CleanupRisk.Destructive && !string.Equals(req.Confirm?.Trim(), FleetConfirmation, StringComparison.OrdinalIgnoreCase))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["confirm"] = [$"Type \"{FleetConfirmation}\" to confirm: this deletes data for good on every selected host."] });
            var wanted = req.HostIds ?? [];
            var known = await db.Hosts.Where(h => wanted.Contains(h.Id)).Select(h => h.Id).ToListAsync(ct);
            var ids = new List<Guid>();
            foreach (var hostId in known)
                if (await CheckAsync(storage, hostId, cleanup, ct) is null) ids.Add(hostId);
            if (ids.Count == 0) return Results.ValidationProblem(new Dictionary<string, string[]> { ["hostIds"] = [$"{cleanup.Title} doesn't apply to any of the selected hosts."] });
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "storage.cleanup", Target = string.Join(",", ids), Details = $"{cleanup.Id} on {ids.Count} host(s)" });
            var cmds = await commands.QueueAsync(ids, AgentCommandTypes.StorageCleanup, new() { ["cleanup"] = cleanup.Id }, user.Actor(), ct);
            return Results.Accepted(value: cmds.Select(Dto.Command).ToList());
        }).RequireAuthorization(AuthPolicies.Admin);
    }

    /// <summary>The host's latest scan must list the cleanup, and the agent must not have refused it there.</summary>
    private static async Task<string?> CheckAsync(StorageService storage, Guid hostId, CleanupDefinition cleanup, CancellationToken ct)
    {
        var report = await storage.ReportAsync(hostId, ct);
        if (report is null) return "This host hasn't reported its disk usage yet. Run a storage scan first.";
        var candidate = report.Cleanups.FirstOrDefault(c => c.Id == cleanup.Id);
        if (candidate is null) return $"{cleanup.Title} doesn't apply to this host.";
        return candidate.Blocked;
    }
}
