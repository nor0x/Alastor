using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Contracts;
using Alastor.Core.Policy;
using Alastor.Core.Software;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;
using Alastor.Server.Services.Software;
using ScheduleDto = Alastor.Server.Endpoints.ReportEndpoints.ScheduleDto;

namespace Alastor.Server.Endpoints;

/// <summary>
/// The installed-software views (per host and fleet-wide) and single-package upgrades and uninstalls. Every change is
/// previewed first: the dashboard asks the agent for a dry run (<c>package-plan</c>), shows it next to the command to run
/// by hand, and only then queues the change (<c>package-action</c>). The agent re-checks protection itself.
/// </summary>
public static class SoftwareEndpoints
{
    public sealed record PlanRequest(string? Op, string? Package);
    public sealed record PackageRequest(string? Package);
    public sealed record BulkUpgradeRequest(string? Package, List<Guid>? HostIds);
    public sealed record PlanResultDto(Guid CommandId, CommandStatus Status, string? Message, PackagePlan? Plan);

    public static void MapSoftwareEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api").WithTags("Software").RequireAuthorization(AuthPolicies.Reader);

        g.MapGet("/hosts/{id:guid}/software", async (Guid id, SoftwareService software, PolicyService policies, CancellationToken ct) =>
        {
            var eff = await policies.GetEffectiveAsync(id, ct);
            var schedules = ScheduleDefaults.Resolve(eff.Document).Where(s => s.Path == "updates.inventorySchedule")
                .Select(s => new ScheduleDto(s.Path, s.Value, s.IsDefault)).ToList();
            return await software.HostAsync(id, schedules, ct) is { } dto ? Results.Ok(dto) : Results.NotFound();
        });

        g.MapGet("/software", async (bool? all, SoftwareService software, CancellationToken ct) => await software.FleetAsync(all == true, ct));

        g.MapGet("/software/{name}/hosts", async (string name, SoftwareService software, CancellationToken ct) =>
            PackageOps.IsValidName(name) ? Results.Ok(await software.PackageHostsAsync(name, ct)) : Results.Problem("Invalid package name.", statusCode: 400));

        g.MapPost("/hosts/{id:guid}/software/plan", async (Guid id, PlanRequest req, AlastorDbContext db, CommandService commands, ClaimsPrincipal user, CancellationToken ct) =>
        {
            if (await ValidateAsync(db, id, req.Op, req.Package, ct) is { } problem) return problem;
            var cmds = await commands.QueueAsync([id], AgentCommandTypes.PackagePlan, new() { ["op"] = req.Op!, ["package"] = req.Package! }, user.Actor(), ct);
            return Results.Accepted(value: Dto.Command(cmds[0]));
        }).RequireAuthorization(AuthPolicies.Admin);

        g.MapGet("/hosts/{id:guid}/software/plan/{commandId:guid}", async (Guid id, Guid commandId, AlastorDbContext db, CancellationToken ct) =>
        {
            var cmd = await db.Commands.AsNoTracking().FirstOrDefaultAsync(c => c.Id == commandId && c.HostId == id && c.Type == AgentCommandTypes.PackagePlan, ct);
            if (cmd is null) return Results.NotFound();
            PackagePlan? plan = null;
            try { plan = cmd.ResultDetail is null ? null : JsonSerializer.Deserialize(cmd.ResultDetail, AgentJsonContext.Default.PackagePlan); }
            catch (JsonException) { }
            return Results.Ok(new PlanResultDto(cmd.Id, cmd.Status, cmd.ResultMessage, plan));
        });

        g.MapPost("/hosts/{id:guid}/software/{op}", async (Guid id, string op, PackageRequest req, AlastorDbContext db, CommandService commands, ClaimsPrincipal user, CancellationToken ct) =>
        {
            if (await ValidateAsync(db, id, op, req.Package, ct) is { } problem) return problem;
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = $"software.{op}", Target = id.ToString(), Details = req.Package });
            var cmds = await commands.QueueAsync([id], AgentCommandTypes.PackageAction, new() { ["op"] = op, ["package"] = req.Package! }, user.Actor(), ct);
            return Results.Accepted(value: Dto.Command(cmds[0]));
        }).RequireAuthorization(AuthPolicies.Admin);

        // Upgrade one package on several hosts: one command per host that has it. There is no bulk uninstall.
        g.MapPost("/software/upgrade", async (BulkUpgradeRequest req, AlastorDbContext db, CommandService commands, ClaimsPrincipal user, CancellationToken ct) =>
        {
            if (!PackageOps.IsValidName(req.Package)) return Results.Problem("Invalid package name.", statusCode: 400);
            var wanted = req.HostIds ?? [];
            var ids = await db.Packages.Where(p => p.Name == req.Package && wanted.Contains(p.HostId)).Select(p => p.HostId).Distinct().ToListAsync(ct);
            if (ids.Count == 0) return Results.ValidationProblem(new Dictionary<string, string[]> { ["hostIds"] = [$"None of the selected hosts has {req.Package} installed."] });
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "software.upgrade", Target = string.Join(",", ids), Details = $"{req.Package} on {ids.Count} host(s)" });
            var cmds = await commands.QueueAsync(ids, AgentCommandTypes.PackageAction, new() { ["op"] = PackageOps.Upgrade, ["package"] = req.Package! }, user.Actor(), ct);
            return Results.Accepted(value: cmds.Select(Dto.Command).ToList());
        }).RequireAuthorization(AuthPolicies.Admin);
    }

    /// <summary>The package must be in the host's latest inventory, and a protected one can't be removed.</summary>
    private static async Task<IResult?> ValidateAsync(AlastorDbContext db, Guid hostId, string? op, string? package, CancellationToken ct)
    {
        if (!PackageOps.IsValid(op)) return Results.Problem($"Unknown operation '{op}'. Use upgrade or remove.", statusCode: 400);
        if (!PackageOps.IsValidName(package)) return Results.Problem("Invalid package name.", statusCode: 400);
        if (!await db.Hosts.AnyAsync(h => h.Id == hostId, ct)) return Results.NotFound();
        var pkg = await db.Packages.AsNoTracking().FirstOrDefaultAsync(p => p.HostId == hostId && p.Name == package, ct);
        if (pkg is null) return Results.Problem($"{package} isn't in this host's software inventory. Refresh the inventory if it was just installed.", statusCode: 400);
        if (op == PackageOps.Remove && (pkg.Protected || ProtectedPackages.IsProtected(package!)))
            return Results.Problem($"{package} is protected: removing it could leave the host unbootable or unreachable.", statusCode: 400);
        return null;
    }
}
