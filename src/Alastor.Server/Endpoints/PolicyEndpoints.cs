using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;

namespace Alastor.Server.Endpoints;

public static class PolicyEndpoints
{
    public sealed record LayerDto(Guid Id, PolicyScope Scope, Guid? TargetId, string TargetName, int CurrentVersion, DateTime? UpdatedAt, string? UpdatedBy);
    public sealed record VersionDto(int Version, string? Comment, DateTime CreatedAt, string CreatedBy);
    public sealed record LayerDetailDto(LayerDto? Layer, string Yaml, IReadOnlyList<VersionDto> Versions);
    public sealed record SaveRequest(string Yaml, string? Comment);
    public sealed record PreviewRequest(PolicyScope Scope, Guid? TargetId, string Yaml);

    public static void MapPolicyEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/policies").WithTags("Policies").RequireAuthorization(AuthPolicies.Reader);

        g.MapGet("/", async (AlastorDbContext db, CancellationToken ct) =>
        {
            var layers = await db.PolicyLayers.AsNoTracking().ToListAsync(ct);
            var result = new List<LayerDto>();
            foreach (var l in layers.OrderBy(l => l.Scope)) result.Add(await ToDtoAsync(db, l, ct));
            return result;
        });

        // /api/policies/global, /api/policies/group/{id}, /api/policies/host/{id}
        g.MapGet("/{scope}/{targetId:guid?}", async (string scope, Guid? targetId, AlastorDbContext db, CancellationToken ct) =>
        {
            if (!TryScope(scope, targetId, out var s)) return Results.Problem("Scope must be global, group/{id} or host/{id}.", statusCode: 400);
            var layer = await db.PolicyLayers.AsNoTracking().FirstOrDefaultAsync(l => l.Scope == s && l.TargetId == targetId, ct);
            if (layer is null) return Results.Ok(new LayerDetailDto(null, "", []));
            var versions = await db.PolicyVersions.AsNoTracking().Where(v => v.LayerId == layer.Id).OrderByDescending(v => v.Version).ToListAsync(ct);
            var current = versions.FirstOrDefault(v => v.Version == layer.CurrentVersion);
            return Results.Ok(new LayerDetailDto(await ToDtoAsync(db, layer, ct), current?.Yaml ?? "",
                versions.Select(v => new VersionDto(v.Version, v.Comment, v.CreatedAt, v.CreatedBy)).ToList()));
        });

        g.MapGet("/layers/{layerId:guid}/versions/{version:int}", async (Guid layerId, int version, AlastorDbContext db, CancellationToken ct) =>
        {
            var v = await db.PolicyVersions.AsNoTracking().FirstOrDefaultAsync(x => x.LayerId == layerId && x.Version == version, ct);
            return v is null ? Results.NotFound() : Results.Ok(new { v.Version, v.Yaml, v.Comment, v.CreatedAt, v.CreatedBy });
        });

        g.MapPut("/{scope}/{targetId:guid?}", async (string scope, Guid? targetId, SaveRequest req, ClaimsPrincipal user, AlastorDbContext db,
            PolicyService policies, DashboardNotifier notifier, Services.Vulnerabilities.VulnerabilityService vulnerabilities,
            Services.Hardening.HardeningService hardening, Services.Network.NetworkService network, Services.Integrity.IntegrityService integrity, HostStateService hostState, CancellationToken ct) =>
        {
            if (!TryScope(scope, targetId, out var s)) return Results.Problem("Scope must be global, group/{id} or host/{id}.", statusCode: 400);
            if (s == PolicyScope.Group && !await db.Groups.AnyAsync(x => x.Id == targetId, ct)) return Results.NotFound();
            if (s == PolicyScope.Host && !await db.Hosts.AnyAsync(x => x.Id == targetId, ct)) return Results.NotFound();
            try
            {
                var v = await policies.SaveAsync(s, targetId, req.Yaml ?? "", req.Comment, user.Actor(), ct);
                await vulnerabilities.RefreshAcceptedAsync(s, targetId, ct);
                await hardening.RefreshAcceptedAsync(s, targetId, ct);
                await network.RefreshAsync(s, targetId, ct);
                await integrity.RefreshAsync(s, targetId, ct);
                await hostState.ChangedAsync(s == PolicyScope.Host ? [targetId!.Value] : null, ct);
                await notifier.PolicyChangedAsync(ct);
                return Results.Ok(new VersionDto(v.Version, v.Comment, v.CreatedAt, v.CreatedBy));
            }
            catch (PolicyValidationException ex)
            {
                return Results.UnprocessableEntity(new { error = "Policy is invalid.", issues = ex.Issues });
            }
            catch (DbUpdateException)
            {
                return Results.Conflict(new { error = "Someone else saved this policy at the same time. Reload and try again." });
            }
        }).RequireAuthorization(AuthPolicies.Admin);

        g.MapPost("/layers/{layerId:guid}/revert/{version:int}", async (Guid layerId, int version, ClaimsPrincipal user,
            AlastorDbContext db, PolicyService policies, DashboardNotifier notifier, Services.Vulnerabilities.VulnerabilityService vulnerabilities,
            Services.Hardening.HardeningService hardening, Services.Network.NetworkService network, Services.Integrity.IntegrityService integrity, HostStateService hostState, CancellationToken ct) =>
        {
            if (!await db.PolicyVersions.AnyAsync(v => v.LayerId == layerId && v.Version == version, ct)) return Results.NotFound();
            var v = await policies.RevertAsync(layerId, version, user.Actor(), ct);
            var layer = await db.PolicyLayers.AsNoTracking().FirstAsync(l => l.Id == layerId, ct);
            await vulnerabilities.RefreshAcceptedAsync(layer.Scope, layer.TargetId, ct);
            await hardening.RefreshAcceptedAsync(layer.Scope, layer.TargetId, ct);
            await network.RefreshAsync(layer.Scope, layer.TargetId, ct);
            await integrity.RefreshAsync(layer.Scope, layer.TargetId, ct);
            await hostState.ChangedAsync(layer.Scope == PolicyScope.Host ? [layer.TargetId!.Value] : null, ct);
            await notifier.PolicyChangedAsync(ct);
            return Results.Ok(new VersionDto(v.Version, v.Comment, v.CreatedAt, v.CreatedBy));
        }).RequireAuthorization(AuthPolicies.Admin);

        g.MapPost("/preview", async (PreviewRequest req, PolicyService policies, CancellationToken ct) =>
            await policies.PreviewAsync(req.Scope, req.TargetId, req.Yaml ?? "", ct));

        g.MapGet("/default-template", () => Results.Text(Bootstrap.DefaultPolicyYaml(), "text/yaml"));
    }

    private static bool TryScope(string scope, Guid? targetId, out PolicyScope s)
    {
        s = scope.ToLowerInvariant() switch { "global" => PolicyScope.Global, "group" => PolicyScope.Group, "host" => PolicyScope.Host, _ => (PolicyScope)(-1) };
        return s switch
        {
            PolicyScope.Global => targetId is null,
            PolicyScope.Group or PolicyScope.Host => targetId is not null,
            _ => false,
        };
    }

    private static async Task<LayerDto> ToDtoAsync(AlastorDbContext db, PolicyLayer l, CancellationToken ct)
    {
        var name = l.Scope switch
        {
            PolicyScope.Global => "All hosts",
            PolicyScope.Group => await db.Groups.Where(g => g.Id == l.TargetId).Select(g => g.Name).FirstOrDefaultAsync(ct) ?? "(deleted group)",
            _ => await db.Hosts.Where(h => h.Id == l.TargetId).Select(h => h.Name).FirstOrDefaultAsync(ct) ?? "(deleted host)",
        };
        var cur = await db.PolicyVersions.AsNoTracking().Where(v => v.LayerId == l.Id && v.Version == l.CurrentVersion)
            .Select(v => new { v.CreatedAt, v.CreatedBy }).FirstOrDefaultAsync(ct);
        return new LayerDto(l.Id, l.Scope, l.TargetId, name, l.CurrentVersion, cur?.CreatedAt, cur?.CreatedBy);
    }
}
