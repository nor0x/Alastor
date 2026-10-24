using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sentinel.Server.Auth;
using Sentinel.Server.Data;

namespace Sentinel.Server.Endpoints;

/// <summary>Groups, enrollment tokens, API keys and the audit log.</summary>
public static class AdminEndpoints
{
    public sealed record GroupRequest(string Name, string? Description);
    public sealed record GroupDto(Guid Id, string Name, string? Description, int HostCount);
    public sealed record CreateTokenRequest(string? Note, Guid? GroupId, List<string>? Tags, int? TtlHours);
    public sealed record TokenDto(Guid Id, string? Note, Guid? GroupId, IReadOnlyList<string> Tags, DateTime CreatedAt, DateTime ExpiresAt, DateTime? ConsumedAt, Guid? ConsumedByHostId, string CreatedBy);
    public sealed record CreatedTokenDto(TokenDto Token, string Secret, string InstallCommand);
    public sealed record CreateApiKeyRequest(string Name);
    public sealed record ApiKeyDto(Guid Id, string Name, string Prefix, DateTime CreatedAt, DateTime? LastUsedAt, DateTime? RevokedAt, string CreatedBy);

    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var groups = app.MapGroup("/api/groups").WithTags("Groups").RequireAuthorization(AuthPolicies.Reader);
        groups.MapGet("/", async (SentinelDbContext db, CancellationToken ct) =>
            await db.Groups.OrderBy(g => g.Name)
                .Select(g => new GroupDto(g.Id, g.Name, g.Description, db.Hosts.Count(h => h.GroupId == g.Id))).ToListAsync(ct));
        groups.MapPost("/", async (GroupRequest req, ClaimsPrincipal user, SentinelDbContext db, CancellationToken ct) =>
        {
            if (req.Name is not { Length: > 0 and <= 64 }) return Results.ValidationProblem(new Dictionary<string, string[]> { ["name"] = ["1-64 characters."] });
            if (await db.Groups.AnyAsync(g => g.Name == req.Name, ct)) return Results.Conflict(new { error = "A group with this name exists." });
            var g = new HostGroup { Name = req.Name.Trim(), Description = req.Description };
            db.Groups.Add(g);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "group.create", Target = g.Name });
            await db.SaveChangesAsync(ct);
            return Results.Created($"/api/groups/{g.Id}", new GroupDto(g.Id, g.Name, g.Description, 0));
        }).RequireAuthorization(AuthPolicies.Admin);
        groups.MapPut("/{id:guid}", async (Guid id, GroupRequest req, SentinelDbContext db, CancellationToken ct) =>
        {
            var g = await db.Groups.FindAsync([id], ct);
            if (g is null) return Results.NotFound();
            if (req.Name is { Length: > 0 and <= 64 }) g.Name = req.Name.Trim();
            g.Description = req.Description;
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);
        groups.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal user, SentinelDbContext db, CancellationToken ct) =>
        {
            var g = await db.Groups.FindAsync([id], ct);
            if (g is null) return Results.NotFound();
            db.Groups.Remove(g);
            var layer = await db.PolicyLayers.FirstOrDefaultAsync(l => l.Scope == PolicyScope.Group && l.TargetId == id, ct);
            if (layer is not null) db.PolicyLayers.Remove(layer);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "group.delete", Target = g.Name });
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);

        var tokens = app.MapGroup("/api/enrollment-tokens").WithTags("Enrollment").RequireAuthorization(AuthPolicies.Admin);
        tokens.MapGet("/", async (SentinelDbContext db, CancellationToken ct) =>
            (await db.EnrollmentTokens.OrderByDescending(t => t.CreatedAt).Take(100).ToListAsync(ct)).Select(ToDto).ToList());
        tokens.MapPost("/", async (CreateTokenRequest req, ClaimsPrincipal user, SentinelDbContext db, IOptions<SentinelOptions> opt,
            HttpContext http, TimeProvider time, CancellationToken ct) =>
        {
            var secret = Secrets.Generate("sve_");
            var now = time.GetUtcNow().UtcDateTime;
            var t = new EnrollmentToken
            {
                TokenHash = Secrets.Hash(secret),
                Note = req.Note,
                GroupId = req.GroupId,
                Tags = req.Tags ?? [],
                CreatedAt = now,
                ExpiresAt = now + (req.TtlHours is { } h ? TimeSpan.FromHours(Math.Clamp(h, 1, 24 * 30)) : opt.Value.EnrollmentTokenTtlValue),
                CreatedBy = user.Actor(),
            };
            db.EnrollmentTokens.Add(t);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "enrollment-token.create", Target = t.Id.ToString(), Details = req.Note });
            await db.SaveChangesAsync(ct);
            var baseUrl = (opt.Value.PublicUrl ?? $"{http.Request.Scheme}://{http.Request.Host}").TrimEnd('/');
            var cmd = $"curl -fsSL {baseUrl}/install/agent.sh | sudo bash -s -- --server {baseUrl} --token {secret}";
            return Results.Ok(new CreatedTokenDto(ToDto(t), secret, cmd));
        });
        tokens.MapDelete("/{id:guid}", async (Guid id, SentinelDbContext db, CancellationToken ct) =>
        {
            var n = await db.EnrollmentTokens.Where(t => t.Id == id && t.ConsumedAt == null).ExecuteDeleteAsync(ct);
            return n == 1 ? Results.NoContent() : Results.NotFound();
        });

        var keys = app.MapGroup("/api/api-keys").WithTags("API keys").RequireAuthorization(AuthPolicies.Admin);
        keys.MapGet("/", async (SentinelDbContext db, CancellationToken ct) =>
            await db.ApiKeys.OrderByDescending(k => k.CreatedAt)
                .Select(k => new ApiKeyDto(k.Id, k.Name, k.Prefix, k.CreatedAt, k.LastUsedAt, k.RevokedAt, k.CreatedBy)).ToListAsync(ct));
        keys.MapPost("/", async (CreateApiKeyRequest req, ClaimsPrincipal user, SentinelDbContext db, CancellationToken ct) =>
        {
            if (req.Name is not { Length: > 0 and <= 64 }) return Results.ValidationProblem(new Dictionary<string, string[]> { ["name"] = ["1-64 characters."] });
            var secret = Secrets.Generate("svk_");
            var k = new ApiKey { Name = req.Name, Prefix = secret[..10], KeyHash = Secrets.Hash(secret), CreatedBy = user.Actor() };
            db.ApiKeys.Add(k);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "api-key.create", Target = k.Name });
            await db.SaveChangesAsync(ct);
            return Results.Ok(new { key = new ApiKeyDto(k.Id, k.Name, k.Prefix, k.CreatedAt, null, null, k.CreatedBy), secret });
        });
        keys.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal user, SentinelDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var k = await db.ApiKeys.FindAsync([id], ct);
            if (k is null) return Results.NotFound();
            k.RevokedAt = time.GetUtcNow().UtcDateTime;
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "api-key.revoke", Target = k.Name });
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        });

        app.MapGet("/api/audit", async (int? limit, SentinelDbContext db, CancellationToken ct) =>
            await db.Audit.OrderByDescending(a => a.At).Take(Math.Clamp(limit ?? 100, 1, 500)).ToListAsync(ct))
            .WithTags("Audit").RequireAuthorization(AuthPolicies.Admin);
    }

    private static TokenDto ToDto(EnrollmentToken t) =>
        new(t.Id, t.Note, t.GroupId, t.Tags, t.CreatedAt, t.ExpiresAt, t.ConsumedAt, t.ConsumedByHostId, t.CreatedBy);
}
