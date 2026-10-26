using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Alastor.Server.Auth;
using Alastor.Server.Data;

namespace Alastor.Server.Endpoints;

/// <summary>Groups, enrollment tokens, API keys and the audit log.</summary>
public static class AdminEndpoints
{
    public sealed record GroupRequest(string Name, string? Description);
    public sealed record GroupDto(Guid Id, string Name, string? Description, int HostCount);
    public sealed record CreateTokenRequest(string? Note, Guid? GroupId, List<string>? Tags, int? TtlHours);
    public sealed record TokenDto(Guid Id, string? Note, Guid? GroupId, IReadOnlyList<string> Tags, DateTime CreatedAt, DateTime ExpiresAt, DateTime? ConsumedAt, Guid? ConsumedByHostId, string CreatedBy);
    public sealed record CreatedTokenDto(TokenDto Token, string Secret, string InstallCommand);
    public sealed record CreateApiKeyRequest(string Name);
    public sealed record ServerSetting(string Group, string Key, string EnvVar, string Value, string Description);
    public sealed record ApiKeyDto(Guid Id, string Name, string Prefix, DateTime CreatedAt, DateTime? LastUsedAt, DateTime? RevokedAt, string CreatedBy);

    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var groups = app.MapGroup("/api/groups").WithTags("Groups").RequireAuthorization(AuthPolicies.Reader);
        groups.MapGet("/", async (AlastorDbContext db, CancellationToken ct) =>
            await db.Groups.OrderBy(g => g.Name)
                .Select(g => new GroupDto(g.Id, g.Name, g.Description, db.Hosts.Count(h => h.GroupId == g.Id))).ToListAsync(ct));
        groups.MapPost("/", async (GroupRequest req, ClaimsPrincipal user, AlastorDbContext db, CancellationToken ct) =>
        {
            if (req.Name is not { Length: > 0 and <= 64 }) return Results.ValidationProblem(new Dictionary<string, string[]> { ["name"] = ["1-64 characters."] });
            if (await db.Groups.AnyAsync(g => g.Name == req.Name, ct)) return Results.Conflict(new { error = "A group with this name exists." });
            var g = new HostGroup { Name = req.Name.Trim(), Description = req.Description };
            db.Groups.Add(g);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "group.create", Target = g.Name });
            await db.SaveChangesAsync(ct);
            return Results.Created($"/api/groups/{g.Id}", new GroupDto(g.Id, g.Name, g.Description, 0));
        }).RequireAuthorization(AuthPolicies.Admin);
        groups.MapPut("/{id:guid}", async (Guid id, GroupRequest req, AlastorDbContext db, CancellationToken ct) =>
        {
            var g = await db.Groups.FindAsync([id], ct);
            if (g is null) return Results.NotFound();
            if (req.Name is { Length: > 0 and <= 64 }) g.Name = req.Name.Trim();
            g.Description = req.Description;
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);
        groups.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal user, AlastorDbContext db, CancellationToken ct) =>
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
        tokens.MapGet("/", async (AlastorDbContext db, CancellationToken ct) =>
            (await db.EnrollmentTokens.OrderByDescending(t => t.CreatedAt).Take(100).ToListAsync(ct)).Select(ToDto).ToList());
        tokens.MapPost("/", async (CreateTokenRequest req, ClaimsPrincipal user, AlastorDbContext db, IOptions<AlastorOptions> opt,
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
            var insecure = baseUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ? " --insecure" : "";
            var cmd = $"curl -fsSL {baseUrl}/install/agent.sh | sudo bash -s -- --server {baseUrl} --token {secret}{insecure}";
            return Results.Ok(new CreatedTokenDto(ToDto(t), secret, cmd));
        });
        tokens.MapDelete("/{id:guid}", async (Guid id, AlastorDbContext db, CancellationToken ct) =>
        {
            var n = await db.EnrollmentTokens.Where(t => t.Id == id && t.ConsumedAt == null).ExecuteDeleteAsync(ct);
            return n == 1 ? Results.NoContent() : Results.NotFound();
        });

        var keys = app.MapGroup("/api/api-keys").WithTags("API keys").RequireAuthorization(AuthPolicies.Admin);
        keys.MapGet("/", async (AlastorDbContext db, CancellationToken ct) =>
            await db.ApiKeys.OrderByDescending(k => k.CreatedAt)
                .Select(k => new ApiKeyDto(k.Id, k.Name, k.Prefix, k.CreatedAt, k.LastUsedAt, k.RevokedAt, k.CreatedBy)).ToListAsync(ct));
        keys.MapPost("/", async (CreateApiKeyRequest req, ClaimsPrincipal user, AlastorDbContext db, CancellationToken ct) =>
        {
            if (req.Name is not { Length: > 0 and <= 64 }) return Results.ValidationProblem(new Dictionary<string, string[]> { ["name"] = ["1-64 characters."] });
            var secret = Secrets.Generate("svk_");
            var k = new ApiKey { Name = req.Name, Prefix = secret[..10], KeyHash = Secrets.Hash(secret), CreatedBy = user.Actor() };
            db.ApiKeys.Add(k);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "api-key.create", Target = k.Name });
            await db.SaveChangesAsync(ct);
            return Results.Ok(new { key = new ApiKeyDto(k.Id, k.Name, k.Prefix, k.CreatedAt, null, null, k.CreatedBy), secret });
        });
        keys.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal user, AlastorDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var k = await db.ApiKeys.FindAsync([id], ct);
            if (k is null) return Results.NotFound();
            k.RevokedAt = time.GetUtcNow().UtcDateTime;
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "api-key.revoke", Target = k.Name });
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        });

        // Read-only view of the server's own configuration (environment variables / appsettings). Secrets are
        // never returned, only whether they are set. Changing these needs a restart, so the UI doesn't edit them.
        app.MapGet("/api/system/settings", (IOptions<AlastorOptions> opt) =>
        {
            var o = opt.Value;
            ServerSetting S(string group, string key, string value, string description) =>
                new(group, key, "ALASTOR_" + key.ToUpperInvariant(), value, description);
            return new[]
            {
                S("General", nameof(o.PublicUrl), o.PublicUrl ?? "(from request)", "URL agents and browsers use; shown in install commands."),
                S("General", nameof(o.DatabaseProvider), o.DatabaseProvider, "sqlite or postgres."),
                S("General", nameof(o.DataDir), o.DataDir, "Database, signing and data-protection keys."),
                S("General", nameof(o.AgentDownloadDir), o.AgentDownloadDir, "Agent binaries served to hosts at /install/agent/."),
                S("General", nameof(o.SecureCookies), o.SecureCookies ? "true" : "false", "Secure flag on the session cookie."),
                S("Agents", nameof(o.HeartbeatInterval), o.HeartbeatInterval, "Default heartbeat when the policy sets no agent.heartbeatInterval."),
                S("Agents", nameof(o.OfflineAfterMissedHeartbeats), o.OfflineAfterMissedHeartbeats.ToString(System.Globalization.CultureInfo.InvariantCulture), "Missed heartbeats (of the host's own interval) before a host is offline."),
                S("Agents", nameof(o.PresenceCheckInterval), o.PresenceCheckInterval, "How often the server looks for silent hosts."),
                S("Agents", nameof(o.EnrollmentTokenTtl), o.EnrollmentTokenTtl, "Default lifetime of a new enrollment token."),
                S("Commands", nameof(o.CommandRedeliverAfter), o.CommandRedeliverAfter, "Re-deliver a fetched but unacknowledged command after this long."),
                S("Commands", nameof(o.CommandMaxAttempts), o.CommandMaxAttempts.ToString(System.Globalization.CultureInfo.InvariantCulture), "Delivery attempts before a command expires."),
                S("Commands", nameof(o.PendingCommandTtl), o.PendingCommandTtl, "Commands for offline hosts expire after this."),
                S("Retention", nameof(o.RetentionRunInterval), o.RetentionRunInterval, "How often old data is pruned."),
                S("Retention", nameof(o.MetricRetention), o.MetricRetention, "Keep host metrics this long."),
                S("Retention", nameof(o.EventRetention), o.EventRetention, "Keep events this long."),
                S("Security", nameof(o.SessionLifetime), o.SessionLifetime, "Dashboard session length."),
                S("Security", nameof(o.AuthRateLimitPerMinute), o.AuthRateLimitPerMinute.ToString(System.Globalization.CultureInfo.InvariantCulture), "Login and enrollment attempts per IP per minute."),
                S("Threat feed", nameof(o.ThreatFeedEnabled), o.ThreatFeedEnabled ? "true" : "false", "Fetch NVD, CISA KEV and security news."),
                S("Threat feed", nameof(o.ThreatFeedInterval), o.ThreatFeedInterval, "How often each source is fetched."),
                S("Threat feed", nameof(o.ThreatFeedRetention), o.ThreatFeedRetention, "Keep feed items this long."),
                S("Software", nameof(o.OsvEnabled), o.OsvEnabled ? "true" : "false", "Look up installed package versions on OSV.dev (names and versions only)."),
                S("Threat feed", nameof(o.NvdApiKey), string.IsNullOrEmpty(o.NvdApiKey) ? "(not set)" : "(set)", "Optional NVD API key for a higher rate limit."),
            };
        }).WithTags("Settings").RequireAuthorization(AuthPolicies.Admin);

        app.MapGet("/api/audit", async (int? limit, AlastorDbContext db, CancellationToken ct) =>
            await db.Audit.OrderByDescending(a => a.At).Take(Math.Clamp(limit ?? 100, 1, 500)).ToListAsync(ct))
            .WithTags("Audit").RequireAuthorization(AuthPolicies.Admin);
    }

    private static TokenDto ToDto(EnrollmentToken t) =>
        new(t.Id, t.Note, t.GroupId, t.Tags, t.CreatedAt, t.ExpiresAt, t.ConsumedAt, t.ConsumedByHostId, t.CreatedBy);
}
