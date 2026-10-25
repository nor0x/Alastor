using System.Net;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Contracts;
using Alastor.Core.Net;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;

namespace Alastor.Server.Endpoints;

public static class BanEndpoints
{
    /// <summary><paramref name="HostIds"/> null or empty means every host.</summary>
    public sealed record BanRequest(string Target, List<Guid>? HostIds, string? Reason);
    public sealed record UnbanRequest(string Target, List<Guid>? HostIds);
    public sealed record AllowlistRequest(string Target, string? Note);
    public sealed record AllowlistDto(Guid Id, string Target, string? Note, DateTime CreatedAt, string CreatedBy);
    public sealed record BanCommandsResponse(string Target, IReadOnlyList<CommandDto> Commands);

    public static void MapBanEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/bans").WithTags("Bans").RequireAuthorization(AuthPolicies.Reader);

        g.MapGet("/", async (Guid? hostId, string? q, bool? manual, AlastorDbContext db, CancellationToken ct) =>
        {
            var query = db.Bans.AsNoTracking().AsQueryable();
            if (hostId is { } h) query = query.Where(b => b.HostId == h);
            if (!string.IsNullOrWhiteSpace(q)) query = query.Where(b => b.Target.Contains(q) || b.Scope.Contains(q));
            if (manual is { } m) query = query.Where(b => b.Manual == m);
            return await query
                .OrderByDescending(b => b.BannedAt).Take(2000)
                .Join(db.Hosts, b => b.HostId, h => h.Id, (b, h) => new BanDto(b.Id, b.HostId, h.Name, b.ToolId, b.Target, b.Scope, b.BannedAt, b.ExpiresAt, b.Manual))
                .ToListAsync(ct);
        });

        g.MapPost("/", async (BanRequest req, ClaimsPrincipal user, HttpContext http, AlastorDbContext db, CommandService commands, CancellationToken ct) =>
        {
            if (!IpTarget.TryParse(req.Target, out var target))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["target"] = ["Not an IP address or CIDR."] });
            var t = target.Value;
            if (t.Network.PrefixLength < (t.Network.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 8 : 32))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["target"] = ["Refusing to ban a network larger than /8 (IPv4) or /32 (IPv6)."] });

            // Never ban the operator's own connection: the most common way to lock yourself out.
            if (http.Connection.RemoteIpAddress is { } self && IpTarget.TryParse(self.IsIPv4MappedToIPv6 ? self.MapToIPv4().ToString() : self.ToString(), out var selfT)
                && !IPAddress.IsLoopback(self) && t.Overlaps(selfT.Value))
                return Results.Conflict(new { error = $"{t} includes your own address ({selfT}). Refusing to lock you out." });

            foreach (var a in await db.Allowlist.Select(a => a.Target).ToListAsync(ct))
                if (IpTarget.TryParse(a, out var at) && at.Value.Overlaps(t))
                    return Results.Conflict(new { error = $"{t} overlaps allowlisted {a}. Remove it from the allowlist first." });

            var hosts = await ResolveHostsAsync(db, req.HostIds, ct);
            if (hosts.Count == 0) return Results.Problem("No matching hosts.", statusCode: 400);
            var payload = new Dictionary<string, string> { ["target"] = t.ToString() };
            if (!string.IsNullOrWhiteSpace(req.Reason)) payload["reason"] = req.Reason.Length > 200 ? req.Reason[..200] : req.Reason;
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "ban.create", Target = t.ToString(), Details = $"{hosts.Count} host(s): {req.Reason}" });
            var cmds = await commands.QueueAsync(hosts, AgentCommandTypes.Ban, payload, user.Actor(), ct);
            return Results.Accepted(value: new BanCommandsResponse(t.ToString(), cmds.Select(Dto.Command).ToList()));
        }).RequireAuthorization(AuthPolicies.Admin);

        g.MapPost("/unban", async (UnbanRequest req, ClaimsPrincipal user, AlastorDbContext db, CommandService commands, CancellationToken ct) =>
        {
            if (!IpTarget.TryParse(req.Target, out var target))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["target"] = ["Not an IP address or CIDR."] });
            var t = target.Value.ToString();
            List<Guid> hosts;
            if (req.HostIds is { Count: > 0 }) hosts = await ResolveHostsAsync(db, req.HostIds, ct);
            else
            {
                // "Unban everywhere": only the hosts where it is actually banned, plus online hosts in case a snapshot is stale.
                hosts = await db.Bans.Where(b => b.Target == t).Select(b => b.HostId).Distinct().ToListAsync(ct);
                hosts.AddRange(await db.Hosts.Where(h => h.IsOnline).Select(h => h.Id).ToListAsync(ct));
            }
            if (hosts.Count == 0) return Results.Problem("No matching hosts.", statusCode: 400);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "ban.remove", Target = t, Details = $"{hosts.Distinct().Count()} host(s)" });
            var cmds = await commands.QueueAsync(hosts, AgentCommandTypes.Unban, new() { ["target"] = t }, user.Actor(), ct);
            return Results.Accepted(value: new BanCommandsResponse(t, cmds.Select(Dto.Command).ToList()));
        }).RequireAuthorization(AuthPolicies.Admin);

        var allow = app.MapGroup("/api/allowlist").WithTags("Bans").RequireAuthorization(AuthPolicies.Reader);
        allow.MapGet("/", async (AlastorDbContext db, CancellationToken ct) =>
            await db.Allowlist.OrderBy(a => a.Target).Select(a => new AllowlistDto(a.Id, a.Target, a.Note, a.CreatedAt, a.CreatedBy)).ToListAsync(ct));

        allow.MapPost("/", async (AllowlistRequest req, ClaimsPrincipal user, AlastorDbContext db, CommandService commands, DashboardNotifier notifier, CancellationToken ct) =>
        {
            if (!IpTarget.TryParse(req.Target, out var target))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["target"] = ["Not an IP address or CIDR."] });
            var t = target.Value.ToString();
            if (await db.Allowlist.AnyAsync(a => a.Target == t, ct)) return Results.Conflict(new { error = $"{t} is already allowlisted." });
            var entry = new AllowlistEntry { Target = t, Note = req.Note, CreatedBy = user.Actor() };
            db.Allowlist.Add(entry);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "allowlist.add", Target = t, Details = req.Note });
            await db.SaveChangesAsync(ct);

            // The allowlist is part of the effective policy (fail2ban ignoreip), so every agent reconciles.
            // Also lift existing bans covered by the new entry.
            var covered = (await db.Bans.Select(b => new { b.HostId, b.Target }).ToListAsync(ct))
                .Where(b => IpTarget.TryParse(b.Target, out var bt) && bt.Value.Overlaps(target.Value)).ToList();
            foreach (var grp in covered.GroupBy(c => c.Target))
                await commands.QueueAsync(grp.Select(x => x.HostId), AgentCommandTypes.Unban, new() { ["target"] = grp.Key }, user.Actor(), ct);
            await commands.WakeAllAsync("policy", ct);
            await notifier.PolicyChangedAsync(ct);
            return Results.Created($"/api/allowlist/{entry.Id}", new AllowlistDto(entry.Id, entry.Target, entry.Note, entry.CreatedAt, entry.CreatedBy));
        }).RequireAuthorization(AuthPolicies.Admin);

        allow.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal user, AlastorDbContext db, CommandService commands, DashboardNotifier notifier, CancellationToken ct) =>
        {
            var entry = await db.Allowlist.FindAsync([id], ct);
            if (entry is null) return Results.NotFound();
            db.Allowlist.Remove(entry);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "allowlist.remove", Target = entry.Target });
            await db.SaveChangesAsync(ct);
            await commands.WakeAllAsync("policy", ct);
            await notifier.PolicyChangedAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);
    }

    private static async Task<List<Guid>> ResolveHostsAsync(AlastorDbContext db, List<Guid>? ids, CancellationToken ct) =>
        ids is { Count: > 0 }
            ? await db.Hosts.Where(h => ids.Contains(h.Id)).Select(h => h.Id).ToListAsync(ct)
            : await db.Hosts.Select(h => h.Id).ToListAsync(ct);
}
