using System.IO.Compression;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Blocklists;
using Alastor.Core.Contracts;
using Alastor.Core.Net;
using Alastor.Core.Policy;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;
using Alastor.Server.Services.Blocklists;

namespace Alastor.Server.Endpoints;

/// <summary>Public IP blocklists: per-host merged sets for agents, and list health, usage and lookups for the dashboard.</summary>
public static class BlocklistEndpoints
{
    public sealed record ListDto(
        string Id,
        string Name,
        string Homepage,
        string Description,
        string Terms,
        IReadOnlyList<string> UsedBy,
        int Entries,
        long Ipv4Addresses,
        int Skipped,
        DateTime? LastSuccessAt,
        DateTime? LastChangedAt,
        DateTime? LastAttemptAt,
        DateTime? NextAttemptAt,
        string? LastError);

    public sealed record HostBlocklistDto(Guid HostId, string Name, bool Online, bool Wanted, bool Active, string? Backend, string? Entries, string? Lists,
        long? Dropped, string? ConfigState, string? LastError, DateTime? LastAppliedAt);

    public sealed record OverviewDto(bool FetchingEnabled, string RefreshInterval, IReadOnlyList<ListDto> Lists, IReadOnlyList<HostBlocklistDto> Hosts);

    public sealed record LookupDto(string Target, bool Reserved, bool Allowlisted, IReadOnlyList<string> Lists, IReadOnlyList<string> Extra);

    public static void MapBlocklistEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/agent/blocklist", AgentBlocklist).WithTags("Agent").RequireAuthorization(AuthPolicies.Agent);

        var g = app.MapGroup("/api/blocklists").WithTags("Blocklists").RequireAuthorization(AuthPolicies.Reader);

        g.MapGet("", async (AlastorDbContext db, PolicyService policies, Microsoft.Extensions.Options.IOptions<AlastorOptions> opt, CancellationToken ct) =>
        {
            var states = await db.BlocklistSources.AsNoTracking()
                .Select(s => new { s.SourceId, s.EntryCount, s.Ipv4Addresses, s.Skipped, s.LastSuccessAt, s.LastChangedAt, s.LastAttemptAt, s.NextAttemptAt, s.LastError })
                .ToDictionaryAsync(s => s.SourceId, ct);
            var usage = await UsageAsync(db, ct);
            var lists = BlocklistCatalog.All.Select(src =>
            {
                var s = states.GetValueOrDefault(src.Id);
                return new ListDto(src.Id, src.Name, src.Homepage, src.Description, src.Terms, usage.GetValueOrDefault(src.Id) ?? [],
                    s?.EntryCount ?? 0, s?.Ipv4Addresses ?? 0, s?.Skipped ?? 0, s?.LastSuccessAt, s?.LastChangedAt, s?.LastAttemptAt, s?.NextAttemptAt, s?.LastError);
            }).ToList();

            var hosts = await db.Hosts.AsNoTracking().OrderBy(h => h.Name).Select(h => new { h.Id, h.Name, h.IsOnline, h.GroupId }).ToListAsync(ct);
            var statuses = await db.ToolStatuses.AsNoTracking().Where(t => t.ToolId == BlocklistIntegration.Info.Id).ToDictionaryAsync(t => t.HostId, ct);
            var hostDtos = new List<HostBlocklistDto>();
            foreach (var h in hosts)
            {
                var eff = await policies.ComputeAsync(h.GroupId, h.Id, ct);
                var t = statuses.GetValueOrDefault(h.Id);
                hostDtos.Add(new HostBlocklistDto(h.Id, h.Name, h.IsOnline, eff.Document.Blocklists?.Enabled == true, t?.Running ?? false,
                    t?.Details.GetValueOrDefault("backend"), t?.Details.GetValueOrDefault("entries"), t?.Details.GetValueOrDefault("lists"),
                    long.TryParse(t?.Details.GetValueOrDefault("dropped"), out var d) ? d : null, t?.ConfigState.ToString(), t?.LastError, t?.LastSuccessAt));
            }
            return new OverviewDto(opt.Value.BlocklistsEnabled, opt.Value.BlocklistRefreshInterval, lists, hostDtos);
        });

        g.MapPost("/{id}/refresh", async (string id, ClaimsPrincipal user, BlocklistService service, AlastorDbContext db, CancellationToken ct) =>
        {
            if (BlocklistCatalog.Find(id) is not { } source) return Results.NotFound();
            var s = await service.RefreshAsync(source, ct);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "blocklist.refresh", Target = id, Details = s.LastError ?? $"{s.EntryCount} entries" });
            await db.SaveChangesAsync(ct);
            return Results.Ok(new { success = s.LastError is null, error = s.LastError, entries = s.EntryCount });
        }).RequireAuthorization(AuthPolicies.Admin);

        // Which lists contain an address, and whether the allowlist or the reserved ranges would exempt it anyway.
        g.MapGet("/lookup", async (string ip, AlastorDbContext db, PolicyService policies, CancellationToken ct) =>
        {
            if (!IpTarget.TryParse(ip, out var target) || !target.Value.IsSingleAddress)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["ip"] = ["Enter a single IPv4 or IPv6 address."] });
            var address = target.Value.Network.BaseAddress;
            var global = await policies.ComputeAsync(null, null, ct);
            var allow = IpRangeSet.From((global.Document.Banning?.Allowlist ?? []).Select(a => IpTarget.TryParse(a, out var t) ? t : null).OfType<IpTarget>());
            var hits = new List<string>();
            foreach (var row in await db.BlocklistSources.AsNoTracking().Where(s => s.ContentHash != null).Select(s => new { s.SourceId, s.Content }).ToListAsync(ct))
            {
                var set = IpRangeSet.From(row.Content.Split('\n').Select(l => IpTarget.TryParse(l, out var t) ? t : null).OfType<IpTarget>());
                if (set.Contains(address)) hits.Add(row.SourceId);
            }
            var extra = (global.Document.Blocklists?.Extra ?? []).Where(e => IpTarget.TryParse(e, out var t) && IpRangeSet.From([t.Value]).Contains(address)).ToList();
            return Results.Ok(new LookupDto(target.Value.ToString(), IpRangeSet.Reserved.Contains(address), allow.Contains(address), hits, extra));
        });
    }

    /// <summary>Policy layers that pick each list: "global", "group web", "host db-1".</summary>
    private static async Task<Dictionary<string, List<string>>> UsageAsync(AlastorDbContext db, CancellationToken ct)
    {
        var layers = await db.PolicyLayers.AsNoTracking()
            .Join(db.PolicyVersions.AsNoTracking(), l => new { Id = l.Id, V = l.CurrentVersion }, v => new { Id = v.LayerId, V = v.Version }, (l, v) => new { l.Scope, l.TargetId, v.Yaml })
            .ToListAsync(ct);
        var groups = await db.Groups.AsNoTracking().ToDictionaryAsync(g => g.Id, g => g.Name, ct);
        var hosts = await db.Hosts.AsNoTracking().ToDictionaryAsync(h => h.Id, h => h.Name, ct);
        var usage = new Dictionary<string, List<string>>();
        foreach (var l in layers.OrderBy(l => l.Scope))
        {
            if (PolicyYaml.Parse(l.Yaml).Document?.Blocklists?.Lists is not { } ids) continue;
            var label = l.Scope switch
            {
                PolicyScope.Global => "global",
                PolicyScope.Group => $"group {groups.GetValueOrDefault(l.TargetId!.Value, "?")}",
                _ => $"host {hosts.GetValueOrDefault(l.TargetId!.Value, "?")}",
            };
            foreach (var id in ids)
            {
                if (!usage.TryGetValue(id, out var list)) usage[id] = list = [];
                list.Add(label);
            }
        }
        return usage;
    }

    private static async Task AgentBlocklist(HttpContext http, ClaimsPrincipal user, AlastorDbContext db, PolicyService policies, BlocklistMerger merger, TimeProvider time, CancellationToken ct)
    {
        var eff = await policies.GetEffectiveAsync(user.HostId(), ct);
        var payload = await merger.BuildAsync(db, eff.Document, time, ct);
        var etag = $"\"{payload.Etag}\"";
        http.Response.Headers.ETag = etag;
        http.Response.Headers.CacheControl = "no-cache";
        if (http.Request.Headers.IfNoneMatch.Any(v => v == etag))
        {
            http.Response.StatusCode = StatusCodes.Status304NotModified;
            return;
        }
        // Compressed by hand rather than with response-compression middleware, so it stays scoped to this large,
        // secret-free body (blanket HTTPS compression invites BREACH-style attacks on responses carrying tokens).
        http.Response.ContentType = "application/json; charset=utf-8";
        var gzip = http.Request.Headers.AcceptEncoding.Any(v => v?.Contains("gzip", StringComparison.OrdinalIgnoreCase) == true);
        if (gzip)
        {
            http.Response.Headers.ContentEncoding = "gzip";
            await using var z = new GZipStream(http.Response.Body, CompressionLevel.Fastest, leaveOpen: true);
            await JsonSerializer.SerializeAsync(z, payload, AgentJsonContext.Default.BlocklistPayload, ct);
        }
        else await JsonSerializer.SerializeAsync(http.Response.Body, payload, AgentJsonContext.Default.BlocklistPayload, ct);
    }
}
