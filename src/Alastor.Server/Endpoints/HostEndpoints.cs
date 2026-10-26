using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Contracts;
using Alastor.Core.Integrations;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;

namespace Alastor.Server.Endpoints;

public static class HostEndpoints
{
    public sealed record UpdateHostRequest(string? Name, Guid? GroupId, bool ClearGroup, List<string>? Tags);
    public sealed record MetricPoint(DateTime At, double Cpu, double Memory, double Disk, double Load1);

    public static void MapHostEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/hosts").WithTags("Hosts").RequireAuthorization(AuthPolicies.Reader);

        g.MapGet("/", async (AlastorDbContext db, PolicyService policies, CancellationToken ct) =>
        {
            var ids = await db.Hosts.OrderBy(h => h.Name).Select(h => h.Id).ToListAsync(ct);
            var list = new List<HostSummaryDto>(ids.Count);
            foreach (var id in ids) list.Add(await SummaryAsync(db, id, (await policies.GetEffectiveAsync(id, ct)).Revision, ct));
            return list;
        });

        g.MapGet("/{id:guid}", async (Guid id, AlastorDbContext db, PolicyService policies, CancellationToken ct) =>
        {
            var h = await db.Hosts.AsNoTracking().Include(x => x.Tools).FirstOrDefaultAsync(x => x.Id == id, ct);
            if (h is null) return Results.NotFound();
            var eff = await policies.GetEffectiveAsync(id, ct);
            var report = h.PolicyReportJson is null ? null : JsonSerializer.Deserialize(h.PolicyReportJson, AgentJsonContext.Default.PolicyApplyReport);
            return Results.Ok(new HostDetailDto(
                await SummaryAsync(db, id, eff.Revision, ct), h.OsId, h.OsVersion, h.KernelVersion, h.MachineId, h.IpAddresses, h.EnrolledAt,
                h.MemoryTotalBytes, h.MemoryUsedBytes, h.DiskTotalBytes, h.DiskUsedBytes, h.Load5, h.Load15, h.UptimeSeconds,
                eff.Revision, h.AppliedRevision, h.PolicyAppliedAt, h.PolicyApplySuccess, report, Dto.ToolMatrix(h.Tools)));
        });

        g.MapGet("/{id:guid}/metrics", async (Guid id, int? hours, AlastorDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var since = time.GetUtcNow().UtcDateTime.AddHours(-Math.Clamp(hours ?? 24, 1, 24 * 7));
            var points = await db.MetricSamples.AsNoTracking().Where(s => s.HostId == id && s.At >= since).OrderBy(s => s.At)
                .Select(s => new MetricPoint(s.At, s.CpuPercent, s.MemoryPercent, s.DiskPercent, s.Load1)).ToListAsync(ct);
            // Downsample to about 300 points so a week of minutely samples stays light for the browser.
            var step = Math.Max(1, points.Count / 300);
            return points.Where((_, i) => i % step == 0).ToList();
        });

        g.MapGet("/{id:guid}/effective-policy", async (Guid id, PolicyService policies, CancellationToken ct) =>
        {
            var eff = await policies.GetEffectiveAsync(id, ct);
            return new { eff.Revision, Yaml = Alastor.Core.Policy.PolicyYaml.Serialize(eff.Document), eff.Layers };
        });

        g.MapGet("/{id:guid}/commands", async (Guid id, AlastorDbContext db, CancellationToken ct) =>
            (await db.Commands.AsNoTracking().Where(c => c.HostId == id).OrderByDescending(c => c.CreatedAt).Take(50).ToListAsync(ct))
                .Select(Dto.Command).ToList());

        g.MapPatch("/{id:guid}", async (Guid id, UpdateHostRequest req, ClaimsPrincipal user, AlastorDbContext db, CommandService commands, CancellationToken ct) =>
        {
            var h = await db.Hosts.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (h is null) return Results.NotFound();
            if (req.Name is { Length: > 0 and <= 128 } name) h.Name = name.Trim();
            if (req.ClearGroup) h.GroupId = null;
            else if (req.GroupId is { } gid)
            {
                if (!await db.Groups.AnyAsync(x => x.Id == gid, ct)) return Results.Problem("Unknown group.", statusCode: 400);
                h.GroupId = gid;
            }
            if (req.Tags is not null) h.Tags = req.Tags.Select(t => t.Trim().ToLowerInvariant()).Where(t => t.Length is > 0 and <= 32).Distinct().Take(20).ToList();
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "host.update", Target = id.ToString() });
            await db.SaveChangesAsync(ct);
            await commands.WakeAsync(id, "policy", ct); // group change may change the effective policy
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);

        g.MapDelete("/{id:guid}", async (Guid id, ClaimsPrincipal user, AlastorDbContext db, CancellationToken ct) =>
        {
            var h = await db.Hosts.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (h is null) return Results.NotFound();
            // Deleting the host invalidates its agent secret. The agent stops, and `alastor-agent uninstall` cleans up locally.
            db.Hosts.Remove(h);
            var layer = await db.PolicyLayers.FirstOrDefaultAsync(l => l.Scope == PolicyScope.Host && l.TargetId == id, ct);
            if (layer is not null) db.PolicyLayers.Remove(layer);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "host.delete", Target = id.ToString(), Details = h.Name });
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);

        // Operator actions: re-run reconcile, reclaim hand-edited files, refresh ban list, re-run the security baseline.
        g.MapPost("/{id:guid}/actions/{action}", async (Guid id, string action, ClaimsPrincipal user, AlastorDbContext db, CommandService commands, CancellationToken ct) =>
        {
            var (type, job) = action switch
            {
                "reconcile" => (AgentCommandTypes.Reconcile, null),
                "reclaim" => (AgentCommandTypes.Reclaim, null),
                "refresh-bans" => (AgentCommandTypes.RefreshBans, null),
                "recheck" => (AgentCommandTypes.BaselineCheck, null),
                "check-updates" => (AgentCommandTypes.RunJob, "updates.check"),
                "apply-updates" => (AgentCommandTypes.RunJob, "updates.apply"),
                "collect-software" => (AgentCommandTypes.RunJob, Alastor.Core.Software.SoftwareIntegration.InventoryJob),
                "scan-vulnerabilities" => (AgentCommandTypes.RunJob, Alastor.Core.Vulnerabilities.VulnerabilityIntegration.ScanJob),
                "run-audit" => (AgentCommandTypes.RunJob, Alastor.Core.Hardening.HardeningIntegration.AuditJob),
                "check-network" => (AgentCommandTypes.RunJob, Alastor.Core.Network.NetworkIntegration.CheckJob),
                "scan-malware" => (AgentCommandTypes.RunJob, Alastor.Core.Malware.ClamAvIntegration.ScanJob),
                "check-integrity" => (AgentCommandTypes.RunJob, Alastor.Core.Integrity.AideIntegration.CheckJob),
                "accept-integrity" => (AgentCommandTypes.RunJob, Alastor.Core.Integrity.AideIntegration.AcceptJob),
                "scan-rootkits" => (AgentCommandTypes.RunJob, Alastor.Core.Malware.RkhunterIntegration.ScanJob),
                "accept-rootkits" => (AgentCommandTypes.RunJob, Alastor.Core.Malware.RkhunterIntegration.AcceptJob),
                "reboot" => (AgentCommandTypes.Reboot, null),
                _ => ((string?)null, (string?)null),
            };
            if (type is null) return Results.Problem($"Unknown action '{action}'.", statusCode: 400);
            var online = await db.Hosts.Where(h => h.Id == id).Select(h => (bool?)h.IsOnline).FirstOrDefaultAsync(ct);
            if (online is null) return Results.NotFound();
            // A queued reboot would run whenever the host comes back, possibly hours later. Only reboot hosts that are online now.
            if (type == AgentCommandTypes.Reboot && online == false)
                return Results.Problem("The host is offline. Reboot it once it's back online.", statusCode: 409);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = $"host.{action}", Target = id.ToString() });
            var cmds = await commands.QueueAsync([id], type, job is null ? [] : new() { ["job"] = job }, user.Actor(), ct);
            return Results.Accepted(value: Dto.Command(cmds[0]));
        }).RequireAuthorization(AuthPolicies.Admin);
    }

    public static async Task<HostSummaryDto> SummaryAsync(AlastorDbContext db, Guid id, string desiredRevision, CancellationToken ct)
    {
        var h = await db.Hosts.AsNoTracking().Include(x => x.Group).Include(x => x.Tools).FirstAsync(x => x.Id == id, ct);
        var bans = await db.Bans.CountAsync(b => b.HostId == id, ct);
        var baselineFailing = await db.BaselineChecks.CountAsync(c => c.HostId == id && c.Status == Alastor.Core.Baseline.CheckStatus.Fail && !c.Accepted, ct);
        var sync = h.AppliedRevision is null ? "pending"
            : h.PolicyApplySuccess == false ? "failed"
            : h.AppliedRevision == desiredRevision ? "in-sync"
            : "pending";
        var problems = h.Tools.Count(Dto.HasProblem);
        return new HostSummaryDto(h.Id, h.Name, h.Hostname, h.OsPrettyName, h.Architecture, h.AgentVersion, h.IsOnline, h.LastSeenAt,
            h.CpuPercent, Dto.Percent(h.MemoryUsedBytes, h.MemoryTotalBytes), Dto.Percent(h.DiskUsedBytes, h.DiskTotalBytes), h.Load1,
            h.GroupId, h.Group?.Name, h.Tags, bans, sync, h.Tools.Count(t => t.Running), problems,
            h.BaselineScore, baselineFailing, h.PendingUpdates, h.SecurityUpdates, h.RebootRequired, h.VulnCritical, h.VulnHigh, h.VulnTotal, h.VulnFixable,
            h.HardeningIndex, h.HardeningWarnings, h.SshExposure, h.SshExposureAccepted, h.TailscaleState, h.MalwareFindings)
        {
            IntegrityChanges = h.IntegrityChanges,
            RootkitWarnings = h.RootkitWarnings,
            UptimeSeconds = h.UptimeSeconds,
            KernelVersion = h.KernelVersion,
            IpAddresses = h.IpAddresses,
        };
    }
}
