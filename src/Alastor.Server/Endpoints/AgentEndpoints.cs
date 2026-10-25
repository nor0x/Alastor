using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Net;
using Alastor.Core.Policy;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;

namespace Alastor.Server.Endpoints;

/// <summary>The agent-facing API. Every route except /enroll requires the Agent scheme (per-host secret).</summary>
public static class AgentEndpoints
{
    public static void MapAgentEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/agent").WithTags("Agent");

        g.MapPost("/enroll", Enroll).AllowAnonymous().RequireRateLimiting("auth");

        var a = g.MapGroup("").RequireAuthorization(AuthPolicies.Agent);
        a.MapPost("/heartbeat", Heartbeat);
        a.MapGet("/desired-state", async (ClaimsPrincipal user, PolicyService policies, CancellationToken ct) =>
        {
            var eff = await policies.GetEffectiveAsync(user.HostId(), ct);
            return new DesiredStateResponse(eff.Revision, eff.Document);
        });
        a.MapPost("/events", async (EventBatch batch, ClaimsPrincipal user, EventIngestService ingest, CancellationToken ct) =>
        {
            if (batch.Events.Count > 1000) return Results.Problem("At most 1000 events per batch.", statusCode: 413);
            var (accepted, dupes) = await ingest.IngestAsync(user.HostId(), batch.Events, ct);
            return Results.Ok(new EventBatchResult(accepted, dupes));
        });
        a.MapPost("/bans", BanSnapshotHandler);
        a.MapGet("/commands", async (ClaimsPrincipal user, AlastorDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var hostId = user.HostId();
            var pending = await db.Commands.Where(c => c.HostId == hostId && c.Status == CommandStatus.Pending)
                .OrderBy(c => c.CreatedAt).Take(50).ToListAsync(ct);
            var now = time.GetUtcNow().UtcDateTime;
            foreach (var c in pending)
            {
                c.Status = CommandStatus.Delivered;
                c.DeliveredAt = now;
                c.Attempts++;
            }
            await db.SaveChangesAsync(ct);
            return pending.Select(c => c.ToContract()).ToList();
        });
        a.MapPost("/commands/{id:guid}/result", async (Guid id, AgentCommandResult result, ClaimsPrincipal user, AlastorDbContext db,
            DashboardNotifier notifier, TimeProvider time, CancellationToken ct) =>
        {
            var hostId = user.HostId();
            var cmd = await db.Commands.FirstOrDefaultAsync(c => c.Id == id && c.HostId == hostId, ct);
            if (cmd is null) return Results.NotFound();
            cmd.Status = result.Success ? CommandStatus.Succeeded : CommandStatus.Failed;
            cmd.CompletedAt = time.GetUtcNow().UtcDateTime;
            cmd.ResultMessage = result.Message.Length > 1000 ? result.Message[..1000] : result.Message;
            await db.SaveChangesAsync(ct);
            await notifier.CommandUpdatedAsync(Dto.Command(cmd), ct);
            return Results.NoContent();
        });
    }

    private static async Task<IResult> Enroll(EnrollRequest req, AlastorDbContext db, EventIngestService ingest, IOptions<AlastorOptions> opt,
        TimeProvider time, ILoggerFactory lf, HttpContext http, CancellationToken ct)
    {
        var log = lf.CreateLogger("Enrollment");
        var now = time.GetUtcNow().UtcDateTime;
        var hash = Secrets.Hash(req.Token ?? "");

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        // Atomic single-use consumption: only one concurrent request can flip ConsumedAt from null.
        var consumed = await db.EnrollmentTokens
            .Where(t => t.TokenHash == hash && t.ConsumedAt == null && t.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.ConsumedAt, now), ct);
        if (consumed != 1)
        {
            log.LogWarning("Rejected enrollment from {Ip} for {Hostname}: invalid, expired or used token", http.Connection.RemoteIpAddress, req.Hostname);
            return Results.Problem("Enrollment token is invalid, expired, or already used.", statusCode: StatusCodes.Status401Unauthorized);
        }
        var token = await db.EnrollmentTokens.FirstAsync(t => t.TokenHash == hash, ct);

        var secret = Secrets.Generate("sva_");
        var host = new ManagedHost
        {
            Name = Clip(req.Hostname, 128),
            Hostname = Clip(req.Hostname, 255),
            SecretHash = Secrets.Hash(secret),
            OsPrettyName = Clip(req.OsPrettyName, 128),
            OsId = Clip(req.OsId, 32),
            OsVersion = Clip(req.OsVersion, 32),
            Architecture = Clip(req.Architecture, 16),
            AgentVersion = Clip(req.AgentVersion, 32),
            MachineId = req.MachineId is null ? null : Clip(req.MachineId, 64),
            GroupId = token.GroupId,
            Tags = token.Tags,
            EnrolledAt = now,
            LastSeenAt = now,
            IsOnline = true,
        };
        db.Hosts.Add(host);
        token.ConsumedByHostId = host.Id;
        db.Audit.Add(new AuditEntry { Actor = "agent", Action = "host.enrolled", Target = host.Id.ToString(), Details = $"{host.Hostname} from {http.Connection.RemoteIpAddress}" });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        await ingest.IngestAsync(host.Id,
        [
            new SecurityEvent
            {
                Id = Guid.NewGuid(), OccurredAt = now, Capability = Capability.Agent, Severity = Severity.Info,
                SourceTool = "alastor-server", Kind = EventKinds.HostEnrolled, Subject = host.Name,
                Message = $"{host.Name} ({host.OsPrettyName}, {host.Architecture}) enrolled",
            },
        ], ct);
        log.LogInformation("Enrolled host {Host} ({HostId})", host.Name, host.Id);
        return Results.Ok(new EnrollResponse(host.Id, $"{host.Id}.{secret}", (int)opt.Value.HeartbeatIntervalValue.TotalSeconds));
    }

    /// <summary>What a heartbeat can change about a host's issues: tool health and the last policy apply.</summary>
    private static string HealthSignature(ManagedHost h) =>
        $"{h.PolicyApplySuccess}|{string.Join(',', h.Tools.Where(Dto.HasProblem).Select(t => $"{t.ToolId}:{t.Availability}:{t.Running}:{t.ConfigState}").Order(StringComparer.Ordinal))}";

    private static async Task<IResult> Heartbeat(HeartbeatRequest hb, ClaimsPrincipal user, AlastorDbContext db, PolicyService policies,
        EventIngestService ingest, DashboardNotifier notifier, HostStateService hostState, IOptions<AlastorOptions> opt, TimeProvider time, HttpContext http, CancellationToken ct)
    {
        var hostId = user.HostId();
        var now = time.GetUtcNow().UtcDateTime;
        var host = await db.Hosts.Include(h => h.Tools).FirstAsync(h => h.Id == hostId, ct);
        var wasOffline = !host.IsOnline;
        var healthBefore = HealthSignature(host);

        host.LastSeenAt = now;
        host.IsOnline = true;
        host.AgentVersion = Clip(hb.AgentVersion, 32);
        host.Hostname = Clip(hb.Hostname, 255);
        host.OsPrettyName = Clip(hb.OsPrettyName, 128);
        host.KernelVersion = Clip(hb.KernelVersion, 128);
        host.IpAddresses = hb.IpAddresses.Take(32).Select(i => Clip(i, 64)).ToList();
        if (http.Connection.RemoteIpAddress is { } remote)
            host.ObservedAddress = (remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote).ToString();
        var m = hb.Metrics;
        host.CpuPercent = Math.Round(m.CpuPercent, 1);
        host.MemoryTotalBytes = m.MemoryTotalBytes;
        host.MemoryUsedBytes = m.MemoryUsedBytes;
        host.DiskTotalBytes = m.DiskTotalBytes;
        host.DiskUsedBytes = m.DiskUsedBytes;
        host.Load1 = m.Load1;
        host.Load5 = m.Load5;
        host.Load15 = m.Load15;
        host.UptimeSeconds = m.UptimeSeconds;

        if (hb.Policy is { } p)
        {
            host.AppliedRevision = Clip(p.Revision, 64);
            host.PolicyAppliedAt = p.AppliedAtUtc;
            host.PolicyApplySuccess = p.Success;
            host.PolicyReportJson = JsonSerializer.Serialize(p, AgentJsonContext.Default.PolicyApplyReport);
        }

        // Replace the tool status set with what the agent reports.
        var reported = hb.Tools.Take(32).ToDictionary(t => t.ToolId);
        host.Tools.RemoveAll(t => !reported.ContainsKey(t.ToolId));
        foreach (var t in reported.Values)
        {
            var row = host.Tools.FirstOrDefault(x => x.ToolId == t.ToolId);
            if (row is null) host.Tools.Add(row = new HostToolStatus { HostId = hostId, ToolId = Clip(t.ToolId, 64) });
            row.Availability = t.Availability;
            row.UnavailableReason = t.UnavailableReason;
            row.Installed = t.Installed;
            row.Version = t.Version;
            row.Running = t.Running;
            row.Ownership = t.Ownership;
            row.ConfigState = t.ConfigState;
            row.AppliedRevision = t.AppliedRevision;
            row.LastError = t.LastError;
            row.LastSuccessAt = t.LastSuccessAt;
            row.Warnings = t.Warnings.Take(20).ToList();
            row.Details = t.Details.Take(32).ToDictionary();
            row.UpdatedAt = now;
        }

        db.MetricSamples.Add(new HostMetricSample
        {
            HostId = hostId,
            At = now,
            CpuPercent = host.CpuPercent,
            MemoryPercent = Dto.Percent(m.MemoryUsedBytes, m.MemoryTotalBytes),
            DiskPercent = Dto.Percent(m.DiskUsedBytes, m.DiskTotalBytes),
            Load1 = m.Load1,
        });
        await db.SaveChangesAsync(ct);

        if (wasOffline)
        {
            await ingest.IngestAsync(hostId,
            [
                new SecurityEvent
                {
                    Id = Guid.NewGuid(), OccurredAt = now, Capability = Capability.Agent, Severity = Severity.Info,
                    SourceTool = "alastor-server", Kind = EventKinds.HostOnline, Subject = host.Name,
                    Message = $"{host.Name} is back online", DedupKey = $"host.online:{hostId}",
                },
            ], ct);
        }
        if (wasOffline || HealthSignature(host) != healthBefore) await hostState.ChangedAsync(hostId, ct);

        var effective = await policies.GetEffectiveAsync(hostId, ct);
        var heartbeat = (int)AgentTimings.From(effective.Document, opt.Value.HeartbeatIntervalValue).HeartbeatInterval.TotalSeconds;
        if (host.HeartbeatIntervalSeconds != heartbeat)
        {
            host.HeartbeatIntervalSeconds = heartbeat;
            await db.SaveChangesAsync(ct);
        }
        var pending = await db.Commands.CountAsync(c => c.HostId == hostId && c.Status == CommandStatus.Pending, ct);
        await notifier.HostUpdatedAsync(await HostEndpoints.SummaryAsync(db, hostId, effective.Revision, ct), ct);
        return Results.Ok(new HeartbeatResponse(effective.Revision, pending, now, heartbeat));
    }

    private static async Task<IResult> BanSnapshotHandler(BanSnapshot snapshot, ClaimsPrincipal user, AlastorDbContext db, DashboardNotifier notifier,
        TimeProvider time, CancellationToken ct)
    {
        var hostId = user.HostId();
        var now = time.GetUtcNow().UtcDateTime;
        var tool = Clip(snapshot.ToolId, 64);
        var existing = await db.Bans.Where(b => b.HostId == hostId && b.ToolId == tool).ToListAsync(ct);
        var incoming = snapshot.Bans
            .Where(b => IpTarget.TryParse(b.Target, out _))
            .Take(100_000)
            .DistinctBy(b => (b.Scope, b.Target))
            .ToDictionary(b => (Scope: Clip(b.Scope, 64), b.Target));

        var changed = false;
        foreach (var row in existing)
        {
            if (!incoming.Remove((row.Scope, row.Target), out var b))
            {
                db.Bans.Remove(row);
                changed = true;
                continue;
            }
            row.LastSeenAt = now;
            row.ExpiresAt = b.ExpiresAt == DateTime.MaxValue ? null : b.ExpiresAt;
            row.BannedAt = b.BannedAt;
            row.Manual = b.Manual;
        }
        foreach (var ((scope, target), b) in incoming)
        {
            db.Bans.Add(new ActiveBan
            {
                HostId = hostId, ToolId = tool, Scope = scope, Target = target, BannedAt = b.BannedAt,
                ExpiresAt = b.ExpiresAt == DateTime.MaxValue ? null : b.ExpiresAt, Manual = b.Manual, LastSeenAt = now,
            });
            changed = true;
        }
        await db.SaveChangesAsync(ct);
        if (changed) await notifier.BansChangedAsync(hostId, ct);
        return Results.NoContent();
    }

    private static string Clip(string? s, int max) => s is null ? "" : s.Length <= max ? s : s[..max];
}
