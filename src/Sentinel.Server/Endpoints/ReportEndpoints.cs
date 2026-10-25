using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Contracts;
using Sentinel.Core.Policy;
using Sentinel.Core.Updates;
using Sentinel.Server.Auth;
using Sentinel.Server.Data;
using Sentinel.Server.Services;

namespace Sentinel.Server.Endpoints;

/// <summary>
/// Reports from agents' scheduled jobs (update checks, CVE scans, Lynis audits, network checks). The
/// server keeps the latest report per host and kind, plus summary columns on the host for list views.
/// </summary>
public static class ReportEndpoints
{
    public sealed record ScheduleDto(string Key, string Value, bool IsDefault);

    public sealed record HostUpdatesDto(
        Guid HostId,
        string HostName,
        UpdatesReport? Report,
        bool? LastCheckSucceeded,
        string? LastCheckError,
        DateTime? CheckedAt,
        IReadOnlyList<ScheduleDto> Schedules);

    public sealed record FleetUpdatesRow(Guid HostId, string Name, bool Online, string? GroupName, int? Pending, int? Security, bool RebootRequired, DateTime? CheckedAt,
        DateTime? LastAppliedAt, bool? LastApplySucceeded, string? LastCheckError);

    public sealed record ApplyRequest(List<Guid> HostIds);

    public static void MapReportEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/agent/reports", Receive).WithTags("Agent").RequireAuthorization(AuthPolicies.Agent);

        var g = app.MapGroup("/api").WithTags("Updates").RequireAuthorization(AuthPolicies.Reader);

        g.MapGet("/hosts/{id:guid}/updates", async (Guid id, SentinelDbContext db, PolicyService policies, CancellationToken ct) =>
        {
            var h = await db.Hosts.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
            if (h is null) return Results.NotFound();
            var row = await db.HostReports.AsNoTracking().FirstOrDefaultAsync(r => r.HostId == id && r.Kind == "updates", ct);
            var report = row is null ? null : JsonSerializer.Deserialize(row.Json, AgentJsonContext.Default.AgentReport);
            var eff = await policies.GetEffectiveAsync(id, ct);
            var schedules = ScheduleDefaults.Resolve(eff.Document).Where(s => s.Path.StartsWith("updates.", StringComparison.Ordinal))
                .Select(s => new ScheduleDto(s.Path, s.Value, s.IsDefault)).ToList();
            return Results.Ok(new HostUpdatesDto(h.Id, h.Name, report?.Updates, row?.Success, row?.Error, row?.FinishedAt, schedules));
        });

        g.MapGet("/updates", async (SentinelDbContext db, CancellationToken ct) =>
        {
            var hosts = await db.Hosts.AsNoTracking().Include(h => h.Group).OrderBy(h => h.Name).ToListAsync(ct);
            var reports = await db.HostReports.AsNoTracking().Where(r => r.Kind == "updates").ToDictionaryAsync(r => r.HostId, ct);
            return hosts.Select(h =>
            {
                var r = reports.GetValueOrDefault(h.Id);
                var apply = r is null ? null : JsonSerializer.Deserialize(r.Json, AgentJsonContext.Default.AgentReport)?.Updates?.LastApply;
                return new FleetUpdatesRow(h.Id, h.Name, h.IsOnline, h.Group?.Name, h.PendingUpdates, h.SecurityUpdates, h.RebootRequired, h.UpdatesCheckedAt,
                    apply?.AtUtc, apply?.Success, r is { Success: false } ? r.Error : null);
            }).ToList();
        });

        // "Apply now" for several hosts at once: one run-job command each.
        g.MapPost("/updates/apply", async (ApplyRequest req, ClaimsPrincipal user, SentinelDbContext db, CommandService commands, CancellationToken ct) =>
        {
            var ids = await db.Hosts.Where(h => req.HostIds.Contains(h.Id)).Select(h => h.Id).ToListAsync(ct);
            if (ids.Count == 0) return Results.ValidationProblem(new Dictionary<string, string[]> { ["hostIds"] = ["No known host selected."] });
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "updates.apply", Target = string.Join(",", ids), Details = $"{ids.Count} host(s)" });
            var cmds = await commands.QueueAsync(ids, AgentCommandTypes.RunJob, new() { ["job"] = UpdatesIntegration.ApplyJob }, user.Actor(), ct);
            return Results.Accepted(value: cmds.Select(Dto.Command).ToList());
        }).RequireAuthorization(AuthPolicies.Admin);
    }

    private static async Task<IResult> Receive(AgentReport report, ClaimsPrincipal user, SentinelDbContext db, PolicyService policies, DashboardNotifier notifier,
        Services.Vulnerabilities.VulnerabilityService vulnerabilities, Services.Hardening.HardeningService hardening,
        Services.Network.NetworkService network, Services.Malware.MalwareService malware, TimeProvider time, CancellationToken ct)
    {
        var hostId = user.HostId();
        if (report.Malware is not null || report.JobId.StartsWith("malware.", StringComparison.Ordinal))
        {
            if (report.Malware is { } m && (m.Findings.Count > Sentinel.Core.Malware.ClamAvIntegration.MaxFindings || m.ErrorSamples.Count > 100 || m.Paths.Count > 200))
                return Results.Problem("Report too large.", statusCode: 413);
            await malware.ReceiveAsync(hostId, report, ct);
            var eff = await policies.GetEffectiveAsync(hostId, ct);
            await notifier.HostUpdatedAsync(await HostEndpoints.SummaryAsync(db, hostId, eff.Revision, ct), ct);
            return Results.NoContent();
        }
        if (report.Vulnerabilities is not null || report.JobId.StartsWith("vulnerabilities.", StringComparison.Ordinal))
        {
            if (report.Vulnerabilities?.Findings.Count > Sentinel.Core.Vulnerabilities.VulnerabilityIntegration.MaxFindings)
                return Results.Problem("Too many findings.", statusCode: 413);
            await vulnerabilities.ReceiveAsync(hostId, report, ct);
            var eff = await policies.GetEffectiveAsync(hostId, ct);
            await notifier.HostUpdatedAsync(await HostEndpoints.SummaryAsync(db, hostId, eff.Revision, ct), ct);
            return Results.NoContent();
        }
        if (report.Hardening is not null || report.JobId.StartsWith("hardening.", StringComparison.Ordinal))
        {
            if (report.Hardening?.Items.Count > Services.Hardening.HardeningService.MaxItems * 2)
                return Results.Problem("Too many items.", statusCode: 413);
            await hardening.ReceiveAsync(hostId, report, ct);
            var eff = await policies.GetEffectiveAsync(hostId, ct);
            await notifier.HostUpdatedAsync(await HostEndpoints.SummaryAsync(db, hostId, eff.Revision, ct), ct);
            return Results.NoContent();
        }
        if (report.Network is not null || report.JobId.StartsWith("network.", StringComparison.Ordinal))
        {
            if (report.Network is { } n && (n.Addresses.Count > 1000 || n.Ssh?.Listeners.Count > 1000))
                return Results.Problem("Report too large.", statusCode: 413);
            await network.ReceiveAsync(hostId, report, ct);
            var eff = await policies.GetEffectiveAsync(hostId, ct);
            await notifier.HostUpdatedAsync(await HostEndpoints.SummaryAsync(db, hostId, eff.Revision, ct), ct);
            return Results.NoContent();
        }
        var kind = report.Updates is not null || report.JobId.StartsWith("updates.", StringComparison.Ordinal) ? "updates" : null;
        if (kind is null) return Results.Problem($"Unknown report '{report.JobId}'.", statusCode: 400);

        var json = JsonSerializer.Serialize(report, AgentJsonContext.Default.AgentReport);
        if (json.Length > 4_000_000) return Results.Problem("Report too large.", statusCode: 413);
        var row = await db.HostReports.FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == kind, ct);
        if (row is null) db.HostReports.Add(row = new HostReport { HostId = hostId, Kind = kind, JobId = report.JobId, Json = json });
        // A failed check still carries the last good package list; keep showing it, with the error.
        row.JobId = report.JobId;
        row.Json = json;
        row.Success = report.Success;
        row.Error = report.Error;
        row.StartedAt = report.StartedAtUtc;
        row.FinishedAt = report.FinishedAtUtc;
        row.ReceivedAt = time.GetUtcNow().UtcDateTime;

        var host = await db.Hosts.FirstAsync(h => h.Id == hostId, ct);
        if (report.Updates is { } u)
        {
            host.PendingUpdates = u.Pending;
            host.SecurityUpdates = u.Security;
            host.RebootRequired = u.RebootRequired;
            if (report.Success) host.UpdatesCheckedAt = report.FinishedAtUtc;
        }
        await db.SaveChangesAsync(ct);
        var effective = await policies.GetEffectiveAsync(hostId, ct);
        await notifier.HostUpdatedAsync(await HostEndpoints.SummaryAsync(db, hostId, effective.Revision, ct), ct);
        return Results.NoContent();
    }
}
