using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Contracts;
using Alastor.Core.Hardening;
using Alastor.Core.Policy;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;
using Alastor.Server.Services.Hardening;

namespace Alastor.Server.Endpoints;

public static class HardeningEndpoints
{
    public sealed record ItemDto(string TestId, LynisItemKind Kind, string Category, string Text, string? Details, string? Solution, bool Accepted, DateTime FirstSeenAt);

    public sealed record LynisToolDto(string? Version, string? Availability, string? Reason, string? Ownership, bool Installed);

    public sealed record HostHardeningDto(
        Guid HostId,
        string HostName,
        LynisToolDto Tool,
        int? HardeningIndex,
        string? LynisVersion,
        int? TestsExecuted,
        DateTime? AuditedAt,
        bool? LastAuditSucceeded,
        string? LastAuditError,
        DateTime? LastAttemptAt,
        ReportEndpoints.ScheduleDto Schedule,
        IReadOnlyList<string> ResolvedSinceLast,
        IReadOnlyList<ItemDto> Items);

    public sealed record FleetHostDto(Guid HostId, string Name, bool Online, string? GroupName, int? HardeningIndex, int? Warnings, int? Suggestions,
        DateTime? AuditedAt, string? Error, string? Availability);

    public sealed record FleetItemDto(string TestId, LynisItemKind Kind, string Category, string Text, string? Solution, int HostCount,
        IReadOnlyList<VulnerabilityEndpoints.HostRef> Hosts);

    public sealed record FleetDto(double? AverageIndex, IReadOnlyList<FleetHostDto> Hosts, IReadOnlyList<FleetItemDto> Items);

    public static void MapHardeningEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api").WithTags("Hardening").RequireAuthorization(AuthPolicies.Reader);
        g.MapGet("/hosts/{id:guid}/hardening", HostAsync);
        g.MapGet("/hardening", FleetAsync);
    }

    private static async Task<IResult> HostAsync(Guid id, AlastorDbContext db, PolicyService policies, CancellationToken ct)
    {
        var h = await db.Hosts.AsNoTracking().Include(x => x.Tools).FirstOrDefaultAsync(x => x.Id == id, ct);
        if (h is null) return Results.NotFound();
        var row = await db.HostReports.AsNoTracking().FirstOrDefaultAsync(r => r.HostId == id && r.Kind == HardeningService.ReportKind, ct);
        var report = row is null ? null : JsonSerializer.Deserialize(row.Json, AgentJsonContext.Default.AgentReport)?.Hardening;
        var eff = (await policies.GetEffectiveAsync(id, ct)).Document;
        var schedule = ScheduleDefaults.Resolve(eff).First(s => s.Path == "hardening.auditSchedule");
        var tool = h.Tools.FirstOrDefault(t => t.ToolId == HardeningIntegration.Info.Id);

        // Warnings first, then by category so the checklist groups naturally.
        var items = (await db.HardeningItems.AsNoTracking().Where(i => i.HostId == id).ToListAsync(ct))
            .Select(i => new ItemDto(i.TestId, i.Kind, LynisReportParser.Category(i.TestId), i.Text, i.Details, i.Solution, i.Accepted, i.FirstSeenAt))
            .OrderBy(i => i.Kind).ThenBy(i => i.Category, StringComparer.Ordinal).ThenBy(i => i.TestId, StringComparer.Ordinal).ToList();

        return Results.Ok(new HostHardeningDto(h.Id, h.Name,
            new LynisToolDto(tool?.Version, tool?.Availability.ToString(), tool?.UnavailableReason, tool?.Ownership.ToString(), tool?.Installed ?? false),
            h.HardeningIndex, report?.LynisVersion, report?.TestsExecuted, h.HardeningAuditedAt, row?.Success, row?.Error, row?.FinishedAt,
            new ReportEndpoints.ScheduleDto(schedule.Path, schedule.Value, schedule.IsDefault), report?.ResolvedSinceLast ?? [], items));
    }

    private static async Task<FleetDto> FleetAsync(AlastorDbContext db, CancellationToken ct, int limit = 100)
    {
        var hosts = await db.Hosts.AsNoTracking().Include(h => h.Group).Include(h => h.Tools).OrderBy(h => h.Name).ToListAsync(ct);
        var names = hosts.ToDictionary(h => h.Id, h => h.Name);
        var reports = await db.HostReports.AsNoTracking().Where(r => r.Kind == HardeningService.ReportKind)
            .Select(r => new { r.HostId, r.Success, r.Error }).ToDictionaryAsync(r => r.HostId, ct);
        var hostRows = hosts.Select(h =>
        {
            var r = reports.GetValueOrDefault(h.Id);
            return new FleetHostDto(h.Id, h.Name, h.IsOnline, h.Group?.Name, h.HardeningIndex, h.HardeningWarnings, h.HardeningSuggestions, h.HardeningAuditedAt,
                r is { Success: false } ? r.Error : null, h.Tools.FirstOrDefault(t => t.ToolId == HardeningIntegration.Info.Id)?.Availability.ToString());
        }).ToList();

        // The checklist across the fleet: what most hosts share is usually one policy change away.
        var rows = await db.HardeningItems.AsNoTracking().Where(i => !i.Accepted).Select(i => new { i.HostId, i.TestId, i.Kind, i.Text, i.Solution }).ToListAsync(ct);
        var items = rows.GroupBy(r => (r.TestId, r.Kind)).Select(grp =>
        {
            var ids = grp.Select(r => r.HostId).Distinct().ToList();
            // A test id can report several texts (FILE-6310 per mount point); the most common one names the group.
            var text = grp.GroupBy(r => r.Text).OrderByDescending(t => t.Count()).ThenBy(t => t.Key, StringComparer.Ordinal).First().Key;
            return new FleetItemDto(grp.Key.TestId, grp.Key.Kind, LynisReportParser.Category(grp.Key.TestId), text, grp.Select(r => r.Solution).FirstOrDefault(s => s is not null),
                ids.Count, ids.Select(h => new VulnerabilityEndpoints.HostRef(h, names.GetValueOrDefault(h, "?"))).OrderBy(h => h.Name).Take(20).ToList());
        }).OrderBy(i => i.Kind).ThenByDescending(i => i.HostCount).ThenBy(i => i.TestId, StringComparer.Ordinal).Take(Math.Clamp(limit, 1, 500)).ToList();

        var audited = hosts.Where(h => h.HardeningIndex is not null).ToList();
        return new FleetDto(audited.Count > 0 ? Math.Round(audited.Average(h => h.HardeningIndex!.Value), 0) : null, hostRows, items);
    }
}
