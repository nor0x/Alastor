using Microsoft.EntityFrameworkCore;
using Alastor.Core.Events;
using Alastor.Core.Integrity;
using Alastor.Core.Malware;
using Alastor.Core.Policy;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;
using Alastor.Server.Services.Integrity;

namespace Alastor.Server.Endpoints;

/// <summary>A host's latest AIDE run and rkhunter check, with their schedules and tool state.</summary>
public static class IntegrityEndpoints
{
    public sealed record ToolDto(bool Installed, string? Version, string? Availability, string? UnavailableReason);

    public sealed record RunDto(DateTime? CheckedAt, bool? LastSucceeded, string? LastError, DateTime? LastAttemptAt, ReportEndpoints.ScheduleDto Schedule, ToolDto Tool);

    public sealed record AideDto(IntegrityReport? Report, IReadOnlyList<string> Paths, IReadOnlyList<string> Exclude, RunDto Run);

    public sealed record RootkitWarningDto(string Title, IReadOnlyList<string> Details, Severity Severity, bool Ignored);

    public sealed record RootkitDto(string? Version, string? Mode, IReadOnlyList<RootkitWarningDto> Warnings, IReadOnlyList<string> Ignore, RunDto Run);

    public sealed record HostIntegrityDto(Guid HostId, string HostName, AideDto Aide, RootkitDto Rootkit);

    public static void MapIntegrityEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/hosts/{id:guid}/integrity", async (Guid id, AlastorDbContext db, PolicyService policies, CancellationToken ct) =>
        {
            var h = await db.Hosts.AsNoTracking().Include(x => x.Tools).FirstOrDefaultAsync(x => x.Id == id, ct);
            if (h is null) return Results.NotFound();
            var rows = await db.HostReports.AsNoTracking().Where(r => r.HostId == id && (r.Kind == IntegrityService.IntegrityKind || r.Kind == IntegrityService.RootkitKind))
                .ToDictionaryAsync(r => r.Kind, ct);
            var eff = (await policies.GetEffectiveAsync(id, ct)).Document;
            var schedules = ScheduleDefaults.Resolve(eff).ToDictionary(s => s.Path);

            RunDto Run(string kind, string scheduleKey, string toolId, DateTime? checkedAt)
            {
                var row = rows.GetValueOrDefault(kind);
                var s = schedules[scheduleKey];
                var tool = h.Tools.FirstOrDefault(t => t.ToolId == toolId);
                return new RunDto(checkedAt, row?.Success, row?.Error, row?.FinishedAt, new ReportEndpoints.ScheduleDto(s.Path, s.Value, s.IsDefault),
                    new ToolDto(tool?.Installed ?? false, tool?.Version, tool?.Availability.ToString(), tool?.UnavailableReason));
            }

            var ignore = eff.Malware?.RootkitIgnore ?? [];
            var rk = IntegrityService.ReadRootkit(rows.GetValueOrDefault(IntegrityService.RootkitKind));
            return Results.Ok(new HostIntegrityDto(h.Id, h.Name,
                new AideDto(IntegrityService.ReadIntegrity(rows.GetValueOrDefault(IntegrityService.IntegrityKind)),
                    eff.Integrity?.Paths ?? AideIntegration.DefaultPaths.ToList(), eff.Integrity?.Exclude ?? [],
                    Run(IntegrityService.IntegrityKind, "integrity.checkSchedule", AideIntegration.Info.Id, h.IntegrityCheckedAt)),
                new RootkitDto(rk?.Version, rk?.Mode, (rk?.Warnings ?? []).Select(w => new RootkitWarningDto(w.Title, w.Details, w.Severity, w.IsIgnored(ignore))).ToList(),
                    ignore, Run(IntegrityService.RootkitKind, "malware.rootkitSchedule", RkhunterIntegration.Info.Id, h.RootkitCheckedAt))));
        }).WithTags("Integrity").RequireAuthorization(AuthPolicies.Reader);
    }
}
