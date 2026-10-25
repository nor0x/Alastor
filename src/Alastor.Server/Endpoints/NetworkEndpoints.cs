using System.Net;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Network;
using Alastor.Core.Policy;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;
using Alastor.Server.Services.Network;

namespace Alastor.Server.Endpoints;

public static class NetworkEndpoints
{
    public sealed record HostNetworkDto(
        Guid HostId,
        string HostName,
        NetworkReport? Report,
        SshExposure? Exposure,
        string? ObservedAddress,
        bool AllowPublicSsh,
        bool TailnetAllowlisted,
        DateTime? CheckedAt,
        bool? LastCheckSucceeded,
        string? LastCheckError,
        DateTime? LastAttemptAt,
        ReportEndpoints.ScheduleDto Schedule)
    {
        /// <summary>The effective <c>network.allowPublicPorts</c>.</summary>
        public IReadOnlyList<string> AllowPublicPorts { get; init; } = [];

        /// <summary>Keys (<c>6379/tcp</c>) of public services that aren't SSH and aren't allowed.</summary>
        public IReadOnlyList<string> UnexpectedPublic { get; init; } = [];
    }

    public sealed record FleetRow(Guid HostId, string Name, bool Online, string? GroupName, SshExposureLevel? Exposure, bool Accepted, bool? PasswordAuth,
        IReadOnlyList<int> Ports, string? FirewallTool, FirewallSshVerdict? Firewall, string? TailscaleState, string? TailscaleIp, bool? TailscaleSsh,
        DateTime? CheckedAt, string? Error)
    {
        /// <summary>Unexpected public services, as "6379/tcp redis-server". Null when the agent doesn't report services yet.</summary>
        public IReadOnlyList<string>? PublicServices { get; init; }

        /// <summary>Listening services in the last report, and how many face the internet (allowed ones included).</summary>
        public int? Services { get; init; }
        public int? PublicTotal { get; init; }
    }

    public static void MapNetworkEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api").WithTags("Network").RequireAuthorization(AuthPolicies.Reader);
        g.MapGet("/hosts/{id:guid}/network", HostAsync);
        g.MapGet("/network", FleetAsync);
    }

    private static async Task<IResult> HostAsync(Guid id, AlastorDbContext db, PolicyService policies, CancellationToken ct)
    {
        var h = await db.Hosts.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        if (h is null) return Results.NotFound();
        var row = await db.HostReports.AsNoTracking().FirstOrDefaultAsync(r => r.HostId == id && r.Kind == NetworkService.ReportKind, ct);
        var report = NetworkService.Read(row);
        var eff = (await policies.GetEffectiveAsync(id, ct)).Document;
        var accepted = eff.Network?.AllowPublicSsh == true;
        var schedule = ScheduleDefaults.Resolve(eff).First(s => s.Path == "network.checkSchedule");
        return Results.Ok(new HostNetworkDto(h.Id, h.Name, report, report is null ? null : NetworkService.Assess(h, report, accepted), h.ObservedAddress, accepted,
            CoversTailnet(eff.Banning?.Allowlist), h.NetworkCheckedAt, row?.Success, row?.Error, row?.FinishedAt,
            new ReportEndpoints.ScheduleDto(schedule.Path, schedule.Value, schedule.IsDefault))
        {
            AllowPublicPorts = eff.Network?.AllowPublicPorts ?? [],
            UnexpectedPublic = report is null ? [] : (NetworkService.UnexpectedPublicServices(report, eff.Network) ?? []).Select(e => e.Split(' ')[0]).ToList(),
        });
    }

    private static async Task<List<FleetRow>> FleetAsync(AlastorDbContext db, CancellationToken ct)
    {
        var hosts = await db.Hosts.AsNoTracking().Include(h => h.Group).OrderBy(h => h.Name).ToListAsync(ct);
        var rows = await db.HostReports.AsNoTracking().Where(r => r.Kind == NetworkService.ReportKind).ToDictionaryAsync(r => r.HostId, ct);
        return hosts.Select(h =>
        {
            var row = rows.GetValueOrDefault(h.Id);
            var report = NetworkService.Read(row);
            return new FleetRow(h.Id, h.Name, h.IsOnline, h.Group?.Name, h.SshExposure, h.SshExposureAccepted, h.SshPasswordAuth, report?.Ssh?.Ports ?? [],
                report?.Firewall.Tool, report?.Firewall.Verdict, h.TailscaleState, h.TailscaleIp, report?.Tailscale?.SshEnabled, h.NetworkCheckedAt,
                row is { Success: false } ? row.Error : null)
            {
                PublicServices = h.PublicServices,
                Services = report?.Services?.Count,
                PublicTotal = report?.Services?.Count(s => s.Reach == ServiceReach.Public),
            };
        }).ToList();
    }

    /// <summary>The allowlist contains the whole tailnet range, so tailnet peers are never banned.</summary>
    private static bool CoversTailnet(IEnumerable<string>? allowlist) =>
        (allowlist ?? []).Any(a => IPNetwork.TryParse(a, out var n) && n.PrefixLength <= 10 && n.Contains(IPAddress.Parse("100.64.0.0")) && n.Contains(IPAddress.Parse("100.127.255.255")));
}
