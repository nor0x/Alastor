using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Contracts;
using Alastor.Core.Network;
using Alastor.Server.Data;

namespace Alastor.Server.Services.Network;

/// <summary>
/// Stores each host's latest network check and re-assesses SSH exposure with two things only the server knows: the
/// address the agent's requests arrive from (a public address on a host with only private ones means 1:1 NAT, so SSH
/// may still be reachable) and the host's effective <c>network.allowPublicSsh</c>, so accepting takes effect at once.
/// </summary>
public sealed class NetworkService(AlastorDbContext db, PolicyService policies, TimeProvider time)
{
    public const string ReportKind = "network";

    public async Task ReceiveAsync(Guid hostId, AgentReport report, CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var row = await db.HostReports.FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == ReportKind, ct);
        var json = JsonSerializer.Serialize(report, AgentJsonContext.Default.AgentReport);
        if (row is null) db.HostReports.Add(row = new HostReport { HostId = hostId, Kind = ReportKind, JobId = report.JobId, Json = json });
        // A failed check keeps the last good report; only the outcome changes.
        if (report.Success && report.Network is not null)
        {
            row.Json = json;
            row.StartedAt = report.StartedAtUtc;
        }
        row.JobId = report.JobId;
        row.Success = report.Success;
        row.Error = report.Error;
        row.FinishedAt = report.FinishedAtUtc;
        row.ReceivedAt = now;

        var host = await db.Hosts.FirstAsync(h => h.Id == hostId, ct);
        if (report.Success && report.Network is { } n)
        {
            Summarize(host, n, await AcceptedAsync(hostId, ct));
            host.NetworkCheckedAt = report.FinishedAtUtc;
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>The agent's facts, assessed with the server's view of the host.</summary>
    public static SshExposure Assess(ManagedHost host, NetworkReport report, bool accepted) =>
        ExposureAssessor.Assess(report.Ssh, report.Addresses, report.Firewall, report.Tailscale, host.ObservedAddress, accepted);

    public static NetworkReport? Read(HostReport? row) =>
        row is null ? null : JsonSerializer.Deserialize(row.Json, AgentJsonContext.Default.AgentReport)?.Network;

    /// <summary>Re-assesses after a policy change in <paramref name="scope"/> (allowPublicSsh may have changed).</summary>
    public async Task RefreshAsync(PolicyScope scope, Guid? targetId, CancellationToken ct)
    {
        var hostIds = scope switch
        {
            PolicyScope.Host when targetId is { } id => [id],
            PolicyScope.Group => await db.Hosts.Where(h => h.GroupId == targetId).Select(h => h.Id).ToListAsync(ct),
            _ => await db.Hosts.Select(h => h.Id).ToListAsync(ct),
        };
        var rows = await db.HostReports.AsNoTracking().Where(r => r.Kind == ReportKind && hostIds.Contains(r.HostId)).ToListAsync(ct);
        foreach (var row in rows)
        {
            if (Read(row) is not { } report) continue;
            var host = await db.Hosts.FirstAsync(h => h.Id == row.HostId, ct);
            Summarize(host, report, await AcceptedAsync(host.Id, ct));
        }
        await db.SaveChangesAsync(ct);
    }

    public async Task<bool> AcceptedAsync(Guid hostId, CancellationToken ct) =>
        (await policies.GetEffectiveAsync(hostId, ct)).Document.Network?.AllowPublicSsh == true;

    private static void Summarize(ManagedHost host, NetworkReport report, bool accepted)
    {
        var exposure = Assess(host, report, accepted);
        host.SshExposure = exposure.Level;
        host.SshExposureAccepted = accepted && exposure.Level is SshExposureLevel.Public or SshExposureLevel.PossiblyPublic;
        host.SshPasswordAuth = report.Ssh?.PasswordAuthentication;
        host.TailscaleState = report.Tailscale?.BackendState;
        host.TailscaleIp = report.Tailscale?.Ips.FirstOrDefault(i => !i.Contains(':')) ?? report.Tailscale?.Ips.FirstOrDefault();
    }
}
