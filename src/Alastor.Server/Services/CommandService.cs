using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Contracts;
using Alastor.Server.Data;
using Alastor.Server.Hubs;

namespace Alastor.Server.Services;

/// <summary>
/// Queues commands for agents and nudges them over SignalR. Delivery is always pull-based: an agent that
/// missed the nudge (SignalR down, polling fallback) sees <c>PendingCommands &gt; 0</c> in its next heartbeat.
/// </summary>
public sealed class CommandService(AlastorDbContext db, IHubContext<AgentHub> agentHub, TimeProvider time)
{
    public async Task<IReadOnlyList<HostCommand>> QueueAsync(IEnumerable<Guid> hostIds, string type, Dictionary<string, string> payload, string actor, CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var created = hostIds.Distinct().Select(h => new HostCommand
        {
            HostId = h,
            Type = type,
            Payload = new Dictionary<string, string>(payload),
            CreatedBy = actor,
            CreatedAt = now,
        }).ToList();
        db.Commands.AddRange(created);
        await db.SaveChangesAsync(ct);
        foreach (var c in created) await WakeAsync(c.HostId, "command", ct);
        return created;
    }

    public Task WakeAsync(Guid hostId, string reason, CancellationToken ct) =>
        agentHub.Clients.Group(AgentHub.GroupFor(hostId)).SendAsync(AgentHubMethods.Wake, reason, ct);

    public async Task WakeAffectedAsync(PolicyScope scope, Guid? targetId, string reason, CancellationToken ct)
    {
        switch (scope)
        {
            case PolicyScope.Global:
                await agentHub.Clients.Group(AgentHub.AllAgentsGroup).SendAsync(AgentHubMethods.Wake, reason, ct);
                break;
            case PolicyScope.Group:
                foreach (var id in await db.Hosts.Where(h => h.GroupId == targetId).Select(h => h.Id).ToListAsync(ct))
                    await WakeAsync(id, reason, ct);
                break;
            case PolicyScope.Host when targetId is { } hostId:
                await WakeAsync(hostId, reason, ct);
                break;
        }
    }

    public Task WakeAllAsync(string reason, CancellationToken ct) =>
        agentHub.Clients.Group(AgentHub.AllAgentsGroup).SendAsync(AgentHubMethods.Wake, reason, ct);
}
