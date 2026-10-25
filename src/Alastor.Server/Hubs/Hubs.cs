using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Alastor.Server.Auth;

namespace Alastor.Server.Hubs;

/// <summary>
/// Agents connect here to receive "wake" nudges. The hub has no methods: agents do all data exchange over
/// REST, so SignalR being blocked (proxies, firewalls) only costs latency, never functionality.
/// </summary>
[Authorize(Policy = AuthPolicies.Agent)]
public sealed class AgentHub(ILogger<AgentHub> logger) : Hub
{
    public const string AllAgentsGroup = "agents";
    public static string GroupFor(Guid hostId) => $"host:{hostId}";

    public override async Task OnConnectedAsync()
    {
        var hostId = Context.User!.HostId();
        await Groups.AddToGroupAsync(Context.ConnectionId, GroupFor(hostId));
        await Groups.AddToGroupAsync(Context.ConnectionId, AllAgentsGroup);
        logger.LogDebug("Agent {HostId} connected via {Transport}", hostId, Context.Features.Get<Microsoft.AspNetCore.Http.Connections.Features.IHttpTransportFeature>()?.TransportType);
        await base.OnConnectedAsync();
    }
}

/// <summary>Browsers subscribe here for live updates. See <see cref="Services.DashboardNotifier"/> for the messages.</summary>
[Authorize(Policy = AuthPolicies.Reader)]
public sealed class DashboardHub : Hub;
