using Microsoft.AspNetCore.SignalR;
using Alastor.Server.Hubs;

namespace Alastor.Server.Services;

/// <summary>
/// Pushes live updates to browsers on <c>/hubs/dashboard</c>. Messages are small invalidation hints with
/// summaries. The SPA re-fetches over REST, so the polling fallback and the live path share one code path.
/// </summary>
public sealed class DashboardNotifier(IHubContext<DashboardHub> hub)
{
    public Task HostUpdatedAsync(object hostSummary, CancellationToken ct = default) =>
        hub.Clients.All.SendAsync("hostUpdated", hostSummary, ct);

    public Task EventsCreatedAsync(object events, CancellationToken ct = default) =>
        hub.Clients.All.SendAsync("eventsCreated", events, ct);

    public Task BansChangedAsync(Guid hostId, CancellationToken ct = default) =>
        hub.Clients.All.SendAsync("bansChanged", hostId, ct);

    public Task PolicyChangedAsync(CancellationToken ct = default) =>
        hub.Clients.All.SendAsync("policyChanged", ct);

    public Task CommandUpdatedAsync(object command, CancellationToken ct = default) =>
        hub.Clients.All.SendAsync("commandUpdated", command, ct);

    public Task BaselineUpdatedAsync(Guid hostId, CancellationToken ct = default) =>
        hub.Clients.All.SendAsync("baselineUpdated", hostId, ct);

    public Task FeedUpdatedAsync(object summary, CancellationToken ct = default) =>
        hub.Clients.All.SendAsync("feedUpdated", summary, ct);
}
