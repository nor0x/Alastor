using Alastor.Server.Services.Issues;
using Alastor.Server.Services.Posture;

namespace Alastor.Server.Services;

/// <summary>
/// Called after anything changes a host's denormalized state (a report, a heartbeat that changed tool health, presence,
/// a policy save that accepts a risk): refreshes today's posture snapshot and the host's open issues.
/// </summary>
public sealed class HostStateService(PostureService posture, IssueService issues)
{
    public Task ChangedAsync(Guid hostId, CancellationToken ct) => ChangedAsync([hostId], ct);

    /// <param name="hostIds">The hosts that changed; null for every host.</param>
    public async Task ChangedAsync(IReadOnlyCollection<Guid>? hostIds, CancellationToken ct)
    {
        await posture.SnapshotAsync(hostIds, ct);
        await issues.ReconcileAsync(hostIds, ct);
    }
}
