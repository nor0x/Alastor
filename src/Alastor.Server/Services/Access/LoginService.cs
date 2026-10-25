using Microsoft.EntityFrameworkCore;
using Alastor.Core.Events;
using Alastor.Core.Net;
using Alastor.Server.Data;

namespace Alastor.Server.Services.Access;

/// <summary>
/// Learns which users log in to each host from where, from the agents' <c>auth.login</c> events, and raises
/// <c>auth.login-new-source</c> on a user's first login from an address: High, Critical for root. A host's first logins
/// after it starts reporting are learned silently (otherwise every admin would alert once), as are addresses in
/// <c>logins.trustedSources</c>. <c>logins.alertOnNewSource: false</c> keeps learning without alerting.
/// </summary>
public sealed class LoginService(AlastorDbContext db, PolicyService policies, EventIngestService ingest)
{
    /// <summary>Login events in a batch that the server hasn't stored yet, so a re-delivered batch never alerts twice.</summary>
    public async Task<List<SecurityEvent>> FreshAsync(IReadOnlyList<SecurityEvent> batch, CancellationToken ct)
    {
        var logins = batch.Where(e => e.Kind == EventKinds.Login).DistinctBy(e => e.Id).ToList();
        if (logins.Count == 0) return [];
        var ids = logins.Select(e => e.Id).ToList();
        var stored = (await db.Events.Where(e => ids.Contains(e.Id)).Select(e => e.Id).ToListAsync(ct)).ToHashSet();
        return logins.Where(e => !stored.Contains(e.Id)).ToList();
    }

    public async Task ProcessAsync(Guid hostId, IReadOnlyList<SecurityEvent> logins, CancellationToken ct)
    {
        if (logins.Count == 0) return;
        var host = await db.Hosts.AsNoTracking().FirstAsync(h => h.Id == hostId, ct);
        var policy = (await policies.GetEffectiveAsync(hostId, ct)).Document.Logins;
        var alert = policy?.AlertOnNewSource != false;
        var trusted = (policy?.TrustedSources ?? []).Select(t => IpTarget.TryParse(t, out var x) ? x : null).OfType<IpTarget>().ToList();
        var sources = await db.LoginSources.Where(s => s.HostId == hostId).ToDictionaryAsync(s => (s.User, s.Address), ct);
        var learning = sources.Count == 0;
        var raised = new List<SecurityEvent>();

        foreach (var e in logins.OrderBy(e => e.OccurredAt))
        {
            var user = Clip(e.Metadata.GetValueOrDefault("user") ?? "?", 64);
            var address = Clip(e.Subject ?? "?", 64);
            var method = Clip(e.Metadata.GetValueOrDefault("method") ?? "", 48);
            if (sources.TryGetValue((user, address), out var known))
            {
                if (e.OccurredAt > known.LastSeenAt) { known.LastSeenAt = e.OccurredAt; known.LastMethod = method; }
                known.Logins++;
                continue;
            }
            var isTrusted = IpTarget.TryParse(address, out var ip) && trusted.Any(t => t.Overlaps(ip.Value));
            var notify = alert && !learning && !isTrusted;
            sources[(user, address)] = known = new HostLoginSource
            {
                HostId = hostId, User = user, Address = address, FirstSeenAt = e.OccurredAt, LastSeenAt = e.OccurredAt, LastMethod = method, Logins = 1, Alerted = notify,
            };
            db.LoginSources.Add(known);
            if (!notify) continue;
            var firstForUser = !sources.Keys.Any(k => k.User == user && k.Address != address);
            raised.Add(new SecurityEvent
            {
                Id = SecurityEvent.StableId("login-new-source", e.Id.ToString()),
                OccurredAt = e.OccurredAt,
                Capability = Capability.Access,
                Severity = user == "root" ? Severity.Critical : Severity.High,
                SourceTool = "alastor-server",
                Kind = EventKinds.LoginNewSource,
                Subject = address,
                Message = firstForUser
                    ? $"First SSH login as {user} on {host.Name}, from {address} ({method}). If this wasn't you or a colleague, treat the host as compromised."
                    : $"{user} logged in to {host.Name} from a new address, {address} ({method}). Earlier logins came from elsewhere.",
                Metadata = new Dictionary<string, string> { ["user"] = user, ["method"] = method, ["key"] = e.Metadata.GetValueOrDefault("key") ?? "" },
                DedupKey = $"{EventKinds.LoginNewSource}:{user}:{address}",
            });
        }
        await db.SaveChangesAsync(ct);
        if (raised.Count > 0) await ingest.IngestAsync(hostId, raised, ct);
    }

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max];
}
