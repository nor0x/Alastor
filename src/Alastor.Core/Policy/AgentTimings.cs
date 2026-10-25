namespace Alastor.Core.Policy;

/// <summary>
/// The agent's loop timings, resolved from <c>agent.*</c> in the effective policy, with defaults and safe bounds.
/// The server uses the same type to tell the agent its heartbeat interval and to decide when a host counts as offline.
/// </summary>
public sealed record AgentTimings(
    TimeSpan HeartbeatInterval,
    TimeSpan DriftCheckInterval,
    TimeSpan EventFlushInterval,
    TimeSpan BanSnapshotInterval,
    TimeSpan ScheduleSpread,
    TimeSpan OfflineGracePeriod)
{
    public static readonly AgentTimings Default = new(
        TimeSpan.FromSeconds(60), TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(5),
        TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), TimeSpan.FromHours(24));

    /// <summary>(key, value, min, max) for each loop timing. Validation and resolution share this table.</summary>
    internal static IEnumerable<(string Key, string? Value, TimeSpan Min, TimeSpan Max)> Bounds(AgentPolicy a) =>
    [
        ("heartbeatInterval", a.HeartbeatInterval, TimeSpan.FromSeconds(10), TimeSpan.FromHours(1)),
        ("driftCheckInterval", a.DriftCheckInterval, TimeSpan.FromMinutes(1), TimeSpan.FromDays(1)),
        ("eventFlushInterval", a.EventFlushInterval, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(10)),
        ("banSnapshotInterval", a.BanSnapshotInterval, TimeSpan.FromSeconds(30), TimeSpan.FromDays(1)),
        ("scheduleSpread", a.ScheduleSpread, TimeSpan.Zero, TimeSpan.FromHours(12)),
    ];

    public static AgentTimings From(PolicyDocument? policy, TimeSpan? defaultHeartbeat = null)
    {
        var a = policy?.Agent ?? new AgentPolicy();
        var d = Default with { HeartbeatInterval = defaultHeartbeat ?? Default.HeartbeatInterval };
        TimeSpan Get(string? value, TimeSpan fallback, TimeSpan min, TimeSpan max) =>
            Duration.TryParseSeconds(value, out var s) && s >= 0
                ? TimeSpan.FromSeconds(Math.Clamp(s, (long)min.TotalSeconds, (long)max.TotalSeconds))
                : fallback;
        var b = Bounds(a).ToDictionary(x => x.Key);
        return new AgentTimings(
            Get(a.HeartbeatInterval, d.HeartbeatInterval, b["heartbeatInterval"].Min, b["heartbeatInterval"].Max),
            Get(a.DriftCheckInterval, d.DriftCheckInterval, b["driftCheckInterval"].Min, b["driftCheckInterval"].Max),
            Get(a.EventFlushInterval, d.EventFlushInterval, b["eventFlushInterval"].Min, b["eventFlushInterval"].Max),
            Get(a.BanSnapshotInterval, d.BanSnapshotInterval, b["banSnapshotInterval"].Min, b["banSnapshotInterval"].Max),
            Get(a.ScheduleSpread, d.ScheduleSpread, b["scheduleSpread"].Min, b["scheduleSpread"].Max),
            !Duration.TryParseSeconds(a.OfflineGracePeriod, out var g) ? d.OfflineGracePeriod
            : g == Duration.Permanent ? TimeSpan.MaxValue   // never release server-pushed state
            : TimeSpan.FromSeconds(g));
    }
}
