using Sentinel.Core.Policy;

namespace Sentinel.Server;

/// <summary>
/// Server-level configuration. Every key can be set as an environment variable (SENTINEL_DATADIR,
/// SENTINEL_RETENTIONRUNINTERVAL=30m, …) or in the "Sentinel" section of appsettings.json.
/// Durations use the same format as policy YAML: 30s, 5m, 1h, 7d, 2w.
/// Per-host timings (heartbeat, scans, update checks, …) live in the policy instead, so they can differ per group/host.
/// </summary>
public sealed class SentinelOptions
{
    public const string Section = "Sentinel";

    /// <summary>Holds the SQLite database, the JWT signing key and data-protection keys. Defaults to ./data next to the binary.</summary>
    public string DataDir { get; set; } = Path.Combine(AppContext.BaseDirectory, "data");

    /// <summary><c>sqlite</c> (default) or <c>postgres</c>.</summary>
    public string DatabaseProvider { get; set; } = "sqlite";

    /// <summary>Connection string. Defaults to <c>Data Source={DataDir}/sentinel.db</c> for SQLite.</summary>
    public string? ConnectionString { get; set; }

    /// <summary>Admin account created on first start if no user exists.</summary>
    public string AdminUser { get; set; } = "admin";

    public string? AdminPassword { get; set; }

    /// <summary>The URL agents and browsers use to reach this server. Used in install commands shown in the UI.</summary>
    public string? PublicUrl { get; set; }

    /// <summary>Set the session cookie's Secure flag. Turn off only for plain-HTTP local development.</summary>
    public bool SecureCookies { get; set; } = true;

    // ---- timings ----

    /// <summary>Default agent heartbeat when the policy sets no agent.heartbeatInterval.</summary>
    public string HeartbeatInterval { get; set; } = "60s";

    /// <summary>A host is marked offline after this many missed heartbeats (of its own effective interval).</summary>
    public int OfflineAfterMissedHeartbeats { get; set; } = 3;

    /// <summary>How often the server checks for hosts that stopped sending heartbeats.</summary>
    public string PresenceCheckInterval { get; set; } = "30s";

    /// <summary>How often old metrics, events and expired bans are pruned.</summary>
    public string RetentionRunInterval { get; set; } = "1h";

    public string MetricRetention { get; set; } = "7d";
    public string EventRetention { get; set; } = "90d";

    /// <summary>Default lifetime of a new enrollment token (the dashboard can choose a different one per token).</summary>
    public string EnrollmentTokenTtl { get; set; } = "24h";

    /// <summary>A command an agent fetched but never acknowledged is re-delivered after this long…</summary>
    public string CommandRedeliverAfter { get; set; } = "5m";

    /// <summary>…at most this many times, then it is marked expired.</summary>
    public int CommandMaxAttempts { get; set; } = 3;

    /// <summary>Commands for hosts that stay offline expire after this, so a host returning weeks later doesn't replay stale bans.</summary>
    public string PendingCommandTtl { get; set; } = "24h";

    /// <summary>Dashboard session (JWT cookie) lifetime.</summary>
    public string SessionLifetime { get; set; } = "12h";

    /// <summary>Login and enrollment attempts allowed per client IP per minute.</summary>
    public int AuthRateLimitPerMinute { get; set; } = 10;

    // ---- threat feed (CVEs and security news, fetched by the server) ----

    /// <summary>Fetch NVD, CISA KEV and security news RSS. Turn off for air-gapped servers.</summary>
    public bool ThreatFeedEnabled { get; set; } = true;

    /// <summary>How often each feed source is fetched after a success. Failures back off on their own schedule.</summary>
    public string ThreatFeedInterval { get; set; } = "20m";

    /// <summary>Feed items older than this are pruned and not fetched.</summary>
    public string ThreatFeedRetention { get; set; } = "30d";

    /// <summary>Optional NVD API key (free, https://nvd.nist.gov/developers/request-an-api-key). Raises NVD's rate limit tenfold.</summary>
    public string? NvdApiKey { get; set; }

    // Parsed values. Validate() runs at startup, so these never see bad input.
    public TimeSpan HeartbeatIntervalValue => Parse(HeartbeatInterval);
    public TimeSpan PresenceCheckIntervalValue => Parse(PresenceCheckInterval);
    public TimeSpan RetentionRunIntervalValue => Parse(RetentionRunInterval);
    public TimeSpan MetricRetentionValue => Parse(MetricRetention);
    public TimeSpan EventRetentionValue => Parse(EventRetention);
    public TimeSpan EnrollmentTokenTtlValue => Parse(EnrollmentTokenTtl);
    public TimeSpan CommandRedeliverAfterValue => Parse(CommandRedeliverAfter);
    public TimeSpan PendingCommandTtlValue => Parse(PendingCommandTtl);
    public TimeSpan SessionLifetimeValue => Parse(SessionLifetime);
    public TimeSpan ThreatFeedIntervalValue => Parse(ThreatFeedInterval);
    public TimeSpan ThreatFeedRetentionValue => Parse(ThreatFeedRetention);

    /// <summary>When a host with the given heartbeat interval counts as offline.</summary>
    public TimeSpan OfflineAfter(TimeSpan heartbeat) => heartbeat * OfflineAfterMissedHeartbeats + TimeSpan.FromSeconds(15);

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        void Check(string name, string value, TimeSpan min, TimeSpan max)
        {
            if (!Duration.TryParseSeconds(value, out var s) || s == Duration.Permanent)
                errors.Add($"{name}='{value}' is not a duration (examples: 30s, 5m, 1h, 7d).");
            else if (TimeSpan.FromSeconds(s) < min || TimeSpan.FromSeconds(s) > max)
                errors.Add($"{name}='{value}' must be between {Duration.Format((long)min.TotalSeconds)} and {Duration.Format((long)max.TotalSeconds)}.");
        }
        Check(nameof(HeartbeatInterval), HeartbeatInterval, TimeSpan.FromSeconds(10), TimeSpan.FromHours(1));
        Check(nameof(PresenceCheckInterval), PresenceCheckInterval, TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(30));
        Check(nameof(RetentionRunInterval), RetentionRunInterval, TimeSpan.FromMinutes(1), TimeSpan.FromDays(1));
        Check(nameof(MetricRetention), MetricRetention, TimeSpan.FromHours(1), TimeSpan.FromDays(3650));
        Check(nameof(EventRetention), EventRetention, TimeSpan.FromHours(1), TimeSpan.FromDays(3650));
        Check(nameof(EnrollmentTokenTtl), EnrollmentTokenTtl, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30));
        Check(nameof(CommandRedeliverAfter), CommandRedeliverAfter, TimeSpan.FromSeconds(30), TimeSpan.FromDays(1));
        Check(nameof(PendingCommandTtl), PendingCommandTtl, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30));
        Check(nameof(SessionLifetime), SessionLifetime, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30));
        Check(nameof(ThreatFeedInterval), ThreatFeedInterval, TimeSpan.FromMinutes(5), TimeSpan.FromDays(1));
        Check(nameof(ThreatFeedRetention), ThreatFeedRetention, TimeSpan.FromDays(1), TimeSpan.FromDays(365));
        if (OfflineAfterMissedHeartbeats is < 1 or > 100) errors.Add("OfflineAfterMissedHeartbeats must be between 1 and 100.");
        if (CommandMaxAttempts is < 1 or > 100) errors.Add("CommandMaxAttempts must be between 1 and 100.");
        if (AuthRateLimitPerMinute is < 1 or > 10_000) errors.Add("AuthRateLimitPerMinute must be between 1 and 10000.");
        return errors;
    }

    private static TimeSpan Parse(string value) =>
        Duration.TryParseSeconds(value, out var s) && s > 0 ? TimeSpan.FromSeconds(s) : throw new InvalidOperationException($"Invalid duration '{value}'");
}
