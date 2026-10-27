using Alastor.Core.Policy;

namespace Alastor.Server;

/// <summary>
/// Server-level configuration. Every key can be set as an environment variable (ALASTOR_DATADIR,
/// ALASTOR_RETENTIONRUNINTERVAL=30m, …) or in the "Alastor" section of appsettings.json.
/// Durations use the same format as policy YAML: 30s, 5m, 1h, 7d, 2w.
/// Per-host timings (heartbeat, scans, update checks, …) live in the policy instead, so they can differ per group/host.
/// </summary>
public sealed class AlastorOptions
{
    public const string Section = "Alastor";

    /// <summary>Holds the SQLite database, the JWT signing key and data-protection keys. Defaults to ./data next to the binary.</summary>
    public string DataDir { get; set; } = Path.Combine(AppContext.BaseDirectory, "data");

    /// <summary><c>sqlite</c> (default) or <c>postgres</c>.</summary>
    public string DatabaseProvider { get; set; } = "sqlite";

    /// <summary>Connection string. Defaults to <c>Data Source={DataDir}/alastor.db</c> for SQLite.</summary>
    public string? ConnectionString { get; set; }

    /// <summary>Admin account created on first start if no user exists.</summary>
    public string AdminUser { get; set; } = "admin";

    public string? AdminPassword { get; set; }

    /// <summary>The URL agents and browsers use to reach this server. Used in install commands shown in the UI.</summary>
    public string? PublicUrl { get; set; }

    /// <summary>Agent binaries (alastor-agent-linux-x64, -arm64, SHA256SUMS) served at /install/agent/ to hosts being installed. Defaults to ./agent next to the binary.</summary>
    public string AgentDownloadDir { get; set; } = Path.Combine(AppContext.BaseDirectory, "agent");

    /// <summary>Set the session cookie's Secure flag. Turn off only for plain-HTTP local development.</summary>
    public bool SecureCookies { get; set; } = true;

    /// <summary>
    /// Where the dashboard drops start/stop requests for this machine's server and agent, which the installer's root
    /// <c>alastor-control.path</c> unit carries out. Set by the installer's systemd unit; empty (Docker, dev) turns it off.
    /// </summary>
    public string ControlDir { get; set; } = "";

    // ---- network access ----

    /// <summary>
    /// Who may reach the dashboard (SPA, /api, /hubs/dashboard, /openapi): a comma list of <c>any</c>, <c>loopback</c>,
    /// <c>private</c>, <c>tailnet</c> and CIDRs. Anyone else gets a bare 404 before authentication.
    /// </summary>
    public string DashboardAllowFrom { get; set; } = "loopback,private,tailnet";

    /// <summary>Who may reach the agent API (/api/agent, /hubs/agent, /install): same format as <see cref="DashboardAllowFrom"/>.</summary>
    public string AgentAllowFrom { get; set; } = "loopback,private,tailnet";

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

    /// <summary>Daily posture snapshots (baseline score, CVE counts, …) behind the dashboard's trend charts.</summary>
    public string PostureRetention { get; set; } = "365d";

    /// <summary>Audit log entries (logins, settings and policy changes, actions).</summary>
    public string AuditRetention { get; set; } = "365d";

    /// <summary>Known SSH login sources (user + address per host) not seen for this long are forgotten; the next login from one alerts again.</summary>
    public string LoginSourceRetention { get; set; } = "365d";

    /// <summary>Policy versions kept per layer (the current one is always kept).</summary>
    public int PolicyVersionsKeep { get; set; } = 50;

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

    // ---- blocklists (pulled by the server, merged per host, served to agents) ----

    /// <summary>Fetch public IP blocklists. Only lists some policy uses are fetched. Turn off for air-gapped servers (extra entries still work).</summary>
    public bool BlocklistsEnabled { get; set; } = true;

    /// <summary>How often each list in use is re-fetched (conditional GET). Providers ask for no more than hourly.</summary>
    public string BlocklistRefreshInterval { get; set; } = "4h";

    // ---- OSV.dev (known vulnerabilities for the software inventory) ----

    /// <summary>Look up installed package versions on OSV.dev (only names and versions are sent). Turn off for air-gapped servers.</summary>
    public bool OsvEnabled { get; set; } = true;

    // ---- update check ----

    /// <summary>Check GitHub for a newer Alastor release twice a day. Only the release list is fetched; nothing about this server is sent. Turn off for air-gapped servers.</summary>
    public bool UpdateCheckEnabled { get; set; } = true;

    /// <summary>GitHub repository (owner/name) whose releases the update check looks at.</summary>
    public string UpdateRepository { get; set; } = "nor0x/Alastor";

    // ---- vulnerability databases ----

    /// <summary>Mirror the Trivy/Grype databases for agents. Only scanners some agent asks for are fetched. Turn off for air-gapped servers and place the files by hand.</summary>
    public bool VulnDbEnabled { get; set; } = true;

    /// <summary>How often a mirrored database is checked for a newer build (Trivy publishes every 6 h, Grype daily).</summary>
    public string VulnDbRefreshInterval { get; set; } = "12h";

    /// <summary>OCI reference of Trivy's database. <c>mirror.gcr.io/aquasec/trivy-db:2</c> is Aqua's official mirror.</summary>
    public string TrivyDbRepository { get; set; } = "ghcr.io/aquasecurity/trivy-db:2";

    /// <summary>Base URL of Grype's database listing (<c>{url}/v6/latest.json</c>).</summary>
    public string GrypeDbUrl { get; set; } = "https://grype.anchore.io/databases";

    /// <summary>freshclam binary the server runs to mirror ClamAV's signatures (only once some host scans for malware).</summary>
    public string FreshclamPath { get; set; } = "freshclam";

    /// <summary>The ClamAV mirror freshclam downloads from.</summary>
    public string ClamAvMirror { get; set; } = "database.clamav.net";

    // ---- alerts ----

    /// <summary>Leaky-bucket dedup: the same alert (host + event key) is sent at most <see cref="AlertBurst"/> times per window; repeats are counted and summarized.</summary>
    public string AlertDedupWindow { get; set; } = "1h";

    public int AlertBurst { get; set; } = 1;

    // Parsed values. Validate() runs at startup, so these never see bad input.
    public TimeSpan HeartbeatIntervalValue => Parse(HeartbeatInterval);
    public TimeSpan PresenceCheckIntervalValue => Parse(PresenceCheckInterval);
    public TimeSpan RetentionRunIntervalValue => Parse(RetentionRunInterval);
    public TimeSpan MetricRetentionValue => Parse(MetricRetention);
    public TimeSpan EventRetentionValue => Parse(EventRetention);
    public TimeSpan PostureRetentionValue => Parse(PostureRetention);
    public TimeSpan AuditRetentionValue => Parse(AuditRetention);
    public TimeSpan LoginSourceRetentionValue => Parse(LoginSourceRetention);
    public TimeSpan EnrollmentTokenTtlValue => Parse(EnrollmentTokenTtl);
    public TimeSpan CommandRedeliverAfterValue => Parse(CommandRedeliverAfter);
    public TimeSpan PendingCommandTtlValue => Parse(PendingCommandTtl);
    public TimeSpan SessionLifetimeValue => Parse(SessionLifetime);
    public TimeSpan ThreatFeedIntervalValue => Parse(ThreatFeedInterval);
    public TimeSpan ThreatFeedRetentionValue => Parse(ThreatFeedRetention);
    public TimeSpan AlertDedupWindowValue => Parse(AlertDedupWindow);
    public TimeSpan BlocklistRefreshIntervalValue => Parse(BlocklistRefreshInterval);
    public TimeSpan VulnDbRefreshIntervalValue => Parse(VulnDbRefreshInterval);

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
        Check(nameof(PostureRetention), PostureRetention, TimeSpan.FromDays(7), TimeSpan.FromDays(3650));
        Check(nameof(AuditRetention), AuditRetention, TimeSpan.FromDays(7), TimeSpan.FromDays(3650));
        Check(nameof(LoginSourceRetention), LoginSourceRetention, TimeSpan.FromDays(7), TimeSpan.FromDays(3650));
        if (PolicyVersionsKeep is < 1 or > 10_000) errors.Add("PolicyVersionsKeep must be between 1 and 10000.");
        foreach (var (name, value) in new[] { (nameof(DashboardAllowFrom), DashboardAllowFrom), (nameof(AgentAllowFrom), AgentAllowFrom) })
            if (!Auth.NetworkAllowList.TryParse(value, out _, out var why)) errors.Add($"{name}='{value}': {why}");
        Check(nameof(EnrollmentTokenTtl), EnrollmentTokenTtl, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30));
        Check(nameof(CommandRedeliverAfter), CommandRedeliverAfter, TimeSpan.FromSeconds(30), TimeSpan.FromDays(1));
        Check(nameof(PendingCommandTtl), PendingCommandTtl, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30));
        Check(nameof(SessionLifetime), SessionLifetime, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30));
        Check(nameof(ThreatFeedInterval), ThreatFeedInterval, TimeSpan.FromMinutes(5), TimeSpan.FromDays(1));
        Check(nameof(ThreatFeedRetention), ThreatFeedRetention, TimeSpan.FromDays(1), TimeSpan.FromDays(365));
        Check(nameof(BlocklistRefreshInterval), BlocklistRefreshInterval, TimeSpan.FromHours(1), TimeSpan.FromDays(7));
        Check(nameof(VulnDbRefreshInterval), VulnDbRefreshInterval, TimeSpan.FromHours(1), TimeSpan.FromDays(7));
        if (!Uri.TryCreate(GrypeDbUrl, UriKind.Absolute, out var g) || g.Scheme != Uri.UriSchemeHttps) errors.Add("GrypeDbUrl must be an https:// URL.");
        if (!System.Text.RegularExpressions.Regex.IsMatch(UpdateRepository ?? "", @"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")) errors.Add("UpdateRepository must be a GitHub repository like owner/name.");
        if (!Alastor.Server.Services.Vulnerabilities.OciReference.TryParse(TrivyDbRepository, out _)) errors.Add("TrivyDbRepository must look like registry/repository:tag, e.g. ghcr.io/aquasecurity/trivy-db:2.");
        Check(nameof(AlertDedupWindow), AlertDedupWindow, TimeSpan.FromMinutes(1), TimeSpan.FromDays(7));
        if (AlertBurst is < 1 or > 100) errors.Add("AlertBurst must be between 1 and 100.");
        if (OfflineAfterMissedHeartbeats is < 1 or > 100) errors.Add("OfflineAfterMissedHeartbeats must be between 1 and 100.");
        if (CommandMaxAttempts is < 1 or > 100) errors.Add("CommandMaxAttempts must be between 1 and 100.");
        if (AuthRateLimitPerMinute is < 1 or > 10_000) errors.Add("AuthRateLimitPerMinute must be between 1 and 10000.");
        return errors;
    }

    private static TimeSpan Parse(string value) =>
        Duration.TryParseSeconds(value, out var s) && s > 0 ? TimeSpan.FromSeconds(s) : throw new InvalidOperationException($"Invalid duration '{value}'");
}
