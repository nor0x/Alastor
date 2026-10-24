using Sentinel.Core.Contracts;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;

namespace Sentinel.Server.Data;

public sealed class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Username { get; set; }
    public required string PasswordHash { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
}

/// <summary>Read-only API key. Only the SHA-256 hash is stored; the plaintext is shown once at creation.</summary>
public sealed class ApiKey
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public required string Prefix { get; set; }
    public required string KeyHash { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastUsedAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public required string CreatedBy { get; set; }
}

/// <summary>Single-use agent enrollment token. Stored hashed and consumed atomically.</summary>
public sealed class EnrollmentToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string TokenHash { get; set; }
    public string? Note { get; set; }
    public Guid? GroupId { get; set; }
    public List<string> Tags { get; set; } = [];
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public DateTime? ConsumedAt { get; set; }
    public Guid? ConsumedByHostId { get; set; }
    public required string CreatedBy { get; set; }
}

public sealed class HostGroup
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public sealed class ManagedHost
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public required string Hostname { get; set; }
    public required string SecretHash { get; set; }
    public string OsPrettyName { get; set; } = "";
    public string OsId { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public string KernelVersion { get; set; } = "";
    public string Architecture { get; set; } = "";
    public string AgentVersion { get; set; } = "";
    public string? MachineId { get; set; }
    public Guid? GroupId { get; set; }
    public HostGroup? Group { get; set; }
    public List<string> Tags { get; set; } = [];
    public List<string> IpAddresses { get; set; } = [];
    public DateTime EnrolledAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastSeenAt { get; set; }
    public bool IsOnline { get; set; }

    /// <summary>The effective agent.heartbeatInterval last sent to this host. Offline detection scales with it.</summary>
    public int HeartbeatIntervalSeconds { get; set; } = 60;

    // Latest metrics, denormalized for cheap list views.
    public double CpuPercent { get; set; }
    public long MemoryTotalBytes { get; set; }
    public long MemoryUsedBytes { get; set; }
    public long DiskTotalBytes { get; set; }
    public long DiskUsedBytes { get; set; }
    public double Load1 { get; set; }
    public double Load5 { get; set; }
    public double Load15 { get; set; }
    public long UptimeSeconds { get; set; }

    // Latest policy apply report from the agent.
    public string? AppliedRevision { get; set; }
    public DateTime? PolicyAppliedAt { get; set; }
    public bool? PolicyApplySuccess { get; set; }
    public string? PolicyReportJson { get; set; }

    public List<HostToolStatus> Tools { get; set; } = [];

    // Latest security baseline run, denormalized for list views. Null until the agent reports one.
    public int? BaselineScore { get; set; }
    public DateTime? BaselineCheckedAt { get; set; }
    public string? BaselineRevision { get; set; }
}

/// <summary>The latest result of one security baseline check on one host. Replaced as a set on every agent report.</summary>
public sealed class HostBaselineCheck
{
    public Guid HostId { get; set; }
    public required string CheckId { get; set; }
    public Sentinel.Core.Baseline.CheckStatus Status { get; set; }
    public string Actual { get; set; } = "";
    public string? Detail { get; set; }
    public List<string> Commands { get; set; } = [];
    public bool Enforced { get; set; }
    public bool Accepted { get; set; }
    public DateTime UpdatedAt { get; set; }

    /// <summary>When the check last went from passing (or unknown) to failing; null while it passes.</summary>
    public DateTime? FailingSince { get; set; }
}

public sealed class HostToolStatus
{
    public Guid HostId { get; set; }
    public required string ToolId { get; set; }
    public Availability Availability { get; set; }
    public string? UnavailableReason { get; set; }
    public bool Installed { get; set; }
    public string? Version { get; set; }
    public bool Running { get; set; }
    public Ownership Ownership { get; set; }
    public ConfigState ConfigState { get; set; }
    public string? AppliedRevision { get; set; }
    public string? LastError { get; set; }
    public DateTime? LastSuccessAt { get; set; }
    public List<string> Warnings { get; set; } = [];
    public Dictionary<string, string> Details { get; set; } = [];
    public DateTime UpdatedAt { get; set; }
}

public sealed class HostMetricSample
{
    public long Id { get; set; }
    public Guid HostId { get; set; }
    public DateTime At { get; set; }
    public double CpuPercent { get; set; }
    public double MemoryPercent { get; set; }
    public double DiskPercent { get; set; }
    public double Load1 { get; set; }
}

/// <summary>A <see cref="SecurityEvent"/> as stored by the server. The id comes from the agent, so re-delivery is idempotent.</summary>
public sealed class StoredEvent
{
    public Guid Id { get; set; }
    public Guid? HostId { get; set; }
    public DateTime OccurredAt { get; set; }
    public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;
    public Capability Capability { get; set; }
    public Severity Severity { get; set; }
    public required string SourceTool { get; set; }
    public required string Kind { get; set; }
    public string? Subject { get; set; }
    public required string Message { get; set; }
    public string? Raw { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = [];
    public required string DedupKey { get; set; }

    /// <summary>What the alert pipeline did with the event: sent to channels, or held back as a repeat.</summary>
    public AlertDisposition Alert { get; set; }
}

public enum AlertDisposition
{
    /// <summary>Below every channel's threshold, or no channel is configured.</summary>
    None,
    Notified,

    /// <summary>A repeat of an alert sent recently (leaky-bucket dedup). Counted in the next notification for the same key.</summary>
    Suppressed,
}

public static class ChannelTypes
{
    public const string Email = "email";
    public const string Webhook = "webhook";
    public const string Ntfy = "ntfy";
    public static readonly string[] All = [Email, Webhook, Ntfy];
}

/// <summary>A place alerts go. Type-specific settings live in <see cref="ConfigProtected"/>, encrypted with ASP.NET Core data protection.</summary>
public sealed class NotificationChannel
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }

    /// <summary>One of <see cref="ChannelTypes"/>.</summary>
    public required string Type { get; set; }

    public bool Enabled { get; set; } = true;

    /// <summary>Events below this severity are never sent to the channel.</summary>
    public Severity MinSeverity { get; set; } = Severity.Medium;

    /// <summary>Only these capabilities (empty: all).</summary>
    public List<string> Capabilities { get; set; } = [];

    /// <summary>Send each alert as it happens (after dedup). Turn off for a digest-only channel.</summary>
    public bool Immediate { get; set; } = true;

    /// <summary>Summary of everything since the last digest, as a <see cref="Sentinel.Core.Policy.Schedule"/> ("0 8 * * *", "every 1d", "off"). Server time zone.</summary>
    public string DigestSchedule { get; set; } = "off";

    public DateTime? LastDigestAt { get; set; }

    /// <summary>The <c>ChannelConfig</c> JSON, encrypted. Holds SMTP passwords, webhook secrets and ntfy tokens.</summary>
    public required string ConfigProtected { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastAttemptAt { get; set; }
    public DateTime? LastSuccessAt { get; set; }
    public string? LastError { get; set; }
}

/// <summary>Leaky-bucket state for one alert key (host + event dedup key). See <c>AlertBucketMath</c>.</summary>
public sealed class AlertBucket
{
    public required string Key { get; set; }
    public double Level { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? LastNotifiedAt { get; set; }
    public Severity LastSeverity { get; set; }

    /// <summary>Repeats held back since the last notification for this key.</summary>
    public int Suppressed { get; set; }
}

public sealed class NotificationDelivery
{
    public long Id { get; set; }
    public Guid ChannelId { get; set; }
    public DateTime At { get; set; }
    public required string Kind { get; set; }
    public required string Title { get; set; }
    public int EventCount { get; set; }
    public bool Success { get; set; }
    public int Attempts { get; set; }
    public string? Error { get; set; }
}

/// <summary>An active ban on a host, rebuilt from the agent's ban snapshots. History lives in <see cref="StoredEvent"/>.</summary>
public sealed class ActiveBan
{
    public long Id { get; set; }
    public Guid HostId { get; set; }
    public required string ToolId { get; set; }
    public required string Target { get; set; }

    /// <summary>The tool-specific bucket the ban lives in, such as a fail2ban jail or a CrowdSec scenario.</summary>
    public required string Scope { get; set; }

    public DateTime? BannedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public bool Manual { get; set; }
    public DateTime LastSeenAt { get; set; }
}

public sealed class AllowlistEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Target { get; set; }
    public string? Note { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public required string CreatedBy { get; set; }
}

public enum PolicyScope
{
    Global,
    Group,
    Host,
}

/// <summary>One policy layer (global, one group, or one host) with its immutable version history.</summary>
public sealed class PolicyLayer
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public PolicyScope Scope { get; set; }

    /// <summary>The group or host id; null for the global layer.</summary>
    public Guid? TargetId { get; set; }

    public int CurrentVersion { get; set; }
    public List<PolicyVersion> Versions { get; set; } = [];
}

public sealed class PolicyVersion
{
    public long Id { get; set; }
    public Guid LayerId { get; set; }
    public int Version { get; set; }
    public required string Yaml { get; set; }
    public string? Comment { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public required string CreatedBy { get; set; }
}

public enum CommandStatus
{
    Pending,
    Delivered,
    Succeeded,
    Failed,
    Expired,
}

public sealed class HostCommand
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid HostId { get; set; }
    public required string Type { get; set; }
    public Dictionary<string, string> Payload { get; set; } = [];
    public CommandStatus Status { get; set; } = CommandStatus.Pending;
    public int Attempts { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? DeliveredAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public string? ResultMessage { get; set; }
    public required string CreatedBy { get; set; }

    public AgentCommand ToContract() => new(Id, Type, Payload, CreatedAt);
}

public sealed class AuditEntry
{
    public long Id { get; set; }
    public DateTime At { get; set; } = DateTime.UtcNow;
    public required string Actor { get; set; }
    public required string Action { get; set; }
    public string? Target { get; set; }
    public string? Details { get; set; }
}

public static class FeedItemTypes
{
    public const string Cve = "cve";
    public const string News = "news";
}

/// <summary>
/// One threat-feed timeline entry: a CVE (NVD, CISA KEV) or a news article (RSS). The id is derived from the
/// source's own item id (the CVE id, or a hash of the RSS guid), so re-fetching the same item updates it in place.
/// A CVE has one row no matter which source saw it first; NVD and KEV merge into it.
/// </summary>
public sealed class FeedItem
{
    public required string Id { get; set; }

    /// <summary>Source id from <see cref="Services.ThreatFeed.FeedSources"/> that created the item, e.g. <c>nvd</c>, <c>cisa-kev</c>, <c>bleepingcomputer</c>.</summary>
    public required string Source { get; set; }

    /// <summary><see cref="FeedItemTypes.Cve"/> or <see cref="FeedItemTypes.News"/>.</summary>
    public required string Type { get; set; }

    /// <summary>The source's own id: the CVE id, or the RSS guid (falling back to the link).</summary>
    public required string SourceItemId { get; set; }

    public required string Title { get; set; }
    public required string Url { get; set; }

    /// <summary>Timeline date in UTC. For a CVE that CISA added to KEV after publication, the KEV date: that is when it became news.</summary>
    public DateTime PublishedAt { get; set; }

    public DateTime FetchedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string Summary { get; set; } = "";

    /// <summary>CVSS severity for CVEs (null until NVD scores it); always null for news.</summary>
    public Severity? Severity { get; set; }

    public double? CvssScore { get; set; }

    /// <summary>The CVE, or a CVE the article mentions, is in the CISA Known Exploited Vulnerabilities catalog.</summary>
    public bool Exploited { get; set; }

    public List<string> Tags { get; set; } = [];

    /// <summary>Affected vendor/product names (CVEs only).</summary>
    public List<string> Products { get; set; } = [];

    /// <summary>CVE ids the item is about or mentions. Used to flag news as exploited when a referenced CVE is in KEV.</summary>
    public List<string> CveIds { get; set; } = [];

    /// <summary>Lower-cased title, summary, tags and products. Lets free-text search stay case-insensitive on both SQLite and PostgreSQL.</summary>
    public string SearchText { get; set; } = "";

    /// <summary>Lower-cased tags as <c>|a|b|</c>, so tag filters are a portable substring match instead of a JSON query.</summary>
    public string TagIndex { get; set; } = "|";
}

/// <summary>One entry of the CISA Known Exploited Vulnerabilities catalog, kept so exploited flags survive restarts and 304 responses.</summary>
public sealed class KevEntry
{
    public required string CveId { get; set; }
    public string VendorProject { get; set; } = "";
    public string Product { get; set; } = "";
    public string VulnerabilityName { get; set; } = "";
    public string ShortDescription { get; set; } = "";
    public DateTime DateAdded { get; set; }
    public DateTime? DueDate { get; set; }
    public bool KnownRansomwareUse { get; set; }
    public List<string> Cwes { get; set; } = [];
}

/// <summary>Fetch bookkeeping per threat-feed source: schedule, backoff, HTTP validators and the NVD cursor.</summary>
/// <summary>One public blocklist as last fetched by the server. <see cref="Content"/> holds the normalized CIDRs, one per line.</summary>
public sealed class BlocklistSourceState
{
    public required string SourceId { get; set; }
    public DateTime? LastAttemptAt { get; set; }
    public DateTime? LastSuccessAt { get; set; }

    /// <summary>When the content last changed (a 304 or identical body counts as a success, not a change).</summary>
    public DateTime? LastChangedAt { get; set; }

    public DateTime? NextAttemptAt { get; set; }
    public int ConsecutiveFailures { get; set; }
    public string? LastError { get; set; }
    public int EntryCount { get; set; }
    public long Ipv4Addresses { get; set; }

    /// <summary>Lines that weren't an address, and entries refused as wider than /8 (IPv4) or /16 (IPv6).</summary>
    public int Skipped { get; set; }

    /// <summary>ETag / Last-Modified per URL, as JSON, for conditional requests.</summary>
    public string? Validators { get; set; }

    public string Content { get; set; } = "";
    public string? ContentHash { get; set; }
}

public sealed class FeedSourceState
{
    public required string SourceId { get; set; }
    public DateTime? LastAttemptAt { get; set; }
    public DateTime? LastSuccessAt { get; set; }
    public DateTime? NextAttemptAt { get; set; }
    public int ConsecutiveFailures { get; set; }
    public string? LastError { get; set; }
    public int LastItemCount { get; set; }
    public string? ETag { get; set; }
    public string? LastModified { get; set; }

    /// <summary>NVD only: end of the last fully fetched lastModified window. The next run continues from here.</summary>
    public DateTime? Cursor { get; set; }
}
