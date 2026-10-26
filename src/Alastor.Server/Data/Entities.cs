using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrations;

namespace Alastor.Server.Data;

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

    // Latest update check, denormalized for list views. Null until the agent reports one.
    public int? PendingUpdates { get; set; }

    /// <summary>Null when the distribution doesn't mark security updates (Alpine).</summary>
    public int? SecurityUpdates { get; set; }

    public bool RebootRequired { get; set; }
    public DateTime? UpdatesCheckedAt { get; set; }

    // Latest software inventory, denormalized for list views. Null until the agent reports one.
    public int? PackagesTotal { get; set; }
    public int? PackagesManual { get; set; }
    public DateTime? SoftwareCollectedAt { get; set; }

    // Latest CVE scan, denormalized for list views (accepted risks excluded). Null until a scan succeeds.
    public int? VulnCritical { get; set; }
    public int? VulnHigh { get; set; }
    public int? VulnTotal { get; set; }

    /// <summary>Findings a package update fixes.</summary>
    public int? VulnFixable { get; set; }

    // Container images scanned with vulnerabilities.scanContainers (not in the counts above, which are the host's own packages).
    public int? ImagesScanned { get; set; }
    public int? ImageVulnCritical { get; set; }
    public int? ImageVulnHigh { get; set; }

    public DateTime? VulnScannedAt { get; set; }

    // Latest Lynis audit, denormalized for list views (accepted items excluded from the counts).
    public int? HardeningIndex { get; set; }
    public int? HardeningWarnings { get; set; }
    public int? HardeningSuggestions { get; set; }
    public DateTime? HardeningAuditedAt { get; set; }

    /// <summary>The address the agent's requests come from, as this server sees it. Reveals 1:1 NAT in clouds.</summary>
    public string? ObservedAddress { get; set; }

    // Latest network check (SSH exposure, Tailscale), denormalized for list views.
    public Alastor.Core.Network.SshExposureLevel? SshExposure { get; set; }
    public bool SshExposureAccepted { get; set; }
    public bool? SshPasswordAuth { get; set; }
    public string? TailscaleState { get; set; }
    public string? TailscaleIp { get; set; }
    public DateTime? NetworkCheckedAt { get; set; }

    /// <summary>Services still running code that updates replaced (needrestart, needs-restarting). Null when the host can't tell.</summary>
    public List<string>? ServicesNeedingRestart { get; set; }

    /// <summary>
    /// Services reachable from the internet that aren't SSH and aren't in <c>network.allowPublicPorts</c>, as
    /// "6379/tcp redis-server" (the owner may be missing). Null until an agent reports its services.
    /// </summary>
    public List<string>? PublicServices { get; set; }

    // Latest ClamAV scan.
    public int? MalwareFindings { get; set; }
    public DateTime? MalwareScannedAt { get; set; }

    // Latest AIDE check: files changed since the accepted baseline, and how many are binaries, SSH or account files.
    public int? IntegrityChanges { get; set; }
    public int? IntegrityCritical { get; set; }
    public DateTime? IntegrityCheckedAt { get; set; }

    // Latest rkhunter check: Medium-and-up warnings not in malware.rootkitIgnore, and the worst one's severity.
    public int? RootkitWarnings { get; set; }
    public Severity? RootkitSeverity { get; set; }
    public DateTime? RootkitCheckedAt { get; set; }
}

/// <summary>One Lynis warning or suggestion on one host, from the latest audit. Replaced as a set per audit.</summary>
public sealed class HostHardeningItem
{
    public long Id { get; set; }
    public Guid HostId { get; set; }
    public required string TestId { get; set; }
    public Alastor.Core.Hardening.LynisItemKind Kind { get; set; }
    public required string Text { get; set; }
    public string? Details { get; set; }
    public string? Solution { get; set; }

    /// <summary>The test id is in the host's effective <c>hardening.ignore</c>. Refreshed when policy changes.</summary>
    public bool Accepted { get; set; }

    public DateTime FirstSeenAt { get; set; }
}

/// <summary>One CVE in one installed package on one host, from the latest successful scan. Replaced as a set per scan.</summary>
public sealed class HostVulnerability
{
    public long Id { get; set; }
    public Guid HostId { get; set; }
    public required string VulnId { get; set; }
    public required string Package { get; set; }
    public string Installed { get; set; } = "";
    public string? Fixed { get; set; }
    public Severity Severity { get; set; }
    public double? Cvss { get; set; }
    public Alastor.Core.Vulnerabilities.FixState Fix { get; set; }
    public string? Title { get; set; }
    public string PkgType { get; set; } = "";
    public string? Path { get; set; }

    /// <summary>The container image the package is in; null for the host's own packages.</summary>
    public string? Image { get; set; }

    /// <summary>Listed in the host's effective <c>vulnerabilities.ignore</c>. Refreshed when policy changes.</summary>
    public bool Accepted { get; set; }

    /// <summary>First scan that reported this (id, package, path) on the host. Kept across scans.</summary>
    public DateTime FirstSeenAt { get; set; }
}

/// <summary>One installed package on one host, from the latest software inventory. Replaced as a set per inventory.</summary>
public sealed class HostPackage
{
    public long Id { get; set; }
    public Guid HostId { get; set; }
    public required string Name { get; set; }
    public required string Version { get; set; }
    public string? Arch { get; set; }

    /// <summary>The source package (Debian <c>Source:</c>, SRPM name, apk origin): what OSV and the distro trackers key on.</summary>
    public string? Source { get; set; }

    /// <summary>Installed on purpose rather than as a dependency (apt-mark showmanual, dnf userinstalled, apk world).</summary>
    public bool Manual { get; set; }

    /// <summary>The dashboard never uninstalls it (essential, kernel, SSH, package manager).</summary>
    public bool Protected { get; set; }

    public long? SizeKb { get; set; }
}

/// <summary>What OSV.dev knows about one package version in one ecosystem (<c>Debian:12</c>, <c>AlmaLinux:9</c>). Shared by every host that has it.</summary>
public sealed class OsvPackageResult
{
    public required string Ecosystem { get; set; }
    public required string Package { get; set; }
    public required string Version { get; set; }

    /// <summary>OSV ids (DSA-…, USN-…, ALSA-…, CVE-…) affecting this version. Empty means none known.</summary>
    public List<string> VulnIds { get; set; } = [];

    public DateTime CheckedAt { get; set; }
}

/// <summary>One OSV advisory, fetched once and refreshed when OSV says it changed.</summary>
public sealed class OsvVulnerability
{
    public required string Id { get; set; }
    public string? Summary { get; set; }

    /// <summary>From the CVSS vector, or the distribution's own rating; null when OSV has neither.</summary>
    public Severity? Severity { get; set; }

    public double? Cvss { get; set; }

    /// <summary>CVE ids and other names for the same issue, used to merge it with the scanner's findings.</summary>
    public List<string> Aliases { get; set; } = [];

    /// <summary>The first fixed version per <c>ecosystem/package</c>.</summary>
    public Dictionary<string, string> Fixed { get; set; } = [];

    public DateTime? Modified { get; set; }
    public DateTime FetchedAt { get; set; }
}

/// <summary>The latest report of one kind (updates, vulnerabilities, hardening, …) from one host's scheduled jobs, as JSON.</summary>
public sealed class HostReport
{
    public Guid HostId { get; set; }
    public required string Kind { get; set; }
    public required string JobId { get; set; }
    public bool Success { get; set; }
    public string? Error { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime FinishedAt { get; set; }
    public DateTime ReceivedAt { get; set; }
    public required string Json { get; set; }
}

/// <summary>The latest result of one security baseline check on one host. Replaced as a set on every agent report.</summary>
public sealed class HostBaselineCheck
{
    public Guid HostId { get; set; }
    public required string CheckId { get; set; }
    public Alastor.Core.Baseline.CheckStatus Status { get; set; }
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

/// <summary>
/// One host's security posture on one UTC day: the latest values seen that day, copied from the host's denormalized
/// columns. Written whenever a report or heartbeat changes them and carried forward daily, so trends survive the
/// latest-only report tables. Feeds the dashboard's trend charts.
/// </summary>
public sealed class HostPostureSnapshot
{
    public Guid HostId { get; set; }
    public DateOnly Day { get; set; }
    public DateTime UpdatedAt { get; set; }
    public bool Online { get; set; }
    public int? BaselineScore { get; set; }
    public int? HardeningIndex { get; set; }
    public int? VulnCritical { get; set; }
    public int? VulnHigh { get; set; }

    /// <summary>Open findings that are in CISA's Known Exploited Vulnerabilities catalog.</summary>
    public int? VulnKev { get; set; }

    /// <summary>Pending security updates (all pending updates on distributions without a security flag).</summary>
    public int? SecurityUpdates { get; set; }

    public bool RebootRequired { get; set; }

    /// <summary>SSH reachable from the internet and not accepted. Null until a network check ran.</summary>
    public bool? PublicSsh { get; set; }

    /// <summary>Unexpected public services (see <see cref="ManagedHost.PublicServices"/>).</summary>
    public int? PublicServices { get; set; }

    /// <summary>Files changed since the AIDE baseline; null until the host runs AIDE.</summary>
    public int? IntegrityChanges { get; set; }

    /// <summary>Open rkhunter warnings; null until the host runs rkhunter.</summary>
    public int? RootkitWarnings { get; set; }

    public int? MalwareFindings { get; set; }
}

/// <summary>
/// An open (or since resolved) problem on one host, such as public SSH, a known-exploited CVE or malware. Derived on the
/// server from the host's current state by <see cref="Alastor.Server.Services.Issues.IssueRules"/>, so it closes on
/// its own when the condition clears. One row per host, rule and subject: a condition that comes back reopens it.
/// </summary>
public sealed class HostIssue
{
    public long Id { get; set; }
    public Guid HostId { get; set; }

    /// <summary>Rule id, e.g. <c>ssh.public</c> or <c>cve.exploited</c>. See <see cref="Alastor.Server.Services.Issues.IssueRules"/>.</summary>
    public required string Rule { get; set; }

    /// <summary>What the issue is about within the rule (a CVE id, check id or tool id); empty when the rule has one issue per host.</summary>
    public string Subject { get; set; } = "";

    public Severity Severity { get; set; }
    public required string Title { get; set; }
    public string? Detail { get; set; }

    /// <summary>The host detail tab that shows the cause and the fix.</summary>
    public string Tab { get; set; } = "overview";

    public DateTime FirstSeenAt { get; set; }
    public DateTime LastSeenAt { get; set; }
    public DateTime? ResolvedAt { get; set; }

    /// <summary>How many times the condition has opened. Reopening clears the acknowledgement.</summary>
    public int Occurrences { get; set; } = 1;

    public DateTime? AcknowledgedAt { get; set; }
    public string? AcknowledgedBy { get; set; }
    public string? AckNote { get; set; }
}

/// <summary>A (user, address) pair that has logged in to a host over SSH, learned from <c>auth.login</c> events.</summary>
public sealed class HostLoginSource
{
    public Guid HostId { get; set; }
    public required string User { get; set; }
    public required string Address { get; set; }
    public DateTime FirstSeenAt { get; set; }
    public DateTime LastSeenAt { get; set; }
    public string LastMethod { get; set; } = "";
    public int Logins { get; set; }

    /// <summary>The first login raised <c>auth.login-new-source</c> (false while the host's sources were still being learned, or for trusted sources).</summary>
    public bool Alerted { get; set; }
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

    /// <summary>Summary of everything since the last digest, as a <see cref="Alastor.Core.Policy.Schedule"/> ("0 8 * * *", "every 1d", "off"). Server time zone.</summary>
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

    /// <summary>Structured result JSON from commands that return one (a package dry run).</summary>
    public string? ResultDetail { get; set; }

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
