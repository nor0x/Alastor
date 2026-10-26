using System.Security.Cryptography;
using System.Text;

namespace Alastor.Core.Events;

/// <summary>Severity scale shared by every bundled tool. Normalizers map tool-specific levels onto it.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>What the platform does for a host. Each bundled tool provides exactly one capability.</summary>
public enum Capability
{
    Agent,
    Banning,
    Blocklist,
    Firewall,
    Updates,
    Vulnerabilities,
    Hardening,
    Network,
    Malware,

    /// <summary>Who logs in: successful SSH logins and first-seen sources.</summary>
    Access,

    /// <summary>File integrity: system binaries and configuration compared with a baseline (AIDE).</summary>
    Integrity,

    /// <summary>Disk space: what uses it, and cleanups that free it.</summary>
    Storage,
}

/// <summary>
/// The single normalized event model. Every bundled tool's output (fail2ban bans, CrowdSec decisions,
/// Trivy findings, Lynis suggestions, update-agent runs, ...) is translated into this shape on the agent,
/// so the server's alert pipeline, storage and UI never need tool-specific code.
/// </summary>
public sealed record SecurityEvent
{
    /// <summary>Generated on the agent; the server treats re-sent ids as duplicates, which makes delivery retry-safe.</summary>
    public required Guid Id { get; init; }

    /// <summary>When the tool says it happened, in UTC (not when we read it).</summary>
    public required DateTime OccurredAt { get; init; }

    public required Capability Capability { get; init; }

    public required Severity Severity { get; init; }

    /// <summary>Tool id from <see cref="Integrations.ToolDescriptor.Id"/>, e.g. <c>fail2ban</c>, <c>trivy</c>, or <c>alastor-agent</c>.</summary>
    public required string SourceTool { get; init; }

    /// <summary>Dotted, tool-independent event type. See <see cref="EventKinds"/>.</summary>
    public required string Kind { get; init; }

    /// <summary>The primary entity the event is about: an IP/CIDR, a CVE id, a package or a check id.</summary>
    public string? Subject { get; init; }

    /// <summary>A one-line, human-readable summary.</summary>
    public required string Message { get; init; }

    /// <summary>The original tool output this event came from, kept verbatim for forensics.</summary>
    public string? Raw { get; init; }

    /// <summary>Structured, tool-specific details such as the jail, ban time, CVSS score or package version.</summary>
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// The key the server's leaky-bucket dedup groups by. Events with the same host and dedup key count as
    /// repeats of one alert. Defaults to tool + kind + subject; normalizers can narrow it, e.g. by adding the jail.
    /// </summary>
    public string DedupKey { get; init; } = "";

    public string EffectiveDedupKey => string.IsNullOrEmpty(DedupKey) ? $"{SourceTool}:{Kind}:{Subject}" : DedupKey;

    /// <summary>Deterministic id derived from content. Re-reading the same log line after a restart yields the same id.</summary>
    public static Guid StableId(params string?[] parts)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\u001f', parts)));
        return new Guid(bytes.AsSpan(0, 16));
    }
}

/// <summary>Well-known values for <see cref="SecurityEvent.Kind"/>. Tools may add their own under their prefix.</summary>
public static class EventKinds
{
    // Banning (fail2ban, CrowdSec)
    public const string BanAdded = "ban.added";
    public const string BanRemoved = "ban.removed";
    public const string BanIncreased = "ban.increased";
    public const string BanRestored = "ban.restored";
    public const string AuthFailures = "auth.failures";

    // Access (SSH logins)
    /// <summary>A successful SSH login (Info). The server learns each host's (user, address) pairs from these.</summary>
    public const string Login = "auth.login";
    /// <summary>Raised by the server: the first login of a user from an address on this host.</summary>
    public const string LoginNewSource = "auth.login-new-source";

    // Tool and agent lifecycle
    public const string ToolError = "tool.error";
    public const string ToolInstalled = "tool.installed";
    public const string ToolAdopted = "tool.adopted";
    public const string ToolDown = "tool.down";
    public const string ToolUnavailable = "tool.unavailable";
    public const string ConfigApplied = "config.applied";
    public const string ConfigDrift = "config.drift";
    public const string ConfigConflict = "config.conflict";
    public const string ConfigRejected = "config.rejected";
    public const string HostOffline = "host.offline";
    public const string HostOnline = "host.online";
    public const string HostEnrolled = "host.enrolled";

    // Security baseline
    public const string BaselineFailed = "baseline.failed";
    public const string BaselineResolved = "baseline.resolved";
    public const string BaselineSummary = "baseline.summary";

    // Updates
    public const string UpdatesPending = "updates.pending";
    public const string UpdatesApplied = "updates.applied";
    public const string UpdatesFailed = "updates.failed";
    public const string RebootRequired = "updates.reboot-required";
    /// <summary>Services still run code from libraries or binaries an update replaced (needrestart, needs-restarting).</summary>
    public const string RestartRequired = "updates.restart-required";

    // Software (single-package upgrades and uninstalls from the dashboard)
    public const string SoftwareUpgraded = "software.upgraded";
    public const string SoftwareRemoved = "software.removed";
    public const string SoftwareFailed = "software.failed";

    // Storage
    /// <summary>Raised by the server: the root filesystem passed 90% used.</summary>
    public const string StorageLow = "storage.low";
    public const string StorageCleaned = "storage.cleaned";
    public const string StorageCleanupFailed = "storage.cleanup-failed";

    // Vulnerabilities
    /// <summary>A scan found new fixable vulnerabilities at or above <c>vulnerabilities.alertSeverity</c>.</summary>
    public const string VulnerabilitiesFound = "vulnerabilities.found";
    /// <summary>Raised by the server: a host has a CVE that is in CISA's Known Exploited Vulnerabilities catalog.</summary>
    public const string VulnerabilitiesExploited = "vulnerabilities.exploited";

    // Hardening (Lynis)
    /// <summary>A Lynis audit reported warnings it didn't report last time.</summary>
    public const string HardeningWarning = "hardening.warning";
    /// <summary>The Lynis hardening index dropped by 5 points or more since the previous audit.</summary>
    public const string HardeningRegressed = "hardening.regressed";

    // Network exposure
    /// <summary>SSH became reachable from the internet (and the host doesn't set network.allowPublicSsh).</summary>
    public const string ExposureDetected = "exposure.detected";
    /// <summary>The host's Tailscale node key expires soon, after which it drops off the tailnet.</summary>
    public const string TailscaleKeyExpiring = "tailscale.key-expiring";
    /// <summary>A service other than SSH became reachable from the internet and isn't in <c>network.allowPublicPorts</c>.</summary>
    public const string ServiceExposed = "exposure.service";

    // File integrity and rootkits
    /// <summary>AIDE found files added, removed or changed since the accepted baseline.</summary>
    public const string IntegrityChanged = "integrity.changed";
    /// <summary>rkhunter reported a warning it hadn't reported before.</summary>
    public const string RootkitWarning = "malware.rootkit-warning";

    // Reserved for later deliverables.
    public const string VulnerabilityFound = "vuln.found";
    public const string HardeningFinding = "hardening.finding";
    public const string MalwareFound = "malware.found";
}
