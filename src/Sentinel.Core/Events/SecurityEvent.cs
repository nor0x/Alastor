using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Core.Events;

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

    /// <summary>Tool id from <see cref="Integrations.ToolDescriptor.Id"/>, e.g. <c>fail2ban</c>, <c>trivy</c>, or <c>sentinel-agent</c>.</summary>
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

    // Reserved for later deliverables.
    public const string VulnerabilityFound = "vuln.found";
    public const string HardeningFinding = "hardening.finding";
    public const string MalwareFound = "malware.found";
    public const string ExposureDetected = "exposure.detected";
}
