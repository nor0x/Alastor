namespace Sentinel.Core.Policy;

/// <summary>
/// Declarative per-host configuration. Layers (global, then group, then host) are stored as YAML and merged
/// into one effective document, which the agent reconciles each bundled tool against.
/// Every property is nullable so a layer can override just the keys it sets.
/// Sections for later capabilities (updates, scans, ...) are added here as those integrations land.
/// </summary>
public sealed class PolicyDocument
{
    public AgentPolicy? Agent { get; set; }
    public BanningPolicy? Banning { get; set; }
    public UpdatesPolicy? Updates { get; set; }
    public VulnerabilitiesPolicy? Vulnerabilities { get; set; }
    public HardeningPolicy? Hardening { get; set; }
    public MalwarePolicy? Malware { get; set; }

    public PolicyDocument Clone() => PolicyMerger.Merge(new PolicyDocument(), this);
}

public sealed class AgentPolicy
{
    /// <summary>
    /// How long the agent keeps server-pushed firewall state after losing contact with the server. After this,
    /// it removes its own nftables chain and ipsets (blocklists). Local fail2ban protection keeps running.
    /// </summary>
    public string? OfflineGracePeriod { get; set; }

    /// <summary>Install missing bundled tools from distro repos (true), or only adopt tools that are already installed (false).</summary>
    public bool? AutoInstall { get; set; }

    // Agent loop timings. Every one is a duration, with defaults and bounds in AgentTimings.

    /// <summary>How often the agent reports metrics and tool health, and polls for policy and commands.</summary>
    public string? HeartbeatInterval { get; set; }

    /// <summary>How often the agent re-checks tools for drift (hand edits, a stopped daemon) without a policy change.</summary>
    public string? DriftCheckInterval { get; set; }

    /// <summary>How often new tool events (bans, failures) are read and shipped to the server.</summary>
    public string? EventFlushInterval { get; set; }

    /// <summary>Upper bound between ban-list snapshots. Changes are always pushed at the next event flush.</summary>
    public string? BanSnapshotInterval { get; set; }

    /// <summary>
    /// Scheduled jobs (scans, audits, update checks) are offset per host by a stable amount in [0, scheduleSpread),
    /// so a fleet doesn't run heavy work in the same minute.
    /// </summary>
    public string? ScheduleSpread { get; set; }
}

// Schedules for capabilities that land in later deliverables. Every recurring action has a Schedule-typed key
// ("every 6h", "0 3 * * *", or "off"); see Schedule.cs. Feature-specific settings join these sections with their integration.

public sealed class UpdatesPolicy
{
    /// <summary>How often pending security updates are counted (unattended-upgrades / dnf-automatic / apk).</summary>
    public string? CheckSchedule { get; set; }

    /// <summary>When pending security updates are installed automatically. "off" means report only; apply via "Apply now".</summary>
    public string? ApplySchedule { get; set; }
}

public sealed class VulnerabilitiesPolicy
{
    /// <summary>Trivy/Grype scan of the package inventory.</summary>
    public string? ScanSchedule { get; set; }
}

public sealed class HardeningPolicy
{
    /// <summary>Lynis audit.</summary>
    public string? AuditSchedule { get; set; }
}

public sealed class MalwarePolicy
{
    /// <summary>ClamAV scan of web roots and upload directories (opt-in, so off by default).</summary>
    public string? ScanSchedule { get; set; }
}

public sealed class BanningPolicy
{
    public bool? Enabled { get; set; }

    /// <summary><c>fail2ban</c> (default) or <c>crowdsec</c> (opt-in, deliverable 10).</summary>
    public string? Engine { get; set; }

    /// <summary>IPs/CIDRs never banned. Merged as a union across layers, plus the server's global allowlist.</summary>
    public List<string>? Allowlist { get; set; }

    public JailSettings? Defaults { get; set; }

    /// <summary>Jails by name. Keys match fail2ban jail names (sshd, nginx-http-auth, postfix, ...).</summary>
    public Dictionary<string, JailSettings>? Jails { get; set; }

    /// <summary>Ban time for bans issued from the dashboard. Defaults to permanent.</summary>
    public string? ManualBantime { get; set; }
}

public sealed class JailSettings
{
    public bool? Enabled { get; set; }
    public string? Bantime { get; set; }
    public string? Findtime { get; set; }
    public int? Maxretry { get; set; }

    /// <summary>fail2ban action, e.g. <c>nftables</c>, <c>ufw</c>, <c>iptables-multiport</c>.</summary>
    public string? Banaction { get; set; }

    public bool? BantimeIncrement { get; set; }
    public string? BantimeMaxtime { get; set; }
    public double? BantimeFactor { get; set; }

    // Per-jail only (ignored in defaults). Usually supplied by the distro's jail.conf.
    public string? Filter { get; set; }
    public string? Port { get; set; }
    public string? Logpath { get; set; }
    public string? Backend { get; set; }

    /// <summary>
    /// Off by default: if the admin already configures this jail in a hand-written <c>.local</c> file,
    /// the agent leaves the jail alone and reports a conflict. Set to true to let SentinelVPS manage it.
    /// </summary>
    public bool? Takeover { get; set; }
}
