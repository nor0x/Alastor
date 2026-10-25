using Alastor.Core.Events;
using Alastor.Core.Net;
using Alastor.Core.Policy;

namespace Alastor.Core.Integrations;

/// <summary>
/// The contract every bundled tool (fail2ban, CrowdSec, Trivy, Grype, Lynis, unattended-upgrades, ClamAV,
/// Tailscale, ...) implements. The agent's supervisor only ever talks to tools through this interface, so a
/// tool can be swapped, disabled, or run standalone without touching the supervisor, server, or UI.
///
/// Lifecycle on every reconcile tick:
///   DetectAsync → (EnsureInstalledAsync) → PlanAsync(desired) → ApplyAsync(plan) → CollectEventsAsync
///
/// Rules every implementation follows:
///   * Consume the tool's own structured output (client commands, JSON, report files). Fall back to its
///     documented log format only where the tool offers nothing else.
///   * Only ever touch artifacts the integration owns: files carrying the <see cref="ManagedFile"/> marker,
///     one named firewall chain or ipset, and so on. Anything else is "foreign": read it, report conflicts,
///     never overwrite it.
///   * ApplyAsync is all-or-nothing: validate with the tool's own checker, swap atomically, reload, verify,
///     and roll back on any failure.
///   * Never throw for expected conditions (not installed, unsupported distro). Report them in <see cref="ToolStatus"/>.
/// </summary>
public interface IToolIntegration
{
    ToolDescriptor Descriptor { get; }

    /// <summary>Read-only probe: is the tool installed, which version, is it running, is its config ours, in sync, or drifted?</summary>
    Task<ToolStatus> DetectAsync(CancellationToken ct);

    /// <summary>
    /// Install the tool from distro repos if it is missing and <see cref="ReconcileRequest.AllowInstall"/> is set.
    /// If it is already present, adopt it (record it as pre-existing) instead.
    /// </summary>
    Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct);

    /// <summary>Whether the effective policy wants this tool at all. A disabled tool is still planned, so its managed state gets removed.</summary>
    bool IsWanted(PolicyDocument policy);

    /// <summary>Pure diff between desired policy and actual tool state. Has no side effects, so it can be unit tested and previewed in the dashboard.</summary>
    Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct);

    /// <summary>Executes a plan atomically, rolling back if the tool rejects the new configuration.</summary>
    Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct);

    /// <summary>Drains normalized events produced since the previous call. Must be cheap: it is called every few seconds.</summary>
    IAsyncEnumerable<SecurityEvent> CollectEventsAsync(CancellationToken ct);

    /// <summary>Removes everything the integration owns (managed files, chains), for uninstall. Leaves the tool itself installed.</summary>
    Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct);
}

/// <summary>Optional capability: tools that hold a ban list (fail2ban, CrowdSec, the agent's nftables blocklist).</summary>
public interface IBanProvider
{
    Task<IReadOnlyList<BanEntry>> ListBansAsync(CancellationToken ct);
    Task<CommandOutcome> BanAsync(IpTarget target, string? reason, CancellationToken ct);
    Task<CommandOutcome> UnbanAsync(IpTarget target, CancellationToken ct);
}

/// <summary>Static facts about a tool. These feed the capability matrix and the About page's license list.</summary>
public sealed record ToolDescriptor(
    string Id,
    string DisplayName,
    Capability Capability,
    string License,
    string Homepage,
    IReadOnlyDictionary<Platform.DistroFamily, string> Packages,
    string Description);

public enum Availability
{
    /// <summary>Installed, or installable from this distro's repos.</summary>
    Available,

    /// <summary>Not offered on this distro/arch (e.g. CrowdSec on Alpine), or the package install failed. See <see cref="ToolStatus.UnavailableReason"/>.</summary>
    Unavailable,

    /// <summary>Disabled by policy.</summary>
    Disabled,
}

public enum Ownership
{
    /// <summary>The agent installed the tool.</summary>
    Managed,

    /// <summary>The tool was already installed; the agent manages only its own config fragments.</summary>
    Adopted,

    NotInstalled,
}

public enum ConfigState
{
    Unknown,
    InSync,

    /// <summary>The desired revision has not been applied yet.</summary>
    Pending,

    /// <summary>Someone hand-edited a file the agent manages. The agent will not overwrite it until the dashboard says "reclaim".</summary>
    Drifted,

    /// <summary>A hand-written config overlaps settings the policy wants to manage. The overlapping part is skipped.</summary>
    Conflict,

    /// <summary>The tool rejected the last apply and the agent rolled back.</summary>
    Rejected,
}

public sealed record ToolStatus
{
    public required string ToolId { get; init; }
    public Availability Availability { get; init; } = Availability.Available;
    public string? UnavailableReason { get; init; }
    public bool Installed { get; init; }
    public string? Version { get; init; }
    public bool Running { get; init; }
    public Ownership Ownership { get; init; } = Ownership.NotInstalled;
    public ConfigState ConfigState { get; init; } = ConfigState.Unknown;
    public string? AppliedRevision { get; init; }
    public string? LastError { get; init; }

    /// <summary>The tool's last successful scan or reload, shown as "last good" in the capability matrix.</summary>
    public DateTime? LastSuccessAt { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = [];
    public IReadOnlyDictionary<string, string> Details { get; init; } = new Dictionary<string, string>();
}

/// <summary>One reconcile pass: the effective policy, its revision, and operator overrides.</summary>
public sealed record ReconcileRequest(PolicyDocument Policy, string Revision)
{
    /// <summary>Overwrite managed files even if they were hand-edited (the dashboard's "reclaim" action).</summary>
    public bool Reclaim { get; init; }

    public bool AllowInstall => Policy.Agent?.AutoInstall ?? true;
}

public enum ChangeKind
{
    WriteFile,
    DeleteFile,
    Reload,
    StartService,
}

public sealed record PlannedChange(ChangeKind Kind, string Target, string Description, string? Content = null);

/// <summary>Something the plan deliberately does not do, and why. <see cref="Kind"/> is an <see cref="EventKinds"/> value such as config.drift.</summary>
public sealed record PlanWarning(string Kind, string Message);

public sealed record ReconcilePlan(
    string ToolId,
    string Revision,
    IReadOnlyList<PlannedChange> Changes,
    IReadOnlyList<PlanWarning> Warnings,
    ConfigState ResultingState)
{
    public bool IsNoop => Changes.Count == 0;
}

public sealed record ReconcileResult(bool Success, ConfigState State, string? Error, IReadOnlyList<SecurityEvent> Events)
{
    public static ReconcileResult Ok(ConfigState state, params SecurityEvent[] events) => new(true, state, null, events);
}

public sealed record BanEntry(string Target, string Scope, DateTime? BannedAt, DateTime? ExpiresAt, bool Manual);

public sealed record CommandOutcome(bool Success, string Message);
