using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Core.Policy;

namespace Sentinel.Core.Contracts;

// Wire contracts between agent and server (all under /api/agent/*). Agents only ever talk to their own
// server. Bans, desired state and commands are pulled by the agent; SignalR is only a "wake up now" nudge.

public sealed record EnrollRequest(
    string Token,
    string Hostname,
    string OsPrettyName,
    string OsId,
    string OsVersion,
    string Architecture,
    string AgentVersion,
    string? MachineId);

public sealed record EnrollResponse(Guid AgentId, string AgentSecret, int HeartbeatIntervalSeconds);

public sealed record HostMetrics(
    double CpuPercent,
    long MemoryTotalBytes,
    long MemoryUsedBytes,
    long DiskTotalBytes,
    long DiskUsedBytes,
    double Load1,
    double Load5,
    double Load15,
    long UptimeSeconds);

public sealed record HeartbeatRequest(
    string AgentVersion,
    string Hostname,
    string OsPrettyName,
    string KernelVersion,
    HostMetrics Metrics,
    IReadOnlyList<ToolStatus> Tools,
    PolicyApplyReport? Policy,
    IReadOnlyList<string> IpAddresses);

public sealed record HeartbeatResponse(
    string DesiredRevision,
    int PendingCommands,
    DateTime ServerTimeUtc,
    int HeartbeatIntervalSeconds);

public sealed record DesiredStateResponse(string Revision, PolicyDocument Policy);

public sealed record PolicyApplyReport(
    string Revision,
    bool Success,
    DateTime AppliedAtUtc,
    IReadOnlyList<ToolApplyReport> Tools);

public sealed record ToolApplyReport(string ToolId, bool Success, ConfigState State, string? Error, IReadOnlyList<string> Warnings, IReadOnlyList<string> Changes);

public sealed record EventBatch(IReadOnlyList<SecurityEvent> Events);

public sealed record EventBatchResult(int Accepted, int Duplicates);

public sealed record BanSnapshot(string ToolId, IReadOnlyList<BanEntry> Bans);

/// <summary>
/// The merged blocklist for one host: its policy's lists plus extra entries, minus the allowlist and reserved ranges,
/// as minimal CIDRs. Addressed by <see cref="Etag"/>: the agent sends <c>If-None-Match</c> and gets 304 when nothing changed.
/// </summary>
public sealed record BlocklistPayload(string Etag, DateTime GeneratedAtUtc, IReadOnlyList<BlocklistListInfo> Lists, IReadOnlyList<string> V4, IReadOnlyList<string> V6);

/// <summary>One source list as merged into a payload. <see cref="UpdatedAtUtc"/> is null if the server hasn't fetched it yet.</summary>
public sealed record BlocklistListInfo(string Id, int Entries, DateTime? UpdatedAtUtc, string? Error);

/// <summary>
/// The outcome of one scheduled job, posted to <c>/api/agent/reports</c>. Exactly one section is set, matching the job
/// (updates.* fill <see cref="Updates"/>, and so on); the server keeps the latest report per host and section.
/// </summary>
public sealed record AgentReport(string JobId, DateTime StartedAtUtc, DateTime FinishedAtUtc, bool Success, string? Error)
{
    public Sentinel.Core.Updates.UpdatesReport? Updates { get; init; }
}

public static class AgentCommandTypes
{
    public const string Ban = "ban";
    public const string Unban = "unban";

    /// <summary>Re-run reconciliation now, even if the revision is unchanged.</summary>
    public const string Reconcile = "reconcile";

    /// <summary>Overwrite hand-edited managed files with policy-rendered content.</summary>
    public const string Reclaim = "reclaim";

    public const string RefreshBans = "refresh-bans";

    /// <summary>Run the security baseline checks now and report the results.</summary>
    public const string BaselineCheck = "baseline-check";

    /// <summary>Run a scheduled job now. Payload: <c>job</c> = the job id (updates.check, updates.apply, …).</summary>
    public const string RunJob = "run-job";
}

public sealed record AgentCommand(Guid Id, string Type, IReadOnlyDictionary<string, string> Payload, DateTime CreatedAtUtc);

public sealed record AgentCommandResult(bool Success, string Message);

/// <summary>Methods the server invokes on agents over SignalR (<c>/hubs/agent</c>). All of them just mean "come and fetch".</summary>
public static class AgentHubMethods
{
    public const string Wake = "Wake";
}

[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(EnrollRequest))]
[JsonSerializable(typeof(EnrollResponse))]
[JsonSerializable(typeof(HeartbeatRequest))]
[JsonSerializable(typeof(HeartbeatResponse))]
[JsonSerializable(typeof(DesiredStateResponse))]
[JsonSerializable(typeof(PolicyApplyReport))]
[JsonSerializable(typeof(EventBatch))]
[JsonSerializable(typeof(EventBatchResult))]
[JsonSerializable(typeof(BanSnapshot))]
[JsonSerializable(typeof(List<AgentCommand>))]
[JsonSerializable(typeof(AgentCommandResult))]
[JsonSerializable(typeof(List<SecurityEvent>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(List<ToolStatus>))]
[JsonSerializable(typeof(Sentinel.Core.Baseline.BaselineReport))]
[JsonSerializable(typeof(BlocklistPayload))]
[JsonSerializable(typeof(AgentReport))]
[JsonSerializable(typeof(Sentinel.Core.Updates.UpdateApplyResult))]
public sealed partial class AgentJsonContext : JsonSerializerContext;
