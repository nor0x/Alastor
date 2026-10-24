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

public static class AgentCommandTypes
{
    public const string Ban = "ban";
    public const string Unban = "unban";

    /// <summary>Re-run reconciliation now, even if the revision is unchanged.</summary>
    public const string Reconcile = "reconcile";

    /// <summary>Overwrite hand-edited managed files with policy-rendered content.</summary>
    public const string Reclaim = "reclaim";

    public const string RefreshBans = "refresh-bans";
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
public sealed partial class AgentJsonContext : JsonSerializerContext;
