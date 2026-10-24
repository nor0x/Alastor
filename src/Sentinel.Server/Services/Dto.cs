using Sentinel.Core.Events;
using Sentinel.Core.Integrations;
using Sentinel.Server.Data;
using Sentinel.Server.Services.ThreatFeed;

namespace Sentinel.Server.Services;

// Dashboard-facing DTOs. Entities never leave the server directly.

public sealed record HostSummaryDto(
    Guid Id,
    string Name,
    string Hostname,
    string OsPrettyName,
    string Architecture,
    string AgentVersion,
    bool IsOnline,
    DateTime? LastSeenAt,
    double CpuPercent,
    double MemoryPercent,
    double DiskPercent,
    double Load1,
    Guid? GroupId,
    string? GroupName,
    IReadOnlyList<string> Tags,
    int ActiveBans,
    string PolicySync,
    int ToolsRunning,
    int ToolsWithProblems,
    int? BaselineScore,
    int BaselineFailing);

public sealed record ToolStatusDto(
    string ToolId,
    string DisplayName,
    Capability Capability,
    bool Implemented,
    bool OptIn,
    string License,
    Availability Availability,
    string? UnavailableReason,
    bool Installed,
    string? Version,
    bool Running,
    Ownership Ownership,
    ConfigState ConfigState,
    string? AppliedRevision,
    string? LastError,
    DateTime? LastSuccessAt,
    IReadOnlyList<string> Warnings,
    IReadOnlyDictionary<string, string> Details,
    DateTime? UpdatedAt);

public sealed record HostDetailDto(
    HostSummaryDto Summary,
    string OsId,
    string OsVersion,
    string KernelVersion,
    string? MachineId,
    IReadOnlyList<string> IpAddresses,
    DateTime EnrolledAt,
    long MemoryTotalBytes,
    long MemoryUsedBytes,
    long DiskTotalBytes,
    long DiskUsedBytes,
    double Load5,
    double Load15,
    long UptimeSeconds,
    string DesiredRevision,
    string? AppliedRevision,
    DateTime? PolicyAppliedAt,
    bool? PolicyApplySuccess,
    object? PolicyReport,
    IReadOnlyList<ToolStatusDto> Tools);

public sealed record EventDto(
    Guid Id,
    Guid? HostId,
    DateTime OccurredAt,
    Capability Capability,
    Severity Severity,
    string SourceTool,
    string Kind,
    string? Subject,
    string Message,
    string? Raw,
    IReadOnlyDictionary<string, string> Metadata,
    AlertDisposition Alert);

public sealed record BanDto(
    long Id,
    Guid HostId,
    string HostName,
    string ToolId,
    string Target,
    string Scope,
    DateTime? BannedAt,
    DateTime? ExpiresAt,
    bool Manual);

public sealed record CommandDto(
    Guid Id,
    Guid HostId,
    string Type,
    IReadOnlyDictionary<string, string> Payload,
    CommandStatus Status,
    DateTime CreatedAt,
    DateTime? CompletedAt,
    string? ResultMessage,
    string CreatedBy);

/// <summary>A threat-feed timeline entry. <c>Type</c> is <c>cve</c> or <c>news</c>; <c>Severity</c> is null for news and unscored CVEs.</summary>
public sealed record FeedItemDto(
    string Id,
    string Source,
    string SourceName,
    string Type,
    string Title,
    string Url,
    DateTime PublishedAt,
    string Summary,
    Severity? Severity,
    double? CvssScore,
    bool Exploited,
    IReadOnlyList<string> Tags,
    IReadOnlyList<string> Products);

public sealed record FeedSourceDto(
    string Id,
    string Name,
    string Kind,
    string Homepage,
    DateTime? LastSuccessAt,
    DateTime? LastAttemptAt,
    DateTime? NextAttemptAt,
    int ConsecutiveFailures,
    string? LastError,
    int Items);

/// <summary>A baseline check: catalog text plus, when for one host, that host's latest result (null fields before the first run).</summary>
public sealed record BaselineCheckDto(
    string Id,
    string Title,
    Sentinel.Core.Baseline.BaselineCategory Category,
    Severity Severity,
    string Why,
    string Expected,
    Sentinel.Core.Baseline.FixKind Fix,
    string Remediation,
    IReadOnlyList<string> PolicyPath,
    string PolicyValue,
    Sentinel.Core.Baseline.CheckStatus? Status,
    string? Actual,
    string? Detail,
    IReadOnlyList<string> Commands,
    bool Enforced,
    bool Accepted,
    DateTime? UpdatedAt,
    DateTime? FailingSince);

public sealed record HostBaselineDto(
    Guid HostId,
    string HostName,
    Guid? GroupId,
    int? Score,
    DateTime? CheckedAt,
    string? PolicyRevision,
    IReadOnlyList<BaselineCheckDto> Checks);

public sealed record BaselineHostRef(Guid Id, string Name, string Actual);

public sealed record BaselineHostDto(
    Guid Id,
    string Name,
    Guid? GroupId,
    string? GroupName,
    bool IsOnline,
    int? Score,
    DateTime? CheckedAt,
    int Failing,
    int FailingHighOrCritical);

/// <summary>One check across the fleet. <c>Failing</c> leaves out accepted risks, which are counted separately.</summary>
public sealed record BaselineFleetCheckDto(
    BaselineCheckDto Check,
    int Passing,
    int Failing,
    int Accepted,
    int Unknown,
    int NotApplicable,
    int Enforced,
    IReadOnlyList<BaselineHostRef> FailingHosts);

public sealed record BaselineFleetDto(
    double? AverageScore,
    int HostsReported,
    int HostsTotal,
    IReadOnlyList<BaselineHostDto> Hosts,
    IReadOnlyList<BaselineFleetCheckDto> Checks);

public static class Dto
{
    public static double Percent(long used, long total) => total <= 0 ? 0 : Math.Round(used * 100.0 / total, 1);

    public static EventDto Event(StoredEvent e) =>
        new(e.Id, e.HostId, e.OccurredAt, e.Capability, e.Severity, e.SourceTool, e.Kind, e.Subject, e.Message, e.Raw, e.Metadata, e.Alert);

    public static FeedItemDto FeedItem(FeedItem i) =>
        new(i.Id, i.Source, FeedSources.Find(i.Source)?.Name ?? i.Source, i.Type, i.Title, i.Url, i.PublishedAt, i.Summary, i.Severity, i.CvssScore,
            i.Exploited, i.Tags, i.Products);

    public static FeedSourceDto FeedSource(FeedSource s, FeedSourceState? state, int items) =>
        new(s.Id, s.Name, s.Kind.ToString().ToLowerInvariant(), s.Homepage, state?.LastSuccessAt, state?.LastAttemptAt, state?.NextAttemptAt,
            state?.ConsecutiveFailures ?? 0, state?.LastError, items);

    public static CommandDto Command(HostCommand c) =>
        new(c.Id, c.HostId, c.Type, c.Payload, c.Status, c.CreatedAt, c.CompletedAt, c.ResultMessage, c.CreatedBy);

    /// <summary>The capability matrix: every catalog tool, merged with what the host reported (or "not reported").</summary>
    public static IReadOnlyList<ToolStatusDto> ToolMatrix(IEnumerable<HostToolStatus> reported)
    {
        var byId = reported.ToDictionary(t => t.ToolId);
        return ToolCatalog.All.Select(entry =>
        {
            var d = entry.Descriptor;
            if (byId.TryGetValue(d.Id, out var t))
                return new ToolStatusDto(d.Id, d.DisplayName, d.Capability, entry.Implemented, entry.OptIn, d.License,
                    t.Availability, t.UnavailableReason, t.Installed, t.Version, t.Running, t.Ownership, t.ConfigState,
                    t.AppliedRevision, t.LastError, t.LastSuccessAt, t.Warnings, t.Details, t.UpdatedAt);
            return new ToolStatusDto(d.Id, d.DisplayName, d.Capability, entry.Implemented, entry.OptIn, d.License,
                entry.Implemented ? Availability.Available : Availability.Disabled,
                entry.Implemented ? "Not reported by the agent yet." : "Integration not implemented yet.",
                false, null, false, Ownership.NotInstalled, ConfigState.Unknown, null, null, null, [], new Dictionary<string, string>(), null);
        }).ToList();
    }
}
