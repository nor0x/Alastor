using Alastor.Core.Network;
using Alastor.Server.Data;

namespace Alastor.Server.Services.Posture;

/// <summary>
/// The fleet's host × capability grid: one judgement per area (ok, warn, bad, unknown, off) with a short label, so the
/// dashboard can show where the fleet stands at a glance. Pure: thresholds live here and are unit tested.
/// </summary>
public static class PostureMatrix
{
    public const string Ok = "ok", Warn = "warn", Bad = "bad", Unknown = "unknown", Off = "off";

    public sealed record Column(string Key, string Label, string Tab);

    public sealed record Cell(string Status, string Label);

    /// <summary>Facts that don't live on the host row.</summary>
    public sealed record Extra(bool FailingHighBaseline, int Kev);

    public static readonly IReadOnlyList<Column> Columns =
    [
        new("agent", "Agent", "overview"),
        new("banning", "Banning", "bans"),
        new("baseline", "Baseline", "baseline"),
        new("hardening", "Hardening", "hardening"),
        new("network", "Exposure", "network"),
        new("updates", "Updates", "updates"),
        new("vulnerabilities", "CVEs", "vulnerabilities"),
        new("malware", "Malware", "malware"),
    ];

    public static Dictionary<string, Cell> Row(ManagedHost h, Extra x) => new()
    {
        ["agent"] = Agent(h),
        ["banning"] = Banning(h),
        ["baseline"] = h.BaselineScore is not { } score ? new(Unknown, "not checked")
            : x.FailingHighBaseline ? new(Bad, $"{score} · high fails")
            : new(score >= 80 ? Ok : Warn, $"{score}"),
        ["hardening"] = h.HardeningIndex is not { } idx ? new(Unknown, "not audited")
            : new(idx >= 75 ? Ok : idx >= 60 ? Warn : Bad, $"{idx}"),
        ["network"] = h.NetworkCheckedAt is null ? new(Unknown, "not checked")
            : h.SshExposureAccepted ? new(Ok, "accepted")
            : h.SshExposure switch
            {
                SshExposureLevel.Public => new(Bad, "public SSH"),
                SshExposureLevel.PossiblyPublic => new(Warn, "SSH maybe public"),
                SshExposureLevel.Unknown => new(Unknown, "unknown"),
                _ => new(Ok, "not public"),
            },
        ["updates"] = Updates(h),
        ["vulnerabilities"] = h.VulnScannedAt is null ? new(Unknown, "not scanned")
            : x.Kev > 0 ? new(Bad, $"{x.Kev} exploited")
            : h.VulnCritical > 0 ? new(Bad, $"{h.VulnCritical} critical")
            : h.VulnHigh > 0 ? new(Warn, $"{h.VulnHigh} high")
            : new(Ok, "none high"),
        ["malware"] = h.MalwareScannedAt is null ? new(Off, "off")
            : h.MalwareFindings > 0 ? new(Bad, $"{h.MalwareFindings} found")
            : new(Ok, "clean"),
    };

    private static Cell Agent(ManagedHost h)
    {
        if (!h.IsOnline) return new(Bad, "offline");
        if (h.PolicyApplySuccess == false) return new(Bad, "policy failed");
        var problems = h.Tools.Count(Dto.HasProblem);
        if (problems > 0) return new(Warn, problems == 1 ? "1 tool problem" : $"{problems} tool problems");
        return h.AppliedRevision is null ? new(Warn, "policy pending") : new(Ok, "healthy");
    }

    private static Cell Banning(ManagedHost h)
    {
        var tool = h.Tools.FirstOrDefault(t => t.ToolId is "crowdsec" && t.Availability != Core.Integrations.Availability.Disabled)
                   ?? h.Tools.FirstOrDefault(t => t.ToolId is "fail2ban");
        if (tool is null) return new(Unknown, "not reported");
        if (tool.Availability == Core.Integrations.Availability.Disabled) return new(Off, "off");
        if (Dto.HasProblem(tool)) return new(Bad, tool.Installed && !tool.Running ? $"{tool.ToolId} down" : $"{tool.ToolId} problem");
        return tool.Running ? new(Ok, tool.ToolId) : new(Unknown, tool.ToolId);
    }

    private static Cell Updates(ManagedHost h)
    {
        if (h.PendingUpdates is null) return new(Unknown, "not checked");
        var security = h.SecurityUpdates ?? h.PendingUpdates.Value;
        if (security > 0) return new(Warn, h.SecurityUpdates is null ? $"{security} pending" : $"{security} security");
        return h.RebootRequired ? new(Warn, "reboot required") : new(Ok, "up to date");
    }
}
