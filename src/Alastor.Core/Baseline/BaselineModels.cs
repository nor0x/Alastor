using Alastor.Core.Events;

namespace Alastor.Core.Baseline;

public enum CheckStatus
{
    Pass,
    Fail,

    /// <summary>The check could not be evaluated, for example because the agent may not read the firewall state.</summary>
    Unknown,

    /// <summary>The check does not apply to this host, for example SSH checks when no SSH server is installed.</summary>
    NotApplicable,
}

public enum BaselineCategory
{
    Ssh,
    Firewall,
    Updates,
    Kernel,
    Accounts,
    System,
}

public enum FixKind
{
    /// <summary>The agent can enforce the fix: setting a policy key makes it write a managed drop-in.</summary>
    Policy,

    /// <summary>The fix needs a judgement call (enabling a firewall, rebooting, locking a user), so the dashboard shows commands to run.</summary>
    Manual,
}

/// <summary>Static description of one baseline check: what it looks at, why it matters, and how it is fixed.</summary>
public sealed record BaselineCheckInfo(
    string Id,
    string Title,
    BaselineCategory Category,
    Severity Severity,
    string Why,
    string Expected,
    FixKind Fix,
    string Remediation)
{
    /// <summary>
    /// For <see cref="FixKind.Policy"/>: the policy key and value that make the agent enforce the fix.
    /// Most checks use <c>baseline.mitigations.&lt;id&gt;: apply</c>; a few map to an existing key (the sshd jail).
    /// </summary>
    public IReadOnlyList<string> PolicyPath { get; init; } = ["baseline", "mitigations", Id];

    public string PolicyValue { get; init; } = BaselineMitigationValues.Apply;
}

public static class BaselineMitigationValues
{
    /// <summary>The agent enforces the fix with a managed drop-in.</summary>
    public const string Apply = "apply";

    /// <summary>Accepted risk: the check still runs but does not count against the score or raise alerts.</summary>
    public const string Ignore = "ignore";

    /// <summary>Only report (the default). Lets a group or host undo an <c>apply</c> or <c>ignore</c> set by a lower layer.</summary>
    public const string Report = "report";
}

/// <summary>The outcome of one check on one host.</summary>
public sealed record BaselineResult(
    string CheckId,
    CheckStatus Status,
    string Actual,
    string? Detail = null)
{
    /// <summary>Copy-paste commands that fix a failed check on this host (filled in with its SSH port, user names, distro).</summary>
    public IReadOnlyList<string> Commands { get; init; } = [];

    /// <summary>The policy sets <c>apply</c> for this check, so the agent's drop-in is in place.</summary>
    public bool Enforced { get; init; }

    /// <summary>The policy sets <c>ignore</c>: accepted risk.</summary>
    public bool Accepted { get; init; }
}

public sealed record BaselineReport(DateTime RanAtUtc, string? PolicyRevision, IReadOnlyList<BaselineResult> Results);

/// <summary>The severity-weighted score shown on the dashboard: 100 means every applicable check passes.</summary>
public static class BaselineScore
{
    public static int Weight(Severity s) => s switch
    {
        Severity.Critical => 10,
        Severity.High => 6,
        Severity.Medium => 3,
        Severity.Low => 1,
        _ => 0,
    };

    /// <summary>Accepted, unknown and not-applicable checks are left out. Null when nothing could be evaluated.</summary>
    public static int? Compute(IEnumerable<BaselineResult> results)
    {
        int total = 0, passed = 0;
        foreach (var r in results)
        {
            if (r.Accepted || r.Status is CheckStatus.Unknown or CheckStatus.NotApplicable) continue;
            var info = BaselineCatalog.Find(r.CheckId);
            if (info is null) continue;
            var w = Weight(info.Severity);
            total += w;
            if (r.Status == CheckStatus.Pass) passed += w;
        }
        return total == 0 ? null : (int)Math.Round(passed * 100.0 / total);
    }
}
