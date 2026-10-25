using Alastor.Core.Baseline;
using Alastor.Core.Events;
using Alastor.Server.Data;
using Alastor.Server.Services.Posture;

namespace Alastor.Server.Services.Issues;

/// <summary>
/// Turns a host's current state into the set of problems that are open right now. Pure, so every rule is unit tested;
/// <see cref="IssueService"/> diffs the result against stored issues. Each condition here already raises its own
/// alerting event when it starts (host.offline, exposure.detected, vulnerabilities.exploited, baseline.failed, …), so
/// issues add state, not notifications.
/// </summary>
public static class IssueRules
{
    public sealed record Condition(string Rule, string Subject, Severity Severity, string Title, string? Detail, string Tab);

    /// <summary>Facts from other tables.</summary>
    /// <param name="ExploitedCves">Open (not accepted) CVEs on the host that are in CISA KEV.</param>
    /// <param name="FailingChecks">Baseline checks failing and not accepted.</param>
    public sealed record Facts(IReadOnlyCollection<string> ExploitedCves, IReadOnlyCollection<string> FailingChecks);

    /// <summary>Rule ids, with the label the Issues page filters by.</summary>
    public static readonly IReadOnlyDictionary<string, string> Rules = new Dictionary<string, string>
    {
        ["host.offline"] = "Host offline",
        ["policy.failed"] = "Policy apply failed",
        ["tool.problem"] = "Tool problem",
        ["ssh.public"] = "SSH reachable from the internet",
        ["ssh.password-public"] = "Password SSH logins on a public host",
        ["service.public"] = "Unexpected public service",
        ["cve.exploited"] = "Known-exploited CVE",
        ["cve.critical"] = "Critical CVEs",
        ["malware.found"] = "Malware found",
        ["integrity.changed"] = "Files changed since the baseline",
        ["rootkit.warning"] = "Rootkit check warnings",
        ["baseline.failed"] = "Baseline check failing",
        ["updates.security"] = "Security updates pending",
        ["updates.reboot"] = "Reboot required",
        ["updates.restart"] = "Services running replaced code",
    };

    public static List<Condition> Evaluate(ManagedHost h, Facts facts)
    {
        var open = new List<Condition>();
        if (!h.IsOnline)
            open.Add(new("host.offline", "", Severity.High, $"{h.Name} is offline",
                h.LastSeenAt is { } seen ? $"No heartbeat since {seen:yyyy-MM-dd HH:mm} UTC." : "The agent never sent a heartbeat.", "overview"));
        if (h.PolicyApplySuccess == false)
            open.Add(new("policy.failed", "", Severity.Medium, "The last policy apply failed",
                "The agent rolled back to the previous working configuration.", "policy"));
        foreach (var t in h.Tools.Where(Dto.HasProblem).OrderBy(t => t.ToolId, StringComparer.Ordinal))
            open.Add(new("tool.problem", t.ToolId, Severity.Medium, $"{t.ToolId}: {ToolProblem(t)}", t.LastError ?? t.UnavailableReason, "overview"));

        if (h.NetworkCheckedAt is not null && PostureService.IsPublicSsh(h))
        {
            open.Add(new("ssh.public", "", Severity.High, "SSH is reachable from the internet",
                "Limit SSH to a VPN or tailnet with the firewall, or accept the risk with network.allowPublicSsh.", "network"));
            // When the ssh-password-auth baseline check is failing it already says this; don't list it twice.
            if (h.SshPasswordAuth == true && !facts.FailingChecks.Contains("ssh-password-auth"))
                open.Add(new("ssh.password-public", "", Severity.High, "Password SSH logins are allowed on a public host",
                    "Turn on the ssh-password-auth baseline fix so only keys work.", "baseline"));
        }

        foreach (var entry in h.PublicServices ?? [])
        {
            var parts = entry.Split(' ', 2);
            open.Add(new("service.public", parts[0], Severity.Medium,
                parts.Length == 2 ? $"{parts[1]} on {parts[0]} is reachable from the internet" : $"Port {parts[0]} is reachable from the internet",
                $"Bind it to localhost or a private address, or firewall it. If it's meant to be public, add {parts[0]} to network.allowPublicPorts.", "network"));
        }

        foreach (var cve in facts.ExploitedCves.Order(StringComparer.Ordinal))
            open.Add(new("cve.exploited", cve, Severity.Critical, $"{cve} is exploited in the wild", "Listed in CISA's Known Exploited Vulnerabilities catalog.", "vulnerabilities"));
        if (h.VulnScannedAt is not null && h.VulnCritical > 0)
            open.Add(new("cve.critical", "", Severity.High, h.VulnCritical == 1 ? "1 critical CVE" : $"{h.VulnCritical} critical CVEs",
                h.VulnFixable > 0 ? $"{h.VulnFixable} finding{(h.VulnFixable == 1 ? "" : "s")} can be fixed by updating packages." : null, "vulnerabilities"));

        if (h.MalwareScannedAt is not null && h.MalwareFindings > 0)
            open.Add(new("malware.found", "", Severity.Critical, h.MalwareFindings == 1 ? "1 infected file" : $"{h.MalwareFindings} infected files",
                "ClamAV matched a signature. Check the files before deleting anything.", "malware"));

        if (h.IntegrityCheckedAt is not null && h.IntegrityChanges > 0)
            open.Add(new("integrity.changed", "", h.IntegrityCritical > 0 ? Severity.High : Severity.Medium,
                h.IntegrityChanges == 1 ? "1 file changed since the integrity baseline" : $"{h.IntegrityChanges} files changed since the integrity baseline",
                h.IntegrityCritical > 0 ? $"{h.IntegrityCritical} of them are binaries, SSH or account files. Review them; accept the baseline once they're explained (an update, an admin's edit)."
                    : "Review them; accept the baseline once they're explained.", "integrity"));
        if (h.RootkitCheckedAt is not null && h.RootkitWarnings > 0)
            open.Add(new("rootkit.warning", "", h.RootkitSeverity ?? Severity.Medium,
                h.RootkitWarnings == 1 ? "1 rkhunter warning" : $"{h.RootkitWarnings} rkhunter warnings",
                "Review them; ignore known ones with malware.rootkitIgnore, or accept file properties after an update.", "integrity"));

        // Only high and critical checks become issues; the rest stay on the baseline score.
        foreach (var id in facts.FailingChecks.Order(StringComparer.Ordinal))
            if (BaselineCatalog.Find(id) is { Severity: >= Severity.High } check)
                open.Add(new("baseline.failed", id, check.Severity, $"Baseline check failing: {check.Title}", check.Why, "baseline"));

        if (h.PendingUpdates is not null && (h.SecurityUpdates ?? h.PendingUpdates) is > 0 and var n)
            open.Add(new("updates.security", "", Severity.Medium,
                h.SecurityUpdates is null ? $"{n} pending update{(n == 1 ? "" : "s")}" : $"{n} security update{(n == 1 ? "" : "s")} pending", null, "updates"));
        if (h.ServicesNeedingRestart is { Count: > 0 } restart)
            open.Add(new("updates.restart", "", Severity.Medium,
                restart.Count == 1 ? $"{restart[0]} runs code an update replaced" : $"{restart.Count} services run code updates replaced",
                $"The fixes aren't active until they restart: sudo systemctl restart {string.Join(' ', restart.Take(10))}", "updates"));
        if (h.RebootRequired)
            open.Add(new("updates.reboot", "", Severity.Low, "A reboot is required", "Updated packages (often the kernel) only take effect after a reboot.", "updates"));
        return open;
    }

    private static string ToolProblem(HostToolStatus t) =>
        t.Availability == Core.Integrations.Availability.Unavailable ? "unavailable"
        : t.Installed && !t.Running ? "not running"
        : t.ConfigState switch
        {
            Core.Integrations.ConfigState.Drifted => "config edited by hand",
            Core.Integrations.ConfigState.Conflict => "config conflict",
            Core.Integrations.ConfigState.Rejected => "config rejected",
            _ => "problem",
        };
}
