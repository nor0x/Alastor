using System.Text;
using Sentinel.Core.Policy;

namespace Sentinel.Core.Baseline;

/// <summary>
/// The settings behind every policy-fixable check, used both to evaluate the check and to render the agent's drop-ins,
/// so "what we check" and "what we set" can never disagree.
/// </summary>
public static class BaselineMitigations
{
    /// <summary>
    /// sshd reads the first value it sees for a keyword, and the stock sshd_config includes sshd_config.d/*.conf at the
    /// top in lexical order. "01-" sorts before cloud-init's "50-cloud-init.conf", which often turns passwords back on.
    /// </summary>
    public const string SshdDropIn = "/etc/ssh/sshd_config.d/01-sentinel-vps.conf";

    /// <summary>systemd-sysctl applies files in lexical order, later wins. "99-zz-" sorts after Debian's 99-sysctl.conf.</summary>
    public const string SysctlDropIn = "/etc/sysctl.d/99-zz-sentinel-vps.conf";

    public sealed record SshSetting(string Keyword, string Value, Func<string, bool> IsCompliant);

    public static readonly IReadOnlyDictionary<string, IReadOnlyList<SshSetting>> SshSettings = new Dictionary<string, IReadOnlyList<SshSetting>>
    {
        ["ssh-root-login"] = [new("PermitRootLogin", "prohibit-password", v => v is "no" or "prohibit-password" or "without-password" or "forced-commands-only")],
        ["ssh-password-auth"] =
        [
            new("PasswordAuthentication", "no", v => v == "no"),
            new("KbdInteractiveAuthentication", "no", v => v == "no"),
            // The pre-8.7 name of KbdInteractiveAuthentication. Only the one this sshd knows is checked and written (see Known).
            new("ChallengeResponseAuthentication", "no", v => v == "no"),
        ],
        ["ssh-empty-passwords"] = [new("PermitEmptyPasswords", "no", v => v == "no")],
        ["ssh-max-auth-tries"] = [new("MaxAuthTries", "3", v => int.TryParse(v, out var n) && n <= 4)],
        ["ssh-x11-forwarding"] = [new("X11Forwarding", "no", v => v == "no")],
        // sshd -T prints seconds; 0 means "no limit".
        ["ssh-login-grace"] = [new("LoginGraceTime", "30", v => int.TryParse(v, out var n) && n is > 0 and <= 60)],
    };

    public sealed record SysctlSetting(string Value, Func<string, bool> IsCompliant);

    private static SysctlSetting Exactly(string v) => new(v, actual => actual == v);

    public static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, SysctlSetting>> SysctlSettings = new Dictionary<string, IReadOnlyDictionary<string, SysctlSetting>>
    {
        ["kernel-aslr"] = new Dictionary<string, SysctlSetting> { ["kernel.randomize_va_space"] = Exactly("2") },
        ["kernel-pointer-leaks"] = new Dictionary<string, SysctlSetting>
        {
            ["kernel.kptr_restrict"] = new("1", v => v is "1" or "2"),
            ["kernel.dmesg_restrict"] = Exactly("1"),
        },
        ["net-redirects"] = new Dictionary<string, SysctlSetting>
        {
            ["net.ipv4.conf.all.accept_redirects"] = Exactly("0"),
            ["net.ipv4.conf.default.accept_redirects"] = Exactly("0"),
            ["net.ipv6.conf.all.accept_redirects"] = Exactly("0"),
            ["net.ipv6.conf.default.accept_redirects"] = Exactly("0"),
            ["net.ipv4.conf.all.send_redirects"] = Exactly("0"),
            ["net.ipv4.conf.default.send_redirects"] = Exactly("0"),
        },
        ["net-source-route"] = new Dictionary<string, SysctlSetting>
        {
            ["net.ipv4.conf.all.accept_source_route"] = Exactly("0"),
            ["net.ipv6.conf.all.accept_source_route"] = Exactly("0"),
        },
        ["net-syncookies"] = new Dictionary<string, SysctlSetting> { ["net.ipv4.tcp_syncookies"] = Exactly("1") },
        ["net-rp-filter"] = new Dictionary<string, SysctlSetting> { ["net.ipv4.conf.all.rp_filter"] = new("2", v => v is "1" or "2") },
        ["fs-protected-links"] = new Dictionary<string, SysctlSetting>
        {
            ["fs.protected_symlinks"] = Exactly("1"),
            ["fs.protected_hardlinks"] = Exactly("1"),
        },
    };

    /// <summary>
    /// The settings of a check that this sshd understands: the keywords <c>sshd -T</c> prints. An unknown keyword in the
    /// drop-in would make <c>sshd -t</c> fail. With no <c>sshd -T</c> output, all settings are returned.
    /// </summary>
    public static IEnumerable<SshSetting> Known(string checkId, IReadOnlyDictionary<string, string>? sshdT) =>
        SshSettings[checkId].Where(s => sshdT is null || sshdT.ContainsKey(s.Keyword.ToLowerInvariant()));

    /// <summary>Check ids the policy sets to <c>apply</c> (or <c>ignore</c>), by value.</summary>
    public static IEnumerable<string> WithValue(PolicyDocument policy, string value) =>
        (policy.Baseline?.Mitigations ?? []).Where(kv => string.Equals(kv.Value, value, StringComparison.OrdinalIgnoreCase)).Select(kv => kv.Key);

    public sealed record LockoutCheck(bool Safe, string? Reason);

    /// <summary>
    /// Refuse SSH changes that could lock the operator out. Turning off passwords needs an admin account with an
    /// authorized key; disallowing root passwords needs root keys or another admin account.
    /// </summary>
    public static LockoutCheck CheckLockout(string checkId, BaselineFacts facts)
    {
        if (facts.AuthorizedKeysCommand) return new(true, null);
        return checkId switch
        {
            "ssh-password-auth" when facts.AdminAccountsWithKeys.Count == 0 =>
                new(false, "No admin account (root, sudo, wheel) has an authorized SSH key. Turning off passwords would lock everyone out. Add a key first: ssh-copy-id you@this-host"),
            "ssh-root-login" when !facts.AdminAccountsWithKeys.Contains("root") && facts.AdminAccounts.All(a => a == "root") =>
                new(false, "root is the only admin account and has no authorized SSH key. Add a key for root or create a sudo user first."),
            _ => new(true, null),
        };
    }

    /// <summary>The sshd drop-in body for the given check ids, or null when none is requested.</summary>
    public static string? RenderSshd(IEnumerable<string> checkIds, IReadOnlyDictionary<string, string>? sshdT = null)
    {
        var lines = checkIds.Where(SshSettings.ContainsKey).Order(StringComparer.Ordinal)
            .SelectMany(id => Known(id, sshdT).Select(s => (id, s))).ToList();
        if (lines.Count == 0) return null;
        var sb = new StringBuilder();
        sb.Append("# Security baseline settings. sshd uses the first value it reads, so this file sorts first.\n");
        foreach (var group in lines.GroupBy(l => l.id))
        {
            sb.Append("# ").Append(group.Key).Append('\n');
            foreach (var (_, s) in group) sb.Append(s.Keyword).Append(' ').Append(s.Value).Append('\n');
        }
        return sb.ToString();
    }

    /// <summary>The sysctl drop-in body for the given check ids, or null when none is requested.</summary>
    public static string? RenderSysctl(IEnumerable<string> checkIds, IReadOnlyDictionary<string, string>? present = null)
    {
        var ids = checkIds.Where(SysctlSettings.ContainsKey).Order(StringComparer.Ordinal).ToList();
        if (ids.Count == 0) return null;
        var sb = new StringBuilder();
        sb.Append("# Security baseline kernel settings.\n");
        foreach (var id in ids)
        {
            sb.Append("# ").Append(id).Append('\n');
            foreach (var (key, s) in SysctlSettings[id])
            {
                // Keys the kernel doesn't have (IPv6 disabled) would make `sysctl -p` fail; leave them out.
                if (present is not null && !present.ContainsKey(key)) continue;
                sb.Append(key).Append(" = ").Append(s.Value).Append('\n');
            }
        }
        return sb.ToString();
    }
}
