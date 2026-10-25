using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Core.Baseline;

/// <summary>Turns gathered facts into check results. Pure: same facts and policy, same results.</summary>
public static class BaselineEvaluator
{
    public static IReadOnlyList<BaselineResult> Evaluate(BaselineFacts facts, PolicyDocument policy)
    {
        var apply = BaselineMitigations.WithValue(policy, BaselineMitigationValues.Apply).ToHashSet(StringComparer.Ordinal);
        var ignore = BaselineMitigations.WithValue(policy, BaselineMitigationValues.Ignore).ToHashSet(StringComparer.Ordinal);
        var sshdJailWanted = policy.Banning is { } b && b.Enabled != false && b.Jails?.GetValueOrDefault("sshd")?.Enabled == true;

        var results = new List<BaselineResult>();
        foreach (var check in BaselineCatalog.All)
        {
            var r = check.Id switch
            {
                _ when BaselineMitigations.SshSettings.ContainsKey(check.Id) => Ssh(check.Id, facts),
                _ when BaselineMitigations.SysctlSettings.ContainsKey(check.Id) => Sysctl(check.Id, facts),
                "ssh-brute-force-protection" => BruteForce(facts),
                "firewall-active" => Firewall(facts),
                "updates-automatic" => Updates(facts),
                "updates-reboot-required" => Reboot(facts),
                "accounts-uid0" => Uid0(facts),
                "accounts-empty-password" => EmptyPasswords(facts),
                "files-sensitive-permissions" => Permissions(facts),
                "time-sync" => TimeSync(facts),
                _ => new BaselineResult(check.Id, CheckStatus.Unknown, "Not evaluated"),
            };
            var enforced = check.Id == "ssh-brute-force-protection" ? sshdJailWanted : apply.Contains(check.Id);
            if (enforced && r.Status == CheckStatus.Fail)
                r = r with
                {
                    Detail = check.Id == "ssh-brute-force-protection"
                        ? "The policy enables the sshd jail, but it isn't active yet. Check fail2ban in the capability matrix."
                        : "The policy applies this fix, but the effective value still fails. The fix may have been refused (see the host's last apply report), or another config file overrides it.",
                };
            results.Add(r with { Enforced = enforced, Accepted = ignore.Contains(check.Id), Commands = r.Status == CheckStatus.Fail ? r.Commands : [] });
        }
        return results;
    }

    private static string SshService(BaselineFacts f) => f.Family == DistroFamily.Debian ? "ssh" : "sshd";
    private static string SshPort(BaselineFacts f) => f.Sshd?.GetValueOrDefault("port") ?? "22";

    private static BaselineResult Ssh(string id, BaselineFacts f)
    {
        if (f.Sshd is null)
            return f.SshdError is null
                ? new(id, CheckStatus.NotApplicable, "No SSH server installed")
                : new(id, CheckStatus.Unknown, "sshd -T failed", f.SshdError);
        var settings = BaselineMitigations.Known(id, f.Sshd).ToList();
        if (settings.Count == 0) return new(id, CheckStatus.Unknown, "sshd -T doesn't report this setting");
        var actual = settings.Select(s => (s, value: f.Sshd[s.Keyword.ToLowerInvariant()])).ToList();
        var failing = actual.Where(a => !a.s.IsCompliant(a.value)).ToList();
        var summary = string.Join(", ", actual.Select(a => $"{a.s.Keyword} {a.value}"));
        if (failing.Count == 0) return new(id, CheckStatus.Pass, summary);
        var conf = string.Join("\\n", settings.Select(s => $"{s.Keyword} {s.Value}"));
        return new(id, CheckStatus.Fail, summary, f.SshdIncludesDropIns ? null : "sshd_config doesn't include sshd_config.d/*.conf, so a drop-in has no effect. Add the setting to sshd_config itself.")
        {
            Commands = f.SshdIncludesDropIns
                ? [$"printf '{conf}\\n' | sudo tee /etc/ssh/sshd_config.d/01-hardening.conf && sudo sshd -t && sudo systemctl reload {SshService(f)}"]
                : [$"sudoedit /etc/ssh/sshd_config   # set: {string.Join(", ", settings.Select(s => $"{s.Keyword} {s.Value}"))}", $"sudo sshd -t && sudo systemctl reload {SshService(f)}"],
        };
    }

    private static BaselineResult Sysctl(string id, BaselineFacts f)
    {
        var settings = BaselineMitigations.SysctlSettings[id];
        var present = settings.Where(kv => f.Sysctl.ContainsKey(kv.Key)).ToList();
        if (present.Count == 0) return new(id, CheckStatus.Unknown, "Could not read the kernel settings");
        var failing = present.Where(kv => !kv.Value.IsCompliant(f.Sysctl[kv.Key])).ToList();
        if (failing.Count == 0) return new(id, CheckStatus.Pass, string.Join(", ", present.Select(kv => $"{kv.Key} = {f.Sysctl[kv.Key]}")));
        var conf = string.Join("\\n", failing.Select(kv => $"{kv.Key} = {kv.Value.Value}"));
        return new(id, CheckStatus.Fail, string.Join(", ", failing.Select(kv => $"{kv.Key} = {f.Sysctl[kv.Key]}")))
        {
            Commands = [$"printf '{conf}\\n' | sudo tee -a /etc/sysctl.d/99-hardening.conf && sudo sysctl --system"],
        };
    }

    private static BaselineResult BruteForce(BaselineFacts f) => f.Fail2BanSshdJail switch
    {
        true => new("ssh-brute-force-protection", CheckStatus.Pass, "fail2ban sshd jail is active"),
        false when f.Sshd is null && f.SshdError is null => new("ssh-brute-force-protection", CheckStatus.NotApplicable, "No SSH server installed"),
        false => new("ssh-brute-force-protection", CheckStatus.Fail, "No active fail2ban sshd jail"),
        null => new("ssh-brute-force-protection", CheckStatus.Unknown, "Could not query fail2ban"),
    };

    private static BaselineResult Firewall(BaselineFacts f)
    {
        if (f.FirewallActive is null) return new("firewall-active", CheckStatus.Unknown, "Could not read the firewall state", f.FirewallError);
        if (f.FirewallActive == true) return new("firewall-active", CheckStatus.Pass, f.FirewallDetail ?? "active");
        var port = SshPort(f);
        return new("firewall-active", CheckStatus.Fail, f.FirewallDetail ?? "No active firewall", $"SSH listens on port {port}; the commands allow it before enabling the firewall.")
        {
            Commands = f.Family == DistroFamily.RedHat
                ? ["sudo dnf install -y firewalld && sudo systemctl enable --now firewalld", $"sudo firewall-cmd --permanent --add-port={port}/tcp && sudo firewall-cmd --reload"]
                : [$"sudo apt-get install -y ufw && sudo ufw allow {port}/tcp", "sudo ufw --force enable   # then allow other public services, e.g. sudo ufw allow 443/tcp"],
        };
    }

    private static BaselineResult Updates(BaselineFacts f)
    {
        if (f.AutomaticUpdates is null) return new("updates-automatic", CheckStatus.NotApplicable, f.AutomaticUpdatesDetail ?? "Not checked on this distribution");
        if (f.AutomaticUpdates == true) return new("updates-automatic", CheckStatus.Pass, f.AutomaticUpdatesDetail ?? "enabled");
        List<string> commands = f.Family == DistroFamily.RedHat
            ? ["sudo dnf install -y dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer"]
            : ["sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -f noninteractive unattended-upgrades"];
        if (f.AutomaticUpdatesDetail?.Contains("APT::Periodic::Enable", StringComparison.Ordinal) == true)
            commands.Add("grep -rn 'APT::Periodic::Enable' /etc/apt/apt.conf.d/   # remove or set it to \"1\"");
        if (f.Family == DistroFamily.Debian) commands.Add("sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer");
        return new("updates-automatic", CheckStatus.Fail, f.AutomaticUpdatesDetail ?? "disabled") { Commands = commands };
    }

    private static BaselineResult Reboot(BaselineFacts f) => f.RebootRequired switch
    {
        null => new("updates-reboot-required", CheckStatus.NotApplicable, "Not detectable on this distribution"),
        false => new("updates-reboot-required", CheckStatus.Pass, "No reboot pending"),
        true => new("updates-reboot-required", CheckStatus.Fail, "Reboot required",
            f.RebootPackages.Count > 0 ? $"Updated: {string.Join(", ", f.RebootPackages.Take(8))}" : null)
        {
            Commands = ["sudo shutdown -r +5 \"Rebooting to finish security updates\"   # cancel with: sudo shutdown -c"],
        },
    };

    private static BaselineResult Uid0(BaselineFacts f)
    {
        if (f.Accounts.Count == 0) return new("accounts-uid0", CheckStatus.Unknown, "Could not list accounts");
        var extra = f.Accounts.Where(a => a.Uid == 0 && a.Name != "root").Select(a => a.Name).ToList();
        if (extra.Count == 0) return new("accounts-uid0", CheckStatus.Pass, "Only root has UID 0");
        return new("accounts-uid0", CheckStatus.Fail, $"UID 0: {string.Join(", ", extra)}")
        {
            Commands = extra.SelectMany(u => new[] { $"getent passwd {u}; sudo lastlog -u {u}   # who is this?", $"sudo usermod -L -s /usr/sbin/nologin {u}   # lock it" }).ToList(),
        };
    }

    private static BaselineResult EmptyPasswords(BaselineFacts f)
    {
        if (f.EmptyPasswordAccounts is null) return new("accounts-empty-password", CheckStatus.Unknown, "passwd -S could not run (needs root)");
        if (f.EmptyPasswordAccounts.Count == 0) return new("accounts-empty-password", CheckStatus.Pass, "No account without a password");
        return new("accounts-empty-password", CheckStatus.Fail, $"No password: {string.Join(", ", f.EmptyPasswordAccounts)}")
        {
            Commands = f.EmptyPasswordAccounts.Select(u => $"sudo passwd -l {u}").ToList(),
        };
    }

    private static BaselineResult Permissions(BaselineFacts f)
    {
        if (f.FileModes.Count == 0) return new("files-sensitive-permissions", CheckStatus.Unknown, "Could not read file permissions");
        var bad = new List<string>();
        foreach (var (path, mode) in f.FileModes)
        {
            var secret = path.EndsWith("shadow", StringComparison.Ordinal);
            var wrong = secret ? (mode & 0b000_000_111) != 0 : (mode & 0b000_010_010) != 0;
            if (wrong) bad.Add($"{path} {Convert.ToString(mode, 8).PadLeft(3, '0')}");
        }
        if (bad.Count == 0) return new("files-sensitive-permissions", CheckStatus.Pass,
            string.Join(", ", f.FileModes.Select(kv => $"{kv.Key} {Convert.ToString(kv.Value, 8).PadLeft(3, '0')}")));
        var commands = new List<string>();
        var secrets = bad.Where(b => b.Contains("shadow", StringComparison.Ordinal)).Select(b => b.Split(' ')[0]).ToList();
        var publics = bad.Where(b => !b.Contains("shadow", StringComparison.Ordinal)).Select(b => b.Split(' ')[0]).ToList();
        if (secrets.Count > 0)
            commands.Add(f.Family == DistroFamily.RedHat
                ? $"sudo chmod 000 {string.Join(' ', secrets)}"
                : $"sudo chown root:shadow {string.Join(' ', secrets)} && sudo chmod 640 {string.Join(' ', secrets)}");
        if (publics.Count > 0) commands.Add($"sudo chmod 644 {string.Join(' ', publics)}");
        return new("files-sensitive-permissions", CheckStatus.Fail, string.Join(", ", bad)) { Commands = commands };
    }

    private static BaselineResult TimeSync(BaselineFacts f) => f.TimeSynchronized switch
    {
        null => new("time-sync", CheckStatus.Unknown, "Could not read the time sync state"),
        true => new("time-sync", CheckStatus.Pass, "NTP synchronized"),
        false => new("time-sync", CheckStatus.Fail, "Clock not synchronized")
        {
            Commands = [f.Family == DistroFamily.RedHat ? "sudo dnf install -y chrony && sudo systemctl enable --now chronyd" : "sudo apt-get install -y systemd-timesyncd && sudo timedatectl set-ntp true"],
        },
    };

}
