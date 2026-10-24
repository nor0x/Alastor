using Sentinel.Core.Platform;

namespace Sentinel.Core.Baseline;

/// <summary>Reads the facts the baseline checks need. Every command is optional: a missing tool means "not applicable" or "unknown", never a crash.</summary>
public sealed class BaselineProbe(ICommandRunner runner, IFileSystem fs, OsInfo os)
{
    public const string SshdConfig = "/etc/ssh/sshd_config";

    public static readonly string[] SysctlKeys = BaselineMitigations.SysctlSettings.Values.SelectMany(v => v.Keys).Distinct().ToArray();

    public async Task<BaselineFacts> GatherAsync(CancellationToken ct)
    {
        var (sshd, sshdError) = await SshdAsync(ct);
        var accounts = await AccountsAsync(ct);
        var admins = await AdminsAsync(accounts, ct);
        var (fw, fwTool, fwDetail, fwError) = await FirewallAsync(ct);
        var (updates, updatesDetail) = await AutomaticUpdatesAsync(ct);
        var (reboot, rebootPkgs) = await RebootAsync(ct);
        var keysCommand = sshd is not null && sshd.GetValueOrDefault("authorizedkeyscommand", "none") is not ("none" or "");

        return new BaselineFacts
        {
            Family = os.Family,
            Sshd = sshd,
            SshdError = sshdError,
            SshdIncludesDropIns = sshd is not null && await IncludesDropInsAsync(ct),
            Sysctl = await SysctlAsync(ct),
            FirewallActive = fw,
            FirewallTool = fwTool,
            FirewallDetail = fwDetail,
            FirewallError = fwError,
            AutomaticUpdates = updates,
            AutomaticUpdatesDetail = updatesDetail,
            RebootRequired = reboot,
            RebootPackages = rebootPkgs,
            Accounts = accounts,
            EmptyPasswordAccounts = await EmptyPasswordsAsync(ct),
            AdminAccounts = admins,
            AdminAccountsWithKeys = await AdminsWithKeysAsync(accounts, admins, sshd, ct),
            AuthorizedKeysCommand = keysCommand,
            FileModes = FileModes(),
            TimeSynchronized = await TimeSyncAsync(ct),
            Fail2BanSshdJail = await Fail2BanSshdAsync(ct),
        };
    }

    private async Task<(Dictionary<string, string>?, string?)> SshdAsync(CancellationToken ct)
    {
        if (runner.Which("sshd") is null) return (null, null);
        var r = await runner.RunAsync("sshd", ["-T"], null, ct);
        return r.Success ? (BaselineParsers.ParseSshdT(r.StdOut), null) : (null, r.CombinedOutput.Trim());
    }

    private async Task<bool> IncludesDropInsAsync(CancellationToken ct)
    {
        var main = await fs.ReadAllTextAsync(SshdConfig, ct) ?? "";
        return main.Split('\n').Any(l =>
        {
            var t = l.Trim();
            return t.StartsWith("Include", StringComparison.OrdinalIgnoreCase) && t.Contains("sshd_config.d/", StringComparison.Ordinal);
        });
    }

    private async Task<Dictionary<string, string>> SysctlAsync(CancellationToken ct)
    {
        if (runner.Which("sysctl") is null) return [];
        // -e: keys that don't exist (IPv6 disabled) are skipped instead of failing the whole call.
        var r = await runner.RunAsync("sysctl", ["-e", .. SysctlKeys], null, ct);
        return BaselineParsers.ParseSysctl(r.StdOut);
    }

    private async Task<(bool?, string?, string?, string?)> FirewallAsync(CancellationToken ct)
    {
        var errors = new List<string>();
        if (runner.Which("ufw") is not null)
        {
            var r = await runner.RunAsync("ufw", ["status"], null, ct);
            if (BaselineParsers.ParseUfwStatus(r.StdOut) is { } active)
            {
                if (active) return (true, "ufw", "ufw is active", null);
            }
            else errors.Add($"ufw: {FirstLine(r.CombinedOutput)}");
        }
        if (runner.Which("firewall-cmd") is not null)
        {
            var r = await runner.RunAsync("firewall-cmd", ["--state"], null, ct);
            if (r.Success && r.StdOut.Trim() == "running") return (true, "firewalld", "firewalld is running", null);
        }
        if (runner.Which("nft") is not null)
        {
            var r = await runner.RunAsync("nft", ["-j", "list", "ruleset"], null, ct);
            if (r.Success)
            {
                try
                {
                    if (BaselineParsers.NftFiltersInput(r.StdOut)) return (true, "nftables", "nftables input chain drops by default", null);
                    return (false, "nftables", "No nftables input chain drops traffic by default", null);
                }
                catch (System.Text.Json.JsonException ex)
                {
                    errors.Add($"nft: {ex.Message}");
                }
            }
            else errors.Add($"nft: {FirstLine(r.CombinedOutput)}");
        }
        if (runner.Which("iptables") is not null)
        {
            var r = await runner.RunAsync("iptables", ["-S", "INPUT"], null, ct);
            if (r.Success) return BaselineParsers.IptablesInputDrops(r.StdOut)
                ? (true, "iptables", "iptables INPUT drops by default", null)
                : (false, "iptables", "iptables INPUT accepts by default", null);
            errors.Add($"iptables: {FirstLine(r.CombinedOutput)}");
        }
        return errors.Count > 0 ? (null, null, null, string.Join("; ", errors)) : (false, null, "No firewall tool found", null);
    }

    private async Task<(bool?, string?)> AutomaticUpdatesAsync(CancellationToken ct)
    {
        switch (os.Family)
        {
            case DistroFamily.Debian:
            {
                var installed = (await runner.RunAsync("dpkg-query", ["-W", "-f=${Status}", "unattended-upgrades"], null, ct)).StdOut.Contains("install ok installed", StringComparison.Ordinal);
                if (!installed) return (false, "unattended-upgrades is not installed");
                var cfg = BaselineParsers.ParseAptConfig((await runner.RunAsync("apt-config", ["dump", "APT::Periodic"], null, ct)).StdOut);
                // apt.systemd.daily exits early when APT::Periodic::Enable is 0, whatever the other settings say.
                if (cfg.GetValueOrDefault("APT::Periodic::Enable") == "0") return (false, "APT::Periodic::Enable is 0, which disables all periodic apt jobs");
                if (cfg.GetValueOrDefault("APT::Periodic::Unattended-Upgrade", "0") == "0") return (false, "APT::Periodic::Unattended-Upgrade is not enabled");
                if (runner.Which("systemctl") is not null && !(await runner.RunAsync("systemctl", ["is-enabled", "apt-daily-upgrade.timer"], null, ct)).Success)
                    return (false, "apt-daily-upgrade.timer is not enabled");
                return (true, "unattended-upgrades enabled");
            }
            case DistroFamily.RedHat:
            {
                foreach (var t in new[] { "dnf-automatic-install.timer", "dnf-automatic.timer", "dnf5-automatic.timer" })
                    if ((await runner.RunAsync("systemctl", ["is-enabled", t], null, ct)).Success) return (true, $"{t} enabled");
                return (false, "No dnf-automatic timer is enabled");
            }
            default:
                return (null, "Automatic updates are not checked on this distribution yet");
        }
    }

    private async Task<(bool?, IReadOnlyList<string>)> RebootAsync(CancellationToken ct)
    {
        if (os.Family == DistroFamily.Debian)
        {
            if (!fs.FileExists("/var/run/reboot-required")) return (false, []);
            var pkgs = (await fs.ReadAllTextAsync("/var/run/reboot-required.pkgs", ct) ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return (true, pkgs.Distinct().ToList());
        }
        if (os.Family == DistroFamily.RedHat && runner.Which("needs-restarting") is not null)
        {
            // Documented: exit 1 means a reboot is required, 0 means not.
            var r = await runner.RunAsync("needs-restarting", ["-r"], null, ct);
            return r.ExitCode switch { 0 => (false, []), 1 => (true, []), _ => (null, []) };
        }
        return (null, []);
    }

    private async Task<List<AccountInfo>> AccountsAsync(CancellationToken ct) =>
        BaselineParsers.ParseGetentPasswd((await runner.RunAsync("getent", ["passwd"], null, ct)).StdOut);

    private async Task<List<string>> AdminsAsync(List<AccountInfo> accounts, CancellationToken ct)
    {
        var members = BaselineParsers.ParseGetentGroupMembers((await runner.RunAsync("getent", ["group", "sudo", "wheel", "admin"], null, ct)).StdOut);
        return ["root", .. members.Where(m => m != "root" && accounts.Any(a => a.Name == m))];
    }

    private async Task<List<string>> AdminsWithKeysAsync(List<AccountInfo> accounts, List<string> admins, IReadOnlyDictionary<string, string>? sshd, CancellationToken ct)
    {
        var patterns = (sshd?.GetValueOrDefault("authorizedkeysfile") ?? ".ssh/authorized_keys .ssh/authorized_keys2")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var result = new List<string>();
        foreach (var name in admins)
        {
            var account = accounts.FirstOrDefault(a => a.Name == name);
            if (account is null) continue;
            foreach (var pattern in patterns)
            {
                if (BaselineParsers.HasAuthorizedKey(await fs.ReadAllTextAsync(BaselineParsers.ExpandAuthorizedKeysPath(pattern, account), ct)))
                {
                    result.Add(name);
                    break;
                }
            }
        }
        return result;
    }

    private async Task<List<string>?> EmptyPasswordsAsync(CancellationToken ct)
    {
        var r = await runner.RunAsync("passwd", ["-S", "-a"], null, ct);
        return r.Success ? BaselineParsers.ParsePasswdStatusNoPassword(r.StdOut) : null;
    }

    private Dictionary<string, int> FileModes()
    {
        var result = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var path in new[] { "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group" })
            if (fs.GetUnixFileMode(path) is { } mode) result[path] = (int)mode;
        return result;
    }

    private async Task<bool?> TimeSyncAsync(CancellationToken ct)
    {
        if (runner.Which("timedatectl") is not null)
        {
            var kv = BaselineParsers.ParseKeyValues((await runner.RunAsync("timedatectl", ["show"], null, ct)).StdOut);
            if (kv.TryGetValue("NTPSynchronized", out var v)) return v == "yes";
        }
        if (runner.Which("chronyc") is not null)
        {
            var r = await runner.RunAsync("chronyc", ["-n", "tracking"], null, ct);
            if (r.Success) return !r.StdOut.Contains("Not synchronised", StringComparison.OrdinalIgnoreCase);
        }
        return null;
    }

    private async Task<bool?> Fail2BanSshdAsync(CancellationToken ct)
    {
        if (runner.Which("fail2ban-client") is null) return false;
        var r = await runner.RunAsync("fail2ban-client", ["status", "sshd"], null, ct);
        return r.Success;
    }

    private static string FirstLine(string s) => s.Trim().Split('\n').FirstOrDefault()?.Trim() ?? "";
}
