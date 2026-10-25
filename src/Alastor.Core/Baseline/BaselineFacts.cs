using System.Text.Json;
using Alastor.Core.Platform;

namespace Alastor.Core.Baseline;

/// <summary>A fact the probe could not read, with the reason (shown as "unknown" instead of guessing).</summary>
public sealed record Unreadable(string Reason);

public sealed record AccountInfo(string Name, int Uid, string Home, string Shell);

/// <summary>Everything the baseline checks look at, gathered in one pass. Pure data, so evaluation is unit testable.</summary>
public sealed record BaselineFacts
{
    /// <summary>Effective sshd settings from <c>sshd -T</c> (lower-case keys), null when no SSH server is installed.</summary>
    public IReadOnlyDictionary<string, string>? Sshd { get; init; }
    public string? SshdError { get; init; }

    /// <summary>The main sshd_config includes sshd_config.d/*.conf, so a drop-in takes effect.</summary>
    public bool SshdIncludesDropIns { get; init; }

    public IReadOnlyDictionary<string, string> Sysctl { get; init; } = new Dictionary<string, string>();

    /// <summary>True/false when the firewall state is known; null with <see cref="FirewallError"/> otherwise.</summary>
    public bool? FirewallActive { get; init; }
    public string? FirewallDetail { get; init; }
    public string? FirewallError { get; init; }
    public string? FirewallTool { get; init; }

    public bool? AutomaticUpdates { get; init; }
    public string? AutomaticUpdatesDetail { get; init; }

    public bool? RebootRequired { get; init; }
    public IReadOnlyList<string> RebootPackages { get; init; } = [];

    public IReadOnlyList<AccountInfo> Accounts { get; init; } = [];

    /// <summary>Accounts that <c>passwd -S</c> reports as having no password (status NP). Null when it couldn't run.</summary>
    public IReadOnlyList<string>? EmptyPasswordAccounts { get; init; }

    /// <summary>root plus members of sudo/wheel/admin.</summary>
    public IReadOnlyList<string> AdminAccounts { get; init; } = [];

    /// <summary>Admin accounts with at least one key in an authorized_keys file sshd reads.</summary>
    public IReadOnlyList<string> AdminAccountsWithKeys { get; init; } = [];

    /// <summary>sshd gets keys from a command (LDAP, cloud metadata), so the files don't tell the whole story.</summary>
    public bool AuthorizedKeysCommand { get; init; }

    /// <summary>Path → octal permission bits, for the sensitive account files.</summary>
    public IReadOnlyDictionary<string, int> FileModes { get; init; } = new Dictionary<string, int>();

    public bool? TimeSynchronized { get; init; }

    /// <summary>fail2ban answers and its sshd jail is loaded (from Alastor's own integration).</summary>
    public bool? Fail2BanSshdJail { get; init; }

    public DistroFamily Family { get; init; }
}

/// <summary>Parsers for the structured output the probe reads. All of them are tested against captured fixtures.</summary>
public static class BaselineParsers
{
    /// <summary><c>sshd -T</c>: one "keyword value" pair per line, keywords lower-case. Repeated keywords (listenaddress) keep the first.</summary>
    public static Dictionary<string, string> ParseSshdT(string output)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            var space = line.IndexOf(' ');
            if (space <= 0) continue;
            result.TryAdd(line[..space].ToLowerInvariant(), line[(space + 1)..].Trim());
        }
        return result;
    }

    /// <summary><c>sysctl key …</c>: "key = value" lines.</summary>
    public static Dictionary<string, string> ParseSysctl(string output)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in output.Split('\n'))
        {
            var eq = line.IndexOf(" = ", StringComparison.Ordinal);
            if (eq > 0) result[line[..eq].Trim()] = line[(eq + 3)..].Trim();
        }
        return result;
    }

    /// <summary><c>ufw status</c>: the first line is "Status: active" or "Status: inactive".</summary>
    public static bool? ParseUfwStatus(string output)
    {
        foreach (var line in output.Split('\n'))
        {
            var t = line.Trim();
            if (t.StartsWith("Status:", StringComparison.OrdinalIgnoreCase))
                return t[7..].Trim().Equals("active", StringComparison.OrdinalIgnoreCase);
        }
        return null;
    }

    /// <summary>
    /// <c>nft -j list ruleset</c> (libnftables-json): true when a base chain on the input hook has policy drop,
    /// or ends in an unconditional drop/reject rule.
    /// </summary>
    public static bool NftFiltersInput(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("nftables", out var items)) return false;
        var inputChains = new HashSet<(string, string, string)>();
        foreach (var item in items.EnumerateArray())
        {
            if (!item.TryGetProperty("chain", out var chain)) continue;
            if (chain.TryGetProperty("hook", out var hook) && hook.GetString() == "input")
            {
                if (chain.TryGetProperty("policy", out var policy) && policy.GetString() == "drop") return true;
                inputChains.Add((Str(chain, "family"), Str(chain, "table"), Str(chain, "name")));
            }
        }
        // A chain with policy accept that ends with a bare "drop" or "reject" rule filters just the same.
        (string, string, string)? lastChain = null;
        var lastRuleUnconditionalDrop = new Dictionary<(string, string, string), bool>();
        foreach (var item in items.EnumerateArray())
        {
            if (!item.TryGetProperty("rule", out var rule)) continue;
            var key = (Str(rule, "family"), Str(rule, "table"), Str(rule, "chain"));
            if (!inputChains.Contains(key)) continue;
            lastChain = key;
            var expr = rule.TryGetProperty("expr", out var e) ? e : default;
            lastRuleUnconditionalDrop[key] = expr.ValueKind == JsonValueKind.Array && expr.GetArrayLength() == 1 &&
                                             (expr[0].TryGetProperty("drop", out _) || expr[0].TryGetProperty("reject", out _));
        }
        return lastChain is not null && lastRuleUnconditionalDrop.Values.Any(v => v);

        static string Str(JsonElement el, string name) => el.TryGetProperty(name, out var v) ? v.GetString() ?? "" : "";
    }

    /// <summary><c>iptables -S INPUT</c>: "-P INPUT DROP" means a default-deny input policy.</summary>
    public static bool IptablesInputDrops(string output) =>
        output.Split('\n').Any(l => l.Trim() is "-P INPUT DROP" or "-P INPUT REJECT") ||
        output.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("-A INPUT", StringComparison.Ordinal)) is { } last &&
        (last == "-A INPUT -j DROP" || last.StartsWith("-A INPUT -j REJECT", StringComparison.Ordinal));

    /// <summary><c>apt-config dump APT::Periodic</c>: lines like <c>APT::Periodic::Unattended-Upgrade "1";</c>.</summary>
    public static Dictionary<string, string> ParseAptConfig(string output)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim().TrimEnd(';');
            var space = line.IndexOf(' ');
            if (space <= 0) continue;
            result[line[..space]] = line[(space + 1)..].Trim().Trim('"');
        }
        return result;
    }

    /// <summary><c>timedatectl show</c>: "Key=value" lines.</summary>
    public static Dictionary<string, string> ParseKeyValues(string output)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in output.Split('\n'))
        {
            var eq = line.IndexOf('=');
            if (eq > 0) result[line[..eq].Trim()] = line[(eq + 1)..].Trim();
        }
        return result;
    }

    /// <summary><c>passwd -S -a</c>: "name status date min max warn inactive"; status NP means no password.</summary>
    public static List<string> ParsePasswdStatusNoPassword(string output) =>
        output.Split('\n')
            .Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Where(f => f.Length >= 2 && f[1] == "NP")
            .Select(f => f[0])
            .ToList();

    /// <summary><c>getent passwd</c>: the standard 7-field colon-separated format.</summary>
    public static List<AccountInfo> ParseGetentPasswd(string output) =>
        output.Split('\n')
            .Select(l => l.Split(':'))
            .Where(f => f.Length >= 7 && int.TryParse(f[2], out _))
            .Select(f => new AccountInfo(f[0], int.Parse(f[2], System.Globalization.CultureInfo.InvariantCulture), f[5], f[6]))
            .ToList();

    /// <summary><c>getent group sudo wheel admin</c>: "name:x:gid:member,member".</summary>
    public static List<string> ParseGetentGroupMembers(string output) =>
        output.Split('\n')
            .Select(l => l.Split(':'))
            .Where(f => f.Length >= 4)
            .SelectMany(f => f[3].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct()
            .ToList();

    /// <summary>An authorized_keys file has a usable key when a non-comment line contains a key type.</summary>
    public static bool HasAuthorizedKey(string? content) =>
        content is not null && content.Split('\n').Any(l =>
        {
            var t = l.Trim();
            return t.Length > 0 && !t.StartsWith('#') &&
                   (t.Contains("ssh-", StringComparison.Ordinal) || t.Contains("ecdsa-", StringComparison.Ordinal) || t.Contains("sk-", StringComparison.Ordinal));
        });

    /// <summary>Expands an sshd AuthorizedKeysFile pattern (%h, %u, %%, relative to home) for one account.</summary>
    public static string ExpandAuthorizedKeysPath(string pattern, AccountInfo account)
    {
        var p = pattern.Replace("%%", "\0", StringComparison.Ordinal).Replace("%h", account.Home, StringComparison.Ordinal)
            .Replace("%u", account.Name, StringComparison.Ordinal).Replace("\0", "%", StringComparison.Ordinal);
        return p.StartsWith('/') ? p : Path.Combine(account.Home, p);
    }
}
