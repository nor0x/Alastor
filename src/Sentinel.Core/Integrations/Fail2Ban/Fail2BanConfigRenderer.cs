using System.Globalization;
using System.Text;
using Sentinel.Core.Policy;

namespace Sentinel.Core.Integrations.Fail2Ban;

/// <summary>
/// Renders the banning policy into fail2ban's INI format. It writes one jail.d fragment that only contains
/// the jails the policy names, plus the agent's own manual-ban jail. It never writes a [DEFAULT] section,
/// so admin-wide defaults in jail.local stay untouched. Values are validated by <see cref="PolicyYaml"/>
/// before they reach this point, so nothing rendered here can inject extra INI sections.
/// </summary>
public static class Fail2BanConfigRenderer
{
    public const string ManualFilterBody = """
        # Filter for SentinelVPS's manual-ban jail. It intentionally matches nothing: bans in this
        # jail only come from `fail2ban-client set sentinel-manual banip`, issued from the dashboard.
        [Definition]
        failregex =
        ignoreregex =
        """;

    public static string RenderJails(BanningPolicy banning, IReadOnlySet<string> skipJails)
    {
        var sb = new StringBuilder();
        var defaults = banning.Defaults ?? new JailSettings();
        var ignoreIp = string.Join(' ', new[] { "127.0.0.1/8", "::1" }.Concat(banning.Allowlist ?? []).Distinct());

        foreach (var (name, jail) in (banning.Jails ?? []).OrderBy(j => j.Key, StringComparer.Ordinal))
        {
            if (skipJails.Contains(name)) continue;
            sb.Append('[').Append(name).Append("]\n");
            if (jail.Enabled != true)
            {
                sb.Append("enabled = false\n\n");
                continue;
            }
            sb.Append("enabled = true\n");
            var eff = PolicyMergerExtensions.Effective(defaults, jail);
            Line(sb, "filter", eff.Filter);
            Line(sb, "port", eff.Port);
            Line(sb, "logpath", eff.Logpath);
            Line(sb, "backend", eff.Backend);
            Line(sb, "bantime", Seconds(eff.Bantime));
            Line(sb, "findtime", Seconds(eff.Findtime));
            Line(sb, "maxretry", eff.Maxretry?.ToString(CultureInfo.InvariantCulture));
            Line(sb, "banaction", eff.Banaction);
            if (eff.BantimeIncrement is { } inc)
            {
                Line(sb, "bantime.increment", inc ? "true" : "false");
                if (inc)
                {
                    Line(sb, "bantime.maxtime", Seconds(eff.BantimeMaxtime));
                    Line(sb, "bantime.factor", eff.BantimeFactor?.ToString(CultureInfo.InvariantCulture));
                }
            }
            Line(sb, "ignoreip", ignoreIp);
            sb.Append('\n');
        }

        // The dashboard's manual-ban jail. It matches no log lines (an empty filter on /dev/null), so it only
        // holds bans issued through fail2ban-client. Its bans survive restarts via fail2ban's own database.
        sb.Append('[').Append(PolicyYaml.ManualJailName).Append("]\n");
        sb.Append("enabled = true\n");
        sb.Append("filter = ").Append(PolicyYaml.ManualJailName).Append('\n');
        sb.Append("logpath = /dev/null\n");
        sb.Append("backend = polling\n");
        sb.Append("maxretry = 1\n");
        sb.Append("bantime = ").Append(Seconds(banning.ManualBantime ?? "permanent")).Append('\n');
        Line(sb, "banaction", defaults.Banaction);
        Line(sb, "ignoreip", ignoreIp);
        return sb.ToString();
    }

    private static void Line(StringBuilder sb, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value)) sb.Append(key).Append(" = ").Append(value).Append('\n');
    }

    private static string? Seconds(string? duration) =>
        duration is not null && Duration.TryParseSeconds(duration, out var s) ? s.ToString(CultureInfo.InvariantCulture) : null;
}

internal static class PolicyMergerExtensions
{
    public static JailSettings Effective(JailSettings defaults, JailSettings jail) => new()
    {
        Enabled = jail.Enabled,
        Bantime = jail.Bantime ?? defaults.Bantime,
        Findtime = jail.Findtime ?? defaults.Findtime,
        Maxretry = jail.Maxretry ?? defaults.Maxretry,
        Banaction = jail.Banaction ?? defaults.Banaction,
        BantimeIncrement = jail.BantimeIncrement ?? defaults.BantimeIncrement,
        BantimeMaxtime = jail.BantimeMaxtime ?? defaults.BantimeMaxtime,
        BantimeFactor = jail.BantimeFactor ?? defaults.BantimeFactor,
        Filter = jail.Filter,
        Port = jail.Port,
        Logpath = jail.Logpath,
        Backend = jail.Backend,
    };
}
