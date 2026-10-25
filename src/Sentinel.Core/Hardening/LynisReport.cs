using System.Globalization;

namespace Sentinel.Core.Hardening;

public enum LynisItemKind
{
    Warning,
    Suggestion,
}

/// <summary>One Lynis warning or suggestion: <c>warning[]=TEST-ID|text|details|solution|</c>.</summary>
/// <param name="Details">Lynis's detail field, often the file, service or setting concerned; null when Lynis writes <c>-</c>.</param>
/// <param name="Solution">A remediation hint where Lynis has one; null when it writes <c>-</c>.</param>
public sealed record LynisItem(string TestId, LynisItemKind Kind, string Text, string? Details, string? Solution);

/// <summary>A Lynis audit, as read from its report file.</summary>
/// <param name="ResolvedSinceLast">Filled in by the server: test ids reported by the previous audit but not this one.</param>
public sealed record HardeningReport(
    string? LynisVersion,
    int? HardeningIndex,
    int TestsExecuted,
    IReadOnlyList<LynisItem> Items,
    IReadOnlyList<string>? ResolvedSinceLast = null);

/// <summary>
/// Reads Lynis's machine-readable report (<c>--report-file</c>, by default <c>/var/log/lynis-report.dat</c>): one
/// <c>key=value</c> per line, <c>key[]=value</c> for lists, with warnings and suggestions as pipe-separated fields
/// (documented in Lynis's README and used by its own <c>lynis show</c> commands). Unknown keys are ignored.
/// </summary>
public static class LynisReportParser
{
    public static HardeningReport Parse(string content)
    {
        string? version = null;
        int? index = null;
        var tests = 0;
        var items = new List<LynisItem>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0 || line[0] == '#') continue;
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq];
            var value = line[(eq + 1)..];
            switch (key)
            {
                case "lynis_version":
                    version = value.Trim();
                    break;
                case "hardening_index" when int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var hi) && hi is >= 0 and <= 100:
                    index = hi;
                    break;
                case "lynis_tests_done" when int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var done):
                    tests = done;
                    break;
                case "warning[]" or "suggestion[]":
                    if (ParseItem(value, key == "warning[]" ? LynisItemKind.Warning : LynisItemKind.Suggestion) is { } item
                        && seen.Add($"{item.Kind}|{item.TestId}|{item.Text}|{item.Details}"))
                        items.Add(item);
                    break;
            }
        }
        return new HardeningReport(version, index, tests, items);
    }

    private static LynisItem? ParseItem(string value, LynisItemKind kind)
    {
        // TEST-ID|text|details|solution|   (trailing pipe; details and solution are "-" when empty)
        var parts = value.Split('|');
        if (parts.Length < 2 || string.IsNullOrWhiteSpace(parts[0]) || string.IsNullOrWhiteSpace(parts[1])) return null;
        static string? Field(string[] p, int i) => i < p.Length && p[i].Trim() is { Length: > 0 } s && s != "-" ? Clip(s, 500) : null;
        // Some solutions carry a "text:" type prefix ("text:Use chmod to change file permissions").
        var solution = Field(parts, 3);
        if (solution?.StartsWith("text:", StringComparison.Ordinal) == true) solution = solution[5..].Trim() is { Length: > 0 } t ? t : null;
        return new LynisItem(Clip(parts[0].Trim(), 32), kind, Clip(parts[1].Trim(), 500), Field(parts, 2), solution);
    }

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    /// <summary>Test-id prefixes (the part before the dash) to the category Lynis groups them under.</summary>
    public static readonly IReadOnlyDictionary<string, string> Categories = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["ACCT"] = "Accounting", ["AUTH"] = "Authentication", ["BANN"] = "Banners", ["BOOT"] = "Boot and services", ["CONT"] = "Containers",
        ["CRYP"] = "Cryptography", ["DBS"] = "Databases", ["DEB"] = "Debian", ["DNS"] = "DNS", ["FILE"] = "File systems", ["FINT"] = "File integrity",
        ["FIRE"] = "Firewall", ["HOME"] = "Home directories", ["HRDN"] = "Hardening", ["HTTP"] = "Web servers", ["INSE"] = "Insecure services",
        ["KRNL"] = "Kernel", ["LDAP"] = "LDAP", ["LOGG"] = "Logging", ["LYNIS"] = "Lynis", ["MACF"] = "MAC frameworks", ["MAIL"] = "Mail",
        ["MALW"] = "Malware", ["NAME"] = "Name services", ["NETW"] = "Networking", ["NTP"] = "Time", ["PHP"] = "PHP", ["PKGS"] = "Packages",
        ["PRNT"] = "Printing", ["PROC"] = "Processes", ["RBAC"] = "Access control", ["SCHD"] = "Scheduling", ["SHLL"] = "Shells", ["SNMP"] = "SNMP",
        ["SQD"] = "Squid", ["SSH"] = "SSH", ["STRG"] = "Storage", ["TIME"] = "Time", ["TOOL"] = "Tools", ["USB"] = "USB", ["CUST"] = "Custom",
    };

    public static string Category(string testId)
    {
        var dash = testId.IndexOf('-');
        var prefix = dash > 0 ? testId[..dash] : testId;
        return Categories.TryGetValue(prefix, out var c) ? c : prefix;
    }
}
