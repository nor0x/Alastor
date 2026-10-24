using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core.Net;

namespace Sentinel.Core.Blocklists;

public enum BlocklistFormat
{
    /// <summary>One IP or CIDR per line; <c>#</c> or <c>;</c> start a comment (FireHOL netset, abuse.ch, blocklist.de, CINS, ET).</summary>
    Netset,

    /// <summary>Spamhaus DROP JSON: one object per line, <c>{"cidr": …, "sblid": …}</c>, plus a final metadata object.</summary>
    SpamhausJson,
}

/// <summary>A public IP blocklist the server can pull. Agents never fetch these themselves.</summary>
public sealed record BlocklistSource(
    string Id,
    string Name,
    string Homepage,
    IReadOnlyList<string> Urls,
    BlocklistFormat Format,
    string Terms,
    string Description);

/// <summary>
/// Curated lists with low false-positive rates that are free to use on your own servers. Spamhaus DROP is consumed
/// through its JSON feed (the structured format Spamhaus recommends since 2024); the others publish only plain
/// netset text, their documented format.
/// </summary>
public static class BlocklistCatalog
{
    public static readonly IReadOnlyList<BlocklistSource> All =
    [
        new("spamhaus-drop", "Spamhaus DROP", "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
            ["https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"], BlocklistFormat.SpamhausJson,
            "Free; Spamhaus DROP terms (https://www.spamhaus.org/drop/terms/)",
            "Netblocks hijacked or leased by spammers and cyber-crime operations. Meant to be dropped by everyone, so false positives are very rare."),
        new("firehol-level1", "FireHOL level 1", "https://iplists.firehol.org/?ipset=firehol_level1",
            ["https://iplists.firehol.org/files/firehol_level1.netset"], BlocklistFormat.Netset,
            "Aggregated from free lists, each under its own terms",
            "Spamhaus DROP, DShield top attackers and Feodo botnet C2s in one list (the bogons it also carries are taken out). FireHOL's 'basic protection for every internet-facing server'."),
        new("abuse-ch-feodo", "abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/blocklist/",
            ["https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"], BlocklistFormat.Netset,
            "CC0", "Active botnet command-and-control servers (Emotet, QakBot, …)."),
        new("et-compromised", "Emerging Threats compromised hosts", "https://rules.emergingthreats.net/",
            ["https://rules.emergingthreats.net/blockrules/compromised-ips.txt"], BlocklistFormat.Netset,
            "Free (Proofpoint ET Open)", "Hosts known to be compromised and attacking others."),
        new("blocklist-de", "blocklist.de (all services)", "https://www.blocklist.de/en/export.html",
            ["https://lists.blocklist.de/lists/all.txt"], BlocklistFormat.Netset,
            "Free", "Addresses reported for SSH, mail, FTP and web attacks in the last 48 hours, by fail2ban users. Large (~30k) and fast-changing."),
        new("cins-army", "CINS Army", "https://cinsscore.com/#list",
            ["https://cinsscore.com/list/ci-badguys.txt"], BlocklistFormat.Netset,
            "Free", "Addresses with poor reputation on Sentinel IPS sensors. Large (15k)."),
    ];

    public static BlocklistSource? Find(string id) => All.FirstOrDefault(s => s.Id == id);

    public const string DefaultList = "spamhaus-drop";
}

/// <summary>The entries of one fetched document, plus what was skipped and why.</summary>
public sealed record ParsedBlocklist(IReadOnlyList<IpTarget> Entries, int Invalid, int TooWide);

public static class BlocklistParser
{
    /// <summary>Entries wider than this are skipped: no legitimate blocklist entry covers a sixteenth of the IPv4 internet.</summary>
    public const int MinPrefixV4 = 8;
    public const int MinPrefixV6 = 16;

    public static ParsedBlocklist Parse(BlocklistFormat format, string text) => format switch
    {
        BlocklistFormat.SpamhausJson => Collect(SpamhausCidrs(text)),
        _ => Collect(NetsetEntries(text)),
    };

    private static IEnumerable<string> NetsetEntries(string text)
    {
        foreach (var raw in text.Split('\n'))
        {
            var line = raw;
            var comment = line.IndexOfAny(['#', ';']);
            if (comment >= 0) line = line[..comment];
            line = line.Trim();
            if (line.Length == 0) continue;
            // Some lists append fields after the address ("1.2.3.0/24 SBL123"); the address always comes first.
            var space = line.IndexOfAny([' ', '\t']);
            yield return space >= 0 ? line[..space] : line;
        }
    }

    private static IEnumerable<string?> SpamhausCidrs(string text)
    {
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            SpamhausRecord? record;
            try { record = JsonSerializer.Deserialize(line, BlocklistJson.Default.SpamhausRecord); }
            catch (JsonException) { record = null; }
            if (record?.Type == "metadata") continue;
            yield return record?.Cidr;
        }
    }

    private static ParsedBlocklist Collect(IEnumerable<string?> values)
    {
        var entries = new List<IpTarget>();
        int invalid = 0, tooWide = 0;
        foreach (var v in values)
        {
            if (!IpTarget.TryParse(v, out var t)) { invalid++; continue; }
            var isV4 = t.Value.Network.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
            if (t.Value.Network.PrefixLength < (isV4 ? MinPrefixV4 : MinPrefixV6) && !IsReservedOnly(t.Value)) { tooWide++; continue; }
            entries.Add(t.Value);
        }
        return new(entries, invalid, tooWide);
    }

    // FireHOL lists 224.0.0.0/3 (multicast + reserved); it disappears with the reserved ranges anyway, so it isn't "too wide".
    private static bool IsReservedOnly(IpTarget t) => IpRangeSet.From([t]).Except(IpRangeSet.Reserved).IsEmpty;
}

public sealed record SpamhausRecord(string? Cidr, string? Type);

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(SpamhausRecord))]
internal sealed partial class BlocklistJson : JsonSerializerContext;
