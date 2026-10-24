using System.Net;
using System.Net.Sockets;

namespace Sentinel.Core.Net;

/// <summary>
/// An immutable set of IPv4 and IPv6 addresses stored as sorted, merged ranges. Used to combine blocklists, take out
/// the allowlist and reserved ranges, and emit the smallest equivalent list of CIDRs for nftables or ipset.
/// </summary>
public sealed class IpRangeSet
{
    private readonly (UInt128 Lo, UInt128 Hi)[] _v4;
    private readonly (UInt128 Lo, UInt128 Hi)[] _v6;

    private IpRangeSet((UInt128, UInt128)[] v4, (UInt128, UInt128)[] v6)
    {
        _v4 = v4;
        _v6 = v6;
    }

    public static readonly IpRangeSet Empty = new([], []);

    /// <summary>
    /// Special-purpose ranges (IANA registries, RFC 6890): private networks, CGNAT (Tailscale uses 100.64.0.0/10),
    /// loopback, link-local, documentation, multicast. Some public lists include them (FireHOL level1 carries the
    /// full bogon list); blocking them would cut a VPS off from its provider's private network, Docker or the tailnet.
    /// </summary>
    public static readonly IpRangeSet Reserved = From(new[]
    {
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
        "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
        "::/127", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
    }.Select(s => IpTarget.TryParse(s, out var t) ? t!.Value : throw new InvalidOperationException(s)));

    public static IpRangeSet From(IEnumerable<IpTarget> targets)
    {
        var v4 = new List<(UInt128, UInt128)>();
        var v6 = new List<(UInt128, UInt128)>();
        foreach (var t in targets)
        {
            var (lo, hi, isV4) = Bounds(t);
            (isV4 ? v4 : v6).Add((lo, hi));
        }
        return new(Normalize(v4), Normalize(v6));
    }

    public int RangeCount => _v4.Length + _v6.Length;
    public bool IsEmpty => RangeCount == 0;

    /// <summary>Number of IPv4 addresses covered, for display ("611 million addresses").</summary>
    public ulong Ipv4AddressCount => _v4.Aggregate(0UL, (sum, r) => sum + (ulong)(r.Hi - r.Lo + 1));

    public IpRangeSet Union(IpRangeSet other) =>
        new(Normalize(_v4.Concat(other._v4).ToList()), Normalize(_v6.Concat(other._v6).ToList()));

    public IpRangeSet Except(IpRangeSet other) => new(Subtract(_v4, other._v4), Subtract(_v6, other._v6));

    public bool Contains(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var isV4 = address.AddressFamily == AddressFamily.InterNetwork;
        var value = ToNumber(address.GetAddressBytes());
        var ranges = isV4 ? _v4 : _v6;
        // Binary search for the last range starting at or before the address.
        int lo = 0, hi = ranges.Length - 1;
        while (lo <= hi)
        {
            var mid = (lo + hi) / 2;
            if (ranges[mid].Lo <= value) lo = mid + 1;
            else hi = mid - 1;
        }
        return hi >= 0 && ranges[hi].Hi >= value;
    }

    /// <summary>The minimal CIDR list covering exactly this set, IPv4 first.</summary>
    public IEnumerable<string> ToCidrs(AddressFamily family)
    {
        var isV4 = family == AddressFamily.InterNetwork;
        var width = isV4 ? 32 : 128;
        foreach (var (rangeLo, rangeHi) in isV4 ? _v4 : _v6)
        {
            var lo = rangeLo;
            while (true)
            {
                // Largest block that starts at lo (alignment) and doesn't run past hi.
                var bits = lo == 0 ? width : Math.Min(width, (int)UInt128.TrailingZeroCount(lo));
                while (bits > 0 && BlockLast(lo, bits, width) > rangeHi) bits--;
                yield return Format(lo, width - bits, isV4);
                var last = BlockLast(lo, bits, width);
                if (last >= rangeHi) break;
                lo = last + 1;
            }
        }
    }

    private static UInt128 BlockLast(UInt128 lo, int bits, int width) =>
        bits >= width ? (width == 128 ? UInt128.MaxValue : (UInt128.One << width) - 1) : lo + ((UInt128.One << bits) - 1);

    private static string Format(UInt128 value, int prefix, bool isV4)
    {
        var bytes = new byte[isV4 ? 4 : 16];
        for (var i = bytes.Length - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }
        var ip = new IPAddress(bytes).ToString();
        return prefix == (isV4 ? 32 : 128) ? ip : $"{ip}/{prefix}";
    }

    private static (UInt128 Lo, UInt128 Hi, bool IsV4) Bounds(IpTarget t)
    {
        var bytes = t.Network.BaseAddress.GetAddressBytes();
        var width = bytes.Length * 8;
        var lo = ToNumber(bytes);
        var hostBits = width - t.Network.PrefixLength;
        var hi = hostBits == 0 ? lo : hostBits == 128 ? UInt128.MaxValue : lo | ((UInt128.One << hostBits) - 1);
        return (lo, hi, bytes.Length == 4);
    }

    private static UInt128 ToNumber(byte[] bytes)
    {
        UInt128 v = 0;
        foreach (var b in bytes) v = (v << 8) | b;
        return v;
    }

    private static (UInt128, UInt128)[] Normalize(List<(UInt128 Lo, UInt128 Hi)> ranges)
    {
        if (ranges.Count == 0) return [];
        ranges.Sort((a, b) => a.Lo.CompareTo(b.Lo));
        var merged = new List<(UInt128 Lo, UInt128 Hi)>(ranges.Count) { ranges[0] };
        foreach (var r in ranges.Skip(1))
        {
            var last = merged[^1];
            // Merge overlapping and adjacent ranges (last.Hi + 1 == r.Lo), guarding the overflow at the top of the space.
            if (r.Lo <= last.Hi || (last.Hi != UInt128.MaxValue && r.Lo == last.Hi + 1))
                merged[^1] = (last.Lo, UInt128.Max(last.Hi, r.Hi));
            else merged.Add(r);
        }
        return merged.ToArray();
    }

    private static (UInt128, UInt128)[] Subtract((UInt128 Lo, UInt128 Hi)[] a, (UInt128 Lo, UInt128 Hi)[] b)
    {
        var result = new List<(UInt128, UInt128)>(a.Length);
        var j = 0;
        foreach (var (rangeLo, hi) in a)
        {
            var lo = rangeLo;
            var alive = true;
            while (j < b.Length && b[j].Hi < lo) j++;
            for (var k = j; k < b.Length && b[k].Lo <= hi; k++)
            {
                if (b[k].Lo > lo) result.Add((lo, b[k].Lo - 1));
                if (b[k].Hi >= hi)
                {
                    alive = false;
                    break;
                }
                lo = b[k].Hi + 1;
            }
            if (alive) result.Add((lo, hi));
        }
        return result.ToArray();
    }
}
