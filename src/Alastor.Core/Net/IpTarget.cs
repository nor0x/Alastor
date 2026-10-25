using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace Alastor.Core.Net;

/// <summary>A single IP address or a CIDR network, normalized (192.0.2.7/32 becomes 192.0.2.7, and host bits are cleared).</summary>
public readonly record struct IpTarget(IPNetwork Network)
{
    public bool IsSingleAddress => Network.PrefixLength == (Network.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);

    public override string ToString() => IsSingleAddress ? Network.BaseAddress.ToString() : Network.ToString();

    public static bool TryParse(string? value, [NotNullWhen(true)] out IpTarget? target)
    {
        target = null;
        value = value?.Trim();
        if (string.IsNullOrEmpty(value)) return false;
        // IPAddress.TryParse accepts legacy inet_aton shorthands ("1.2.3" means 1.2.0.3). Require a full dotted quad for IPv4.
        var addressPart = value.Split('/')[0];
        if (!addressPart.Contains(':') && addressPart.Count(c => c == '.') != 3) return false;
        if (!value.Contains('/'))
        {
            if (!IPAddress.TryParse(value, out var ip)) return false;
            target = new IpTarget(new IPNetwork(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip, ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork || ip.IsIPv4MappedToIPv6 ? 32 : 128));
            return true;
        }
        var slash = value.IndexOf('/');
        if (!IPAddress.TryParse(value[..slash], out var addr) || !int.TryParse(value[(slash + 1)..], out var prefix)) return false;
        var max = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > max) return false;
        // IPNetwork rejects non-zero host bits, so clear them ourselves (10.1.2.3/8 becomes 10.0.0.0/8).
        var bytes = addr.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var bitsInByte = Math.Clamp(prefix - i * 8, 0, 8);
            bytes[i] &= (byte)(0xFF << (8 - bitsInByte));
        }
        target = new IpTarget(new IPNetwork(new IPAddress(bytes), prefix));
        return true;
    }

    public bool Overlaps(IpTarget other) =>
        Network.BaseAddress.AddressFamily == other.Network.BaseAddress.AddressFamily &&
        (Network.Contains(other.Network.BaseAddress) || other.Network.Contains(Network.BaseAddress));
}
