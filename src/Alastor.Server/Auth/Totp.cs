using System.Security.Cryptography;
using System.Text;

namespace Alastor.Server.Auth;

/// <summary>
/// Time-based one-time passwords (RFC 6238) as authenticator apps expect them: HMAC-SHA1, 6 digits, 30-second steps.
/// A code is accepted one step either side of now, to allow for clock drift and typing time.
/// </summary>
public static class Totp
{
    public const int Digits = 6;
    public const int StepSeconds = 30;

    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(20);

    public static long StepAt(DateTimeOffset time) => time.ToUnixTimeSeconds() / StepSeconds;

    public static string Code(byte[] key, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> hash = stackalloc byte[20];
        HMACSHA1.HashData(key, counter, hash);
        var offset = hash[^1] & 0x0F;
        var binary = (hash[offset] & 0x7F) << 24 | hash[offset + 1] << 16 | hash[offset + 2] << 8 | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>The step the code matches, if it is valid now and newer than <paramref name="lastUsedStep"/> (no replays).</summary>
    public static long? Verify(byte[] key, string? code, DateTimeOffset now, long lastUsedStep)
    {
        code = new string((code ?? "").Where(char.IsAsciiDigit).ToArray());
        if (code.Length != Digits) return null;
        var current = StepAt(now);
        for (var step = current - 1; step <= current + 1; step++)
        {
            if (step <= lastUsedStep) continue;
            if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Code(key, step)), Encoding.ASCII.GetBytes(code))) return step;
        }
        return null;
    }

    /// <summary>The <c>otpauth://</c> URI authenticator apps scan as a QR code.</summary>
    public static string ProvisioningUri(string issuer, string account, byte[] key) =>
        $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}?secret={Base32(key)}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={Digits}&period={StepSeconds}";

    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Base32(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = buffer << 8 | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static byte[] FromBase32(string text)
    {
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (var c in text.ToUpperInvariant())
        {
            var v = Alphabet.IndexOf(c);
            if (v < 0) continue; // padding, spaces
            buffer = buffer << 5 | v;
            bits += 5;
            if (bits >= 8)
            {
                bytes.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return [.. bytes];
    }

    /// <summary>Ten single-use recovery codes like <c>k3fq2-9zxmb</c> (50 bits each), for when the authenticator is lost.</summary>
    public static List<string> NewRecoveryCodes() =>
        Enumerable.Range(0, 10).Select(_ =>
        {
            var s = Base32(RandomNumberGenerator.GetBytes(7)).ToLowerInvariant();
            return $"{s[..5]}-{s[5..10]}";
        }).ToList();

    public static string HashRecoveryCode(string code) =>
        Secrets.Hash(new string(code.Where(char.IsAsciiLetterOrDigit).ToArray()).ToLowerInvariant());
}
