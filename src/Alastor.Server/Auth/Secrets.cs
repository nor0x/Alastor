using System.Security.Cryptography;
using System.Text;

namespace Alastor.Server.Auth;

/// <summary>
/// Random high-entropy secrets: enrollment tokens, agent secrets and API keys. These are 256-bit random
/// values, so a fast SHA-256 is the right storage hash (a slow KDF only matters for human-chosen passwords,
/// which use PBKDF2 via <c>PasswordHasher</c>).
/// </summary>
public static class Secrets
{
    public static string Generate(string prefix, int bytes = 32) =>
        prefix + Base64UrlEncode(RandomNumberGenerator.GetBytes(bytes));

    public static string Hash(string secret) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    public static bool FixedTimeEquals(string hashA, string hashB) =>
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(hashA), Encoding.ASCII.GetBytes(hashB));

    private static string Base64UrlEncode(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
