using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Alastor.Core.Access;

/// <summary>One key line in an authorized_keys file (sshd(8), AUTHORIZED_KEYS FILE FORMAT).</summary>
/// <param name="Line">1-based line number in <paramref name="File"/>, as of the scan.</param>
/// <param name="Fingerprint">"SHA256:…", the way <c>ssh-keygen -lf</c> and sshd's "Accepted publickey" log line print it.</param>
/// <param name="Bits">Key size: the RSA/DSA modulus, or the curve size. Null when the blob didn't say.</param>
/// <param name="Options">The leading options (<c>from="…",no-pty</c>), verbatim; empty when there are none.</param>
public sealed record AuthorizedKey(string File, int Line, string Type, string Fingerprint, int? Bits, string Comment, string Options)
{
    /// <summary>Why this key is weak (DSA; RSA under 2048 bits), or null.</summary>
    public string? Weakness => SshKeyParser.Weakness(Type, Bits);
}

/// <summary>An account that can log in over SSH, with the keys in the authorized_keys files sshd reads for it.</summary>
/// <param name="Files">The files sshd reads for this account (<c>AuthorizedKeysFile</c>, expanded), existing or not. A key is added to the first.</param>
/// <param name="Admin">root, or a member of sudo/wheel/admin.</param>
public sealed record KeyAccount(string User, int Uid, string Home, bool Admin, IReadOnlyList<string> Files, IReadOnlyList<AuthorizedKey> Keys);

/// <summary>Who can log in over SSH with which key, on one host.</summary>
/// <param name="KeysCommand">sshd also asks a command for keys (<c>AuthorizedKeysCommand</c>: LDAP, cloud metadata), so the files aren't the whole story.</param>
/// <param name="PasswordLogin">sshd accepts passwords (or keyboard-interactive). Null when <c>sshd -T</c> couldn't run.</param>
public sealed record SshKeysReport(IReadOnlyList<KeyAccount> Accounts, bool KeysCommand, bool? PasswordLogin)
{
    /// <summary>Lines that couldn't be read as keys, files that couldn't be read, and the like.</summary>
    public IReadOnlyList<string> Notes { get; init; } = [];
}

/// <summary>A key line taken apart, with its fingerprint computed from the blob.</summary>
public sealed record ParsedKey(string Options, string Type, string Blob, string Comment, string Fingerprint, int? Bits)
{
    /// <summary>The line as it goes into authorized_keys.</summary>
    public string ToLine() => string.Join(' ', new[] { Options, Type, Blob, Comment }.Where(p => p.Length > 0));
}

/// <summary>
/// Reads and checks OpenSSH public key lines without running ssh-keygen. The blob is the SSH wire encoding
/// (RFC 4253 §6.6): a length-prefixed type name that must match the line's type, then the key's fields.
/// </summary>
public static class SshKeyParser
{
    public const int MaxLineLength = 16 * 1024;
    public const int MaxCommentLength = 200;

    public static readonly IReadOnlySet<string> KeyTypes = new HashSet<string>(StringComparer.Ordinal)
    {
        "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-dss",
    };

    /// <summary>A key line from an authorized_keys file, or null for blank lines, comments and lines that aren't keys.</summary>
    public static ParsedKey? Parse(string line)
    {
        var t = line.Trim();
        if (t.Length == 0 || t[0] == '#' || t.Length > MaxLineLength) return null;
        var options = "";
        var rest = t;
        if (!KeyTypes.Contains(FirstToken(t)))
        {
            // Options run to the first whitespace outside double quotes (from="a, b" can contain spaces).
            var quoted = false;
            var end = 0;
            for (; end < t.Length; end++)
            {
                if (t[end] == '\\' && quoted && end + 1 < t.Length) { end++; continue; }
                if (t[end] == '"') quoted = !quoted;
                else if (!quoted && char.IsWhiteSpace(t[end])) break;
            }
            if (end >= t.Length) return null;
            options = t[..end];
            rest = t[end..].TrimStart();
        }
        var parts = rest.Split((char[])[' ', '\t'], 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !KeyTypes.Contains(parts[0])) return null;
        var blob = Decode(parts[1]);
        if (blob is null || ReadString(blob, 0, out var next) is not { } embedded || embedded != parts[0]) return null;
        return new ParsedKey(options, parts[0], parts[1], parts.Length > 2 ? parts[2].Trim() : "", Fingerprint(blob), Bits(parts[0], blob, next));
    }

    /// <summary>
    /// A key someone wants to add: exactly one line, a plain key (no options, so no <c>command=</c> sneaks in), not weak,
    /// with a printable comment. Returns null and the reason when it isn't acceptable.
    /// </summary>
    public static ParsedKey? ParseNew(string? text, out string? error)
    {
        error = null;
        var lines = (text ?? "").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        if (lines.Count == 0) { error = "Paste a public key (the contents of a .pub file)."; return null; }
        if (lines.Count > 1) { error = "Paste one key at a time."; return null; }
        var line = lines[0];
        if (line.StartsWith("-----BEGIN", StringComparison.Ordinal))
        {
            error = line.Contains("PRIVATE", StringComparison.Ordinal)
                ? "That is a private key. Never share it; paste the matching .pub file instead."
                : "That's a PEM key. Paste the OpenSSH form (ssh-ed25519 AAAA… or ssh-rsa AAAA…), e.g. from ssh-keygen -y -f key.";
            return null;
        }
        if (line.Length > MaxLineLength) { error = "That key is too long."; return null; }
        var key = Parse(line);
        if (key is null)
        {
            error = KeyTypes.Contains(FirstToken(line))
                ? "The key data is damaged (it doesn't decode, or doesn't match its type). Copy the whole line again."
                : $"Not an OpenSSH public key. It should start with one of: {string.Join(", ", KeyTypes.Where(k => k != "ssh-dss"))}.";
            return null;
        }
        if (key.Options.Length > 0) { error = "Paste the key without options (from=, command=, …)."; return null; }
        if (Weakness(key.Type, key.Bits) is { } weak) { error = $"Alastor doesn't add weak keys: {weak}."; return null; }
        if (key.Comment.Length > MaxCommentLength || key.Comment.Any(char.IsControl)) { error = $"Keep the comment printable and under {MaxCommentLength} characters."; return null; }
        return key;
    }

    public static string? Weakness(string type, int? bits) => type switch
    {
        "ssh-dss" => "DSA keys are obsolete and OpenSSH no longer accepts them",
        "ssh-rsa" when bits < 2048 => $"RSA keys need at least 2048 bits (this one has {bits})",
        _ => null,
    };

    /// <summary>"SHA256:" and the unpadded base64 of the blob's SHA-256, as OpenSSH prints it.</summary>
    public static string Fingerprint(byte[] blob) => "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');

    /// <summary>An account name the way useradd accepts it (a trailing $ for machine accounts): no paths, spaces or leading dashes.</summary>
    public static bool IsValidUser(string? s)
    {
        if (s is null || s.Length is 0 or > 32) return false;
        var name = s[^1] == '$' ? s[..^1] : s;
        return name.Length > 0 && (char.IsAsciiLetter(name[0]) || name[0] == '_')
            && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-');
    }

    /// <summary>A fingerprint as the dashboard sends it: "SHA256:" and 43 base64 characters.</summary>
    public static bool IsFingerprint(string? s) =>
        s is { Length: 50 } && s.StartsWith("SHA256:", StringComparison.Ordinal) && s[7..].All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/');

    private static string FirstToken(string s)
    {
        var i = s.IndexOfAny([' ', '\t']);
        return i < 0 ? s : s[..i];
    }

    private static byte[]? Decode(string base64)
    {
        try { return Convert.FromBase64String(base64); }
        catch (FormatException) { return null; }
    }

    private static int? Bits(string type, byte[] blob, int offset)
    {
        switch (type)
        {
            case "ssh-ed25519" or "sk-ssh-ed25519@openssh.com":
                return 256;
            case "ecdsa-sha2-nistp256" or "sk-ecdsa-sha2-nistp256@openssh.com":
                return 256;
            case "ecdsa-sha2-nistp384":
                return 384;
            case "ecdsa-sha2-nistp521":
                return 521;
            case "ssh-rsa":
                // string "ssh-rsa", mpint e, mpint n
                return ReadBytes(blob, offset, out var afterE) is null ? null : MpintBits(ReadBytes(blob, afterE, out _));
            case "ssh-dss":
                // string "ssh-dss", mpint p, …
                return MpintBits(ReadBytes(blob, offset, out _));
            default:
                return null;
        }
    }

    private static int? MpintBits(byte[]? n)
    {
        if (n is null) return null;
        var i = 0;
        while (i < n.Length && n[i] == 0) i++;
        if (i == n.Length) return 0;
        var top = n[i];
        var bits = 0;
        while (top != 0) { bits++; top >>= 1; }
        return (n.Length - i - 1) * 8 + bits;
    }

    private static string? ReadString(byte[] blob, int offset, out int next) =>
        ReadBytes(blob, offset, out next) is { } b ? System.Text.Encoding.ASCII.GetString(b) : null;

    private static byte[]? ReadBytes(byte[] blob, int offset, out int next)
    {
        next = offset;
        if (offset + 4 > blob.Length) return null;
        var len = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(offset));
        if (len > blob.Length - offset - 4) return null;
        next = offset + 4 + (int)len;
        return blob.AsSpan(offset + 4, (int)len).ToArray();
    }
}
