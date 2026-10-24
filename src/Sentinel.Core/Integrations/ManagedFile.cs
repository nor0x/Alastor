using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Sentinel.Core.Integrations;

public enum ManagedFileState
{
    Missing,
    Owned,

    /// <summary>Carries our marker, but the body no longer matches the recorded hash: someone edited it by hand.</summary>
    Drifted,

    /// <summary>Exists at our path without our marker. We never overwrite it.</summary>
    Foreign,
}

public sealed record ManagedFileInspection(ManagedFileState State, string? Revision, string? Body);

/// <summary>
/// The ownership marker on every config file the agent writes. The header holds the policy revision and a
/// hash of the body, so a hand edit shows up as drift instead of being overwritten silently.
/// </summary>
public static partial class ManagedFile
{
    public const string Marker = "Managed by SentinelVPS";

    public static string Render(string body, string revision, string commentPrefix = "#")
    {
        body = body.ReplaceLineEndings("\n").TrimEnd('\n') + "\n";
        var sb = new StringBuilder();
        sb.Append(commentPrefix).Append(' ').Append(Marker).Append(". Do not edit: manual changes\n");
        sb.Append(commentPrefix).Append(" are reported as drift and block further updates. Change the policy in the dashboard instead.\n");
        sb.Append(commentPrefix).Append(" sentinel-revision: ").Append(revision).Append('\n');
        sb.Append(commentPrefix).Append(" sentinel-sha256: ").Append(Hash(body)).Append('\n');
        sb.Append('\n');
        sb.Append(body);
        return sb.ToString();
    }

    public static ManagedFileInspection Inspect(string? content)
    {
        if (content is null) return new(ManagedFileState.Missing, null, null);
        content = content.ReplaceLineEndings("\n");
        var rev = RevisionRegex().Match(content);
        var sha = ShaRegex().Match(content);
        if (!content.Contains(Marker, StringComparison.Ordinal) || !sha.Success)
            return new(ManagedFileState.Foreign, null, content);
        // The body starts after the first blank line that follows the header.
        var split = content.IndexOf("\n\n", StringComparison.Ordinal);
        var body = split < 0 ? "" : content[(split + 2)..];
        var state = Hash(body) == sha.Groups[1].Value ? ManagedFileState.Owned : ManagedFileState.Drifted;
        return new(state, rev.Success ? rev.Groups[1].Value : null, body);
    }

    private static string Hash(string body) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(body)));

    [GeneratedRegex(@"sentinel-revision: (\S+)")]
    private static partial Regex RevisionRegex();

    [GeneratedRegex(@"sentinel-sha256: ([0-9a-f]{64})")]
    private static partial Regex ShaRegex();
}
