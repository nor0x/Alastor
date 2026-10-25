namespace Alastor.Core.Platform;

public enum DistroFamily
{
    Unknown,
    Debian,
    RedHat,
    Alpine,
}

/// <summary>Parsed from <c>/etc/os-release</c> (freedesktop.org format), which every supported distro ships.</summary>
public sealed record OsInfo(string Id, string VersionId, string PrettyName, DistroFamily Family, string Architecture)
{
    public static async Task<OsInfo> DetectAsync(IFileSystem fs, CancellationToken ct = default)
    {
        var text = await fs.ReadAllTextAsync("/etc/os-release", ct) ?? await fs.ReadAllTextAsync("/usr/lib/os-release", ct) ?? "";
        return Parse(text, System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant());
    }

    public static OsInfo Parse(string osRelease, string arch)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in osRelease.Split('\n'))
        {
            var idx = line.IndexOf('=');
            if (idx <= 0 || line.TrimStart().StartsWith('#')) continue;
            values[line[..idx].Trim()] = line[(idx + 1)..].Trim().Trim('"', '\'');
        }
        var id = values.GetValueOrDefault("ID", "linux");
        var like = $"{id} {values.GetValueOrDefault("ID_LIKE", "")}";
        var family =
            like.Contains("debian") || like.Contains("ubuntu") ? DistroFamily.Debian :
            like.Contains("rhel") || like.Contains("fedora") || like.Contains("centos") ? DistroFamily.RedHat :
            like.Contains("alpine") ? DistroFamily.Alpine :
            DistroFamily.Unknown;
        return new OsInfo(id, values.GetValueOrDefault("VERSION_ID", ""), values.GetValueOrDefault("PRETTY_NAME", id), family, arch);
    }
}
