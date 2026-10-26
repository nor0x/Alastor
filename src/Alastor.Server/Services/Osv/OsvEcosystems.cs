namespace Alastor.Server.Services.Osv;

/// <summary>
/// Maps a host's <c>/etc/os-release</c> to the OSV.dev ecosystem that tracks its packages, and says which package name
/// OSV keys on there. Debian, Ubuntu and Alpine advisories name source packages; AlmaLinux and Rocky name binary RPMs.
/// RHEL itself (whose OSV ecosystem is split per repository) and Fedora aren't covered.
/// </summary>
public static class OsvEcosystems
{
    public static string? For(string osId, string osVersion)
    {
        var parts = osVersion.Split('.');
        var major = parts[0];
        if (major.Length == 0 || !major.All(char.IsAsciiDigit)) return null;
        return osId.ToLowerInvariant() switch
        {
            "debian" => $"Debian:{major}",
            // LTS releases are April releases of even years (22.04, 24.04); OSV names them with an ":LTS" suffix.
            "ubuntu" when parts.Length >= 2 => int.Parse(major, System.Globalization.CultureInfo.InvariantCulture) % 2 == 0 && parts[1] == "04"
                ? $"Ubuntu:{major}.{parts[1]}:LTS" : $"Ubuntu:{major}.{parts[1]}",
            "almalinux" => $"AlmaLinux:{major}",
            "rocky" => $"Rocky Linux:{major}",
            "alpine" when parts.Length >= 2 => $"Alpine:v{major}.{parts[1]}",
            _ => null,
        };
    }

    /// <summary>True where OSV keys advisories on the source package rather than the binary one.</summary>
    public static bool UsesSourceName(string ecosystem) =>
        ecosystem.StartsWith("Debian:", StringComparison.Ordinal) || ecosystem.StartsWith("Ubuntu:", StringComparison.Ordinal) || ecosystem.StartsWith("Alpine:", StringComparison.Ordinal);

    public static string QueryName(string ecosystem, string name, string? source) =>
        UsesSourceName(ecosystem) && !string.IsNullOrEmpty(source) ? source : name;
}
