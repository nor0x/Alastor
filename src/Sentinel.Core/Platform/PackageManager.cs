namespace Sentinel.Core.Platform;

public sealed record PackageInstallResult(bool Success, string? Error);

/// <summary>
/// Installs bundled tools from the distro's own repositories. The agent never downloads or vendors binaries;
/// if the distro does not ship a package, the capability is reported as unavailable with the reason.
/// </summary>
public interface IPackageManager
{
    string Name { get; }
    Task<bool> IsInstalledAsync(string package, CancellationToken ct);
    Task<string?> InstalledVersionAsync(string package, CancellationToken ct);
    Task<bool> IsAvailableAsync(string package, CancellationToken ct);
    Task<PackageInstallResult> InstallAsync(string package, CancellationToken ct);
}

public static class PackageManagers
{
    public static IPackageManager? For(DistroFamily family, ICommandRunner runner) => family switch
    {
        DistroFamily.Debian => new AptPackageManager(runner),
        DistroFamily.RedHat => new DnfPackageManager(runner),
        DistroFamily.Alpine => new ApkPackageManager(runner),
        _ => null,
    };
}

public sealed class AptPackageManager(ICommandRunner runner) : IPackageManager
{
    private static readonly CommandOptions Install = new()
    {
        Timeout = TimeSpan.FromMinutes(10),
        Environment = new Dictionary<string, string> { ["DEBIAN_FRONTEND"] = "noninteractive" },
    };

    public string Name => "apt";

    public async Task<bool> IsInstalledAsync(string package, CancellationToken ct) =>
        (await InstalledVersionAsync(package, ct)) is not null;

    public async Task<string?> InstalledVersionAsync(string package, CancellationToken ct)
    {
        var r = await runner.RunAsync("dpkg-query", ["-W", "-f=${Status}\t${Version}", package], null, ct);
        if (!r.Success) return null;
        var parts = r.StdOut.Split('\t');
        return parts.Length == 2 && parts[0].EndsWith("installed", StringComparison.Ordinal) && !parts[0].Contains("not-installed")
            ? parts[1].Trim()
            : null;
    }

    public async Task<bool> IsAvailableAsync(string package, CancellationToken ct)
    {
        var r = await runner.RunAsync("apt-cache", ["policy", package], null, ct);
        return r.Success && r.StdOut.Contains("Candidate:") && !r.StdOut.Contains("Candidate: (none)");
    }

    public async Task<PackageInstallResult> InstallAsync(string package, CancellationToken ct)
    {
        var update = await runner.RunAsync("apt-get", ["update", "-qq"], Install, ct);
        if (!update.Success) return new(false, $"apt-get update failed: {update.StdErr.Trim()}");
        var r = await runner.RunAsync("apt-get", ["install", "-y", "-qq", "--no-install-recommends", package], Install, ct);
        return new(r.Success, r.Success ? null : r.CombinedOutput);
    }
}

public sealed class DnfPackageManager(ICommandRunner runner) : IPackageManager
{
    private static readonly CommandOptions Install = new() { Timeout = TimeSpan.FromMinutes(10) };
    public string Name => "dnf";

    public async Task<bool> IsInstalledAsync(string package, CancellationToken ct) =>
        (await InstalledVersionAsync(package, ct)) is not null;

    public async Task<string?> InstalledVersionAsync(string package, CancellationToken ct)
    {
        var r = await runner.RunAsync("rpm", ["-q", "--qf", "%{VERSION}-%{RELEASE}", package], null, ct);
        return r.Success ? r.StdOut.Trim() : null;
    }

    public async Task<bool> IsAvailableAsync(string package, CancellationToken ct) =>
        (await runner.RunAsync("dnf", ["-q", "info", package], null, ct)).Success;

    public async Task<PackageInstallResult> InstallAsync(string package, CancellationToken ct)
    {
        var r = await runner.RunAsync("dnf", ["-y", "-q", "install", package], Install, ct);
        if (r.Success) return new(true, null);
        // fail2ban, ClamAV and friends live in EPEL on RHEL clones. Say so instead of "no match".
        return new(false, r.CombinedOutput.Contains("No match", StringComparison.OrdinalIgnoreCase)
            ? $"Package '{package}' not found. On RHEL-family systems enable EPEL first: dnf install epel-release"
            : r.CombinedOutput);
    }
}

public sealed class ApkPackageManager(ICommandRunner runner) : IPackageManager
{
    private static readonly CommandOptions Install = new() { Timeout = TimeSpan.FromMinutes(10) };
    public string Name => "apk";

    public async Task<bool> IsInstalledAsync(string package, CancellationToken ct) =>
        (await runner.RunAsync("apk", ["info", "-e", package], null, ct)).Success;

    public async Task<string?> InstalledVersionAsync(string package, CancellationToken ct)
    {
        if (!await IsInstalledAsync(package, ct)) return null;
        var r = await runner.RunAsync("apk", ["info", "-v", package], null, ct);
        var first = r.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
        return first.StartsWith(package + "-", StringComparison.Ordinal) ? first[(package.Length + 1)..] : first;
    }

    public async Task<bool> IsAvailableAsync(string package, CancellationToken ct)
    {
        var r = await runner.RunAsync("apk", ["search", "-e", package], null, ct);
        return r.Success && !string.IsNullOrWhiteSpace(r.StdOut);
    }

    public async Task<PackageInstallResult> InstallAsync(string package, CancellationToken ct)
    {
        var r = await runner.RunAsync("apk", ["add", "--no-progress", package], Install, ct);
        return new(r.Success, r.Success ? null : r.CombinedOutput);
    }
}
