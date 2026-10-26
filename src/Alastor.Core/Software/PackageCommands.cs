namespace Alastor.Core.Software;

/// <summary>A program and its literal arguments.</summary>
public sealed record PackageCommand(string FileName, IReadOnlyList<string> Args);

/// <summary>
/// The one place that knows how each package manager upgrades, removes and simulates a single package. The agent
/// runs <see cref="Run"/> and <see cref="Simulate"/>; the dashboard shows <see cref="Display"/>, so the command an
/// operator copies is the command the one-click button runs.
/// </summary>
public static class PackageCommands
{
    // Wait for a running apt (the daily timer, an admin) instead of failing on its lock, and keep locally changed config files.
    private static readonly string[] AptLock = ["-o", "DPkg::Lock::Timeout=300"];
    private static readonly string[] AptKeepConfig = ["-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"];

    public static PackageCommand? Run(string manager, string op, string package) => (manager, op) switch
    {
        ("apt", PackageOps.Upgrade) => new("apt-get", ["install", "-y", "-q", "--only-upgrade", .. AptLock, .. AptKeepConfig, package]),
        // -y never answers apt's "Yes, do as I say!" prompt for essential packages, so apt refuses those by itself too.
        ("apt", PackageOps.Remove) => new("apt-get", ["remove", "-y", "-q", .. AptLock, package]),
        ("dnf", PackageOps.Upgrade) => new("dnf", ["-y", "-q", "upgrade", package]),
        ("dnf", PackageOps.Remove) => new("dnf", ["-y", "-q", "remove", package]),
        ("apk", PackageOps.Upgrade) => new("apk", ["upgrade", "-q", package]),
        ("apk", PackageOps.Remove) => new("apk", ["del", "-q", package]),
        _ => null,
    };

    /// <summary>A dry run that changes nothing and needs no lock.</summary>
    public static PackageCommand? Simulate(string manager, string op, string package) => (manager, op) switch
    {
        ("apt", PackageOps.Upgrade) => new("apt-get", ["-s", "-o", "Debug::NoLocking=1", "install", "--only-upgrade", package]),
        ("apt", PackageOps.Remove) => new("apt-get", ["-s", "-o", "Debug::NoLocking=1", "remove", package]),
        ("dnf", PackageOps.Upgrade) => new("dnf", ["--assumeno", "upgrade", package]),
        ("dnf", PackageOps.Remove) => new("dnf", ["--assumeno", "remove", package]),
        ("apk", PackageOps.Upgrade) => new("apk", ["upgrade", "--simulate", package]),
        ("apk", PackageOps.Remove) => new("apk", ["del", "--simulate", package]),
        _ => null,
    };

    /// <summary>The command to run by hand, with a note after <c>#</c> that the dashboard's copy button leaves out.</summary>
    public static string? Display(string manager, string op, string package) => (manager, op) switch
    {
        ("apt", PackageOps.Upgrade) => $"sudo apt-get update && sudo apt-get install --only-upgrade {package}",
        ("apt", PackageOps.Remove) => $"sudo apt-get remove {package}  # keeps its config files; apt-get purge deletes them too",
        ("dnf", PackageOps.Upgrade) => $"sudo dnf upgrade {package}",
        ("dnf", PackageOps.Remove) => $"sudo dnf remove {package}  # also removes dependencies nothing else needs",
        ("apk", PackageOps.Upgrade) => $"sudo apk update && sudo apk upgrade {package}",
        ("apk", PackageOps.Remove) => $"sudo apk del {package}  # only works for packages in /etc/apk/world",
        _ => null,
    };
}
