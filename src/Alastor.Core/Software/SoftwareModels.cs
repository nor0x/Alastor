using System.Text.RegularExpressions;

namespace Alastor.Core.Software;

/// <summary>One installed package, as the package database lists it.</summary>
/// <param name="Source">The source package it was built from (Debian <c>Source:</c>, the SRPM name, apk's origin); the name OSV and distro trackers use.</param>
/// <param name="Manual">Installed on purpose (apt-mark showmanual, dnf userinstalled, apk world), not pulled in as a dependency.</param>
/// <param name="Protected">Removing it would break the host or cut off access (essential/required packages, kernel, SSH, the package manager).</param>
public sealed record InstalledPackage(string Name, string Version, string? Arch, string? Source, bool Manual, bool Protected)
{
    public long? SizeKb { get; init; }
}

/// <summary>The outcome of one upgrade or uninstall started from the dashboard.</summary>
public sealed record PackageActionResult(DateTime AtUtc, string Op, string Package, bool Success, string? From, string? To, string? Error, string LogTail);

/// <summary>Every installed package on one host.</summary>
public sealed record SoftwareReport(string Manager, IReadOnlyList<InstalledPackage> Packages, PackageActionResult? LastAction)
{
    public int Manual => Packages.Count(p => p.Manual);
}

/// <summary>One package a simulated transaction would touch.</summary>
/// <param name="Action"><c>upgrade</c>, <c>remove</c>, <c>install</c> or <c>downgrade</c>.</param>
public sealed record PlannedPackage(string Name, string Action, string? From, string? To);

/// <summary>A dry run of an upgrade or uninstall: what the package manager says it would do, and what blocks it.</summary>
/// <param name="Blocked">Protected packages the transaction would remove. Non-empty means the agent refuses to run it.</param>
public sealed record PackagePlan(string Op, string Package, bool Success, string? Error, IReadOnlyList<PlannedPackage> Changes, IReadOnlyList<string> Blocked);

public static partial class PackageOps
{
    public const string Upgrade = "upgrade";
    public const string Remove = "remove";

    public static bool IsValid(string? op) => op is Upgrade or Remove;

    /// <summary>
    /// Package names as the package managers allow them. The first character can't be <c>-</c>, so a name can never
    /// turn into an option, and commands are always run with an argument list, never a shell.
    /// </summary>
    public static bool IsValidName(string? name) => name is not null && NameRegex().IsMatch(name);

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9.+_:~@-]{0,127}$")]
    private static partial Regex NameRegex();
}
