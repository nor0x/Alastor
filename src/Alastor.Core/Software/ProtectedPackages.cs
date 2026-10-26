namespace Alastor.Core.Software;

/// <summary>
/// Packages the dashboard never uninstalls: removing them breaks booting, logging in, or the package manager itself,
/// and on a remote host there is nobody at the console to fix it. Debian also marks its own with <c>Essential: yes</c>
/// and <c>Priority: required</c>, which the inventory adds per package. Upgrading them is always allowed.
/// </summary>
public static class ProtectedPackages
{
    private static readonly HashSet<string> Names = new(StringComparer.Ordinal)
    {
        // package managers
        "apt", "dpkg", "rpm", "dnf", "dnf5", "yum", "microdnf", "apk-tools", "libapk2",
        // init, libc and the base system
        "systemd", "systemd-sysv", "init", "init-system-helpers", "libc6", "glibc", "glibc-common", "musl", "busybox",
        "alpine-baselayout", "alpine-base", "base-files", "base-passwd", "bash", "coreutils", "util-linux", "login", "passwd",
        "shadow-utils", "setup", "filesystem", "sudo",
        // remote access: removing these locks you out of a headless host
        "openssh-server", "openssh", "openssh-server-pam",
        // boot
        "grub-common", "grub2-common", "grub-pc", "grub-efi-amd64", "grub-efi-arm64", "shim", "shim-signed", "shim-x64",
        "linux-generic", "linux-virtual", "linux-lts", "linux-virt", "kernel", "kernel-core", "kernel-modules",
        // the agent itself, if it was packaged
        "alastor-agent",
    };

    private static readonly string[] Prefixes = ["linux-image-", "linux-modules-", "kernel-core-", "kernel-modules-", "grub2-"];

    public static bool IsProtected(string name)
    {
        var bare = name.Split(':')[0];
        return Names.Contains(bare) || Prefixes.Any(p => bare.StartsWith(p, StringComparison.Ordinal));
    }
}
