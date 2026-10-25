using Alastor.Core.Events;

namespace Alastor.Core.Baseline;

/// <summary>
/// The security baseline: the handful of settings that matter most on an internet-facing Linux server, each with
/// a fix. Checks read the system's own authoritative output (<c>sshd -T</c> for the effective SSH config,
/// <c>sysctl</c>, <c>ufw status</c>, <c>nft -j</c>, <c>apt-config</c>, <c>timedatectl show</c>, <c>passwd -S</c>), never config files
/// guessed at by hand. Lynis (deliverable 8) audits far more broadly. This list exists because Lynis only
/// suggests: the baseline's policy fixes are applied by the agent as managed, reversible drop-ins.
/// </summary>
public static class BaselineCatalog
{
    public static readonly IReadOnlyList<BaselineCheckInfo> All =
    [
        // ---- SSH (effective values from `sshd -T`; fixes go to /etc/ssh/sshd_config.d/01-alastor.conf) ----
        new("ssh-root-login", "Root can't log in with a password", BaselineCategory.Ssh, Severity.High,
            "Root is the first account every brute-force bot tries. With a password allowed, one guessed password is full control.",
            "PermitRootLogin prohibit-password (or no)", FixKind.Policy,
            "Sets PermitRootLogin prohibit-password: root keeps key-based login, password guessing stops working."),
        new("ssh-password-auth", "SSH accepts keys only", BaselineCategory.Ssh, Severity.High,
            "Password logins can be brute-forced and phished; keys can't be guessed.",
            "PasswordAuthentication no, KbdInteractiveAuthentication no", FixKind.Policy,
            "Turns off password and keyboard-interactive login. The agent refuses to apply this unless an admin account has an authorized SSH key, so you can't lock yourself out."),
        new("ssh-empty-passwords", "SSH refuses empty passwords", BaselineCategory.Ssh, Severity.Critical,
            "An account without a password would be open to anyone.",
            "PermitEmptyPasswords no", FixKind.Policy,
            "Sets PermitEmptyPasswords no."),
        new("ssh-max-auth-tries", "SSH limits attempts per connection", BaselineCategory.Ssh, Severity.Low,
            "Fewer attempts per connection slow down guessing and make fail2ban react sooner.",
            "MaxAuthTries 4 or lower", FixKind.Policy,
            "Sets MaxAuthTries 3."),
        new("ssh-x11-forwarding", "SSH X11 forwarding is off", BaselineCategory.Ssh, Severity.Low,
            "Servers rarely need graphical forwarding, and it exposes the client's display to the server.",
            "X11Forwarding no", FixKind.Policy,
            "Sets X11Forwarding no."),
        new("ssh-login-grace", "SSH drops idle logins quickly", BaselineCategory.Ssh, Severity.Low,
            "A long grace time lets unauthenticated connections pile up.",
            "LoginGraceTime 60 seconds or less", FixKind.Policy,
            "Sets LoginGraceTime 30."),

        // ---- Brute-force protection (Alastor's own fail2ban integration) ----
        new("ssh-brute-force-protection", "SSH brute-force protection is on", BaselineCategory.Ssh, Severity.High,
            "Without it, bots can guess passwords around the clock.",
            "fail2ban running with the sshd jail enabled", FixKind.Policy,
            "Enables the sshd jail in the banning policy; the agent installs or adopts fail2ban.")
        {
            PolicyPath = ["banning", "jails", "sshd", "enabled"],
            PolicyValue = "true",
        },

        // ---- Firewall ----
        new("firewall-active", "A firewall filters incoming traffic", BaselineCategory.Firewall, Severity.High,
            "Without one, every service that listens on a public address is reachable from the internet, including ones meant to be local.",
            "ufw or firewalld active, or an nftables/iptables input chain that drops by default", FixKind.Manual,
            "Enable a firewall that allows SSH first. It is a manual step because the agent can't know which other ports you need."),

        // ---- Updates ----
        new("updates-automatic", "Security updates install automatically", BaselineCategory.Updates, Severity.Medium,
            "Most compromises use vulnerabilities that already have a fix. Automatic updates close them within a day.",
            "unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL family) enabled", FixKind.Manual,
            "Install and enable the distribution's automatic security updates. Alastor will manage this with the update integration (deliverable 6)."),
        new("updates-reboot-required", "No reboot is pending", BaselineCategory.Updates, Severity.Medium,
            "Kernel and library fixes only take effect after a reboot.",
            "No pending reboot", FixKind.Manual,
            "Reboot when convenient."),

        // ---- Kernel / network (fixes go to /etc/sysctl.d/99-zz-alastor.conf) ----
        new("kernel-aslr", "Address space randomization is on", BaselineCategory.Kernel, Severity.Medium,
            "ASLR makes memory-corruption exploits much harder to land.",
            "kernel.randomize_va_space = 2", FixKind.Policy,
            "Sets kernel.randomize_va_space = 2."),
        new("kernel-pointer-leaks", "Kernel addresses are hidden", BaselineCategory.Kernel, Severity.Low,
            "Leaked kernel pointers and logs help attackers build local privilege escalations.",
            "kernel.kptr_restrict ≥ 1, kernel.dmesg_restrict = 1", FixKind.Policy,
            "Sets kernel.kptr_restrict = 1 and kernel.dmesg_restrict = 1."),
        new("net-redirects", "ICMP redirects are ignored", BaselineCategory.Kernel, Severity.Medium,
            "Redirects let anyone on the network reroute this server's traffic. Servers never need them.",
            "accept_redirects = 0 (IPv4 and IPv6), send_redirects = 0", FixKind.Policy,
            "Sets net.ipv4.conf.{all,default}.accept_redirects, net.ipv6.conf.{all,default}.accept_redirects and net.ipv4.conf.{all,default}.send_redirects to 0."),
        new("net-source-route", "Source-routed packets are dropped", BaselineCategory.Kernel, Severity.Medium,
            "Source routing lets a sender choose the path through your network, which can bypass filtering.",
            "accept_source_route = 0 (IPv4 and IPv6)", FixKind.Policy,
            "Sets net.ipv4.conf.all.accept_source_route and net.ipv6.conf.all.accept_source_route to 0."),
        new("net-syncookies", "SYN flood protection is on", BaselineCategory.Kernel, Severity.Medium,
            "SYN cookies keep the server reachable during a SYN flood.",
            "net.ipv4.tcp_syncookies = 1", FixKind.Policy,
            "Sets net.ipv4.tcp_syncookies = 1."),
        new("net-rp-filter", "Spoofed source addresses are filtered", BaselineCategory.Kernel, Severity.Low,
            "Reverse-path filtering drops packets whose source address could not have arrived on that interface.",
            "net.ipv4.conf.all.rp_filter = 1 or 2", FixKind.Policy,
            "Sets net.ipv4.conf.all.rp_filter = 2 (loose mode, safe for hosts with several interfaces or a VPN)."),
        new("fs-protected-links", "Symlink and hardlink protection is on", BaselineCategory.Kernel, Severity.Low,
            "Blocks a classic family of /tmp race attacks used to escalate privileges.",
            "fs.protected_symlinks = 1, fs.protected_hardlinks = 1", FixKind.Policy,
            "Sets fs.protected_symlinks = 1 and fs.protected_hardlinks = 1."),

        // ---- Accounts ----
        new("accounts-uid0", "Only root has UID 0", BaselineCategory.Accounts, Severity.Critical,
            "Any other account with UID 0 is a second root account, a common backdoor.",
            "root is the only UID 0 account", FixKind.Manual,
            "Find out why the account exists, then remove or lock it."),
        new("accounts-empty-password", "No account has an empty password", BaselineCategory.Accounts, Severity.Critical,
            "An empty password lets anyone log in locally, and over SSH if empty passwords are allowed.",
            "Every account has a password or is locked", FixKind.Manual,
            "Lock the account, or set a password if someone uses it."),

        // ---- System ----
        new("files-sensitive-permissions", "Password files are protected", BaselineCategory.System, Severity.Medium,
            "/etc/shadow holds password hashes; if anyone can read it, offline cracking starts.",
            "/etc/shadow and /etc/gshadow not world-readable, /etc/passwd and /etc/group not world-writable", FixKind.Manual,
            "Restore the distribution's default permissions."),
        new("time-sync", "The clock is synchronized", BaselineCategory.System, Severity.Low,
            "Log correlation, TLS and two-factor codes depend on the right time.",
            "NTP synchronized", FixKind.Manual,
            "Enable time synchronization."),
    ];

    private static readonly Dictionary<string, BaselineCheckInfo> ById = All.ToDictionary(c => c.Id);

    public static BaselineCheckInfo? Find(string id) => ById.GetValueOrDefault(id);
}
