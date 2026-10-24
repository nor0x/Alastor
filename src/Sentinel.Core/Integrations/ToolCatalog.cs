using Sentinel.Core.Events;
using Sentinel.Core.Integrations.Fail2Ban;
using Sentinel.Core.Platform;

namespace Sentinel.Core.Integrations;

/// <summary>
/// Every bundled tool SentinelVPS orchestrates, implemented or planned. It drives the capability matrix
/// (which tools a host should report on) and the About page's license manifest.
/// </summary>
public static class ToolCatalog
{
    public sealed record Entry(ToolDescriptor Descriptor, bool Implemented, bool OptIn);

    private static ToolDescriptor D(string id, string name, Capability cap, string license, string url, string pkg, string desc, string? alpinePkg = "") =>
        new(id, name, cap, license, url,
            new Dictionary<DistroFamily, string> { [DistroFamily.Debian] = pkg, [DistroFamily.RedHat] = pkg, [DistroFamily.Alpine] = alpinePkg == "" ? pkg : alpinePkg ?? "" },
            desc);

    public static readonly IReadOnlyList<Entry> All =
    [
        new(Fail2BanIntegration.Info, Implemented: true, OptIn: false),
        new(D("crowdsec", "CrowdSec Security Engine", Capability.Banning, "MIT", "https://github.com/crowdsecurity/crowdsec", "crowdsec",
            "Collaborative behaviour-based banning with community blocklist and AppSec WAF.", alpinePkg: null), false, true),
        new(D("nftables", "nftables", Capability.Firewall, "GPL-2.0", "https://netfilter.org/projects/nftables/", "nftables",
            "Kernel packet filtering. The agent owns a single 'sentinel' table for blocklists."), false, false),
        new(D("ufw", "ufw", Capability.Firewall, "GPL-3.0", "https://launchpad.net/ufw", "ufw", "Uncomplicated Firewall front-end."), false, false),
        new(D("firehol-ipsets", "FireHOL IP lists", Capability.Blocklist, "Various (per list)", "https://iplists.firehol.org/", "",
            "Curated public IP blocklists, pulled by the server only."), false, false),
        new(D("unattended-upgrades", "unattended-upgrades / dnf-automatic", Capability.Updates, "GPL-2.0", "https://wiki.debian.org/UnattendedUpgrades", "unattended-upgrades",
            "Automatic security updates."), false, false),
        new(D("trivy", "Trivy", Capability.Vulnerabilities, "Apache-2.0", "https://github.com/aquasecurity/trivy", "trivy", "SBOM / package CVE scanner."), false, false),
        new(D("grype", "Grype", Capability.Vulnerabilities, "Apache-2.0", "https://github.com/anchore/grype", "grype", "Package CVE scanner (alternative to Trivy)."), false, false),
        new(D("lynis", "Lynis", Capability.Hardening, "GPL-3.0", "https://cisofy.com/lynis/", "lynis", "Security auditing and hardening index."), false, false),
        new(D("tailscale", "Tailscale", Capability.Network, "BSD-3-Clause", "https://tailscale.com/", "tailscale", "WireGuard-based private networking."), false, true),
        new(D("clamav", "ClamAV", Capability.Malware, "GPL-2.0", "https://www.clamav.net/", "clamav", "Antivirus scanning of web roots and upload dirs."), false, true),
    ];

    public static Entry? Find(string id) => All.FirstOrDefault(e => e.Descriptor.Id == id);
}
