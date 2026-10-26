using Alastor.Core.Events;
using Alastor.Core.Integrations.Fail2Ban;
using Alastor.Core.Platform;

namespace Alastor.Core.Integrations;

/// <summary>
/// Every bundled tool Alastor orchestrates, implemented or planned. It drives the capability matrix
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
        new(Baseline.BaselineIntegration.Info, Implemented: true, OptIn: false),
        new(CrowdSec.CrowdSecIntegration.Info, Implemented: true, OptIn: true),
        new(Firewall.UfwIntegration.Info, Implemented: true, OptIn: true),
        new(Blocklists.BlocklistIntegration.Info, Implemented: true, OptIn: false),
        new(Updates.UpdatesIntegration.Info, Implemented: true, OptIn: false),
        new(Software.SoftwareIntegration.Info, Implemented: true, OptIn: false),
        new(Vulnerabilities.VulnerabilityIntegration.Info, Implemented: true, OptIn: false),
        new(Hardening.HardeningIntegration.Info, Implemented: true, OptIn: false),
        new(Network.NetworkIntegration.Info, Implemented: true, OptIn: true),
        new(Malware.ClamAvIntegration.Info, Implemented: true, OptIn: true),
        new(Access.LoginIntegration.Info, Implemented: true, OptIn: false),
        new(Integrity.AideIntegration.Info, Implemented: true, OptIn: true),
        new(Malware.RkhunterIntegration.Info, Implemented: true, OptIn: true),
    ];

    public static Entry? Find(string id) => All.FirstOrDefault(e => e.Descriptor.Id == id);
}
