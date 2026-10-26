namespace Alastor.Core.Policy;

/// <summary>
/// Built-in schedule defaults, applied when no policy layer sets a key, for example on servers whose global
/// policy predates a key. policy/default.yaml mirrors these values, and a test keeps the two identical.
/// </summary>
public static class ScheduleDefaults
{
    public const string UpdatesCheck = "every 6h";
    public const string UpdatesApply = "off";
    public const string SoftwareInventory = "every 6h";
    public const string VulnerabilityScan = "0 3 * * *";
    public const string HardeningAudit = "0 5 * * 0";
    public const string MalwareScan = "off";
    public const string BaselineCheck = "every 1h";
    public const string BlocklistRefresh = "every 1h";
    public const string NetworkCheck = "every 1h";
    public const string IntegrityCheck = "off";
    public const string RootkitScan = "off";

    /// <summary>Every schedule key, with its effective value and whether that value came from the built-in default.</summary>
    public static IReadOnlyList<(string Path, string Value, bool IsDefault)> Resolve(PolicyDocument doc) =>
    [
        Pick("updates.checkSchedule", doc.Updates?.CheckSchedule, UpdatesCheck),
        Pick("updates.applySchedule", doc.Updates?.ApplySchedule, UpdatesApply),
        Pick("updates.inventorySchedule", doc.Updates?.InventorySchedule, SoftwareInventory),
        Pick("vulnerabilities.scanSchedule", doc.Vulnerabilities?.ScanSchedule, VulnerabilityScan),
        Pick("hardening.auditSchedule", doc.Hardening?.AuditSchedule, HardeningAudit),
        Pick("malware.scanSchedule", doc.Malware?.ScanSchedule, MalwareScan),
        Pick("baseline.checkSchedule", doc.Baseline?.CheckSchedule, BaselineCheck),
        Pick("blocklists.refreshSchedule", doc.Blocklists?.RefreshSchedule, BlocklistRefresh),
        Pick("network.checkSchedule", doc.Network?.CheckSchedule, NetworkCheck),
        Pick("integrity.checkSchedule", doc.Integrity?.CheckSchedule, IntegrityCheck),
        Pick("malware.rootkitSchedule", doc.Malware?.RootkitSchedule, RootkitScan),
    ];

    public static Schedule For(PolicyDocument doc, string path) =>
        Schedule.Parse(Resolve(doc).Single(x => x.Path == path).Value);

    private static (string, string, bool) Pick(string path, string? value, string fallback) =>
        value is null ? (path, fallback, true) : (path, value, false);
}
