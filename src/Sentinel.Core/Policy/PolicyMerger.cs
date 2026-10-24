namespace Sentinel.Core.Policy;

/// <summary>Merges policy layers. Values set in the overlay win; lists marked as unions (allowlists) are combined.</summary>
public static class PolicyMerger
{
    public static PolicyDocument MergeLayers(IEnumerable<PolicyDocument> layersLowToHigh) =>
        layersLowToHigh.Aggregate(new PolicyDocument(), Merge);

    public static PolicyDocument Merge(PolicyDocument baseDoc, PolicyDocument overlay) => new()
    {
        Agent = Merge(baseDoc.Agent, overlay.Agent),
        Banning = Merge(baseDoc.Banning, overlay.Banning),
        Blocklists = Merge(baseDoc.Blocklists, overlay.Blocklists),
        Updates = baseDoc.Updates is null && overlay.Updates is null ? null : new UpdatesPolicy
        {
            CheckSchedule = overlay.Updates?.CheckSchedule ?? baseDoc.Updates?.CheckSchedule,
            ApplySchedule = overlay.Updates?.ApplySchedule ?? baseDoc.Updates?.ApplySchedule,
        },
        Vulnerabilities = Merge(baseDoc.Vulnerabilities, overlay.Vulnerabilities),
        Hardening = baseDoc.Hardening is null && overlay.Hardening is null ? null : new HardeningPolicy
        {
            AuditSchedule = overlay.Hardening?.AuditSchedule ?? baseDoc.Hardening?.AuditSchedule,
        },
        Malware = baseDoc.Malware is null && overlay.Malware is null ? null : new MalwarePolicy
        {
            ScanSchedule = overlay.Malware?.ScanSchedule ?? baseDoc.Malware?.ScanSchedule,
        },
        Baseline = Merge(baseDoc.Baseline, overlay.Baseline),
    };

    private static VulnerabilitiesPolicy? Merge(VulnerabilitiesPolicy? b, VulnerabilitiesPolicy? o)
    {
        if (b is null && o is null) return null;
        List<string>? ignore = null;
        if (b?.Ignore is not null || o?.Ignore is not null)
            ignore = (b?.Ignore ?? []).Concat(o?.Ignore ?? []).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return new VulnerabilitiesPolicy
        {
            ScanSchedule = o?.ScanSchedule ?? b?.ScanSchedule,
            Scanner = o?.Scanner ?? b?.Scanner,
            LanguagePackages = o?.LanguagePackages ?? b?.LanguagePackages,
            IgnorePackages = (o?.IgnorePackages ?? b?.IgnorePackages)?.ToList(),
            Ignore = ignore,
            AlertSeverity = o?.AlertSeverity ?? b?.AlertSeverity,
        };
    }

    private static BaselinePolicy? Merge(BaselinePolicy? b, BaselinePolicy? o)
    {
        if (b is null && o is null) return null;
        Dictionary<string, string>? mitigations = null;
        if (b?.Mitigations is not null || o?.Mitigations is not null)
        {
            mitigations = new Dictionary<string, string>(b?.Mitigations ?? [], StringComparer.Ordinal);
            foreach (var (id, value) in o?.Mitigations ?? []) mitigations[id] = value;
        }
        return new BaselinePolicy
        {
            CheckSchedule = o?.CheckSchedule ?? b?.CheckSchedule,
            Mitigations = mitigations,
        };
    }

    private static BlocklistsPolicy? Merge(BlocklistsPolicy? b, BlocklistsPolicy? o)
    {
        if (b is null && o is null) return null;
        List<string>? extra = null;
        if (b?.Extra is not null || o?.Extra is not null)
            extra = (b?.Extra ?? []).Concat(o?.Extra ?? []).Distinct(StringComparer.Ordinal).ToList();
        return new BlocklistsPolicy
        {
            Enabled = o?.Enabled ?? b?.Enabled,
            Lists = (o?.Lists ?? b?.Lists)?.ToList(),
            Extra = extra,
            RefreshSchedule = o?.RefreshSchedule ?? b?.RefreshSchedule,
        };
    }

    private static AgentPolicy? Merge(AgentPolicy? b, AgentPolicy? o)
    {
        if (b is null && o is null) return null;
        return new AgentPolicy
        {
            OfflineGracePeriod = o?.OfflineGracePeriod ?? b?.OfflineGracePeriod,
            AutoInstall = o?.AutoInstall ?? b?.AutoInstall,
            HeartbeatInterval = o?.HeartbeatInterval ?? b?.HeartbeatInterval,
            DriftCheckInterval = o?.DriftCheckInterval ?? b?.DriftCheckInterval,
            EventFlushInterval = o?.EventFlushInterval ?? b?.EventFlushInterval,
            BanSnapshotInterval = o?.BanSnapshotInterval ?? b?.BanSnapshotInterval,
            ScheduleSpread = o?.ScheduleSpread ?? b?.ScheduleSpread,
        };
    }

    private static BanningPolicy? Merge(BanningPolicy? b, BanningPolicy? o)
    {
        if (b is null && o is null) return null;
        var jails = new Dictionary<string, JailSettings>(StringComparer.Ordinal);
        foreach (var (name, j) in b?.Jails ?? []) jails[name] = Merge(null, j)!;
        foreach (var (name, j) in o?.Jails ?? []) jails[name] = Merge(jails.GetValueOrDefault(name), j)!;

        List<string>? allow = null;
        if (b?.Allowlist is not null || o?.Allowlist is not null)
            allow = (b?.Allowlist ?? []).Concat(o?.Allowlist ?? []).Distinct(StringComparer.Ordinal).ToList();

        return new BanningPolicy
        {
            Enabled = o?.Enabled ?? b?.Enabled,
            Engine = o?.Engine ?? b?.Engine,
            Allowlist = allow,
            Defaults = Merge(b?.Defaults, o?.Defaults),
            Jails = b?.Jails is null && o?.Jails is null ? null : jails,
            ManualBantime = o?.ManualBantime ?? b?.ManualBantime,
        };
    }

    private static JailSettings? Merge(JailSettings? b, JailSettings? o)
    {
        if (b is null && o is null) return null;
        return new JailSettings
        {
            Enabled = o?.Enabled ?? b?.Enabled,
            Bantime = o?.Bantime ?? b?.Bantime,
            Findtime = o?.Findtime ?? b?.Findtime,
            Maxretry = o?.Maxretry ?? b?.Maxretry,
            Banaction = o?.Banaction ?? b?.Banaction,
            BantimeIncrement = o?.BantimeIncrement ?? b?.BantimeIncrement,
            BantimeMaxtime = o?.BantimeMaxtime ?? b?.BantimeMaxtime,
            BantimeFactor = o?.BantimeFactor ?? b?.BantimeFactor,
            Filter = o?.Filter ?? b?.Filter,
            Port = o?.Port ?? b?.Port,
            Logpath = o?.Logpath ?? b?.Logpath,
            Backend = o?.Backend ?? b?.Backend,
            Takeover = o?.Takeover ?? b?.Takeover,
        };
    }
}
