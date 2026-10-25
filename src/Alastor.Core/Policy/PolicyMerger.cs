namespace Alastor.Core.Policy;

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
            Ignore = baseDoc.Hardening?.Ignore is null && overlay.Hardening?.Ignore is null ? null
                : (baseDoc.Hardening?.Ignore ?? []).Concat(overlay.Hardening?.Ignore ?? []).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        },
        Malware = baseDoc.Malware is null && overlay.Malware is null ? null : new MalwarePolicy
        {
            ScanSchedule = overlay.Malware?.ScanSchedule ?? baseDoc.Malware?.ScanSchedule,
            Paths = (overlay.Malware?.Paths ?? baseDoc.Malware?.Paths)?.ToList(),
            Exclude = baseDoc.Malware?.Exclude is null && overlay.Malware?.Exclude is null ? null
                : (baseDoc.Malware?.Exclude ?? []).Concat(overlay.Malware?.Exclude ?? []).Distinct(StringComparer.Ordinal).ToList(),
            MaxFileSize = overlay.Malware?.MaxFileSize ?? baseDoc.Malware?.MaxFileSize,
            RootkitSchedule = overlay.Malware?.RootkitSchedule ?? baseDoc.Malware?.RootkitSchedule,
            RootkitIgnore = baseDoc.Malware?.RootkitIgnore is null && overlay.Malware?.RootkitIgnore is null ? null
                : (baseDoc.Malware?.RootkitIgnore ?? []).Concat(overlay.Malware?.RootkitIgnore ?? []).Distinct(StringComparer.Ordinal).ToList(),
        },
        Baseline = Merge(baseDoc.Baseline, overlay.Baseline),
        Firewall = baseDoc.Firewall is null && overlay.Firewall is null ? null : new FirewallPolicy
        {
            Manage = overlay.Firewall?.Manage ?? baseDoc.Firewall?.Manage,
            Ssh = (overlay.Firewall?.Ssh ?? baseDoc.Firewall?.Ssh)?.ToList(),
            Allow = baseDoc.Firewall?.Allow is null && overlay.Firewall?.Allow is null ? null
                : (baseDoc.Firewall?.Allow ?? []).Concat(overlay.Firewall?.Allow ?? []).Distinct(StringComparer.Ordinal).ToList(),
            DefaultIncoming = overlay.Firewall?.DefaultIncoming ?? baseDoc.Firewall?.DefaultIncoming,
        },
        Integrity = baseDoc.Integrity is null && overlay.Integrity is null ? null : new IntegrityPolicy
        {
            CheckSchedule = overlay.Integrity?.CheckSchedule ?? baseDoc.Integrity?.CheckSchedule,
            Paths = (overlay.Integrity?.Paths ?? baseDoc.Integrity?.Paths)?.ToList(),
            Exclude = baseDoc.Integrity?.Exclude is null && overlay.Integrity?.Exclude is null ? null
                : (baseDoc.Integrity?.Exclude ?? []).Concat(overlay.Integrity?.Exclude ?? []).Distinct(StringComparer.Ordinal).ToList(),
        },
        Logins = baseDoc.Logins is null && overlay.Logins is null ? null : new LoginsPolicy
        {
            Monitor = overlay.Logins?.Monitor ?? baseDoc.Logins?.Monitor,
            AlertOnNewSource = overlay.Logins?.AlertOnNewSource ?? baseDoc.Logins?.AlertOnNewSource,
            TrustedSources = baseDoc.Logins?.TrustedSources is null && overlay.Logins?.TrustedSources is null ? null
                : (baseDoc.Logins?.TrustedSources ?? []).Concat(overlay.Logins?.TrustedSources ?? []).Distinct(StringComparer.Ordinal).ToList(),
        },
        Network = baseDoc.Network is null && overlay.Network is null ? null : new NetworkPolicy
        {
            CheckSchedule = overlay.Network?.CheckSchedule ?? baseDoc.Network?.CheckSchedule,
            AllowPublicSsh = overlay.Network?.AllowPublicSsh ?? baseDoc.Network?.AllowPublicSsh,
            AllowPublicPorts = baseDoc.Network?.AllowPublicPorts is null && overlay.Network?.AllowPublicPorts is null ? null
                : (baseDoc.Network?.AllowPublicPorts ?? []).Concat(overlay.Network?.AllowPublicPorts ?? []).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        },
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
            ScanContainers = o?.ScanContainers ?? b?.ScanContainers,
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
            CrowdsecCentralApi = o?.CrowdsecCentralApi ?? b?.CrowdsecCentralApi,
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
