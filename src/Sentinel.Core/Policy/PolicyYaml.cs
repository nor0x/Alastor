using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Sentinel.Core.Net;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Sentinel.Core.Policy;

public enum IssueLevel
{
    Warning,
    Error,
}

public sealed record PolicyIssue(IssueLevel Level, string Path, string Message, int? Line = null);

public sealed record PolicyParseResult(PolicyDocument? Document, IReadOnlyList<PolicyIssue> Issues)
{
    public bool IsValid => Document is not null && Issues.All(i => i.Level != IssueLevel.Error);
}

/// <summary>Reads, writes, validates and fingerprints policy YAML. Unknown keys are errors, which catches typos like <c>maxretires</c>.</summary>
public static partial class PolicyYaml
{
    public const string ManualJailName = "sentinel-manual";
    public static readonly string[] Engines = ["fail2ban", "crowdsec"];
    public static readonly string[] Backends = ["auto", "systemd", "polling", "pyinotify"];

    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .Build();

    private static readonly ISerializer Serializer = new SerializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull)
        .Build();

    public static PolicyParseResult Parse(string? yaml)
    {
        if (string.IsNullOrWhiteSpace(yaml)) return new(new PolicyDocument(), []);
        PolicyDocument? doc;
        try
        {
            doc = Deserializer.Deserialize<PolicyDocument?>(yaml) ?? new PolicyDocument();
        }
        catch (YamlException ex)
        {
            var message = ex.InnerException?.Message ?? ex.Message;
            return new(null, [new PolicyIssue(IssueLevel.Error, "", message, (int)ex.Start.Line)]);
        }
        return new(doc, Validate(doc));
    }

    public static string Serialize(PolicyDocument doc) => Serializer.Serialize(doc);

    /// <summary>A content hash of the canonical JSON form. Agents report the revision they applied, and the server compares it to this.</summary>
    public static string Revision(PolicyDocument doc)
    {
        // Canonical form: sort map keys and union lists so key order in YAML never changes the revision.
        var canonical = doc.Clone();
        if (canonical.Banning is { } b)
        {
            if (b.Jails is not null) b.Jails = b.Jails.OrderBy(kv => kv.Key, StringComparer.Ordinal).ToDictionary(StringComparer.Ordinal);
            if (b.Allowlist is not null) b.Allowlist = b.Allowlist.Order(StringComparer.Ordinal).ToList();
        }
        if (canonical.Baseline?.Mitigations is { } m)
            canonical.Baseline.Mitigations = m.OrderBy(kv => kv.Key, StringComparer.Ordinal).ToDictionary(StringComparer.Ordinal);
        var json = JsonSerializer.SerializeToUtf8Bytes(canonical, PolicyJsonContext.Default.PolicyDocument);
        return Convert.ToHexStringLower(SHA256.HashData(json))[..16];
    }

    public static string ToJson(PolicyDocument doc) => JsonSerializer.Serialize(doc, PolicyJsonContext.Default.PolicyDocument);

    public static PolicyDocument? FromJson(string json) => JsonSerializer.Deserialize(json, PolicyJsonContext.Default.PolicyDocument);

    public static IReadOnlyList<PolicyIssue> Validate(PolicyDocument doc)
    {
        var issues = new List<PolicyIssue>();
        void Error(string path, string msg) => issues.Add(new(IssueLevel.Error, path, msg));
        void Warn(string path, string msg) => issues.Add(new(IssueLevel.Warning, path, msg));

        if (doc.Agent?.OfflineGracePeriod is { } grace && !Duration.TryParseSeconds(grace, out _))
            Error("agent.offlineGracePeriod", $"'{grace}' is not a duration (examples: 30m, 6h, 2d, permanent).");
        if (doc.Agent is { } agent)
        {
            foreach (var (key, value, min, max) in AgentTimings.Bounds(agent))
            {
                if (value is null) continue;
                if (!Duration.TryParseSeconds(value, out var secs) || secs == Duration.Permanent)
                    Error($"agent.{key}", $"'{value}' is not a duration (examples: 5s, 1m, 10m).");
                else if (secs < min.TotalSeconds || secs > max.TotalSeconds)
                    Error($"agent.{key}", $"Must be between {Duration.Format((long)min.TotalSeconds)} and {Duration.Format((long)max.TotalSeconds)}.");
            }
        }
        void CheckSchedule(string path, string? value)
        {
            if (value is not null && !Schedule.TryParse(value, out _, out var err)) Error(path, err!);
        }
        CheckSchedule("updates.checkSchedule", doc.Updates?.CheckSchedule);
        CheckSchedule("updates.applySchedule", doc.Updates?.ApplySchedule);
        CheckSchedule("vulnerabilities.scanSchedule", doc.Vulnerabilities?.ScanSchedule);
        CheckSchedule("hardening.auditSchedule", doc.Hardening?.AuditSchedule);
        CheckSchedule("malware.scanSchedule", doc.Malware?.ScanSchedule);
        CheckSchedule("baseline.checkSchedule", doc.Baseline?.CheckSchedule);
        foreach (var (id, value) in doc.Baseline?.Mitigations ?? [])
        {
            var path = $"baseline.mitigations.{id}";
            var check = Sentinel.Core.Baseline.BaselineCatalog.Find(id);
            if (check is null)
                Error(path, $"Unknown baseline check '{id}'. See the Baseline page for the list.");
            else if (value is not (Sentinel.Core.Baseline.BaselineMitigationValues.Apply or Sentinel.Core.Baseline.BaselineMitigationValues.Ignore or Sentinel.Core.Baseline.BaselineMitigationValues.Report))
                Error(path, "Use 'apply' (the agent enforces the fix), 'ignore' (accepted risk) or 'report' (only report).");
            else if (value == Sentinel.Core.Baseline.BaselineMitigationValues.Apply && !check.PolicyPath.SequenceEqual(["baseline", "mitigations", id]))
                Error(path, $"'{id}' is fixed with {string.Join('.', check.PolicyPath)}: {check.PolicyValue}, not here.");
            else if (value == Sentinel.Core.Baseline.BaselineMitigationValues.Apply && check.Fix == Sentinel.Core.Baseline.FixKind.Manual)
                Error(path, $"'{id}' can't be applied automatically. Fix it with the commands on the Baseline page, or set 'ignore' to accept the risk.");
        }

        var b = doc.Banning;
        if (b is null) return issues;

        if (b.Engine is not null && !Engines.Contains(b.Engine))
            Error("banning.engine", $"Unknown engine '{b.Engine}'. Use one of: {string.Join(", ", Engines)}.");

        if (b.ManualBantime is not null) CheckDuration(issues, "banning.manualBantime", b.ManualBantime, allowPermanent: true);

        var allowTargets = new List<IpTarget>();
        foreach (var (entry, i) in (b.Allowlist ?? []).Select((e, i) => (e, i)))
        {
            if (IpTarget.TryParse(entry, out var t)) allowTargets.Add(t.Value);
            else Error($"banning.allowlist[{i}]", $"'{entry}' is not an IP address or CIDR.");
        }
        if (b.Enabled != false && allowTargets.Count == 0)
            Warn("banning.allowlist", "Allowlist is empty. Add your admin IP or tailnet range (100.64.0.0/10) so you can't lock yourself out.");

        if (b.Defaults is not null) ValidateJail(issues, "banning.defaults", b.Defaults, isDefaults: true);

        foreach (var (name, jail) in b.Jails ?? [])
        {
            var path = $"banning.jails.{name}";
            if (!JailNameRegex().IsMatch(name))
                Error(path, "Jail names may only contain letters, digits, '.', '_' and '-' (max 64).");
            else if (name is ManualJailName or "DEFAULT" or "INCLUDES" or "Definition" or "Init")
                Error(path, $"'{name}' is reserved.");
            ValidateJail(issues, path, jail, isDefaults: false);

            var maxretry = jail.Maxretry ?? b.Defaults?.Maxretry;
            if (name == "sshd" && maxretry is < 3 && jail.Enabled != false)
                Warn($"{path}.maxretry", "maxretry below 3 on sshd makes it easy to ban yourself after a couple of typos.");
        }

        if (b.Enabled != false && (b.Jails is null || !b.Jails.Values.Any(j => j.Enabled == true)))
            Warn("banning.jails", "Banning is enabled but no jail is enabled. Only dashboard (manual) bans will apply.");

        return issues;
    }

    private static void ValidateJail(List<PolicyIssue> issues, string path, JailSettings j, bool isDefaults)
    {
        void Error(string p, string msg) => issues.Add(new(IssueLevel.Error, $"{path}.{p}", msg));

        if (j.Bantime is not null) CheckDuration(issues, $"{path}.bantime", j.Bantime, allowPermanent: true);
        if (j.Findtime is not null) CheckDuration(issues, $"{path}.findtime", j.Findtime, allowPermanent: false);
        if (j.BantimeMaxtime is not null) CheckDuration(issues, $"{path}.bantimeMaxtime", j.BantimeMaxtime, allowPermanent: false);
        if (j.Maxretry is < 1 or > 1000) Error("maxretry", "maxretry must be between 1 and 1000.");
        if (j.BantimeFactor is <= 0 or > 100) Error("bantimeFactor", "bantimeFactor must be greater than 0 and at most 100.");
        if (j.Banaction is not null && !BanactionRegex().IsMatch(j.Banaction))
            Error("banaction", "banaction must be an action name with optional [options], e.g. nftables or nftables[type=allports].");
        if (j.Backend is not null && !Backends.Contains(j.Backend))
            Error("backend", $"backend must be one of: {string.Join(", ", Backends)}.");
        if (j.Filter is not null && !JailNameRegex().IsMatch(j.Filter))
            Error("filter", "filter must be a filter name from /etc/fail2ban/filter.d (letters, digits, '.', '_', '-').");
        if (j.Port is not null && !PortRegex().IsMatch(j.Port))
            Error("port", "port must be a comma-separated list of ports, ranges (1000:2000) or service names.");
        if (j.Logpath is not null && !LogpathRegex().IsMatch(j.Logpath))
            Error("logpath", "logpath must be one or more absolute paths separated by spaces.");
        if (isDefaults && (j.Filter ?? j.Port ?? j.Logpath ?? j.Backend) is not null)
            Error("", "filter, port, logpath and backend can only be set per jail, not in defaults.");
        if (isDefaults && j.Takeover is not null)
            Error("takeover", "takeover can only be set per jail.");
    }

    private static void CheckDuration(List<PolicyIssue> issues, string path, string value, bool allowPermanent)
    {
        if (!Duration.TryParseSeconds(value, out var s))
            issues.Add(new(IssueLevel.Error, path, $"'{value}' is not a duration (examples: 90s, 10m, 1h, 7d, 2w{(allowPermanent ? ", permanent" : "")})."));
        else if (s == Duration.Permanent && !allowPermanent)
            issues.Add(new(IssueLevel.Error, path, "permanent is not allowed here."));
    }

    // These patterns also stop INI injection: rendered values can never contain newlines or section headers.
    [GeneratedRegex(@"^[A-Za-z0-9_.\-]{1,64}$")]
    private static partial Regex JailNameRegex();

    [GeneratedRegex(@"^[A-Za-z0-9_.\-]{1,64}(\[[A-Za-z0-9_.,=\-""' ]{0,200}\])?$")]
    private static partial Regex BanactionRegex();

    [GeneratedRegex(@"^[A-Za-z0-9_\-]+(:[0-9]+)?(,[A-Za-z0-9_\-]+(:[0-9]+)?)*$")]
    private static partial Regex PortRegex();

    [GeneratedRegex(@"^/[A-Za-z0-9_.\-/*]+( /[A-Za-z0-9_.\-/*]+)*$")]
    private static partial Regex LogpathRegex();
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, WriteIndented = false)]
[JsonSerializable(typeof(PolicyDocument))]
internal sealed partial class PolicyJsonContext : JsonSerializerContext;
