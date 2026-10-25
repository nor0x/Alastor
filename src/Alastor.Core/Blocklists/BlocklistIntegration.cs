using System.Globalization;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Core.Blocklists;

/// <summary>Integrations that enforce a server-provided blocklist. The supervisor fetches it and hands it over before reconciling.</summary>
public interface IBlocklistConsumer
{
    /// <summary>The ETag of the payload last handed over, so the supervisor can send <c>If-None-Match</c>.</summary>
    string? DesiredEtag { get; }

    /// <param name="neverBlock">Addresses that must stay reachable whatever the lists say: the Alastor server itself.</param>
    void SetDesired(BlocklistPayload payload, IReadOnlyList<IPAddress> neverBlock);

    /// <summary>Removes the enforced set because the server has been unreachable beyond the grace period. Returns whether anything was removed.</summary>
    Task<bool> ReleaseAfterServerLossAsync(TimeSpan since, CancellationToken ct);
}

public enum BlocklistBackend
{
    None,
    Nftables,

    /// <summary>ipset sets matched from an iptables chain, for hosts without the nft tool.</summary>
    Ipset,
}

/// <summary>
/// Drops traffic from blocklisted networks in the kernel. The agent owns exactly one object per backend and never
/// touches anything else in the ruleset:
/// <list type="bullet">
/// <item><b>nftables</b> (preferred): table <c>inet alastor</c> with interval sets and a prerouting chain at raw
/// priority (-300), so matching packets are dropped before connection tracking, for the host and for containers
/// alike. Replaced in one <c>nft -f</c> transaction after <c>nft -c</c> validates it, so a failed update leaves
/// the previous set in place.</item>
/// <item><b>ipset + iptables</b>: sets <c>alastor4</c>/<c>alastor6</c> (filled off to the side, then
/// swapped in atomically) and a <c>ALASTOR</c> chain in the raw table, jumped to from PREROUTING.</item>
/// </list>
/// Removed when blocklists are disabled, on uninstall, and when the server has been unreachable beyond
/// <c>agent.offlineGracePeriod</c>.
/// </summary>
public sealed partial class BlocklistIntegration(
    ICommandRunner runner,
    IFileSystem fs,
    IPackageManager? packages,
    IStateStore state,
    string workDir,
    ILogger<BlocklistIntegration> logger,
    TimeProvider time) : IToolIntegration, IBlocklistConsumer
{
    public const string Table = "alastor";
    public const string Chain = "ALASTOR";
    public const string Set4 = "alastor4";
    public const string Set6 = "alastor6";

    private const string StateHash = "blocklist.appliedHash";
    private const string StateEtag = "blocklist.appliedEtag";
    private const string StateBackend = "blocklist.backend";
    private const string StateCounts = "blocklist.counts";
    private const string StateLists = "blocklist.lists";
    private const string StateLastApply = "blocklist.lastApplyUtc";
    private const string StateConfigState = "blocklist.configState";
    private const string StateLastError = "blocklist.lastError";
    private const string StateInstalledByAgent = "blocklist.installedNftables";
    private static readonly UnixFileMode Mode600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly Queue<SecurityEvent> _events = new();
    private BlocklistPayload? _desired;
    private IReadOnlyList<IPAddress> _neverBlock = [];

    public static readonly ToolDescriptor Info = new(
        "blocklist",
        "IP blocklists (nftables / ipset)",
        Capability.Blocklist,
        "GPL-2.0 (nftables, ipset)",
        "https://netfilter.org/projects/nftables/",
        new Dictionary<DistroFamily, string> { [DistroFamily.Debian] = "nftables", [DistroFamily.RedHat] = "nftables", [DistroFamily.Alpine] = "nftables" },
        "Drops traffic from public blocklists (Spamhaus DROP, FireHOL, abuse.ch, …) that the server pulls and merges, in the agent's own nftables table.");

    public ToolDescriptor Descriptor => Info;

    public string ScriptPath => Path.Combine(workDir, "blocklist.nft");
    public string IpsetScriptPath => Path.Combine(workDir, "blocklist.ipset");

    public string? DesiredEtag => _desired?.Etag;

    public void SetDesired(BlocklistPayload payload, IReadOnlyList<IPAddress> neverBlock)
    {
        _desired = payload;
        _neverBlock = neverBlock;
    }

    public bool IsWanted(PolicyDocument policy) => policy.Blocklists?.Enabled == true;

    public BlocklistBackend Backend =>
        runner.Which("nft") is not null ? BlocklistBackend.Nftables :
        runner.Which("ipset") is not null && runner.Which("iptables") is not null ? BlocklistBackend.Ipset :
        BlocklistBackend.None;

    public async Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        var backend = Backend;
        if (backend == BlocklistBackend.None)
            return new ToolStatus { ToolId = Info.Id, Installed = false, Ownership = Ownership.NotInstalled, UnavailableReason = "Neither nftables nor ipset/iptables is installed." };

        var (active, error) = await IsActiveAsync(backend, ct);
        var version = backend == BlocklistBackend.Nftables
            ? VersionRegex().Match((await runner.RunAsync("nft", ["--version"], ct: ct)).StdOut) is { Success: true } m ? m.Groups[1].Value : null
            : VersionRegex().Match((await runner.RunAsync("ipset", ["version"], ct: ct)).StdOut) is { Success: true } m2 ? m2.Groups[1].Value : null;

        var details = new Dictionary<string, string> { ["backend"] = backend == BlocklistBackend.Nftables ? "nftables" : "ipset" };
        if (state.Get(StateCounts) is { } counts) details["entries"] = counts;
        if (state.Get(StateLists) is { } lists) details["lists"] = lists;
        if (active && backend == BlocklistBackend.Nftables && await DroppedPacketsAsync(ct) is { } dropped)
            details["dropped"] = dropped.ToString(CultureInfo.InvariantCulture);

        return new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Version = version,
            Running = active,
            Ownership = state.Get(StateInstalledByAgent) == "true" ? Ownership.Managed : Ownership.Adopted,
            ConfigState = Enum.TryParse<ConfigState>(state.Get(StateConfigState), out var cs) ? cs : ConfigState.Unknown,
            AppliedRevision = state.Get(StateEtag),
            LastError = state.Get(StateLastError) ?? (active ? null : error),
            LastSuccessAt = DateTime.TryParse(state.Get(StateLastApply), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var t) ? t : null,
            Details = details,
        };
    }

    public async Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct)
    {
        if (Backend != BlocklistBackend.None) return await DetectAsync(ct);
        if (!request.AllowInstall || packages is null)
        {
            var reason = packages is null ? "nftables is not installed and this distribution has no supported package manager." : "nftables is not installed and agent.autoInstall is off.";
            return new ToolStatus { ToolId = Info.Id, Availability = Availability.Unavailable, UnavailableReason = reason };
        }
        var result = await packages.InstallAsync("nftables", ct);
        if (!result.Success)
            return new ToolStatus { ToolId = Info.Id, Availability = Availability.Unavailable, UnavailableReason = $"Installing nftables failed: {result.Error}" };
        await state.SetAsync(StateInstalledByAgent, "true", ct);
        return await DetectAsync(ct);
    }

    public async Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct)
    {
        var backend = Backend;
        var (active, _) = await IsActiveAsync(backend, ct);
        if (!IsWanted(request.Policy))
        {
            return active || state.Get(StateHash) is not null
                ? new(Info.Id, request.Revision, [new(ChangeKind.DeleteFile, Target(backend), "Remove the blocklist (blocklists are disabled)")], [], ConfigState.InSync)
                : new(Info.Id, request.Revision, [], [], ConfigState.InSync);
        }
        if (_desired is null)
            return new(Info.Id, request.Revision, [], [new(EventKinds.ConfigApplied, "Waiting for the blocklist from the server.")], ConfigState.Pending);

        var content = backend == BlocklistBackend.Ipset ? RenderIpset(_desired) : RenderNft(_desired, _neverBlock);
        var hash = Hash(content + string.Join(',', _neverBlock));
        if (active && hash == state.Get(StateHash))
            return new(Info.Id, request.Revision, [], [], ConfigState.InSync);

        var summary = $"{_desired.V4.Count + _desired.V6.Count} networks from {Lists(_desired)}";
        return new(Info.Id, request.Revision,
            [new(ChangeKind.WriteFile, Target(backend), active ? $"Update the blocklist ({summary})" : $"Load the blocklist ({summary})", content), new(ChangeKind.Reload, Target(backend), backend == BlocklistBackend.Ipset ? "Swap the ipsets" : "Load the table in one nft transaction", hash)],
            [], ConfigState.InSync);
    }

    public async Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct)
    {
        if (plan.IsNoop) return ReconcileResult.Ok(plan.ResultingState);
        if (plan.Changes[0].Kind == ChangeKind.DeleteFile)
        {
            var removed = await RemoveManagedStateAsync(ct);
            if (removed.Success) Emit(EventKinds.ConfigApplied, Severity.Info, "Blocklist removed: blocklists are disabled for this host.");
            return removed;
        }

        var backend = Backend;
        var content = plan.Changes[0].Content!;
        var hash = plan.Changes[1].Content!;
        var wasActive = state.Get(StateHash) is not null;
        var previousLists = state.Get(StateLists);
        var error = backend == BlocklistBackend.Ipset ? await ApplyIpsetAsync(content, ct) : await ApplyNftAsync(content, ct);
        if (error is not null)
        {
            var message = Explain(error);
            // The drift check retries every few minutes; the same refusal is one event, not one per retry.
            var repeated = state.Get(StateLastError) == message;
            await state.SetAsync(StateConfigState, nameof(ConfigState.Rejected), ct);
            await state.SetAsync(StateLastError, message, ct);
            logger.LogWarning("Blocklist not applied: {Error}", message);
            return new ReconcileResult(false, ConfigState.Rejected, message,
                repeated ? [] : [Event(EventKinds.ConfigRejected, Severity.Medium, $"Blocklist not applied: {message}", error)]);
        }

        var lists = Lists(_desired!);
        await state.SetAsync(StateHash, hash, ct);
        await state.SetAsync(StateEtag, _desired!.Etag, ct);
        await state.SetAsync(StateBackend, backend.ToString(), ct);
        await state.SetAsync(StateCounts, $"{_desired.V4.Count} IPv4, {_desired.V6.Count} IPv6", ct);
        await state.SetAsync(StateLists, lists, ct);
        await state.SetAsync(StateLastApply, time.GetUtcNow().UtcDateTime.ToString("O"), ct);
        await state.SetAsync(StateConfigState, nameof(ConfigState.InSync), ct);
        await state.SetAsync(StateLastError, null, ct);
        logger.LogInformation("Blocklist applied with {Backend}: {V4} IPv4 and {V6} IPv6 networks ({Lists})", backend, _desired.V4.Count, _desired.V6.Count, lists);
        // Lists like blocklist.de change every hour; only activation and a different choice of lists are worth an event.
        if (!wasActive || previousLists != lists)
            return ReconcileResult.Ok(ConfigState.InSync, Event(EventKinds.ConfigApplied, Severity.Info,
                $"Blocklist active ({backend.ToString().ToLowerInvariant()}): {_desired.V4.Count} IPv4 and {_desired.V6.Count} IPv6 networks from {lists}", null));
        return ReconcileResult.Ok(ConfigState.InSync);
    }

    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        await Task.CompletedTask;
        while (_events.TryDequeue(out var e)) yield return e;
    }

    public async Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct)
    {
        var errors = new List<string>();
        if (runner.Which("nft") is not null && (await runner.RunAsync("nft", ["list", "table", "inet", Table], ct: ct)).Success)
        {
            var r = await runner.RunAsync("nft", ["delete", "table", "inet", Table], ct: ct);
            if (!r.Success) errors.Add(r.CombinedOutput);
        }
        if (runner.Which("ipset") is not null && runner.Which("iptables") is not null)
        {
            foreach (var (tool, set) in new[] { ("iptables", Set4), ("ip6tables", Set6) })
            {
                if (runner.Which(tool) is null) continue;
                // -D removes one jump per call; loop in case someone (or an old agent) added it twice.
                for (var i = 0; i < 5 && (await runner.RunAsync(tool, ["-t", "raw", "-C", "PREROUTING", "-j", Chain], ct: ct)).Success; i++)
                    await runner.RunAsync(tool, ["-t", "raw", "-D", "PREROUTING", "-j", Chain], ct: ct);
                await runner.RunAsync(tool, ["-t", "raw", "-F", Chain], ct: ct);
                await runner.RunAsync(tool, ["-t", "raw", "-X", Chain], ct: ct);
                await runner.RunAsync("ipset", ["destroy", set], ct: ct);
                await runner.RunAsync("ipset", ["destroy", set + "-new"], ct: ct);
            }
        }
        foreach (var file in new[] { ScriptPath, IpsetScriptPath })
            if (fs.FileExists(file)) fs.DeleteFile(file);
        foreach (var key in new[] { StateHash, StateEtag, StateCounts, StateLists, StateLastError })
            await state.SetAsync(key, null, ct);
        await state.SetAsync(StateConfigState, errors.Count == 0 ? nameof(ConfigState.InSync) : nameof(ConfigState.Rejected), ct);
        return errors.Count == 0 ? ReconcileResult.Ok(ConfigState.InSync) : new(false, ConfigState.Rejected, Explain(string.Join("; ", errors)), []);
    }

    /// <summary>Called by the supervisor when the server has been unreachable beyond the grace period.</summary>
    public async Task<bool> ReleaseAfterServerLossAsync(TimeSpan since, CancellationToken ct)
    {
        if (state.Get(StateHash) is null) return false;
        var r = await RemoveManagedStateAsync(ct);
        Emit(EventKinds.ConfigApplied, Severity.Medium,
            $"Blocklist released after {Duration.Format((long)since.TotalSeconds)} without contact to the Alastor server (agent.offlineGracePeriod). It is restored when the server is reachable again.{(r.Success ? "" : $" Removal failed: {r.Error}")}");
        _desired = null; // fetch afresh on reconnect rather than reloading a set that may be days old
        return true;
    }

    // ---- rendering ----

    public static string RenderNft(BlocklistPayload p, IReadOnlyList<IPAddress> neverBlock)
    {
        var allow4 = neverBlock.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(a => a.ToString()).ToList();
        var allow6 = neverBlock.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6).Select(a => a.ToString()).ToList();
        var sb = new StringBuilder();
        sb.Append("# ").Append(ManagedFile.Marker).Append(". The agent replaces this table on every blocklist update and removes it on uninstall.\n");
        sb.Append("# Lists: ").Append(Lists(p)).Append(" (etag ").Append(p.Etag).Append(")\n");
        // Declaring the table first makes the delete valid when it doesn't exist yet; the whole file is one transaction.
        sb.Append($"table inet {Table}\n");
        sb.Append($"delete table inet {Table}\n");
        sb.Append($"table inet {Table} {{\n");
        Set(sb, "allow4", "ipv4_addr", allow4);
        Set(sb, "allow6", "ipv6_addr", allow6);
        Set(sb, "blocklist4", "ipv4_addr", p.V4);
        Set(sb, "blocklist6", "ipv6_addr", p.V6);
        sb.Append("\tchain prerouting {\n");
        sb.Append("\t\ttype filter hook prerouting priority -300; policy accept;\n");
        sb.Append("\t\tip saddr @allow4 accept\n");
        sb.Append("\t\tip6 saddr @allow6 accept\n");
        sb.Append("\t\tip saddr @blocklist4 counter drop\n");
        sb.Append("\t\tip6 saddr @blocklist6 counter drop\n");
        sb.Append("\t}\n}\n");
        return sb.ToString();
    }

    private static void Set(StringBuilder sb, string name, string type, IReadOnlyList<string> elements)
    {
        sb.Append($"\tset {name} {{\n\t\ttype {type}; flags interval;\n");
        if (elements.Count > 0)
        {
            sb.Append("\t\telements = {\n");
            for (var i = 0; i < elements.Count; i++)
                sb.Append("\t\t\t").Append(elements[i]).Append(i == elements.Count - 1 ? "\n" : ",\n");
            sb.Append("\t\t}\n");
        }
        sb.Append("\t}\n");
    }

    public static string RenderIpset(BlocklistPayload p)
    {
        var sb = new StringBuilder();
        foreach (var (set, family, entries) in new[] { (Set4, "inet", p.V4), (Set6, "inet6", p.V6) })
        {
            var maxelem = Math.Max(65536, (int)System.Numerics.BitOperations.RoundUpToPowerOf2((uint)Math.Max(1, entries.Count * 2)));
            sb.Append($"create {set} hash:net family {family} maxelem {maxelem}\n");
            sb.Append($"create {set}-new hash:net family {family} maxelem {maxelem}\n");
            sb.Append($"flush {set}-new\n");
            foreach (var e in entries) sb.Append($"add {set}-new {e}\n");
            sb.Append($"swap {set}-new {set}\n");
            sb.Append($"destroy {set}-new\n");
        }
        return sb.ToString();
    }

    // ---- backends ----

    private async Task<string?> ApplyNftAsync(string script, CancellationToken ct)
    {
        fs.CreateDirectory(workDir);
        await fs.WriteAllTextAtomicAsync(ScriptPath, script, Mode600, ct);
        var check = await runner.RunAsync("nft", ["-c", "-f", ScriptPath], new CommandOptions { Timeout = TimeSpan.FromMinutes(1) }, ct);
        if (!check.Success) return check.CombinedOutput;
        var apply = await runner.RunAsync("nft", ["-f", ScriptPath], new CommandOptions { Timeout = TimeSpan.FromMinutes(1) }, ct);
        if (!apply.Success) return apply.CombinedOutput;
        var verify = await runner.RunAsync("nft", ["list", "table", "inet", Table], ct: ct);
        return verify.Success ? null : $"The table didn't appear after loading: {verify.CombinedOutput}";
    }

    private async Task<string?> ApplyIpsetAsync(string script, CancellationToken ct)
    {
        fs.CreateDirectory(workDir);
        await fs.WriteAllTextAtomicAsync(IpsetScriptPath, script, Mode600, ct);
        var restore = await runner.RunAsync("ipset", ["restore", "-exist", "-file", IpsetScriptPath], new CommandOptions { Timeout = TimeSpan.FromMinutes(1) }, ct);
        if (!restore.Success) return restore.CombinedOutput;
        foreach (var (tool, set) in new[] { ("iptables", Set4), ("ip6tables", Set6) })
        {
            if (runner.Which(tool) is null) continue;
            await runner.RunAsync(tool, ["-t", "raw", "-N", Chain], ct: ct); // fails harmlessly when the chain exists
            var rules = new List<string[]> { new[] { "-t", "raw", "-F", Chain } };
            foreach (var a in _neverBlock.Where(a => (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) == (tool == "iptables")))
                rules.Add(["-t", "raw", "-A", Chain, "-s", a.ToString(), "-j", "RETURN"]);
            rules.Add(["-t", "raw", "-A", Chain, "-m", "set", "--match-set", set, "src", "-j", "DROP"]);
            foreach (var args in rules)
            {
                var r = await runner.RunAsync(tool, args, ct: ct);
                if (!r.Success) return $"{tool} {string.Join(' ', args)}: {r.CombinedOutput}";
            }
            if (!(await runner.RunAsync(tool, ["-t", "raw", "-C", "PREROUTING", "-j", Chain], ct: ct)).Success)
            {
                var jump = await runner.RunAsync(tool, ["-t", "raw", "-I", "PREROUTING", "1", "-j", Chain], ct: ct);
                if (!jump.Success) return $"{tool}: {jump.CombinedOutput}";
            }
        }
        return null;
    }

    private async Task<(bool Active, string? Error)> IsActiveAsync(BlocklistBackend backend, CancellationToken ct)
    {
        switch (backend)
        {
            case BlocklistBackend.Nftables:
                var r = await runner.RunAsync("nft", ["list", "table", "inet", Table], ct: ct);
                return (r.Success, r.Success || r.CombinedOutput.Contains("No such file", StringComparison.Ordinal) ? null : Explain(r.CombinedOutput));
            case BlocklistBackend.Ipset:
                var s = await runner.RunAsync("ipset", ["list", "-n", Set4], ct: ct);
                return (s.Success, null);
            default:
                return (false, null);
        }
    }

    /// <summary>Packets dropped since the table was loaded, from the rule counters in nft's JSON output (libnftables-json(5)).</summary>
    public async Task<long?> DroppedPacketsAsync(CancellationToken ct)
    {
        var r = await runner.RunAsync("nft", ["-j", "list", "chain", "inet", Table, "prerouting"], ct: ct);
        return r.Success ? SumCounters(r.StdOut) : null;
    }

    public static long? SumCounters(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            long total = 0;
            foreach (var item in doc.RootElement.GetProperty("nftables").EnumerateArray())
            {
                if (!item.TryGetProperty("rule", out var rule) || !rule.TryGetProperty("expr", out var expr)) continue;
                var counted = 0L;
                var drops = false;
                foreach (var e in expr.EnumerateArray())
                {
                    if (e.TryGetProperty("counter", out var c) && c.TryGetProperty("packets", out var p)) counted = p.GetInt64();
                    if (e.TryGetProperty("drop", out _)) drops = true;
                }
                if (drops) total += counted;
            }
            return total;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return null;
        }
    }

    // ---- helpers ----

    /// <summary>Turns the kernel's terse refusal into something actionable.</summary>
    public static string Explain(string error)
    {
        var e = error.Trim();
        if (e.Contains("Operation not permitted", StringComparison.Ordinal) || e.Contains("you must be root", StringComparison.Ordinal))
            return "The kernel refused the firewall change (Operation not permitted). Containers and some VPS plans (LXC, OpenVZ) don't let the guest change firewall rules; use the hosting provider's firewall there. " +
                   $"Output: {FirstLine(e)}";
        return e.Length > 500 ? e[..500] : e;
    }

    private static string FirstLine(string s) => s.Split('\n', 2)[0].Trim();

    private static string Lists(BlocklistPayload p)
    {
        var names = p.Lists.Select(l => l.Id).ToList();
        return names.Count == 0 ? "extra entries only" : string.Join(", ", names);
    }

    private static string Target(BlocklistBackend backend) => backend == BlocklistBackend.Ipset ? $"ipset {Set4}/{Set6}, iptables raw {Chain}" : $"nft table inet {Table}";

    private static string Hash(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)))[..16];

    private void Emit(string kind, Severity severity, string message) => _events.Enqueue(Event(kind, severity, message, null));

    private SecurityEvent Event(string kind, Severity severity, string message, string? raw) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow().UtcDateTime,
        Capability = Capability.Blocklist,
        Severity = severity,
        SourceTool = Info.Id,
        Kind = kind,
        Message = message,
        Raw = raw,
        DedupKey = $"{Info.Id}:{kind}",
    };

    [GeneratedRegex(@"v(\d+(?:\.\d+)+)")]
    private static partial Regex VersionRegex();
}
