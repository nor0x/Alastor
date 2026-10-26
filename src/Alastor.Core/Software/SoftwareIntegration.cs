using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Core.Software;

/// <summary>
/// The installed-software inventory, and single-package upgrades and uninstalls from the dashboard:
/// <list type="bullet">
/// <item>Debian/Ubuntu: <c>dpkg-query -W</c> and <c>apt-mark showmanual</c>; <c>apt-get install --only-upgrade</c> / <c>apt-get remove</c>.</item>
/// <item>RHEL family: <c>rpm -qa</c> and <c>dnf repoquery --userinstalled</c>; <c>dnf upgrade</c> / <c>dnf remove</c>.</item>
/// <item>Alpine: <c>apk list --installed</c> and <c>/etc/apk/world</c>; <c>apk upgrade</c> / <c>apk del</c>.</item>
/// </list>
/// Every change is simulated first (the dashboard shows that dry run), and a removal that would take a
/// <see cref="ProtectedPackages">protected package</see> with it is refused here, whatever the server asked for.
/// </summary>
public sealed class SoftwareIntegration(
    ICommandRunner runner,
    IFileSystem fs,
    IStateStore state,
    OsInfo os,
    ILogger<SoftwareIntegration> logger,
    TimeProvider time) : IToolIntegration, IScheduledJobProvider
{
    public const string InventoryJob = "software.inventory";
    public const string ActionJob = "software.action";
    public const int MaxPackages = 20_000;

    private const string StateLastReport = "software.lastReport";
    private const string StateLastAction = "software.lastAction";

    private static readonly CommandOptions Query = new() { Timeout = TimeSpan.FromMinutes(2) };
    private static readonly CommandOptions Change = new() { Timeout = TimeSpan.FromMinutes(30), Environment = new Dictionary<string, string> { ["DEBIAN_FRONTEND"] = "noninteractive" } };

    private readonly Queue<SecurityEvent> _events = new();

    public static readonly ToolDescriptor Info = new(
        "software",
        "Software inventory (dpkg / rpm / apk)",
        Capability.Updates,
        "GPL-2.0 (dpkg, rpm, apk-tools)",
        "https://wiki.debian.org/Teams/Dpkg",
        new Dictionary<DistroFamily, string> { [DistroFamily.Debian] = "dpkg", [DistroFamily.RedHat] = "rpm", [DistroFamily.Alpine] = "apk-tools" },
        "Lists installed packages and versions from the package database, and upgrades or removes one package on request.");

    public ToolDescriptor Descriptor => Info;

    public IReadOnlyList<ScheduledJob> Jobs =>
    [
        new(InventoryJob, "Collect software inventory", "updates.inventorySchedule", RunOnFirstStart: true, (_, _, ct) => InventoryAsync(ct)),
    ];

    public bool IsWanted(PolicyDocument policy) => true;

    public string? Manager => os.Family switch
    {
        DistroFamily.Debian when runner.Which("dpkg-query") is not null => "apt",
        DistroFamily.RedHat when runner.Which("rpm") is not null => "dnf",
        DistroFamily.Alpine when runner.Which("apk") is not null => "apk",
        _ => null,
    };

    public Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        if (Manager is not { } manager)
            return Task.FromResult(new ToolStatus { ToolId = Info.Id, Availability = Availability.Unavailable, UnavailableReason = $"No supported package database on {os.PrettyName}." });
        var details = new Dictionary<string, string> { ["manager"] = manager };
        var last = LastReport();
        if (last?.Software is { } s)
        {
            details["packages"] = s.Packages.Count.ToString(CultureInfo.InvariantCulture);
            details["manual"] = s.Manual.ToString(CultureInfo.InvariantCulture);
        }
        return Task.FromResult(new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Running = true,
            Ownership = Ownership.Adopted,
            ConfigState = ConfigState.InSync,
            LastError = last is { Success: false } ? last.Error : null,
            LastSuccessAt = last is { Success: true } ? last.FinishedAtUtc : null,
            Details = details,
        });
    }

    public Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct) => DetectAsync(ct);

    public Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct) =>
        Task.FromResult(new ReconcilePlan(Info.Id, request.Revision, [], [], ConfigState.InSync));

    public Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        await Task.CompletedTask;
        while (_events.TryDequeue(out var e)) yield return e;
    }

    public Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    // ---- inventory ----

    public async Task<AgentReport> InventoryAsync(CancellationToken ct)
    {
        var started = time.GetUtcNow().UtcDateTime;
        try
        {
            var report = new SoftwareReport(Manager ?? "?", await CollectAsync(ct), LastAction());
            var result = new AgentReport(InventoryJob, started, time.GetUtcNow().UtcDateTime, true, null) { Software = report };
            await SaveReportAsync(result, ct);
            logger.LogInformation("Software inventory: {Count} packages, {Manual} installed manually", report.Packages.Count, report.Manual);
            return result;
        }
        catch (InventoryException ex)
        {
            logger.LogWarning("Software inventory failed: {Error}", ex.Message);
            var failed = new AgentReport(InventoryJob, started, time.GetUtcNow().UtcDateTime, false, ex.Message);
            await SaveReportAsync(failed with { Software = LastReport()?.Software }, ct);
            return failed;
        }
    }

    private async Task<List<InstalledPackage>> CollectAsync(CancellationToken ct)
    {
        var packages = Manager switch
        {
            "apt" => await CollectDpkgAsync(ct),
            "dnf" => await CollectRpmAsync(ct),
            "apk" => await CollectApkAsync(ct),
            _ => throw new InventoryException($"No supported package database on {os.PrettyName}."),
        };
        return packages.Count > MaxPackages ? packages.Take(MaxPackages).ToList() : packages;
    }

    private async Task<List<InstalledPackage>> CollectDpkgAsync(CancellationToken ct)
    {
        var q = await runner.RunAsync("dpkg-query", ["-W", "-f=" + SoftwareParsers.DpkgFormat], Query, ct);
        if (!q.Success) throw new InventoryException($"dpkg-query failed: {Tail(q.CombinedOutput, 400)}");
        // apt-mark is part of apt; without it every package counts as a dependency rather than failing the inventory.
        var manual = runner.Which("apt-mark") is null ? [] : await runner.RunAsync("apt-mark", ["showmanual"], Query, ct) is { Success: true } m
            ? SoftwareParsers.ParseNameList(m.StdOut) : [];
        return SoftwareParsers.ParseDpkgQuery(q.StdOut, manual);
    }

    private async Task<List<InstalledPackage>> CollectRpmAsync(CancellationToken ct)
    {
        var q = await runner.RunAsync("rpm", ["-qa", "--qf", SoftwareParsers.RpmFormat], Query, ct);
        if (!q.Success) throw new InventoryException($"rpm -qa failed: {Tail(q.CombinedOutput, 400)}");
        HashSet<string> manual = [];
        if (runner.Which("dnf") is not null)
        {
            // From the metadata cache when there is one (no network); without a cache dnf -C refuses, so ask once more normally.
            var m = await runner.RunAsync("dnf", ["-q", "-C", "repoquery", "--userinstalled", "--qf", "%{name}\\n"], Query, ct);
            if (!m.Success) m = await runner.RunAsync("dnf", ["-q", "repoquery", "--userinstalled", "--qf", "%{name}\\n"], Query, ct);
            if (m.Success) manual = SoftwareParsers.ParseNameList(m.StdOut);
        }
        return SoftwareParsers.ParseRpmQuery(q.StdOut, manual);
    }

    private async Task<List<InstalledPackage>> CollectApkAsync(CancellationToken ct)
    {
        var q = await runner.RunAsync("apk", ["list", "--installed"], Query, ct);
        if (!q.Success) throw new InventoryException($"apk list failed: {Tail(q.CombinedOutput, 400)}");
        var world = await fs.ReadAllTextAsync("/etc/apk/world", ct) ?? "";
        return SoftwareParsers.ParseApkInstalled(q.StdOut, SoftwareParsers.ParseApkWorld(world));
    }

    // ---- dry run ----

    /// <summary>Asks the package manager what upgrading or removing <paramref name="package"/> would do. Changes nothing.</summary>
    public async Task<PackagePlan> PreviewAsync(string op, string package, CancellationToken ct)
    {
        var (installed, error) = await FindInstalledAsync(op, package, ct);
        if (error is not null) return Failed(op, package, error);
        if (op == PackageOps.Remove && installed!.Protected)
            return new PackagePlan(op, package, true, null, [new PlannedPackage(package, "remove", installed.Version, null)], [package]);

        var sim = PackageCommands.Simulate(Manager!, op, package)!;
        var r = await runner.RunAsync(sim.FileName, sim.Args, Query, ct);
        // dnf --assumeno always exits 1 after printing the transaction; its real errors come without a table.
        var changes = Manager switch
        {
            "apt" => SoftwareParsers.ParseAptPlan(r.StdOut),
            "dnf" => SoftwareParsers.ParseDnfPlan(r.StdOut),
            _ => SoftwareParsers.ParseApkPlan(r.StdOut),
        };
        if (!r.Success && !(Manager == "dnf" && changes.Count > 0) && !(Manager == "dnf" && IsDnfNothingToDo(r.CombinedOutput)))
        {
            // apt and dnf print their reason on "E:"/"Error:" lines; the rest is progress noise.
            var reasons = r.CombinedOutput.Split('\n').Select(l => l.Trim())
                .Where(l => l.StartsWith("E:", StringComparison.Ordinal) || l.StartsWith("Error:", StringComparison.OrdinalIgnoreCase)
                    || (l.Contains(" : ", StringComparison.Ordinal) && l.Contains("Depends", StringComparison.Ordinal))).ToList();
            return Failed(op, package, $"{sim.FileName} dry run failed: {Tail(reasons.Count > 0 ? string.Join('\n', reasons) : r.CombinedOutput, 600)}");
        }

        var inventory = (LastReport()?.Software?.Packages ?? []).ToDictionary(p => p.Name, StringComparer.Ordinal);
        changes = changes.Select(c => c.From is null && c.Action is "upgrade" or "downgrade" && inventory.TryGetValue(c.Name, out var p) ? c with { From = p.Version } : c).ToList();
        var blocked = changes.Where(c => c.Action == "remove" && (ProtectedPackages.IsProtected(c.Name) || inventory.GetValueOrDefault(c.Name)?.Protected == true))
            .Select(c => c.Name).Distinct().ToList();
        return new PackagePlan(op, package, true, null, changes, blocked);
    }

    // ---- upgrade / remove ----

    /// <summary>
    /// Upgrades or removes one package, then reports the fresh inventory with the outcome in <see cref="SoftwareReport.LastAction"/>.
    /// Refuses (without running anything) when the dry run would remove a protected package.
    /// </summary>
    public async Task<AgentReport> RunActionAsync(string op, string package, CancellationToken ct)
    {
        await PackageManagerLock.Instance.WaitAsync(ct);
        try
        {
            var started = time.GetUtcNow().UtcDateTime;
            var plan = await PreviewAsync(op, package, ct);
            var before = LastReport()?.Software?.Packages.FirstOrDefault(p => p.Name == package)?.Version;
            CommandResult r;
            if (!plan.Success) r = new CommandResult(1, "", plan.Error ?? "Dry run failed.");
            else if (plan.Blocked.Count > 0) r = new CommandResult(1, "", $"Refused: this would remove protected package{(plan.Blocked.Count == 1 ? "" : "s")} {string.Join(", ", plan.Blocked)}.");
            else r = await RunCoreAsync(op, package, ct);

            List<InstalledPackage> packages;
            try { packages = await CollectAsync(ct); }
            catch (InventoryException) { packages = LastReport()?.Software?.Packages.ToList() ?? []; }
            var after = packages.FirstOrDefault(p => p.Name == package)?.Version;
            var action = new PackageActionResult(time.GetUtcNow().UtcDateTime, op, package, r.Success, before, after,
                r.Success ? null : Tail(r.CombinedOutput, 500), Tail(r.CombinedOutput, 3000));
            await state.SetAsync(StateLastAction, JsonSerializer.Serialize(action, AgentJsonContext.Default.PackageActionResult), ct);
            RaiseActionEvent(action);
            logger.LogInformation("Package {Op} {Package}: success={Success} {From} -> {To}", op, package, r.Success, before, after);

            var report = new SoftwareReport(Manager ?? "?", packages, action);
            var result = new AgentReport(ActionJob, started, time.GetUtcNow().UtcDateTime, r.Success, action.Error) { Software = report };
            await SaveReportAsync(new AgentReport(InventoryJob, started, result.FinishedAtUtc, true, null) { Software = report }, ct);
            return result;
        }
        finally
        {
            PackageManagerLock.Instance.Release();
        }
    }

    private async Task<CommandResult> RunCoreAsync(string op, string package, CancellationToken ct)
    {
        // Upgrade to what the repositories offer now, not what they offered at the last update check.
        var refresh = (Manager, op) switch
        {
            ("apt", PackageOps.Upgrade) => await runner.RunAsync("apt-get", ["update", "-q", "-o", "DPkg::Lock::Timeout=300"], Change, ct),
            ("apk", PackageOps.Upgrade) => await runner.RunAsync("apk", ["update", "-q"], Change, ct),
            _ => null,
        };
        if (refresh is { Success: false }) return refresh;
        var cmd = PackageCommands.Run(Manager!, op, package)!;
        return await runner.RunAsync(cmd.FileName, cmd.Args, Change, ct);
    }

    private async Task<(InstalledPackage? Package, string? Error)> FindInstalledAsync(string op, string package, CancellationToken ct)
    {
        if (!PackageOps.IsValid(op)) return (null, $"Unknown operation '{op}'.");
        if (!PackageOps.IsValidName(package)) return (null, "Invalid package name.");
        if (Manager is null) return (null, $"No supported package manager on {os.PrettyName}.");
        var found = LastReport()?.Software?.Packages.FirstOrDefault(p => p.Name == package);
        if (found is not null) return (found, null);
        // Installed since the last inventory: refresh once before saying no.
        await InventoryAsync(ct);
        found = LastReport()?.Software?.Packages.FirstOrDefault(p => p.Name == package);
        return found is null ? (null, $"{package} is not installed.") : (found, null);
    }

    private static bool IsDnfNothingToDo(string output) =>
        output.Contains("Nothing to do", StringComparison.OrdinalIgnoreCase) || output.Contains("No packages marked for upgrade", StringComparison.OrdinalIgnoreCase);

    private static PackagePlan Failed(string op, string package, string error) => new(op, package, false, error, [], []);

    private void RaiseActionEvent(PackageActionResult a)
    {
        var (kind, severity, message) = (a.Success, a.Op) switch
        {
            (true, PackageOps.Upgrade) => (EventKinds.SoftwareUpgraded, Severity.Info,
                a.From == a.To ? $"{a.Package} is already the newest version ({a.To})" : $"Upgraded {a.Package} from {a.From} to {a.To}"),
            (true, _) => (EventKinds.SoftwareRemoved, Severity.Low, $"Uninstalled {a.Package} {a.From}"),
            _ => (EventKinds.SoftwareFailed, Severity.Medium, $"{(a.Op == PackageOps.Upgrade ? "Upgrading" : "Uninstalling")} {a.Package} failed: {a.Error}"),
        };
        _events.Enqueue(new SecurityEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = a.AtUtc,
            Capability = Capability.Updates,
            Severity = severity,
            SourceTool = Info.Id,
            Kind = kind,
            Subject = a.Package,
            Message = message,
            Raw = a.Success ? null : a.LogTail,
            Metadata = new Dictionary<string, string> { ["op"] = a.Op, ["from"] = a.From ?? "", ["to"] = a.To ?? "" },
        });
    }

    // ---- state ----

    private AgentReport? LastReport() =>
        state.Get(StateLastReport) is { } json ? JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentReport) : null;

    private PackageActionResult? LastAction() =>
        state.Get(StateLastAction) is { } json ? JsonSerializer.Deserialize(json, AgentJsonContext.Default.PackageActionResult) : null;

    private Task SaveReportAsync(AgentReport report, CancellationToken ct) =>
        state.SetAsync(StateLastReport, JsonSerializer.Serialize(report, AgentJsonContext.Default.AgentReport), ct);

    private static string Tail(string s, int max)
    {
        s = s.Trim();
        return s.Length <= max ? s : "…" + s[^max..];
    }

    private sealed class InventoryException(string message) : Exception(message);
}
