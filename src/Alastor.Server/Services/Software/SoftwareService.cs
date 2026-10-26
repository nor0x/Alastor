using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Software;
using Alastor.Core.Updates;
using Alastor.Server.Data;
using Alastor.Server.Services.Osv;
using ScheduleDto = Alastor.Server.Endpoints.ReportEndpoints.ScheduleDto;

namespace Alastor.Server.Services.Software;

/// <summary>A known vulnerability in one installed package, from the host's own scan or from OSV.dev.</summary>
/// <param name="Id">A CVE id where one is known, else the advisory id.</param>
/// <param name="Source"><c>scan</c> (Trivy/Grype on the host) or <c>osv</c>.</param>
/// <param name="Advisory">The OSV advisory the finding came from (DSA-…, USN-…), when <paramref name="Id"/> is its CVE.</param>
public sealed record PackageVulnDto(string Id, Severity? Severity, double? Cvss, string? Fixed, string Source, bool Exploited, string? Title, string? Advisory);

public sealed record SoftwarePackageDto(
    string Name, string Version, string? Arch, string? Source, bool Manual, bool Protected, long? SizeKb,
    string? Candidate, bool? Security, IReadOnlyList<PackageVulnDto> Vulns, string? UpgradeCommand, string? RemoveCommand)
{
    public int Critical => Vulns.Count(v => v.Severity == Severity.Critical);
    public int High => Vulns.Count(v => v.Severity == Severity.High);
    public bool Exploited => Vulns.Any(v => v.Exploited);
}

public sealed record HostSoftwareDto(
    Guid HostId, string Name, bool Online, string? Manager, DateTime? CollectedAt, bool? Success, string? Error,
    PackageActionResult? LastAction, string? OsvEcosystem, bool OsvEnabled, DateTime? OsvCheckedAt, int Total, int Manual,
    IReadOnlyList<SoftwarePackageDto> Packages, IReadOnlyList<ScheduleDto> Schedules);

public sealed record SoftwareVersionCount(string Version, int Hosts);

/// <summary>One package across the fleet: where it's installed, in which versions, and how many hosts need an update or have CVEs.</summary>
public sealed record FleetSoftwareRow(
    string Name, int Hosts, int ManualHosts, IReadOnlyList<SoftwareVersionCount> Versions, int Outdated, int SecurityOutdated,
    int VulnerableHosts, int Cves, int Critical, int High, bool Exploited);

public sealed record SoftwareHostRow(
    Guid HostId, string Name, bool Online, string? GroupName, string? Manager, string Version, bool Manual, bool Protected,
    string? Candidate, bool? Security, int Vulns, int Critical, int High, bool Exploited, string? UpgradeCommand, string? RemoveCommand);

/// <summary>
/// Stores software inventories (one <see cref="HostPackage"/> row per package, replaced per report) and builds the
/// Software views by joining them, at read time, with the host's pending updates, its CVE scan and cached OSV.dev results.
/// </summary>
public sealed class SoftwareService(AlastorDbContext db, TimeProvider time, Microsoft.Extensions.Options.IOptions<AlastorOptions> options)
{
    public const string ReportKind = "software";
    private static readonly HashSet<string> OsPkgTypes = new(StringComparer.Ordinal) { "deb", "rpm", "apk" };

    public async Task ReceiveAsync(Guid hostId, AgentReport report, CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var row = await db.HostReports.FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == ReportKind, ct);
        var s = report.Software;
        if (s is null)
        {
            // A failed inventory keeps the last good package list; only the outcome changes.
            if (row is null)
                db.HostReports.Add(new HostReport
                {
                    HostId = hostId, Kind = ReportKind, JobId = report.JobId, Success = false, Error = report.Error, StartedAt = report.StartedAtUtc,
                    FinishedAt = report.FinishedAtUtc, ReceivedAt = now, Json = JsonSerializer.Serialize(report, AgentJsonContext.Default.AgentReport),
                });
            else
            {
                row.Success = false;
                row.Error = report.Error;
                row.FinishedAt = report.FinishedAtUtc;
                row.ReceivedAt = now;
            }
            await db.SaveChangesAsync(ct);
            return;
        }

        // The packages live in their own table; the report row keeps the manager and the last action.
        var meta = report with { Software = s with { Packages = [] } };
        var json = JsonSerializer.Serialize(meta, AgentJsonContext.Default.AgentReport);
        if (row is null) db.HostReports.Add(row = new HostReport { HostId = hostId, Kind = ReportKind, JobId = report.JobId, Json = json });
        row.JobId = report.JobId;
        row.Json = json;
        // An upgrade that failed still came with a fresh inventory; its failure is in LastAction.
        row.Success = true;
        row.Error = null;
        row.StartedAt = report.StartedAtUtc;
        row.FinishedAt = report.FinishedAtUtc;
        row.ReceivedAt = now;

        await db.Packages.Where(p => p.HostId == hostId).ExecuteDeleteAsync(ct);
        var rows = s.Packages.Where(p => PackageOps.IsValidName(p.Name)).Take(SoftwareIntegration.MaxPackages).Select(p => new HostPackage
        {
            HostId = hostId,
            Name = p.Name,
            Version = Clip(p.Version, 200),
            Arch = p.Arch is null ? null : Clip(p.Arch, 32),
            Source = p.Source is null ? null : Clip(p.Source, 200),
            Manual = p.Manual,
            // The server's own list counts too, so an old agent can't make a protected package removable.
            Protected = p.Protected || ProtectedPackages.IsProtected(p.Name),
            SizeKb = p.SizeKb,
        }).ToList();
        db.Packages.AddRange(rows);

        var host = await db.Hosts.FirstAsync(h => h.Id == hostId, ct);
        host.PackagesTotal = rows.Count;
        host.PackagesManual = rows.Count(r => r.Manual);
        host.SoftwareCollectedAt = report.FinishedAtUtc;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>The manager (apt/dnf/apk) and last action from the host's latest software report.</summary>
    public async Task<(SoftwareReport? Report, HostReport? Row)> LatestAsync(Guid hostId, CancellationToken ct)
    {
        var row = await db.HostReports.AsNoTracking().FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == ReportKind, ct);
        return (row is null ? null : JsonSerializer.Deserialize(row.Json, AgentJsonContext.Default.AgentReport)?.Software, row);
    }

    public async Task<HostSoftwareDto?> HostAsync(Guid hostId, IReadOnlyList<ScheduleDto> schedules, CancellationToken ct)
    {
        var host = await db.Hosts.AsNoTracking().FirstOrDefaultAsync(h => h.Id == hostId, ct);
        if (host is null) return null;
        var (report, row) = await LatestAsync(hostId, ct);
        var packages = await db.Packages.AsNoTracking().Where(p => p.HostId == hostId).OrderBy(p => p.Name).ToListAsync(ct);
        var ctx = await LoadContextAsync([host], packages, ct);
        var enriched = packages.Select(p => Enrich(p, ctx, report?.Manager)).ToList();
        var ecosystem = OsvEcosystems.For(host.OsId, host.OsVersion);
        DateTime? osvChecked = ecosystem is null ? null : ctx.OsvCheckedAt(ecosystem, packages);
        return new HostSoftwareDto(host.Id, host.Name, host.IsOnline, report?.Manager, host.SoftwareCollectedAt, row?.Success, row?.Error,
            report?.LastAction, ecosystem, options.Value.OsvEnabled, osvChecked, packages.Count, packages.Count(p => p.Manual), enriched, schedules);
    }

    /// <summary>
    /// Every package name in the fleet, grouped. Without <paramref name="all"/>, only packages someone installed on purpose
    /// on at least one host, or that have an update or a known vulnerability somewhere.
    /// </summary>
    public async Task<List<FleetSoftwareRow>> FleetAsync(bool all, CancellationToken ct)
    {
        var hosts = await db.Hosts.AsNoTracking().Where(h => h.PackagesTotal != null).ToListAsync(ct);
        var packages = await db.Packages.AsNoTracking().ToListAsync(ct);
        var ctx = await LoadContextAsync(hosts, packages, ct);
        var managers = await ManagersAsync(ct);
        return packages
            .Select(p => (p.HostId, P: Enrich(p, ctx, managers.GetValueOrDefault(p.HostId))))
            .GroupBy(x => x.P.Name, StringComparer.Ordinal)
            .Select(g =>
            {
                var list = g.Select(x => x.P).ToList();
                var vulnerable = list.Where(p => p.Vulns.Count > 0).ToList();
                return new FleetSoftwareRow(g.Key, list.Count, list.Count(p => p.Manual),
                    list.GroupBy(p => p.Version).Select(v => new SoftwareVersionCount(v.Key, v.Count())).OrderByDescending(v => v.Hosts).ThenBy(v => v.Version).ToList(),
                    list.Count(p => p.Candidate is not null), list.Count(p => p.Candidate is not null && p.Security == true),
                    vulnerable.Count,
                    vulnerable.SelectMany(p => p.Vulns).Select(v => v.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                    vulnerable.SelectMany(p => p.Vulns).Where(v => v.Severity == Severity.Critical).Select(v => v.Id).Distinct().Count(),
                    vulnerable.SelectMany(p => p.Vulns).Where(v => v.Severity == Severity.High).Select(v => v.Id).Distinct().Count(),
                    vulnerable.Any(p => p.Exploited));
            })
            .Where(r => all || r.ManualHosts > 0 || r.Outdated > 0 || r.VulnerableHosts > 0)
            .OrderByDescending(r => r.Exploited).ThenByDescending(r => r.Critical).ThenByDescending(r => r.High).ThenByDescending(r => r.Outdated).ThenBy(r => r.Name)
            .ToList();
    }

    /// <summary>The hosts that have <paramref name="name"/> installed.</summary>
    public async Task<List<SoftwareHostRow>> PackageHostsAsync(string name, CancellationToken ct)
    {
        var packages = await db.Packages.AsNoTracking().Where(p => p.Name == name).ToListAsync(ct);
        var ids = packages.Select(p => p.HostId).ToList();
        var hosts = await db.Hosts.AsNoTracking().Include(h => h.Group).Where(h => ids.Contains(h.Id)).ToDictionaryAsync(h => h.Id, ct);
        var ctx = await LoadContextAsync(hosts.Values.ToList(), packages, ct);
        var managers = await ManagersAsync(ct);
        return packages.Where(p => hosts.ContainsKey(p.HostId)).Select(p =>
        {
            var h = hosts[p.HostId];
            var e = Enrich(p, ctx, managers.GetValueOrDefault(p.HostId));
            return new SoftwareHostRow(h.Id, h.Name, h.IsOnline, h.Group?.Name, managers.GetValueOrDefault(h.Id), e.Version, e.Manual, e.Protected,
                e.Candidate, e.Security, e.Vulns.Count, e.Critical, e.High, e.Exploited, e.UpgradeCommand, e.RemoveCommand);
        }).OrderBy(r => r.Name).ToList();
    }

    private async Task<Dictionary<Guid, string>> ManagersAsync(CancellationToken ct) =>
        (await db.HostReports.AsNoTracking().Where(r => r.Kind == ReportKind).Select(r => new { r.HostId, r.Json }).ToListAsync(ct))
            .Select(r => (r.HostId, M: JsonSerializer.Deserialize(r.Json, AgentJsonContext.Default.AgentReport)?.Software?.Manager))
            .Where(r => r.M is not null).ToDictionary(r => r.HostId, r => r.M!);

    // ---- enrichment ----

    private sealed class Context
    {
        public Dictionary<Guid, Dictionary<string, PendingUpdate>> Updates { get; } = [];
        public Dictionary<Guid, ILookup<string, HostVulnerability>> Scans { get; } = [];
        public Dictionary<Guid, HashSet<string>> Accepted { get; } = [];
        public Dictionary<Guid, string> Ecosystems { get; } = [];
        public Dictionary<(string Eco, string Pkg, string Ver), OsvPackageResult> Osv { get; } = [];
        public Dictionary<string, OsvVulnerability> Advisories { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Kev { get; } = new(StringComparer.OrdinalIgnoreCase);

        public DateTime? OsvCheckedAt(string ecosystem, IEnumerable<HostPackage> packages) =>
            packages.Select(p => Osv.GetValueOrDefault((ecosystem, OsvEcosystems.QueryName(ecosystem, p.Name, p.Source), p.Version))?.CheckedAt).Min();
    }

    private async Task<Context> LoadContextAsync(IReadOnlyCollection<ManagedHost> hosts, IReadOnlyCollection<HostPackage> packages, CancellationToken ct)
    {
        var ctx = new Context();
        var ids = hosts.Select(h => h.Id).ToList();

        foreach (var r in await db.HostReports.AsNoTracking().Where(r => ids.Contains(r.HostId) && r.Kind == "updates").ToListAsync(ct))
        {
            var updates = JsonSerializer.Deserialize(r.Json, AgentJsonContext.Default.AgentReport)?.Updates;
            if (updates is null) continue;
            var byName = new Dictionary<string, PendingUpdate>(StringComparer.Ordinal);
            foreach (var u in updates.Packages)
            {
                byName.TryAdd(u.Name, u);
                // dnf names updates "name.arch".
                var dot = u.Name.LastIndexOf('.');
                if (updates.Manager == "dnf" && dot > 0) byName.TryAdd(u.Name[..dot], u);
            }
            ctx.Updates[r.HostId] = byName;
        }

        var scans = await db.Vulnerabilities.AsNoTracking().Where(v => ids.Contains(v.HostId) && v.Image == null).ToListAsync(ct);
        foreach (var g in scans.GroupBy(v => v.HostId))
        {
            ctx.Scans[g.Key] = g.Where(v => !v.Accepted && OsPkgTypes.Contains(v.PkgType)).ToLookup(v => v.Package, StringComparer.Ordinal);
            ctx.Accepted[g.Key] = g.Where(v => v.Accepted).Select(v => v.VulnId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        }

        foreach (var h in hosts)
            if (OsvEcosystems.For(h.OsId, h.OsVersion) is { } eco) ctx.Ecosystems[h.Id] = eco;
        var ecosystems = ctx.Ecosystems.Values.Distinct().ToList();
        if (ecosystems.Count > 0)
        {
            var names = packages.Select(p => p.Source ?? p.Name).Concat(packages.Select(p => p.Name)).Distinct().ToList();
            var osv = names.Count > 2000
                ? await db.OsvPackages.AsNoTracking().Where(o => ecosystems.Contains(o.Ecosystem)).ToListAsync(ct)
                : await db.OsvPackages.AsNoTracking().Where(o => ecosystems.Contains(o.Ecosystem) && names.Contains(o.Package)).ToListAsync(ct);
            foreach (var o in osv) ctx.Osv[(o.Ecosystem, o.Package, o.Version)] = o;
            var vulnIds = osv.SelectMany(o => o.VulnIds).Distinct().ToList();
            foreach (var chunk in vulnIds.Chunk(500))
                foreach (var a in await db.OsvVulnerabilities.AsNoTracking().Where(v => chunk.Contains(v.Id)).ToListAsync(ct))
                    ctx.Advisories[a.Id] = a;
        }

        var cves = scans.Select(v => v.VulnId).Concat(ctx.Advisories.Values.SelectMany(CveIds)).Distinct().ToList();
        foreach (var chunk in cves.Chunk(500))
            ctx.Kev.UnionWith(await db.KevEntries.AsNoTracking().Where(k => chunk.Contains(k.CveId)).Select(k => k.CveId).ToListAsync(ct));
        return ctx;
    }

    private static SoftwarePackageDto Enrich(HostPackage p, Context ctx, string? manager)
    {
        var update = ctx.Updates.GetValueOrDefault(p.HostId) is { } u
            ? u.GetValueOrDefault(p.Name) ?? (p.Arch is null ? null : u.GetValueOrDefault($"{p.Name}.{p.Arch}"))
            : null;

        var vulns = new Dictionary<string, PackageVulnDto>(StringComparer.OrdinalIgnoreCase);
        if (ctx.Scans.GetValueOrDefault(p.HostId) is { } scan)
            foreach (var v in scan[p.Name])
                vulns.TryAdd(v.VulnId, new PackageVulnDto(v.VulnId, v.Severity, v.Cvss, v.Fixed, "scan", ctx.Kev.Contains(v.VulnId), v.Title, null));

        if (ctx.Ecosystems.GetValueOrDefault(p.HostId) is { } eco
            && ctx.Osv.GetValueOrDefault((eco, OsvEcosystems.QueryName(eco, p.Name, p.Source), p.Version)) is { } osv)
        {
            var accepted = ctx.Accepted.GetValueOrDefault(p.HostId);
            var key = $"{eco}/{OsvEcosystems.QueryName(eco, p.Name, p.Source)}";
            foreach (var id in osv.VulnIds)
            {
                var a = ctx.Advisories.GetValueOrDefault(id);
                var names = a is null ? (id.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) ? [id] : []) : CveIds(a).ToList();
                if (names.Count == 0) names = [id];
                if (accepted is not null && (accepted.Contains(id) || names.Any(accepted.Contains))) continue;
                foreach (var cve in names)
                    vulns.TryAdd(cve, new PackageVulnDto(cve, a?.Severity, a?.Cvss, a?.Fixed.GetValueOrDefault(key), "osv", ctx.Kev.Contains(cve), a?.Summary,
                        string.Equals(cve, id, StringComparison.OrdinalIgnoreCase) ? null : id));
            }
        }

        return new SoftwarePackageDto(p.Name, p.Version, p.Arch, p.Source, p.Manual, p.Protected, p.SizeKb,
            update?.Candidate, update?.Security,
            vulns.Values.OrderByDescending(v => v.Exploited).ThenByDescending(v => v.Severity ?? Severity.Info).ThenBy(v => v.Id).ToList(),
            manager is null ? null : PackageCommands.Display(manager, PackageOps.Upgrade, p.Name),
            manager is null || p.Protected ? null : PackageCommands.Display(manager, PackageOps.Remove, p.Name));
    }

    /// <summary>The CVE ids an advisory covers: its own id if it is one, plus CVE aliases.</summary>
    private static IEnumerable<string> CveIds(OsvVulnerability a) =>
        new[] { a.Id }.Concat(a.Aliases).Where(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase);

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max];
}
