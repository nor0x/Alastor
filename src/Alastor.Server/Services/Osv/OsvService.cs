using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Alastor.Server.Data;

namespace Alastor.Server.Services.Osv;

/// <summary>
/// Looks up every distinct (ecosystem, package, version) in the fleet's software inventories on OSV.dev and caches the
/// answer for a day, so the Software view also shows known vulnerabilities on hosts without Trivy or Grype. Only package
/// names and versions leave the server, never host names or addresses. Turned off with <see cref="AlastorOptions.OsvEnabled"/>.
/// </summary>
public sealed class OsvService(AlastorDbContext db, IHttpClientFactory httpFactory, TimeProvider time, ILogger<OsvService> logger)
{
    public const string HttpClientName = "osv";
    public static readonly Uri BaseUri = new("https://api.osv.dev/");

    private const int BatchSize = 1000; // the querybatch limit
    private const int MaxQueriesPerRun = 10_000;
    private const int MaxDetailsPerRun = 1_000;
    private static readonly TimeSpan MaxAge = TimeSpan.FromHours(24);
    private static readonly TimeSpan Forget = TimeSpan.FromDays(7);

    public async Task RunDueAsync(CancellationToken ct)
    {
        var hosts = await db.Hosts.AsNoTracking().Where(h => h.PackagesTotal != null).Select(h => new { h.Id, h.OsId, h.OsVersion }).ToListAsync(ct);
        var ecoByHost = hosts.Select(h => (h.Id, Eco: OsvEcosystems.For(h.OsId, h.OsVersion))).Where(x => x.Eco is not null).ToDictionary(x => x.Id, x => x.Eco!);
        if (ecoByHost.Count == 0) return;
        var hostIds = ecoByHost.Keys.ToList();
        var ecosystems = ecoByHost.Values.Distinct().ToList();
        var now = time.GetUtcNow().UtcDateTime;

        var packages = await db.Packages.AsNoTracking().Where(p => hostIds.Contains(p.HostId)).Select(p => new { p.HostId, p.Name, p.Source, p.Version }).ToListAsync(ct);
        var wanted = packages.Select(p => (Eco: ecoByHost[p.HostId], Name: OsvEcosystems.QueryName(ecoByHost[p.HostId], p.Name, p.Source), p.Version)).Distinct().ToList();
        var checkedAt = (await db.OsvPackages.AsNoTracking().Where(o => ecosystems.Contains(o.Ecosystem)).Select(o => new { o.Ecosystem, o.Package, o.Version, o.CheckedAt }).ToListAsync(ct))
            .ToDictionary(o => (o.Ecosystem, o.Package, o.Version), o => o.CheckedAt);
        var due = wanted.Where(w => !checkedAt.TryGetValue(w, out var at) || now - at > MaxAge).Take(MaxQueriesPerRun).ToList();

        var http = httpFactory.CreateClient(HttpClientName);
        var modified = new Dictionary<string, DateTime?>(StringComparer.Ordinal);
        foreach (var batch in due.Chunk(BatchSize))
        {
            List<List<(string Id, DateTime? Modified)>> results;
            try
            {
                using var resp = await http.PostAsync(new Uri(BaseUri, "v1/querybatch"), new StringContent(QueryBody(batch), Encoding.UTF8, "application/json"), ct);
                resp.EnsureSuccessStatusCode();
                results = OsvParsers.ParseQueryBatch(await resp.Content.ReadAsStringAsync(ct));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException && !ct.IsCancellationRequested)
            {
                logger.LogWarning("OSV.dev query failed, retrying on the next run: {Message}", ex.Message);
                return;
            }
            for (var i = 0; i < batch.Length && i < results.Count; i++)
            {
                var (eco, name, version) = batch[i];
                foreach (var (id, mod) in results[i]) modified[id] = mod;
                var row = new OsvPackageResult { Ecosystem = eco, Package = name, Version = version, VulnIds = results[i].Select(r => r.Id).Distinct().ToList(), CheckedAt = now };
                if (checkedAt.ContainsKey(batch[i])) db.OsvPackages.Update(row);
                else db.OsvPackages.Add(row);
            }
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
        if (due.Count > 0) logger.LogInformation("OSV.dev: checked {Count} package versions", due.Count);

        await FetchDetailsAsync(ecosystems, modified, http, ct);
        await db.OsvPackages.Where(o => o.CheckedAt < now - Forget).ExecuteDeleteAsync(ct);
    }

    /// <summary>Fetches advisories the cache references but doesn't have yet, and ones OSV reports as changed.</summary>
    private async Task FetchDetailsAsync(List<string> ecosystems, Dictionary<string, DateTime?> modified, HttpClient http, CancellationToken ct)
    {
        var referenced = (await db.OsvPackages.AsNoTracking().Where(o => ecosystems.Contains(o.Ecosystem)).Select(o => o.VulnIds).ToListAsync(ct))
            .SelectMany(v => v).ToHashSet(StringComparer.Ordinal);
        var known = (await db.OsvVulnerabilities.AsNoTracking().Select(v => new { v.Id, v.Modified }).ToListAsync(ct)).ToDictionary(v => v.Id, v => v.Modified, StringComparer.Ordinal);
        var fetch = referenced.Where(id => !known.TryGetValue(id, out var have) || (modified.GetValueOrDefault(id) is { } m && (have is null || m > have)))
            .Take(MaxDetailsPerRun).ToList();
        if (fetch.Count == 0) return;

        var fetched = new ConcurrentBag<OsvAdvisory>();
        var failures = 0;
        await Parallel.ForEachAsync(fetch, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (id, token) =>
        {
            try
            {
                var json = await http.GetStringAsync(new Uri(BaseUri, $"v1/vulns/{Uri.EscapeDataString(id)}"), token);
                fetched.Add(OsvParsers.ParseVuln(json));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException && !token.IsCancellationRequested)
            {
                Interlocked.Increment(ref failures);
            }
        });

        var now = time.GetUtcNow().UtcDateTime;
        foreach (var a in fetched)
        {
            var row = new OsvVulnerability
            {
                Id = a.Id, Summary = a.Summary, Severity = a.Severity, Cvss = a.Cvss, Aliases = a.Aliases.Take(50).ToList(),
                Fixed = a.Fixed.Take(200).ToDictionary(), Modified = a.Modified, FetchedAt = now,
            };
            if (known.ContainsKey(a.Id)) db.OsvVulnerabilities.Update(row);
            else db.OsvVulnerabilities.Add(row);
        }
        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
        if (failures > 0) logger.LogWarning("OSV.dev: {Failures} of {Count} advisories could not be fetched; retrying on the next run", failures, fetch.Count);
    }

    private static string QueryBody(IEnumerable<(string Eco, string Name, string Version)> batch)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            w.WriteStartArray("queries");
            foreach (var (eco, name, version) in batch)
            {
                w.WriteStartObject();
                w.WriteStartObject("package");
                w.WriteString("ecosystem", eco);
                w.WriteString("name", name);
                w.WriteEndObject();
                w.WriteString("version", version);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }
}
