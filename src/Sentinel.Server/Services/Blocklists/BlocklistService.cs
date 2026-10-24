using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sentinel.Core.Blocklists;
using Sentinel.Core.Contracts;
using Sentinel.Core.Net;
using Sentinel.Core.Policy;
using Sentinel.Server.Data;

namespace Sentinel.Server.Services.Blocklists;

/// <summary>
/// Pulls the public blocklists that some policy uses (and only those), normalizes them to merged CIDRs and stores
/// them. Agents never contact the list providers: they get one merged set per host from <see cref="BlocklistMerger"/>.
/// </summary>
public sealed class BlocklistService(
    SentinelDbContext db,
    IHttpClientFactory httpFactory,
    IOptions<SentinelOptions> options,
    TimeProvider time,
    ILogger<BlocklistService> logger)
{
    public const string HttpClientName = "blocklists";

    /// <summary>A refetch that shrinks a list below this fraction of its previous size is refused (a truncated or broken download).</summary>
    public const double MinRetainedFraction = 0.1;

    private static readonly TimeSpan MaxBackoff = TimeSpan.FromHours(4);

    /// <summary>List ids referenced by any policy layer that enables blocklists. Lists nobody uses are never fetched.</summary>
    public async Task<IReadOnlySet<string>> ListsInUseAsync(CancellationToken ct)
    {
        var yamls = await db.PolicyLayers.AsNoTracking()
            .Join(db.PolicyVersions.AsNoTracking(), l => new { Id = l.Id, V = l.CurrentVersion }, v => new { Id = v.LayerId, V = v.Version }, (l, v) => v.Yaml)
            .ToListAsync(ct);
        var docs = yamls.Select(y => PolicyYaml.Parse(y).Document).Where(d => d?.Blocklists is not null).ToList();
        if (!docs.Any(d => d!.Blocklists!.Enabled == true)) return new HashSet<string>();
        return docs.SelectMany(d => d!.Blocklists!.Lists ?? []).Where(id => BlocklistCatalog.Find(id) is not null).ToHashSet(StringComparer.Ordinal);
    }

    public async Task<int> RunDueAsync(CancellationToken ct)
    {
        var inUse = await ListsInUseAsync(ct);
        var now = time.GetUtcNow().UtcDateTime;
        var states = await db.BlocklistSources.Where(s => inUse.Contains(s.SourceId))
            .Select(s => new { s.SourceId, s.NextAttemptAt }).ToDictionaryAsync(s => s.SourceId, s => s.NextAttemptAt, ct);
        var ran = 0;
        foreach (var source in BlocklistCatalog.All.Where(s => inUse.Contains(s.Id)))
        {
            if (states.TryGetValue(source.Id, out var next) && next > now) continue;
            await RefreshAsync(source, ct);
            ran++;
        }
        return ran;
    }

    /// <summary>Fetches one list now. Never throws for network or format problems: they are recorded on the source.</summary>
    public async Task<BlocklistSourceState> RefreshAsync(BlocklistSource source, CancellationToken ct)
    {
        var state = await db.BlocklistSources.FirstOrDefaultAsync(s => s.SourceId == source.Id, ct);
        if (state is null) db.BlocklistSources.Add(state = new BlocklistSourceState { SourceId = source.Id });
        var now = time.GetUtcNow().UtcDateTime;
        state.LastAttemptAt = now;
        try
        {
            var validators = string.IsNullOrEmpty(state.Validators) ? new Dictionary<string, string>() :
                JsonSerializer.Deserialize<Dictionary<string, string>>(state.Validators) ?? [];
            var documents = await FetchAsync(source, validators, hasContent: state.ContentHash is not null, ct);
            if (documents is null)
            {
                logger.LogDebug("Blocklist {Id}: not modified", source.Id);
            }
            else
            {
                var entries = new List<IpTarget>();
                var skipped = 0;
                foreach (var text in documents)
                {
                    var parsed = BlocklistParser.Parse(source.Format, text);
                    entries.AddRange(parsed.Entries);
                    skipped += parsed.Invalid + parsed.TooWide;
                }
                var set = IpRangeSet.From(entries).Except(IpRangeSet.Reserved);
                var cidrs = set.ToCidrs(AddressFamily.InterNetwork).Concat(set.ToCidrs(AddressFamily.InterNetworkV6)).ToList();
                if (cidrs.Count == 0 || (state.EntryCount > 100 && cidrs.Count < state.EntryCount * MinRetainedFraction))
                    throw new InvalidDataException($"The download has {cidrs.Count} entries where the last good copy had {state.EntryCount}; keeping the last good copy.");
                var content = string.Join('\n', cidrs);
                var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
                if (hash != state.ContentHash) state.LastChangedAt = now;
                state.Content = content;
                state.ContentHash = hash;
                state.EntryCount = cidrs.Count;
                state.Ipv4Addresses = (long)set.Ipv4AddressCount;
                state.Skipped = skipped;
                logger.LogInformation("Blocklist {Id}: {Count} networks ({Skipped} lines skipped)", source.Id, cidrs.Count, skipped);
            }
            state.Validators = JsonSerializer.Serialize(validators);
            state.LastSuccessAt = now;
            state.ConsecutiveFailures = 0;
            state.LastError = null;
            state.NextAttemptAt = now + options.Value.BlocklistRefreshIntervalValue * (0.95 + Random.Shared.NextDouble() * 0.1);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException or JsonException)
        {
            state.ConsecutiveFailures++;
            state.LastError = ex switch
            {
                TaskCanceledException => "Timed out",
                HttpRequestException { StatusCode: { } code } => $"HTTP {(int)code} from the list provider",
                HttpRequestException h => $"Network error: {h.Message}",
                _ => ex.Message,
            };
            var backoff = TimeSpan.FromMinutes(5 * Math.Pow(2, Math.Min(state.ConsecutiveFailures - 1, 6)));
            state.NextAttemptAt = now + (backoff > MaxBackoff ? MaxBackoff : backoff);
            logger.LogWarning("Blocklist {Id} fetch failed: {Error}", source.Id, state.LastError);
        }
        await db.SaveChangesAsync(ct);
        return state;
    }

    /// <summary>
    /// Downloads every URL of a source. Returns null when all of them are unchanged (304). If only some changed, the
    /// unchanged ones are fetched again in full, because only the merged result is stored.
    /// </summary>
    private async Task<List<string>?> FetchAsync(BlocklistSource source, Dictionary<string, string> validators, bool hasContent, CancellationToken ct)
    {
        var client = httpFactory.CreateClient(HttpClientName);
        var bodies = new Dictionary<string, string>();
        foreach (var url in source.Urls)
        {
            var body = await GetAsync(client, url, hasContent ? validators.GetValueOrDefault(url) : null, validators, ct);
            if (body is not null) bodies[url] = body;
        }
        if (bodies.Count == 0) return null;
        foreach (var url in source.Urls.Where(u => !bodies.ContainsKey(u)))
            bodies[url] = (await GetAsync(client, url, null, validators, ct))!;
        return source.Urls.Select(u => bodies[u]).ToList();
    }

    private static async Task<string?> GetAsync(HttpClient client, string url, string? validator, Dictionary<string, string> validators, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (validator is not null)
        {
            if (validator.StartsWith("etag:", StringComparison.Ordinal)) req.Headers.TryAddWithoutValidation("If-None-Match", validator[5..]);
            else if (validator.StartsWith("lm:", StringComparison.Ordinal)) req.Headers.TryAddWithoutValidation("If-Modified-Since", validator[3..]);
        }
        using var resp = await client.SendAsync(req, ct);
        if (resp.StatusCode == HttpStatusCode.NotModified) return null;
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"{url}: HTTP {(int)resp.StatusCode}", null, resp.StatusCode);
        if (resp.Headers.ETag is { } etag) validators[url] = "etag:" + etag;
        else if (resp.Content.Headers.LastModified is { } lm) validators[url] = "lm:" + lm.ToString("R");
        else validators.Remove(url);
        return await resp.Content.ReadAsStringAsync(ct);
    }
}

/// <summary>
/// Builds each host's blocklist: the union of its policy's lists and extra entries, minus the allowlist (server-wide
/// and policy) and reserved ranges. Results are cached by content, so a fleet sharing one policy costs one merge.
/// </summary>
public sealed class BlocklistMerger
{
    private readonly ConcurrentDictionary<string, IpRangeSet> _parsed = new();
    private readonly ConcurrentDictionary<string, BlocklistPayload> _payloads = new();

    public async Task<BlocklistPayload> BuildAsync(SentinelDbContext db, PolicyDocument policy, TimeProvider time, CancellationToken ct)
    {
        var bl = policy.Blocklists;
        var enabled = bl?.Enabled == true;
        var ids = enabled ? (bl!.Lists ?? []).Where(id => BlocklistCatalog.Find(id) is not null).Distinct().ToList() : [];
        var sources = await db.BlocklistSources.AsNoTracking().Where(s => ids.Contains(s.SourceId))
            .Select(s => new { s.SourceId, s.ContentHash, s.EntryCount, s.LastChangedAt, s.LastError }).ToListAsync(ct);
        var extra = enabled ? Targets(bl!.Extra) : [];
        var allow = Targets(policy.Banning?.Allowlist);

        var key = string.Join('|', ids.Select(id => $"{id}:{sources.FirstOrDefault(s => s.SourceId == id)?.ContentHash}"))
                  + "|x:" + string.Join(',', extra.Select(t => t.ToString()).Order())
                  + "|a:" + string.Join(',', allow.Select(t => t.ToString()).Order());
        var etag = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..20];
        if (_payloads.TryGetValue(etag, out var cached)) return cached;

        var set = IpRangeSet.From(extra);
        foreach (var s in sources.Where(s => s.ContentHash is not null))
        {
            var parsed = _parsed.GetOrAdd(s.ContentHash!, _ =>
            {
                var content = db.BlocklistSources.AsNoTracking().Where(x => x.SourceId == s.SourceId).Select(x => x.Content).First();
                return IpRangeSet.From(content.Split('\n').Select(l => IpTarget.TryParse(l, out var t) ? t : null).OfType<IpTarget>());
            });
            set = set.Union(parsed);
        }
        set = set.Except(IpRangeSet.Reserved).Except(IpRangeSet.From(allow));

        var lists = ids.Select(id => sources.FirstOrDefault(s => s.SourceId == id) is { } s
            ? new BlocklistListInfo(id, s.EntryCount, s.LastChangedAt, s.LastError)
            : new BlocklistListInfo(id, 0, null, "Not fetched yet")).ToList();
        var payload = new BlocklistPayload(etag, time.GetUtcNow().UtcDateTime, lists,
            set.ToCidrs(AddressFamily.InterNetwork).ToList(), set.ToCidrs(AddressFamily.InterNetworkV6).ToList());

        // Bounded caches: a handful of distinct policies is the norm, and stale list versions are never asked for again.
        if (_payloads.Count > 64) _payloads.Clear();
        if (_parsed.Count > 64) _parsed.Clear();
        _payloads[etag] = payload;
        return payload;
    }

    private static List<IpTarget> Targets(IEnumerable<string>? values) =>
        (values ?? []).Select(v => IpTarget.TryParse(v, out var t) ? t : null).OfType<IpTarget>().ToList();
}
