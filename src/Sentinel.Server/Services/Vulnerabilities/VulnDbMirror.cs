using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using Sentinel.Core.Vulnerabilities;

namespace Sentinel.Server.Services.Vulnerabilities;

/// <summary>registry/repository:tag, e.g. <c>ghcr.io/aquasecurity/trivy-db:2</c>.</summary>
public sealed partial record OciReference(string Registry, string Repository, string Tag)
{
    public static bool TryParse(string value, out OciReference reference)
    {
        var m = Pattern().Match(value);
        reference = m.Success ? new OciReference(m.Groups["reg"].Value, m.Groups["repo"].Value, m.Groups["tag"].Value) : null!;
        return m.Success;
    }

    [GeneratedRegex(@"^(?<reg>[a-z0-9.-]+(?::\d+)?)/(?<repo>[a-z0-9._/-]+):(?<tag>[A-Za-z0-9._-]+)$")]
    private static partial Regex Pattern();
}

/// <summary>What the server holds for one scanner. <see cref="Etag"/> is the upstream sha256 of the archive.</summary>
public sealed record VulnDbState
{
    public string? Etag { get; init; }
    public DateTime? BuiltAt { get; init; }
    public DateTime? FetchedAt { get; init; }
    public long Size { get; init; }
    public DateTime? LastCheckedAt { get; init; }
    public string? LastError { get; init; }
    public DateTime? NextAttemptAt { get; init; }
    public DateTime? LastRequestedAt { get; init; }
}

public sealed record VulnDbStatusDto(string Scanner, bool Available, bool DownloadsEnabled, string? Etag, DateTime? BuiltAt, DateTime? FetchedAt, long Size,
    DateTime? LastCheckedAt, string? LastError, DateTime? LastRequestedAt, string Source);

/// <summary>
/// Mirrors the scanners' vulnerability databases so agents never contact Aqua or Anchore (the spec: feeds are pulled by
/// the server). A database is fetched the first time an agent asks for it, then refreshed while agents keep asking:
/// <list type="bullet">
/// <item>Trivy: the OCI artifact <c>ghcr.io/aquasecurity/trivy-db:2</c>, a single <c>db.tar.gz</c> layer, pulled with the
/// registry's anonymous token flow.</item>
/// <item>Grype: <c>{url}/v6/latest.json</c> names the current archive and its checksum.</item>
/// </list>
/// Downloads are verified against the upstream sha256 before they replace the served file. With downloads off, an admin
/// can place <c>data/vulndb/trivy/db.tar.gz</c> or <c>data/vulndb/grype/db.tar.zst</c> by hand.
/// </summary>
public sealed class VulnDbMirror(IHttpClientFactory httpFactory, IOptions<SentinelOptions> options, TimeProvider time, ILogger<VulnDbMirror> logger)
{
    public const string HttpClientName = "vulndb";
    public static readonly IReadOnlyList<string> Scanners = [VulnerabilityIntegration.Trivy, VulnerabilityIntegration.Grype];

    /// <summary>A database nobody asked for in this long stops being refreshed.</summary>
    public static readonly TimeSpan DemandWindow = TimeSpan.FromDays(7);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly ConcurrentDictionary<string, VulnDbState> _states = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();
    private readonly Channel<string> _requests = Channel.CreateBounded<string>(new BoundedChannelOptions(8) { FullMode = BoundedChannelFullMode.DropOldest });

    public ChannelReader<string> Requests => _requests.Reader;

    private string Dir(string scanner) => Path.Combine(options.Value.DataDir, "vulndb", scanner);
    public string FilePath(string scanner) => Path.Combine(Dir(scanner), scanner == VulnerabilityIntegration.Trivy ? "db.tar.gz" : "db.tar.zst");
    private string MetaPath(string scanner) => Path.Combine(Dir(scanner), "meta.json");

    public string Source(string scanner) => scanner == VulnerabilityIntegration.Trivy ? options.Value.TrivyDbRepository : $"{options.Value.GrypeDbUrl.TrimEnd('/')}/v6/latest.json";

    public VulnDbState State(string scanner) => _states.GetOrAdd(scanner, Load);

    private VulnDbState Load(string scanner)
    {
        try
        {
            if (File.Exists(MetaPath(scanner)) && JsonSerializer.Deserialize<VulnDbState>(File.ReadAllText(MetaPath(scanner)), Json) is { } s)
                return File.Exists(FilePath(scanner)) ? s : s with { Etag = null, Size = 0 };
        }
        catch (JsonException ex)
        {
            logger.LogWarning("Ignoring unreadable {Path}: {Error}", MetaPath(scanner), ex.Message);
        }
        // Placed by hand (air-gapped): hash it once so agents can still use conditional requests.
        if (File.Exists(FilePath(scanner)))
        {
            using var f = File.OpenRead(FilePath(scanner));
            var info = new FileInfo(FilePath(scanner));
            var state = new VulnDbState { Etag = Convert.ToHexStringLower(SHA256.HashData(f)), BuiltAt = info.LastWriteTimeUtc, FetchedAt = info.LastWriteTimeUtc, Size = info.Length };
            Save(scanner, state);
            return state;
        }
        return new VulnDbState();
    }

    private void Save(string scanner, VulnDbState state)
    {
        _states[scanner] = state;
        Directory.CreateDirectory(Dir(scanner));
        var tmp = MetaPath(scanner) + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(state, Json));
        File.Move(tmp, MetaPath(scanner), overwrite: true);
    }

    /// <summary>An agent asked for this database: remember the demand, and fetch it now if we have none yet.</summary>
    public VulnDbState Request(string scanner)
    {
        var s = State(scanner);
        // Placed by hand while the server runs (air-gapped): pick it up without a restart.
        if (s.Etag is null && File.Exists(FilePath(scanner)))
        {
            File.Delete(MetaPath(scanner));
            s = _states[scanner] = Load(scanner) with { LastRequestedAt = s.LastRequestedAt };
        }
        var now = time.GetUtcNow().UtcDateTime;
        if (s.LastRequestedAt is null || now - s.LastRequestedAt > TimeSpan.FromMinutes(10)) Save(scanner, s = s with { LastRequestedAt = now });
        if (s.Etag is null && options.Value.VulnDbEnabled) _requests.Writer.TryWrite(scanner);
        return s;
    }

    public IReadOnlyList<VulnDbStatusDto> Status() => Scanners.Select(s =>
    {
        var st = State(s);
        return new VulnDbStatusDto(s, st.Etag is not null, options.Value.VulnDbEnabled, st.Etag, st.BuiltAt, st.FetchedAt, st.Size, st.LastCheckedAt, st.LastError, st.LastRequestedAt, Source(s));
    }).ToList();

    /// <summary>Refreshes every database agents asked for recently whose check is due.</summary>
    public async Task RunDueAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        foreach (var scanner in Scanners)
        {
            var s = State(scanner);
            if (s.LastRequestedAt is null || now - s.LastRequestedAt > DemandWindow) continue;
            if (s.NextAttemptAt > now) continue;
            if (s.Etag is not null && s.LastCheckedAt is { } checkedAt && now - checkedAt < options.Value.VulnDbRefreshIntervalValue) continue;
            await RefreshAsync(scanner, ct);
        }
    }

    /// <summary>Checks upstream and downloads a newer build. Never throws for network or format problems: they're recorded with a backoff.</summary>
    public async Task<VulnDbState> RefreshAsync(string scanner, CancellationToken ct)
    {
        var gate = _locks.GetOrAdd(scanner, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var s = State(scanner);
            var now = time.GetUtcNow().UtcDateTime;
            try
            {
                var http = httpFactory.CreateClient(HttpClientName);
                var (digest, built, download) = scanner == VulnerabilityIntegration.Trivy ? await ResolveTrivyAsync(http, ct) : await ResolveGrypeAsync(http, ct);
                if (digest == s.Etag && File.Exists(FilePath(scanner)))
                {
                    Save(scanner, s = s with { LastCheckedAt = now, LastError = null, NextAttemptAt = null });
                    return s;
                }
                logger.LogInformation("Downloading the {Scanner} database built {Built}", scanner, built);
                var size = await DownloadVerifiedAsync(http, download, digest, FilePath(scanner), ct);
                Save(scanner, s = s with { Etag = digest, BuiltAt = built, FetchedAt = now, Size = size, LastCheckedAt = now, LastError = null, NextAttemptAt = null });
                logger.LogInformation("Mirrored the {Scanner} database ({Size} MB)", scanner, size / 1024 / 1024);
                return s;
            }
            catch (Exception ex) when (ex is HttpRequestException or JsonException or InvalidDataException or IOException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                // 5 min, doubling per consecutive failure up to 6 h.
                var previous = s.NextAttemptAt is { } n && s.LastCheckedAt is { } c ? n - c : TimeSpan.Zero;
                var backoff = TimeSpan.FromTicks(Math.Clamp(previous.Ticks * 2, TimeSpan.FromMinutes(5).Ticks, TimeSpan.FromHours(6).Ticks));
                logger.LogWarning("Mirroring the {Scanner} database failed: {Error}", scanner, ex.Message);
                Save(scanner, s = s with { LastCheckedAt = now, LastError = ex.Message, NextAttemptAt = now + backoff });
                return s;
            }
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<(string Digest, DateTime? Built, Func<HttpRequestMessage> Download)> ResolveTrivyAsync(HttpClient http, CancellationToken ct)
    {
        if (!OciReference.TryParse(options.Value.TrivyDbRepository, out var oci)) throw new InvalidDataException($"Bad TrivyDbRepository '{options.Value.TrivyDbRepository}'.");
        var baseUrl = $"https://{oci.Registry}/v2/{oci.Repository}";
        string? token = null;
        HttpRequestMessage Manifest()
        {
            var r = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/manifests/{oci.Tag}");
            r.Headers.Accept.ParseAdd("application/vnd.oci.image.manifest.v1+json");
            if (token is not null) r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return r;
        }
        var resp = await http.SendAsync(Manifest(), ct);
        if (resp.StatusCode == HttpStatusCode.Unauthorized && resp.Headers.WwwAuthenticate.FirstOrDefault(h => h.Scheme == "Bearer") is { Parameter: { } challenge })
        {
            // Anonymous pull: the registry names its token endpoint (realm, service, scope) in the challenge.
            var p = Regex.Matches(challenge, @"(\w+)=""([^""]*)""").ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Value);
            var tokenUrl = $"{p["realm"]}?service={Uri.EscapeDataString(p.GetValueOrDefault("service", ""))}&scope={Uri.EscapeDataString(p.GetValueOrDefault("scope", $"repository:{oci.Repository}:pull"))}";
            using var tr = await http.GetAsync(tokenUrl, ct);
            tr.EnsureSuccessStatusCode();
            using var tdoc = JsonDocument.Parse(await tr.Content.ReadAsStringAsync(ct));
            token = (tdoc.RootElement.TryGetProperty("token", out var t) ? t : tdoc.RootElement.GetProperty("access_token")).GetString();
            resp.Dispose();
            resp = await http.SendAsync(Manifest(), ct);
        }
        using (resp)
        {
            resp.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            var layer = doc.RootElement.GetProperty("layers").EnumerateArray()
                .FirstOrDefault(l => l.GetProperty("mediaType").GetString() == "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip");
            if (layer.ValueKind != JsonValueKind.Object) throw new InvalidDataException("The manifest has no Trivy database layer.");
            var digest = layer.GetProperty("digest").GetString() ?? "";
            if (!digest.StartsWith("sha256:", StringComparison.Ordinal)) throw new InvalidDataException($"Unsupported digest '{digest}'.");
            DateTime? built = doc.RootElement.TryGetProperty("annotations", out var a) && a.TryGetProperty("org.opencontainers.image.created", out var c)
                && DateTime.TryParse(c.GetString(), null, System.Globalization.DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
            var bearer = token;
            return (digest["sha256:".Length..], built, () =>
            {
                var r = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/blobs/{digest}");
                if (bearer is not null) r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
                return r;
            });
        }
    }

    private async Task<(string Digest, DateTime? Built, Func<HttpRequestMessage> Download)> ResolveGrypeAsync(HttpClient http, CancellationToken ct)
    {
        var baseUrl = $"{options.Value.GrypeDbUrl.TrimEnd('/')}/v6";
        using var resp = await http.GetAsync($"{baseUrl}/latest.json", ct);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var root = doc.RootElement;
        var path = root.GetProperty("path").GetString() ?? throw new InvalidDataException("latest.json has no path.");
        var checksum = root.GetProperty("checksum").GetString() ?? "";
        if (!checksum.StartsWith("sha256:", StringComparison.Ordinal)) throw new InvalidDataException($"Unsupported checksum '{checksum}'.");
        // The archive name is relative to the listing; refuse anything that tries to leave it.
        if (path.Contains("..", StringComparison.Ordinal) || path.Contains("://", StringComparison.Ordinal)) throw new InvalidDataException($"Unexpected archive path '{path}'.");
        DateTime? built = root.TryGetProperty("built", out var b) && DateTime.TryParse(b.GetString(), null, System.Globalization.DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
        return (checksum["sha256:".Length..], built, () => new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/{path}"));
    }

    private static async Task<long> DownloadVerifiedAsync(HttpClient http, Func<HttpRequestMessage> request, string sha256, string target, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        var tmp = target + ".part";
        using var req = request();
        using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        long size;
        using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            await using (var file = File.Create(tmp))
            await using (var body = await resp.Content.ReadAsStreamAsync(ct))
            {
                var buffer = new byte[1 << 16];
                int read;
                while ((read = await body.ReadAsync(buffer, ct)) > 0)
                {
                    hash.AppendData(buffer, 0, read);
                    await file.WriteAsync(buffer.AsMemory(0, read), ct);
                }
                size = file.Length;
            }
            var actual = Convert.ToHexStringLower(hash.GetHashAndReset());
            if (!string.Equals(actual, sha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(tmp);
                throw new InvalidDataException($"Checksum mismatch (expected {sha256[..12]}…, got {actual[..12]}…).");
            }
        }
        File.Move(tmp, target, overwrite: true);
        return size;
    }
}
