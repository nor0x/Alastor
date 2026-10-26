using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Alastor.Server.Services.Updates;

/// <summary>The newest published release, as last seen on GitHub.</summary>
public sealed record LatestRelease(string Tag, string Url, DateTime? PublishedAt, DateTime CheckedAt);

/// <summary>
/// Asks GitHub for the repository's latest release (drafts and prereleases are skipped by that endpoint) so the dashboard
/// can point at a newer version. Only the public release list is fetched; nothing about this server is sent.
/// </summary>
public sealed class UpdateCheckService(IHttpClientFactory httpFactory, IOptions<AlastorOptions> options, TimeProvider time, ILogger<UpdateCheckService> logger)
{
    public const string HttpClientName = "updates";

    /// <summary>The running server's version without build metadata ("0.2.0"), "dev" when unstamped.</summary>
    public static string CurrentVersion { get; } =
        typeof(UpdateCheckService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "dev";

    private volatile LatestRelease? _latest;
    private bool _warned;

    public LatestRelease? Latest => _latest;

    public async Task CheckAsync(CancellationToken ct)
    {
        var repo = options.Value.UpdateRepository;
        using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{repo}/releases/latest");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        try
        {
            using var res = await httpFactory.CreateClient(HttpClientName).SendAsync(req, ct);
            if (res.StatusCode == HttpStatusCode.NotFound)
            {
                // A private repository looks the same as one without releases.
                logger.LogDebug("No published release of {Repository} is visible", repo);
                _latest = null;
                return;
            }
            res.EnsureSuccessStatusCode();
            using var doc = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            var tag = doc.RootElement.TryGetProperty("tag_name", out var t) ? t.GetString() : null;
            if (string.IsNullOrWhiteSpace(tag)) throw new JsonException("The release has no tag_name.");
            DateTime? published = doc.RootElement.TryGetProperty("published_at", out var p) && p.TryGetDateTime(out var d) ? d.ToUniversalTime() : null;
            // The link is built here rather than taken from the response, so the dashboard only ever links to the release page.
            _latest = new LatestRelease(tag, $"https://github.com/{repo}/releases/tag/{Uri.EscapeDataString(tag)}", published, time.GetUtcNow().UtcDateTime);
            _warned = false;
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            // Keep the last result; warn once per outage.
            if (!_warned) logger.LogWarning("Update check against {Repository} failed: {Error}", repo, ex.Message);
            _warned = true;
        }
    }

    /// <summary>
    /// Whether release <paramref name="tag"/> ("v0.3.0") is newer than <paramref name="current"/> ("0.2.0"). The final
    /// release is newer than its own prereleases (0.3.0 over 0.3.0-rc1). Unparseable versions never are.
    /// </summary>
    public static bool IsNewer(string current, string tag) =>
        TryParse(tag, out var latest) && TryParse(current, out var running)
        && (latest > running || latest == running && IsPrerelease(current) && !IsPrerelease(tag));

    private static bool IsPrerelease(string value) => value.Split('+')[0].Contains('-');

    private static bool TryParse(string value, out Version version)
    {
        var v = value.Trim().TrimStart('v', 'V');
        var cut = v.IndexOfAny(['-', '+']);
        if (cut >= 0) v = v[..cut];
        if (Version.TryParse(v, out var parsed))
        {
            // Normalize "1.2" and "1.2.0" so they compare equal.
            version = new Version(parsed.Major, parsed.Minor, Math.Max(parsed.Build, 0));
            return true;
        }
        version = new Version();
        return false;
    }
}
