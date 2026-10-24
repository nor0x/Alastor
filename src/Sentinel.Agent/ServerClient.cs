using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using Sentinel.Core.Contracts;
using Sentinel.Core.Vulnerabilities;

namespace Sentinel.Agent;

/// <summary>The agent's only network peer: its own SentinelVPS server. HTTPS, bearer credential, optional certificate pin.</summary>
public sealed class ServerClient(HttpClient http) : IVulnDbSource
{
    private static readonly AgentJsonContext Json = AgentJsonContext.Default;

    public static HttpMessageHandler CreateHandler(string? certificatePin) => new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(10),
        AutomaticDecompression = System.Net.DecompressionMethods.All,
        SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = certificatePin is null
                ? null
                : (_, cert, _, _) => cert is not null &&
                    string.Equals(Convert.ToHexString(SHA256.HashData(cert.GetRawCertData())), certificatePin.Replace(":", ""), StringComparison.OrdinalIgnoreCase),
        },
    };

    public static HttpClient CreateHttpClient(string serverUrl, string? credential, string? certificatePin)
    {
        var client = new HttpClient(CreateHandler(certificatePin)) { BaseAddress = new Uri(serverUrl.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("sentinel-agent", AgentInfo.Version));
        if (credential is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        return client;
    }

    public async Task<EnrollResponse> EnrollAsync(EnrollRequest req, CancellationToken ct)
    {
        using var resp = await http.PostAsJsonAsync("api/agent/enroll", req, Json.EnrollRequest, ct);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Enrollment failed ({(int)resp.StatusCode}): {await resp.Content.ReadAsStringAsync(ct)}", null, resp.StatusCode);
        return (await resp.Content.ReadFromJsonAsync(Json.EnrollResponse, ct))!;
    }

    public async Task<HeartbeatResponse> HeartbeatAsync(HeartbeatRequest req, CancellationToken ct)
    {
        using var resp = await http.PostAsJsonAsync("api/agent/heartbeat", req, Json.HeartbeatRequest, ct);
        resp.EnsureSuccessStatusCode();
        return (await resp.Content.ReadFromJsonAsync(Json.HeartbeatResponse, ct))!;
    }

    public async Task<DesiredStateResponse> GetDesiredStateAsync(CancellationToken ct) =>
        (await http.GetFromJsonAsync("api/agent/desired-state", Json.DesiredStateResponse, ct))!;

    public async Task<EventBatchResult> SendEventsAsync(EventBatch batch, CancellationToken ct)
    {
        using var resp = await http.PostAsJsonAsync("api/agent/events", batch, Json.EventBatch, ct);
        resp.EnsureSuccessStatusCode();
        return (await resp.Content.ReadFromJsonAsync(Json.EventBatchResult, ct))!;
    }

    public async Task SendBanSnapshotAsync(BanSnapshot snapshot, CancellationToken ct)
    {
        using var resp = await http.PostAsJsonAsync("api/agent/bans", snapshot, Json.BanSnapshot, ct);
        resp.EnsureSuccessStatusCode();
    }

    public async Task SendBaselineAsync(Sentinel.Core.Baseline.BaselineReport report, CancellationToken ct)
    {
        using var resp = await http.PostAsJsonAsync("api/agent/baseline", report, Json.BaselineReport, ct);
        resp.EnsureSuccessStatusCode();
    }

    public async Task SendReportAsync(AgentReport report, CancellationToken ct)
    {
        using var resp = await http.PostAsJsonAsync("api/agent/reports", report, Json.AgentReport, ct);
        resp.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// A scanner database mirrored by the server (100-200 MB), streamed to <paramref name="destinationPath"/>. With
    /// <see cref="HttpCompletionOption.ResponseHeadersRead"/> the client's 30 s timeout covers only the headers; the body
    /// is bounded by its own 30 minute limit.
    /// </summary>
    public async Task<VulnDbFetch> FetchAsync(string scanner, string? etag, string destinationPath, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"api/agent/vulndb/{scanner}");
        if (etag is not null) req.Headers.IfNoneMatch.Add(new EntityTagHeaderValue($"\"{etag}\""));
        using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotModified) return new VulnDbFetch(VulnDbFetchStatus.NotModified, etag);
        if (resp.StatusCode == System.Net.HttpStatusCode.ServiceUnavailable)
        {
            var message = await ProblemDetailAsync(resp, ct);
            return resp.Headers.RetryAfter?.Delta is { } retry
                ? new VulnDbFetch(VulnDbFetchStatus.NotReady, RetryAfter: retry, Message: message)
                : new VulnDbFetch(VulnDbFetchStatus.Unavailable, Message: message);
        }
        resp.EnsureSuccessStatusCode();
        using var body = CancellationTokenSource.CreateLinkedTokenSource(ct);
        body.CancelAfter(TimeSpan.FromMinutes(30));
        await using (var file = File.Create(destinationPath))
        await using (var stream = await resp.Content.ReadAsStreamAsync(body.Token))
            await stream.CopyToAsync(file, body.Token);
        var built = resp.Headers.TryGetValues("X-Sentinel-Db-Built", out var b) && DateTime.TryParse(b.FirstOrDefault(), System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var d) ? d : (DateTime?)null;
        return new VulnDbFetch(VulnDbFetchStatus.Downloaded, resp.Headers.ETag?.Tag.Trim('"'), built);
    }

    private static async Task<string?> ProblemDetailAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            return doc.RootElement.TryGetProperty("detail", out var d) ? d.GetString() : null;
        }
        catch (System.Text.Json.JsonException) { return null; }
    }

    /// <summary>The merged blocklist for this host, or null when it still matches <paramref name="etag"/> (304).</summary>
    public async Task<BlocklistPayload?> GetBlocklistAsync(string? etag, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "api/agent/blocklist");
        if (etag is not null) req.Headers.IfNoneMatch.Add(new EntityTagHeaderValue($"\"{etag}\""));
        using var resp = await http.SendAsync(req, ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotModified) return null;
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadFromJsonAsync(Json.BlocklistPayload, ct);
    }

    public async Task<List<AgentCommand>> GetCommandsAsync(CancellationToken ct) =>
        (await http.GetFromJsonAsync("api/agent/commands", Json.ListAgentCommand, ct)) ?? [];

    public async Task ReportCommandAsync(Guid id, AgentCommandResult result, CancellationToken ct)
    {
        using var resp = await http.PostAsJsonAsync($"api/agent/commands/{id}/result", result, Json.AgentCommandResult, ct);
        resp.EnsureSuccessStatusCode();
    }
}
