using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using Sentinel.Core.Contracts;

namespace Sentinel.Agent;

/// <summary>The agent's only network peer: its own SentinelVPS server. HTTPS, bearer credential, optional certificate pin.</summary>
public sealed class ServerClient(HttpClient http)
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
