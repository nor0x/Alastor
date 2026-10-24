using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sentinel.Server.Data;

namespace Sentinel.Server.Auth;

/// <summary>
/// Agents authenticate with <c>Authorization: Bearer {hostId}.{secret}</c>. SignalR WebSocket and SSE
/// connections send the same value as <c>?access_token=</c>. The server stores only the secret's hash.
/// </summary>
public sealed class AgentAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    SentinelDbContext db) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string HostIdClaim = "sentinel:host";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? credential = null;
        var header = Request.Headers.Authorization.ToString();
        if (header.StartsWith("Bearer ", StringComparison.Ordinal)) credential = header["Bearer ".Length..].Trim();
        else if (Request.Path.StartsWithSegments("/hubs/agent")) credential = Request.Query["access_token"];
        if (string.IsNullOrEmpty(credential)) return AuthenticateResult.NoResult();

        var dot = credential.IndexOf('.');
        if (dot <= 0 || !Guid.TryParse(credential[..dot], out var hostId)) return AuthenticateResult.Fail("Malformed agent credential");

        var host = await db.Hosts.AsNoTracking()
            .Where(h => h.Id == hostId)
            .Select(h => new { h.Id, h.SecretHash, h.Name })
            .FirstOrDefaultAsync(Context.RequestAborted);
        if (host is null || !Secrets.FixedTimeEquals(host.SecretHash, Secrets.Hash(credential[(dot + 1)..])))
            return AuthenticateResult.Fail("Unknown agent or bad secret");

        var identity = new ClaimsIdentity(
        [
            new Claim(HostIdClaim, host.Id.ToString()),
            new Claim(ClaimTypes.Name, host.Name),
            new Claim(ClaimTypes.Role, Roles.Agent),
        ], Scheme.Name);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }
}

/// <summary>Read-only API keys: <c>X-Api-Key: svk_...</c>. They can call every GET endpoint the dashboard uses, and nothing else.</summary>
public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    SentinelDbContext db,
    TimeProvider time) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string HeaderName = "X-Api-Key";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var key = Request.Headers[HeaderName].ToString();
        if (string.IsNullOrEmpty(key)) return AuthenticateResult.NoResult();
        var hash = Secrets.Hash(key);
        var apiKey = await db.ApiKeys.FirstOrDefaultAsync(k => k.KeyHash == hash && k.RevokedAt == null, Context.RequestAborted);
        if (apiKey is null) return AuthenticateResult.Fail("Invalid API key");

        var now = time.GetUtcNow().UtcDateTime;
        if (apiKey.LastUsedAt is null || now - apiKey.LastUsedAt > TimeSpan.FromMinutes(5))
        {
            apiKey.LastUsedAt = now;
            await db.SaveChangesAsync(Context.RequestAborted);
        }

        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, $"apikey:{apiKey.Name}"),
            new Claim(ClaimTypes.Role, Roles.Reader),
        ], Scheme.Name);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }
}
