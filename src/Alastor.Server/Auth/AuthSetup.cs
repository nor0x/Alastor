using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace Alastor.Server.Auth;

public static class AuthSchemes
{
    public const string Session = "Session";   // JWT in httpOnly cookie (dashboard users)
    public const string ApiKey = "ApiKey";     // X-Api-Key header (read-only integrations)
    public const string Agent = "Agent";       // Bearer {agentId}.{secret}
    public const string Dashboard = "Dashboard"; // policy scheme: ApiKey if header present, else Session
}

public static class AuthPolicies
{
    /// <summary>Read access: a signed-in user or a read-only API key.</summary>
    public const string Reader = "Reader";

    /// <summary>Write access: signed-in users only, never API keys.</summary>
    public const string Admin = "Admin";

    public const string Agent = "Agent";
}

public static class Roles
{
    public const string Admin = "admin";
    public const string Reader = "reader";
    public const string Agent = "agent";
}

public sealed class JwtIssuer(byte[] key, TimeSpan lifetime)
{
    public const string CookieName = "alastor_session";
    public TimeSpan Lifetime { get; } = lifetime;
    public SymmetricSecurityKey SigningKey { get; } = new(key);

    public string Issue(Guid userId, string username)
    {
        var token = new JwtSecurityToken(
            issuer: "alastor",
            audience: "alastor-dashboard",
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, username),
                new Claim(ClaimTypes.Role, Roles.Admin),
            ],
            expires: DateTime.UtcNow.Add(Lifetime),
            signingCredentials: new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>Loads the signing key from ALASTOR_JWTKEY (base64), or generates one and stores it in the data dir with mode 0600.</summary>
    public static byte[] LoadOrCreateKey(string dataDir, string? configured)
    {
        if (!string.IsNullOrEmpty(configured)) return Convert.FromBase64String(configured);
        var path = Path.Combine(dataDir, "jwt.key");
        if (File.Exists(path)) return Convert.FromBase64String(File.ReadAllText(path).Trim());
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(64);
        File.WriteAllText(path, Convert.ToBase64String(key));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return key;
    }
}

public static class AuthSetup
{
    public static IServiceCollection AddAlastorAuth(this IServiceCollection services, JwtIssuer issuer)
    {
        services.AddSingleton(issuer);
        JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

        services.AddAuthentication(AuthSchemes.Dashboard)
            .AddPolicyScheme(AuthSchemes.Dashboard, "Session or API key", o =>
            {
                o.ForwardDefaultSelector = ctx => ctx.Request.Headers.ContainsKey(ApiKeyAuthenticationHandler.HeaderName)
                    ? AuthSchemes.ApiKey
                    : AuthSchemes.Session;
            })
            .AddJwtBearer(AuthSchemes.Session, o =>
            {
                o.MapInboundClaims = false;
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = "alastor",
                    ValidAudience = "alastor-dashboard",
                    IssuerSigningKey = issuer.SigningKey,
                    ValidateIssuerSigningKey = true,
                    NameClaimType = JwtRegisteredClaimNames.UniqueName,
                    RoleClaimType = ClaimTypes.Role,
                    ClockSkew = TimeSpan.FromMinutes(1),
                };
                o.Events = new JwtBearerEvents
                {
                    // The token lives in an httpOnly cookie, never in JS-accessible storage.
                    OnMessageReceived = ctx =>
                    {
                        ctx.Token = ctx.Request.Cookies[JwtIssuer.CookieName];
                        return Task.CompletedTask;
                    },
                };
            })
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(AuthSchemes.ApiKey, null)
            .AddScheme<AuthenticationSchemeOptions, AgentAuthenticationHandler>(AuthSchemes.Agent, null);

        services.AddAuthorizationBuilder()
            .AddPolicy(AuthPolicies.Reader, p => p
                .AddAuthenticationSchemes(AuthSchemes.Dashboard)
                .RequireAuthenticatedUser()
                .RequireRole(Roles.Admin, Roles.Reader))
            .AddPolicy(AuthPolicies.Admin, p => p
                // API keys authenticate here too but only carry the reader role, so writes get 403 instead of 401.
                .AddAuthenticationSchemes(AuthSchemes.Dashboard)
                .RequireAuthenticatedUser()
                .RequireRole(Roles.Admin))
            .AddPolicy(AuthPolicies.Agent, p => p
                .AddAuthenticationSchemes(AuthSchemes.Agent)
                .RequireAuthenticatedUser()
                .RequireRole(Roles.Agent));
        return services;
    }

    public static string Actor(this ClaimsPrincipal user) =>
        user.FindFirstValue(JwtRegisteredClaimNames.UniqueName) ?? user.Identity?.Name ?? "unknown";

    public static Guid HostId(this ClaimsPrincipal user) =>
        Guid.Parse(user.FindFirstValue(AgentAuthenticationHandler.HostIdClaim)!);

    /// <summary>
    /// CSRF protection on top of SameSite=Strict: a state-changing request authenticated by cookie must carry
    /// a custom header, which a cross-site form post cannot add without a CORS preflight.
    /// </summary>
    public static IApplicationBuilder UseCsrfHeaderCheck(this IApplicationBuilder app) => app.Use(async (ctx, next) =>
    {
        var req = ctx.Request;
        var unsafeMethod = !(HttpMethods.IsGet(req.Method) || HttpMethods.IsHead(req.Method) || HttpMethods.IsOptions(req.Method));
        if (unsafeMethod && req.Path.StartsWithSegments("/api") && !req.Path.StartsWithSegments("/api/agent")
            && req.Cookies.ContainsKey(JwtIssuer.CookieName) && !req.Headers.ContainsKey("X-Alastor-Request"))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsJsonAsync(new { error = "Missing X-Alastor-Request header." });
            return;
        }
        await next();
    });
}


