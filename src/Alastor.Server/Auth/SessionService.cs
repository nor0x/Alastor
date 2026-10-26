using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Alastor.Server.Data;

namespace Alastor.Server.Auth;

/// <summary>
/// Dashboard sessions: each sign-in gets a <see cref="UserSession"/> row whose id is the JWT's <c>jti</c>, so a session
/// can be revoked (sign-out, password change, "sign out other browsers") before its token expires. Lookups are cached
/// for 30 seconds; revocations through this service take effect at once.
/// </summary>
public sealed class SessionService(IServiceScopeFactory scopes, IMemoryCache cache, JwtIssuer jwt, IOptions<AlastorOptions> options, TimeProvider time)
{
    public const string SessionClaim = "jti";
    private static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan TouchEvery = TimeSpan.FromMinutes(5);

    /// <summary>Records the session and sets the cookie.</summary>
    public async Task SignInAsync(AlastorDbContext db, User user, HttpContext http, CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var session = new UserSession
        {
            UserId = user.Id,
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = now + jwt.Lifetime,
            Address = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = Clip(http.Request.Headers.UserAgent.ToString(), 256),
        };
        db.Sessions.Add(session);
        await db.SaveChangesAsync(ct);
        http.Response.Cookies.Append(JwtIssuer.CookieName, jwt.Issue(user.Id, user.Username, session.Id), new CookieOptions
        {
            HttpOnly = true,
            Secure = options.Value.SecureCookies,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            MaxAge = jwt.Lifetime,
        });
    }

    /// <summary>True while the session exists, isn't revoked and hasn't expired. Called for every cookie-authenticated request.</summary>
    public async Task<bool> IsActiveAsync(Guid id, CancellationToken ct)
    {
        if (cache.TryGetValue(Key(id), out bool active)) return active;
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AlastorDbContext>();
        var now = time.GetUtcNow().UtcDateTime;
        var s = await db.Sessions.FirstOrDefaultAsync(x => x.Id == id, ct);
        active = s is not null && s.RevokedAt is null && s.ExpiresAt > now;
        if (active && now - s!.LastSeenAt > TouchEvery)
        {
            s.LastSeenAt = now;
            await db.SaveChangesAsync(ct);
        }
        cache.Set(Key(id), active, CacheFor);
        return active;
    }

    public async Task RevokeAsync(AlastorDbContext db, IEnumerable<Guid> ids, CancellationToken ct)
    {
        var list = ids.ToList();
        if (list.Count == 0) return;
        var now = time.GetUtcNow().UtcDateTime;
        await db.Sessions.Where(s => list.Contains(s.Id) && s.RevokedAt == null).ExecuteUpdateAsync(u => u.SetProperty(s => s.RevokedAt, now), ct);
        foreach (var id in list) cache.Remove(Key(id));
    }

    /// <summary>Revokes every live session of a user, except <paramref name="keep"/>.</summary>
    public async Task RevokeAllAsync(AlastorDbContext db, Guid userId, Guid? keep, CancellationToken ct)
    {
        var ids = await db.Sessions.Where(s => s.UserId == userId && s.RevokedAt == null && s.Id != keep).Select(s => s.Id).ToListAsync(ct);
        await RevokeAsync(db, ids, ct);
    }

    public static Guid? CurrentId(System.Security.Claims.ClaimsPrincipal user) =>
        Guid.TryParse(user.FindFirst(SessionClaim)?.Value, out var id) ? id : null;

    private static string Key(Guid id) => "session:" + id;
    private static string? Clip(string? s, int max) => string.IsNullOrEmpty(s) ? null : s.Length <= max ? s : s[..max];
}
