using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Alastor.Server.Auth;
using Alastor.Server.Data;

namespace Alastor.Server.Endpoints;

public static class AuthEndpoints
{
    public sealed record LoginRequest(string Username, string Password);
    public sealed record SecondFactorRequest(string? Code, string? RecoveryCode);
    public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
    public sealed record MeResponse(string Username, string Role, bool ReadOnly, bool TwoFactor = false);
    public sealed record LoginResponse(string? Username, string? Role, bool ReadOnly, bool TwoFactorRequired);
    public sealed record SessionDto(Guid Id, DateTime CreatedAt, DateTime LastSeenAt, DateTime ExpiresAt, string? Address, string? UserAgent, bool Current);
    public sealed record TwoFactorSetup(string Secret, string Uri);
    public sealed record TwoFactorEnableRequest(string Code);
    public sealed record TwoFactorDisableRequest(string Password, string Code);

    /// <summary>Consecutive failures before an account locks. The lock starts at a minute and doubles, up to an hour.</summary>
    public const int LockoutThreshold = 5;
    public static readonly TimeSpan MaxLockout = TimeSpan.FromHours(1);

    private const string PendingCookie = "alastor_2fa";
    private const string TotpPurpose = "alastor.totp";
    private const string PendingPurpose = "alastor.2fa-pending";
    private static readonly TimeSpan PendingLifetime = TimeSpan.FromMinutes(5);

    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/auth").WithTags("Auth");

        g.MapPost("/login", async (LoginRequest req, AlastorDbContext db, SessionService sessions, IDataProtectionProvider dp,
            IOptions<AlastorOptions> opt, HttpContext http, TimeProvider time, CancellationToken ct) =>
        {
            var now = time.GetUtcNow().UtcDateTime;
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == req.Username, ct);
            var hasher = new PasswordHasher<User>();
            var locked = user?.LockedUntil > now;
            // Verify against a dummy hash when the user doesn't exist or is locked, so response timing reveals neither.
            var result = hasher.VerifyHashedPassword(locked ? DummyUser : user ?? DummyUser,
                locked ? DummyUser.PasswordHash : user?.PasswordHash ?? DummyUser.PasswordHash, req.Password ?? "");
            if (user is null || locked || result == PasswordVerificationResult.Failed)
            {
                if (user is not null && !locked) await FailedAsync(db, user, http, now, ct);
                return Results.Problem("Invalid username or password.", statusCode: StatusCodes.Status401Unauthorized);
            }
            if (result == PasswordVerificationResult.SuccessRehashNeeded) user.PasswordHash = hasher.HashPassword(user, req.Password!);

            if (user.TotpEnabledAt is not null)
            {
                await db.SaveChangesAsync(ct);
                var ticket = dp.CreateProtector(PendingPurpose).ToTimeLimitedDataProtector().Protect(user.Id.ToString(), PendingLifetime);
                http.Response.Cookies.Append(PendingCookie, ticket, new CookieOptions
                {
                    HttpOnly = true, Secure = opt.Value.SecureCookies, SameSite = SameSiteMode.Strict, Path = "/api/auth", MaxAge = PendingLifetime,
                });
                return Results.Ok(new LoginResponse(null, null, false, true));
            }

            await SucceededAsync(db, sessions, user, http, now, "password", ct);
            return Results.Ok(new LoginResponse(user.Username, Roles.Admin, false, false));
        }).AllowAnonymous().RequireRateLimiting("auth");

        // Second step for users with two-factor sign-in: a code from the authenticator app, or a recovery code.
        g.MapPost("/login/2fa", async (SecondFactorRequest req, AlastorDbContext db, SessionService sessions, IDataProtectionProvider dp,
            HttpContext http, TimeProvider time, CancellationToken ct) =>
        {
            var now = time.GetUtcNow().UtcDateTime;
            Guid userId;
            try
            {
                var ticket = http.Request.Cookies[PendingCookie] ?? throw new System.Security.Cryptography.CryptographicException();
                userId = Guid.Parse(dp.CreateProtector(PendingPurpose).ToTimeLimitedDataProtector().Unprotect(ticket));
            }
            catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or FormatException)
            {
                return Results.Problem("Sign in again: the sign-in took too long.", statusCode: StatusCodes.Status401Unauthorized);
            }
            var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
            if (user?.TotpEnabledAt is null || user.TotpSecret is null || user.LockedUntil > now)
                return Results.Problem("Invalid code.", statusCode: StatusCodes.Status401Unauthorized);

            string method;
            if (!string.IsNullOrWhiteSpace(req.RecoveryCode))
            {
                var hash = Totp.HashRecoveryCode(req.RecoveryCode);
                if (!user.RecoveryCodeHashes.Contains(hash))
                {
                    await FailedAsync(db, user, http, now, ct);
                    return Results.Problem("Invalid code.", statusCode: StatusCodes.Status401Unauthorized);
                }
                user.RecoveryCodeHashes = user.RecoveryCodeHashes.Where(h => h != hash).ToList();
                method = "recovery code";
            }
            else
            {
                var step = Totp.Verify(Secret(dp, user), req.Code, time.GetUtcNow(), user.TotpLastStep);
                if (step is null)
                {
                    await FailedAsync(db, user, http, now, ct);
                    return Results.Problem("Invalid code.", statusCode: StatusCodes.Status401Unauthorized);
                }
                user.TotpLastStep = step.Value;
                method = "password + authenticator";
            }
            http.Response.Cookies.Delete(PendingCookie, new CookieOptions { Path = "/api/auth" });
            await SucceededAsync(db, sessions, user, http, now, method, ct);
            return Results.Ok(new MeResponse(user.Username, Roles.Admin, false, true));
        }).AllowAnonymous().RequireRateLimiting("auth");

        g.MapPost("/logout", async (ClaimsPrincipal principal, AlastorDbContext db, SessionService sessions, HttpContext http, CancellationToken ct) =>
        {
            if (SessionService.CurrentId(principal) is { } id) await sessions.RevokeAsync(db, [id], ct);
            http.Response.Cookies.Delete(JwtIssuer.CookieName, new CookieOptions { Path = "/" });
            return Results.NoContent();
        }).AllowAnonymous();

        g.MapGet("/me", async (ClaimsPrincipal user, AlastorDbContext db, CancellationToken ct) =>
        {
            var admin = user.IsInRole(Roles.Admin);
            var name = user.Actor();
            var twoFactor = admin && await db.Users.AnyAsync(u => u.Username == name && u.TotpEnabledAt != null, ct);
            return new MeResponse(name, admin ? Roles.Admin : Roles.Reader, !admin, twoFactor);
        }).RequireAuthorization(AuthPolicies.Reader);

        g.MapPost("/password", async (ChangePasswordRequest req, ClaimsPrincipal principal, AlastorDbContext db, SessionService sessions, TimeProvider time, CancellationToken ct) =>
        {
            if (req.NewPassword is not { Length: >= 12 })
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["newPassword"] = ["Use at least 12 characters."] });
            var user = await db.Users.FirstAsync(u => u.Username == principal.Actor(), ct);
            var hasher = new PasswordHasher<User>();
            if (hasher.VerifyHashedPassword(user, user.PasswordHash, req.CurrentPassword) == PasswordVerificationResult.Failed)
                return Results.Problem("Current password is wrong.", statusCode: StatusCodes.Status400BadRequest);
            user.PasswordHash = hasher.HashPassword(user, req.NewPassword);
            user.PasswordChangedAt = time.GetUtcNow().UtcDateTime;
            db.Audit.Add(new AuditEntry { Actor = user.Username, Action = "auth.password-changed" });
            await db.SaveChangesAsync(ct);
            // Whoever knew the old password may hold a session: end every other one.
            await sessions.RevokeAllAsync(db, user.Id, SessionService.CurrentId(principal), ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);

        g.MapGet("/sessions", async (ClaimsPrincipal principal, AlastorDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var user = await db.Users.FirstAsync(u => u.Username == principal.Actor(), ct);
            var now = time.GetUtcNow().UtcDateTime;
            var current = SessionService.CurrentId(principal);
            var rows = await db.Sessions.Where(s => s.UserId == user.Id && s.RevokedAt == null && s.ExpiresAt > now).ToListAsync(ct);
            return rows.OrderByDescending(s => s.LastSeenAt)
                .Select(s => new SessionDto(s.Id, s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.Address, s.UserAgent, s.Id == current)).ToList();
        }).RequireAuthorization(AuthPolicies.Admin);

        g.MapDelete("/sessions/{id:guid}", async (Guid id, ClaimsPrincipal principal, AlastorDbContext db, SessionService sessions, CancellationToken ct) =>
        {
            var user = await db.Users.FirstAsync(u => u.Username == principal.Actor(), ct);
            if (!await db.Sessions.AnyAsync(s => s.Id == id && s.UserId == user.Id, ct)) return Results.NotFound();
            await sessions.RevokeAsync(db, [id], ct);
            db.Audit.Add(new AuditEntry { Actor = user.Username, Action = "auth.session-revoked", Target = id.ToString() });
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);

        // ---- optional two-factor sign-in (TOTP) ----

        g.MapPost("/2fa/setup", async (ClaimsPrincipal principal, AlastorDbContext db, IDataProtectionProvider dp, CancellationToken ct) =>
        {
            var user = await db.Users.FirstAsync(u => u.Username == principal.Actor(), ct);
            if (user.TotpEnabledAt is not null) return Results.Conflict(new { error = "Two-factor sign-in is already on. Turn it off first to use a new authenticator." });
            var key = Totp.NewSecret();
            user.TotpSecret = dp.CreateProtector(TotpPurpose).Protect(Totp.Base32(key));
            await db.SaveChangesAsync(ct);
            return Results.Ok(new TwoFactorSetup(Totp.Base32(key), Totp.ProvisioningUri("Alastor", user.Username, key)));
        }).RequireAuthorization(AuthPolicies.Admin);

        g.MapPost("/2fa/enable", async (TwoFactorEnableRequest req, ClaimsPrincipal principal, AlastorDbContext db, IDataProtectionProvider dp,
            SessionService sessions, TimeProvider time, CancellationToken ct) =>
        {
            var user = await db.Users.FirstAsync(u => u.Username == principal.Actor(), ct);
            if (user.TotpEnabledAt is not null) return Results.Conflict(new { error = "Two-factor sign-in is already on." });
            if (user.TotpSecret is null) return Results.BadRequest(new { error = "Start the setup first." });
            var step = Totp.Verify(Secret(dp, user), req.Code, time.GetUtcNow(), 0);
            if (step is null) return Results.BadRequest(new { error = "That code doesn't match. Check the time on your phone and try the next code." });
            var codes = Totp.NewRecoveryCodes();
            user.TotpLastStep = step.Value;
            user.TotpEnabledAt = time.GetUtcNow().UtcDateTime;
            user.RecoveryCodeHashes = codes.Select(Totp.HashRecoveryCode).ToList();
            db.Audit.Add(new AuditEntry { Actor = user.Username, Action = "auth.2fa-enabled" });
            await db.SaveChangesAsync(ct);
            await sessions.RevokeAllAsync(db, user.Id, SessionService.CurrentId(principal), ct);
            return Results.Ok(new { recoveryCodes = codes });
        }).RequireAuthorization(AuthPolicies.Admin);

        g.MapPost("/2fa/disable", async (TwoFactorDisableRequest req, ClaimsPrincipal principal, AlastorDbContext db, IDataProtectionProvider dp,
            TimeProvider time, CancellationToken ct) =>
        {
            var user = await db.Users.FirstAsync(u => u.Username == principal.Actor(), ct);
            if (user.TotpEnabledAt is null || user.TotpSecret is null) return Results.NoContent();
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, req.Password ?? "") == PasswordVerificationResult.Failed)
                return Results.BadRequest(new { error = "Password is wrong." });
            var byCode = Totp.Verify(Secret(dp, user), req.Code, time.GetUtcNow(), user.TotpLastStep) is not null;
            var byRecovery = user.RecoveryCodeHashes.Contains(Totp.HashRecoveryCode(req.Code ?? ""));
            if (!byCode && !byRecovery) return Results.BadRequest(new { error = "Enter a current code from your authenticator, or a recovery code." });
            user.TotpSecret = null;
            user.TotpEnabledAt = null;
            user.TotpLastStep = 0;
            user.RecoveryCodeHashes = [];
            db.Audit.Add(new AuditEntry { Actor = user.Username, Action = "auth.2fa-disabled" });
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);
    }

    private static byte[] Secret(IDataProtectionProvider dp, User user) =>
        Totp.FromBase32(dp.CreateProtector(TotpPurpose).Unprotect(user.TotpSecret!));

    private static async Task FailedAsync(AlastorDbContext db, User user, HttpContext http, DateTime now, CancellationToken ct)
    {
        user.FailedLogins++;
        if (user.FailedLogins >= LockoutThreshold)
        {
            var minutes = Math.Min(Math.Pow(2, user.FailedLogins - LockoutThreshold), MaxLockout.TotalMinutes);
            user.LockedUntil = now + TimeSpan.FromMinutes(minutes);
            db.Audit.Add(new AuditEntry
            {
                Actor = user.Username, Action = "auth.locked",
                Details = $"{user.FailedLogins} failed sign-ins, last from {http.Connection.RemoteIpAddress}; locked for {minutes:0} min",
            });
        }
        await db.SaveChangesAsync(ct);
    }

    private static async Task SucceededAsync(AlastorDbContext db, SessionService sessions, User user, HttpContext http, DateTime now, string method, CancellationToken ct)
    {
        user.FailedLogins = 0;
        user.LockedUntil = null;
        user.LastLoginAt = now;
        db.Audit.Add(new AuditEntry { Actor = user.Username, Action = "auth.login", Details = $"{http.Connection.RemoteIpAddress} ({method})" });
        await sessions.SignInAsync(db, user, http, ct);
    }

    private static readonly User DummyUser = CreateDummy();

    private static User CreateDummy()
    {
        var u = new User { Username = "\0", PasswordHash = "" };
        u.PasswordHash = new PasswordHasher<User>().HashPassword(u, Guid.NewGuid().ToString());
        return u;
    }
}
