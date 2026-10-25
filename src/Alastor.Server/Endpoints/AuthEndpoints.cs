using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Alastor.Server.Auth;
using Alastor.Server.Data;

namespace Alastor.Server.Endpoints;

public static class AuthEndpoints
{
    public sealed record LoginRequest(string Username, string Password);
    public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
    public sealed record MeResponse(string Username, string Role, bool ReadOnly);

    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/auth").WithTags("Auth");

        g.MapPost("/login", async (LoginRequest req, AlastorDbContext db, JwtIssuer jwt, IOptions<AlastorOptions> opt, HttpContext http, TimeProvider time) =>
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == req.Username);
            var hasher = new PasswordHasher<User>();
            // Verify against a dummy hash when the user doesn't exist, so response timing doesn't reveal valid usernames.
            var result = hasher.VerifyHashedPassword(user ?? DummyUser, user?.PasswordHash ?? DummyUser.PasswordHash, req.Password ?? "");
            if (user is null || result == PasswordVerificationResult.Failed)
                return Results.Problem("Invalid username or password.", statusCode: StatusCodes.Status401Unauthorized);
            if (result == PasswordVerificationResult.SuccessRehashNeeded) user.PasswordHash = hasher.HashPassword(user, req.Password!);
            user.LastLoginAt = time.GetUtcNow().UtcDateTime;
            db.Audit.Add(new AuditEntry { Actor = user.Username, Action = "auth.login", Details = http.Connection.RemoteIpAddress?.ToString() });
            await db.SaveChangesAsync();

            http.Response.Cookies.Append(JwtIssuer.CookieName, jwt.Issue(user.Id, user.Username), new CookieOptions
            {
                HttpOnly = true,
                Secure = opt.Value.SecureCookies,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                MaxAge = jwt.Lifetime,
            });
            return Results.Ok(new MeResponse(user.Username, Roles.Admin, false));
        }).AllowAnonymous().RequireRateLimiting("auth");

        g.MapPost("/logout", (HttpContext http) =>
        {
            http.Response.Cookies.Delete(JwtIssuer.CookieName, new CookieOptions { Path = "/" });
            return Results.NoContent();
        }).AllowAnonymous();

        g.MapGet("/me", (ClaimsPrincipal user) =>
        {
            var admin = user.IsInRole(Roles.Admin);
            return new MeResponse(user.Actor(), admin ? Roles.Admin : Roles.Reader, !admin);
        }).RequireAuthorization(AuthPolicies.Reader);

        g.MapPost("/password", async (ChangePasswordRequest req, ClaimsPrincipal principal, AlastorDbContext db) =>
        {
            if (req.NewPassword is not { Length: >= 12 })
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["newPassword"] = ["Use at least 12 characters."] });
            var user = await db.Users.FirstAsync(u => u.Username == principal.Actor());
            var hasher = new PasswordHasher<User>();
            if (hasher.VerifyHashedPassword(user, user.PasswordHash, req.CurrentPassword) == PasswordVerificationResult.Failed)
                return Results.Problem("Current password is wrong.", statusCode: StatusCodes.Status400BadRequest);
            user.PasswordHash = hasher.HashPassword(user, req.NewPassword);
            db.Audit.Add(new AuditEntry { Actor = user.Username, Action = "auth.password-changed" });
            await db.SaveChangesAsync();
            return Results.NoContent();
        }).RequireAuthorization(AuthPolicies.Admin);
    }

    private static readonly User DummyUser = CreateDummy();

    private static User CreateDummy()
    {
        var u = new User { Username = "\0", PasswordHash = "" };
        u.PasswordHash = new PasswordHasher<User>().HashPassword(u, Guid.NewGuid().ToString());
        return u;
    }
}
