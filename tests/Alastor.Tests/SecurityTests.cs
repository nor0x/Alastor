using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Alastor.Server;
using Alastor.Server.Auth;
using Alastor.Server.Services.Security;

namespace Alastor.Tests;

public sealed class TotpTests
{
    // RFC 6238 appendix B, SHA-1 key "12345678901234567890"; the RFC lists 8 digits, authenticators use the last 6.
    [Theory]
    [InlineData(59L, "287082")]
    [InlineData(1111111109L, "081804")]
    [InlineData(1111111111L, "050471")]
    [InlineData(1234567890L, "005924")]
    [InlineData(2000000000L, "279037")]
    public void Codes_match_the_rfc_vectors(long unixTime, string expected)
    {
        var key = "12345678901234567890"u8.ToArray();
        Assert.Equal(expected, Totp.Code(key, unixTime / Totp.StepSeconds));
    }

    [Fact]
    public void A_code_is_accepted_once_and_within_one_step()
    {
        var key = Totp.NewSecret();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var step = Totp.StepAt(now);
        Assert.Equal(step, Totp.Verify(key, Totp.Code(key, step), now, 0));
        Assert.Equal(step - 1, Totp.Verify(key, Totp.Code(key, step - 1), now, 0));
        Assert.Null(Totp.Verify(key, Totp.Code(key, step - 2), now, 0));
        Assert.Null(Totp.Verify(key, Totp.Code(key, step), now, step)); // replay
        Assert.Equal(step, Totp.Verify(key, Totp.Code(key, step)[..3] + " " + Totp.Code(key, step)[3..], now, 0)); // spaces are fine
        Assert.Null(Totp.Verify(key, "12345", now, 0));
    }

    [Fact]
    public void Base32_round_trips_and_recovery_codes_hash_loosely()
    {
        var key = Totp.NewSecret();
        Assert.Equal(key, Totp.FromBase32(Totp.Base32(key)));
        var codes = Totp.NewRecoveryCodes();
        Assert.Equal(10, codes.Distinct().Count());
        Assert.All(codes, c => Assert.Matches("^[a-z2-7]{5}-[a-z2-7]{5}$", c));
        Assert.Equal(Totp.HashRecoveryCode(codes[0]), Totp.HashRecoveryCode(codes[0].ToUpperInvariant().Replace("-", " ")));
        Assert.StartsWith("otpauth://totp/Alastor:admin?secret=", Totp.ProvisioningUri("Alastor", "admin", key));
    }
}

public sealed class NetworkAllowListTests
{
    [Theory]
    [InlineData("loopback,tailnet", "127.0.0.1", true)]
    [InlineData("loopback,tailnet", "::1", true)]
    [InlineData("loopback,tailnet", "100.101.102.103", true)]
    [InlineData("loopback,tailnet", "fd7a:115c:a1e0::5", true)]
    [InlineData("loopback,tailnet", "192.168.1.5", false)]
    [InlineData("loopback,tailnet", "203.0.113.9", false)]
    [InlineData("private", "10.1.2.3", true)]
    [InlineData("private", "::ffff:172.16.0.4", true)]
    [InlineData("loopback, 198.51.100.0/24", "198.51.100.77", true)]
    [InlineData("any", "203.0.113.9", true)]
    public void Matches_keywords_and_cidrs(string list, string address, bool allowed) =>
        Assert.Equal(allowed, NetworkAllowList.Parse(list).Allows(IPAddress.Parse(address)));

    [Fact]
    public void Rejects_unknown_entries_and_reports_public_reach()
    {
        Assert.False(NetworkAllowList.TryParse("loopback,office", out _, out var error));
        Assert.Contains("office", error);
        Assert.False(NetworkAllowList.TryParse("  ", out _, out _));
        Assert.True(NetworkAllowList.Parse("any").AllowsPublic);
        Assert.True(NetworkAllowList.Parse("loopback,0.0.0.0/0").AllowsPublic);
        Assert.True(NetworkAllowList.Parse("198.51.100.0/24").AllowsPublic);
        Assert.False(NetworkAllowList.Parse("loopback,private,tailnet,10.8.0.0/16").AllowsPublic);
        Assert.True(NetworkAllowList.Parse("loopback").Allows(null)); // no IP: in-process or Unix socket
    }

    [Fact]
    public void Options_validation_names_the_bad_setting()
    {
        var errors = new AlastorOptions { AgentAllowFrom = "tailnet,somewhere" }.Validate();
        Assert.Contains(errors, e => e.StartsWith("AgentAllowFrom="));
    }
}

public sealed class SelfCheckTests
{
    private static SelfCheckInputs Inputs(AlastorOptions o, string[] urls, string[]? nics = null, bool root = false, UnixFileMode? dataDir = null) =>
        new(urls, nics ?? ["127.0.0.1", "203.0.113.10", "100.90.1.2"], o, root, dataDir, null);

    private static SelfCheck Get(List<SelfCheck> checks, string id) => checks.Single(c => c.Id == id);

    [Fact]
    public void Tailnet_install_passes()
    {
        var o = new AlastorOptions { PublicUrl = "http://100.90.1.2:8080", DashboardAllowFrom = "loopback,tailnet", AgentAllowFrom = "loopback,tailnet" };
        var checks = SelfChecks.Static(Inputs(o, ["http://100.90.1.2:8080"], dataDir: (UnixFileMode)0b111_000_000));
        Assert.All(checks, c => Assert.Equal(CheckStatus.Pass, c.Status));
    }

    [Fact]
    public void Public_plain_http_install_fails()
    {
        var o = new AlastorOptions { PublicUrl = "http://203.0.113.10:8080", DashboardAllowFrom = "any", AgentAllowFrom = "any" };
        var checks = SelfChecks.Static(Inputs(o, ["http://0.0.0.0:8080"], root: true, dataDir: (UnixFileMode)0b111_101_101));
        Assert.Equal(CheckStatus.Fail, Get(checks, "listen").Status);
        Assert.Contains("203.0.113.10", Get(checks, "listen").Detail);
        Assert.Equal(CheckStatus.Fail, Get(checks, "tls").Status);
        Assert.Equal(CheckStatus.Fail, Get(checks, "dashboard-access").Status);
        Assert.Equal(CheckStatus.Warn, Get(checks, "agent-access").Status);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(CheckStatus.Warn, Get(checks, "user").Status);
            Assert.Equal(CheckStatus.Fail, Get(checks, "permissions").Status);
        }
    }

    [Fact]
    public void Https_domain_behind_caddy_warns_about_internet_facing_dashboard()
    {
        var o = new AlastorOptions { PublicUrl = "https://alastor.example.com", DashboardAllowFrom = "any", AgentAllowFrom = "any" };
        var checks = SelfChecks.Static(Inputs(o, ["http://127.0.0.1:8080"]));
        Assert.Equal(CheckStatus.Pass, Get(checks, "listen").Status);
        Assert.Equal(CheckStatus.Pass, Get(checks, "tls").Status);
        Assert.Equal(CheckStatus.Warn, Get(checks, "dashboard-access").Status);
    }

    [Fact]
    public void Wildcard_without_public_nic_still_warns_about_nat()
    {
        var o = new AlastorOptions { PublicUrl = "http://10.0.0.5:8080" };
        var checks = SelfChecks.Static(Inputs(o, ["http://+:8080", "http://[::]:8080"], nics: ["127.0.0.1", "10.0.0.5"]));
        Assert.Equal(CheckStatus.Warn, Get(checks, "listen").Status);
    }
}

/// <summary>Sign-in hardening, sessions and two-factor sign-in, end to end against the real server.</summary>
[Collection(ServerHostCollection.Name)]
public sealed class AuthSecurityTests : IClassFixture<AuthSecurityTests.Factory>
{
    public sealed class Factory : WebApplicationFactory<Program>
    {
        public string DataDir { get; } = Path.Combine(Path.GetTempPath(), "alastor-test-" + Guid.NewGuid().ToString("N"));

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("DataDir", DataDir);
            builder.UseSetting("AdminPassword", "test-password-123");
            builder.UseSetting("SecureCookies", "false");
            builder.UseSetting("ThreatFeedEnabled", "false");
            builder.UseSetting("OsvEnabled", "false");
            builder.UseSetting("BlocklistsEnabled", "false");
            builder.UseSetting("VulnDbEnabled", "false");
            builder.UseSetting("AuthRateLimitPerMinute", "1000");
            builder.UseSetting("DashboardAllowFrom", "loopback,tailnet");
            builder.UseSetting("AgentAllowFrom", "loopback,10.0.0.0/8");
            // The test host has no client addresses: take one from a header, ahead of the app's own middleware.
            builder.ConfigureServices(s => s.AddTransient<IStartupFilter, TestRemoteAddress>());
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try { Directory.Delete(DataDir, true); } catch (IOException) { }
        }
    }

    private sealed class TestRemoteAddress : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (ctx, n) =>
            {
                if (ctx.Request.Headers.TryGetValue("X-Test-Remote", out var v)) ctx.Connection.RemoteIpAddress = IPAddress.Parse(v.ToString());
                await n();
            });
            next(app);
        };
    }

    private readonly Factory _factory;
    public AuthSecurityTests(Factory factory) => _factory = factory;

    private HttpClient Client()
    {
        var c = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        c.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        return c;
    }

    private async Task<HttpClient> SignInAsync(string password = "test-password-123")
    {
        var c = Client();
        var r = await c.PostAsJsonAsync("/api/auth/login", new { username = "admin", password });
        r.EnsureSuccessStatusCode();
        return c;
    }

    [Fact]
    public async Task Requests_from_outside_the_allowlists_get_404_before_auth()
    {
        var c = Client();
        HttpRequestMessage From(string ip, string path) { var m = new HttpRequestMessage(HttpMethod.Get, path); m.Headers.Add("X-Test-Remote", ip); return m; }

        Assert.Equal(HttpStatusCode.NotFound, (await c.SendAsync(From("203.0.113.9", "/api/hosts"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.SendAsync(From("203.0.113.9", "/"))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.SendAsync(From("100.64.1.1", "/api/hosts"))).StatusCode);
        // Agents have their own list: a private 10.x address may enroll but not see the dashboard.
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(From("10.2.3.4", "/install/agent.sh"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.SendAsync(From("10.2.3.4", "/api/hosts"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.SendAsync(From("100.64.1.1", "/api/agent/desired-state"))).StatusCode);

        var page = await c.SendAsync(From("127.0.0.1", "/"));
        Assert.Contains("frame-ancestors 'none'", page.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("nosniff", page.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task OpenApi_and_version_need_a_sign_in()
    {
        var anon = Client();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/openapi/v1.json")).StatusCode);
        var about = await anon.GetFromJsonAsync<JsonElement>("/api/about");
        Assert.Equal(JsonValueKind.Null, about.GetProperty("version").ValueKind);
        Assert.True(about.GetProperty("bundledTools").GetArrayLength() > 0); // license notices stay public

        var admin = await SignInAsync();
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/openapi/v1.json")).StatusCode);
        Assert.Equal(JsonValueKind.String, (await admin.GetFromJsonAsync<JsonElement>("/api/about")).GetProperty("version").ValueKind);
    }

    [Fact]
    public async Task Logout_and_revocation_end_sessions_before_they_expire()
    {
        var a = await SignInAsync();
        var b = await SignInAsync();
        Assert.True((await a.GetFromJsonAsync<JsonElement>("/api/auth/sessions")).GetArrayLength() >= 2);

        // Revoking b's session from a: b's cookie stops working at once.
        var bId = (await b.GetFromJsonAsync<JsonElement>("/api/auth/sessions")).EnumerateArray().Single(s => s.GetProperty("current").GetBoolean()).GetProperty("id").GetString();
        Assert.Equal(HttpStatusCode.NoContent, (await a.DeleteAsync($"/api/auth/sessions/{bId}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await b.GetAsync("/api/auth/me")).StatusCode);

        // Signing out revokes the session itself: a copy of the cookie stops working too.
        var raw = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var login = await raw.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" });
        var cookie = login.Headers.GetValues("Set-Cookie").First(h => h.StartsWith(JwtIssuer.CookieName, StringComparison.Ordinal)).Split(';')[0];
        HttpRequestMessage WithCookie(HttpMethod method, string path)
        {
            var m = new HttpRequestMessage(method, path);
            m.Headers.Add("Cookie", cookie);
            m.Headers.Add("X-Alastor-Request", "1");
            return m;
        }
        Assert.Equal(HttpStatusCode.OK, (await raw.SendAsync(WithCookie(HttpMethod.Get, "/api/auth/me"))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await raw.SendAsync(WithCookie(HttpMethod.Post, "/api/auth/logout"))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await raw.SendAsync(WithCookie(HttpMethod.Get, "/api/auth/me"))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await a.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Repeated_failures_lock_the_account_and_success_resets_the_count()
    {
        // A separate user so other tests keep signing in.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<Alastor.Server.Data.AlastorDbContext>();
            var u = new Alastor.Server.Data.User { Username = "locky", PasswordHash = "" };
            u.PasswordHash = new Microsoft.AspNetCore.Identity.PasswordHasher<Alastor.Server.Data.User>().HashPassword(u, "locky-password-1");
            db.Users.Add(u);
            await db.SaveChangesAsync();
        }
        var c = Client();
        for (var i = 0; i < 4; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await c.PostAsJsonAsync("/api/auth/login", new { username = "locky", password = "nope" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsJsonAsync("/api/auth/login", new { username = "locky", password = "locky-password-1" })).StatusCode);
        for (var i = 0; i < 5; i++)
            await c.PostAsJsonAsync("/api/auth/login", new { username = "locky", password = "nope" });
        // Locked now: even the right password gets the same generic answer.
        var locked = await c.PostAsJsonAsync("/api/auth/login", new { username = "locky", password = "locky-password-1" });
        Assert.Equal(HttpStatusCode.Unauthorized, locked.StatusCode);
        Assert.Contains("Invalid username or password", await locked.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Two_factor_is_optional_and_works_end_to_end()
    {
        // A separate user so turning 2FA on doesn't change how the other tests sign in.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<Alastor.Server.Data.AlastorDbContext>();
            var u = new Alastor.Server.Data.User { Username = "totp", PasswordHash = "" };
            u.PasswordHash = new Microsoft.AspNetCore.Identity.PasswordHasher<Alastor.Server.Data.User>().HashPassword(u, "totp-password-1");
            db.Users.Add(u);
            await db.SaveChangesAsync();
        }
        var c = Client();
        var first = await (await c.PostAsJsonAsync("/api/auth/login", new { username = "totp", password = "totp-password-1" })).Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(first.GetProperty("twoFactorRequired").GetBoolean()); // off by default: one step, as before
        Assert.False((await c.GetFromJsonAsync<JsonElement>("/api/auth/me")).GetProperty("twoFactor").GetBoolean());

        var setup = await (await c.PostAsync("/api/auth/2fa/setup", null)).Content.ReadFromJsonAsync<JsonElement>();
        var key = Totp.FromBase32(setup.GetProperty("secret").GetString()!);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.PostAsJsonAsync("/api/auth/2fa/enable", new { code = "000000" == Totp.Code(key, Totp.StepAt(DateTimeOffset.UtcNow)) ? "111111" : "000000" })).StatusCode);
        var enabled = await c.PostAsJsonAsync("/api/auth/2fa/enable", new { code = Totp.Code(key, Totp.StepAt(DateTimeOffset.UtcNow)) });
        enabled.EnsureSuccessStatusCode();
        var recovery = (await enabled.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("recoveryCodes").EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.Equal(10, recovery.Count);

        // Now the password alone isn't enough.
        var d = Client();
        var step1 = await (await d.PostAsJsonAsync("/api/auth/login", new { username = "totp", password = "totp-password-1" })).Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(step1.GetProperty("twoFactorRequired").GetBoolean());
        Assert.Equal(HttpStatusCode.Unauthorized, (await d.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await d.PostAsJsonAsync("/api/auth/login/2fa", new { recoveryCode = "aaaaa-bbbbb" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await d.PostAsJsonAsync("/api/auth/login/2fa", new { recoveryCode = recovery[0] })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await d.GetAsync("/api/auth/me")).StatusCode);

        // A recovery code works once; the second step without the password step fails.
        var e = Client();
        await e.PostAsJsonAsync("/api/auth/login", new { username = "totp", password = "totp-password-1" });
        Assert.Equal(HttpStatusCode.Unauthorized, (await e.PostAsJsonAsync("/api/auth/login/2fa", new { recoveryCode = recovery[0] })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client().PostAsJsonAsync("/api/auth/login/2fa", new { recoveryCode = recovery[1] })).StatusCode);

        // Turning it off needs the password and a code.
        Assert.Equal(HttpStatusCode.BadRequest, (await d.PostAsJsonAsync("/api/auth/2fa/disable", new { password = "wrong", code = recovery[2] })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await d.PostAsJsonAsync("/api/auth/2fa/disable", new { password = "totp-password-1", code = recovery[2] })).StatusCode);
        var again = await (await Client().PostAsJsonAsync("/api/auth/login", new { username = "totp", password = "totp-password-1" })).Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(again.GetProperty("twoFactorRequired").GetBoolean());
    }

    [Fact]
    public async Task Password_change_signs_out_other_sessions_and_self_check_reports()
    {
        var a = await SignInAsync();
        var b = await SignInAsync();
        var checks = await a.GetFromJsonAsync<JsonElement>("/api/system/security");
        var byId = checks.EnumerateArray().ToDictionary(c => c.GetProperty("id").GetString()!, c => c.GetProperty("status").GetString());
        Assert.Equal("Warn", byId["initial-password"]);
        Assert.Equal("Info", byId["two-factor"]);

        Assert.Equal(HttpStatusCode.NoContent, (await a.PostAsJsonAsync("/api/auth/password", new { currentPassword = "test-password-123", newPassword = "test-password-456" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await a.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await b.GetAsync("/api/auth/me")).StatusCode);
        var after = await a.GetFromJsonAsync<JsonElement>("/api/system/security");
        Assert.DoesNotContain(after.EnumerateArray(), c => c.GetProperty("id").GetString() == "initial-password" && c.GetProperty("status").GetString() == "Warn"
            && c.GetProperty("detail").GetString()!.StartsWith("admin", StringComparison.Ordinal));
        // Put it back for the other tests in this class.
        Assert.Equal(HttpStatusCode.NoContent, (await a.PostAsJsonAsync("/api/auth/password", new { currentPassword = "test-password-456", newPassword = "test-password-123" })).StatusCode);
    }

    [Fact]
    public async Task Data_overview_prune_and_compact()
    {
        var admin = await SignInAsync();
        var data = await admin.GetFromJsonAsync<JsonElement>("/api/system/data");
        Assert.Equal("sqlite", data.GetProperty("provider").GetString());
        Assert.Contains(data.GetProperty("tables").EnumerateArray(), t => t.GetProperty("table").GetString() == "Audit");
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync("/api/system/data/prune", null)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync("/api/system/data/compact", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync("/api/system/data/cleanup/nope", null)).StatusCode);
    }

    [Fact]
    public async Task Retention_covers_tables_that_used_to_grow_forever()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<Alastor.Server.Data.AlastorDbContext>();
        var old = DateTime.UtcNow.AddDays(-400);
        db.Audit.Add(new Alastor.Server.Data.AuditEntry { Actor = "t", Action = "retention.old", At = old });
        db.Audit.Add(new Alastor.Server.Data.AuditEntry { Actor = "t", Action = "retention.new" });
        var layer = new Alastor.Server.Data.PolicyLayer { Scope = Alastor.Server.Data.PolicyScope.Group, TargetId = Guid.NewGuid(), CurrentVersion = 3 };
        db.PolicyLayers.Add(layer);
        for (var v = 1; v <= 60; v++)
            db.PolicyVersions.Add(new Alastor.Server.Data.PolicyVersion { LayerId = layer.Id, Version = v, Yaml = "{}", CreatedBy = "t" });
        await db.SaveChangesAsync();

        await scope.ServiceProvider.GetRequiredService<Alastor.Server.Services.Storage.ServerDataService>().PruneAsync(force: true, default);

        Assert.False(db.Audit.Any(a => a.Action == "retention.old"));
        Assert.True(db.Audit.Any(a => a.Action == "retention.new"));
        var kept = db.PolicyVersions.Where(v => v.LayerId == layer.Id).Select(v => v.Version).ToList();
        Assert.Equal(51, kept.Count); // the newest 50, plus the current one
        Assert.Contains(3, kept);
        Assert.Contains(60, kept);
    }
}
