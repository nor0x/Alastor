using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sentinel.Server.Data;

namespace Sentinel.Server.Services;

/// <summary>First-run setup: apply EF migrations, create the admin from env vars, seed the global default policy.</summary>
public static class Bootstrap
{
    public static async Task RunAsync(IServiceProvider root, CancellationToken ct = default)
    {
        await using var scope = root.CreateAsyncScope();
        var sp = scope.ServiceProvider;
        var db = sp.GetRequiredService<SentinelDbContext>();
        var opt = sp.GetRequiredService<IOptions<SentinelOptions>>().Value;
        var log = sp.GetRequiredService<ILoggerFactory>().CreateLogger("Bootstrap");

        // New SQLite databases created by EF Core migrations use WAL journal mode.
        await db.Database.MigrateAsync(ct);

        if (!await db.Users.AnyAsync(ct))
        {
            var password = opt.AdminPassword;
            var generated = false;
            if (string.IsNullOrEmpty(password))
            {
                password = Auth.Secrets.Generate("", 18);
                generated = true;
            }
            var user = new User { Username = opt.AdminUser, PasswordHash = "" };
            user.PasswordHash = new PasswordHasher<User>().HashPassword(user, password);
            db.Users.Add(user);
            await db.SaveChangesAsync(ct);
            if (generated)
                log.LogWarning("Created admin user '{User}' with generated password: {Password}  (set SENTINEL_ADMINPASSWORD to choose one)", opt.AdminUser, password);
            else
                log.LogInformation("Created admin user '{User}' from SENTINEL_ADMINPASSWORD", opt.AdminUser);
        }

        if (!await db.PolicyLayers.AnyAsync(l => l.Scope == PolicyScope.Global, ct))
        {
            var layer = new PolicyLayer { Scope = PolicyScope.Global, CurrentVersion = 1 };
            db.PolicyLayers.Add(layer);
            db.PolicyVersions.Add(new PolicyVersion { LayerId = layer.Id, Version = 1, Yaml = DefaultPolicyYaml(), Comment = "Default policy", CreatedBy = "system" });
            await db.SaveChangesAsync(ct);
            log.LogInformation("Seeded global default policy");
        }
    }

    public static string DefaultPolicyYaml()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Sentinel.Server.policy.default.yaml")
            ?? throw new InvalidOperationException("Embedded default policy missing");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
