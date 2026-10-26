using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Alastor.Core.Network;
using Alastor.Server.Auth;
using Alastor.Server.Data;

namespace Alastor.Server.Services.Security;

public enum CheckStatus { Pass, Info, Warn, Fail }

/// <param name="Fix">What to change, when the check doesn't pass.</param>
public sealed record SelfCheck(string Id, string Title, CheckStatus Status, string Detail, string? Fix = null);

/// <summary>What the static checks look at, gathered from the running server or from configuration (the CLI).</summary>
public sealed record SelfCheckInputs(
    IReadOnlyList<string> ListenUrls,
    IReadOnlyList<string> LocalAddresses,
    AlastorOptions Options,
    bool RunningAsRoot,
    UnixFileMode? DataDirMode,
    UnixFileMode? JwtKeyMode);

/// <summary>
/// Does Alastor itself add exposure to the machine it runs on? Looks at where the server listens, who may connect,
/// whether traffic is encrypted, and how its secrets are stored, and says what to change. Shown in Settings → Security,
/// logged at startup, and printed by <c>alastor-server security-check</c>.
/// </summary>
public static class SelfChecks
{
    private const string Group = "Owner-only permissions";

    public static List<SelfCheck> Static(SelfCheckInputs i)
    {
        var o = i.Options;
        var checks = new List<SelfCheck> { Listen(i) };

        var publicUrl = Uri.TryCreate(o.PublicUrl, UriKind.Absolute, out var u) ? u : null;
        var urlLocal = publicUrl is not null && IsLoopbackOrTailnet(publicUrl.Host);
        var plainHttp = publicUrl?.Scheme == Uri.UriSchemeHttp && !urlLocal;
        checks.Add(publicUrl switch
        {
            null => new("tls", "Encrypted connections", CheckStatus.Warn,
                "PublicUrl isn't set, so install commands use whatever address a browser used.",
                "Set ALASTOR_PUBLICURL to the https:// or tailnet address agents should use."),
            { Scheme: "https" } => new("tls", "Encrypted connections", CheckStatus.Pass, $"Agents and browsers use {o.PublicUrl}."),
            _ when urlLocal => new("tls", "Encrypted connections", CheckStatus.Pass,
                $"{o.PublicUrl} is plain HTTP, but on loopback or the tailnet, which WireGuard already encrypts."),
            _ => new("tls", "Encrypted connections", CheckStatus.Fail,
                $"{o.PublicUrl} is plain HTTP: passwords, session cookies and agent secrets cross the network unencrypted.",
                "Re-run the installer with --access tailscale, or --domain your.domain for HTTPS through Caddy."),
        });
        if (!o.SecureCookies && publicUrl?.Scheme == "https")
            checks.Add(new("cookies", "Secure session cookie", CheckStatus.Warn,
                "SecureCookies is off although the dashboard is served over HTTPS, so a browser may send the session over plain HTTP.",
                "Set ALASTOR_SECURECOOKIES=true."));

        var dashboard = NetworkAllowList.Parse(o.DashboardAllowFrom);
        checks.Add(dashboard.AllowsPublic
            ? new("dashboard-access", "Who can reach the dashboard", plainHttp ? CheckStatus.Fail : CheckStatus.Warn,
                $"DashboardAllowFrom is '{o.DashboardAllowFrom}': anyone on the internet who can reach the server gets the sign-in page.",
                "Set ALASTOR_DASHBOARDALLOWFROM=loopback,tailnet (or your VPN's CIDR), and reach the dashboard over Tailscale or a VPN.")
            : new("dashboard-access", "Who can reach the dashboard", CheckStatus.Pass, $"Only {Describe(dashboard)}."));

        var agents = NetworkAllowList.Parse(o.AgentAllowFrom);
        checks.Add(agents.AllowsPublic
            ? new("agent-access", "Who can reach the agent API", CheckStatus.Warn,
                $"AgentAllowFrom is '{o.AgentAllowFrom}'. Agents authenticate with secrets, but the enrollment and agent endpoints are open to the internet.",
                "If every host can join your tailnet, set ALASTOR_AGENTALLOWFROM=loopback,tailnet and use the tailnet address as PublicUrl.")
            : new("agent-access", "Who can reach the agent API", CheckStatus.Pass, $"Only {Describe(agents)}."));

        if (!OperatingSystem.IsWindows())
        {
            checks.Add(i.RunningAsRoot
                ? new("user", "Runs without root", CheckStatus.Warn, "The server runs as root. It needs no privileges.",
                    "Run it as its own user, as install.sh does (User=alastor in the systemd unit).")
                : new("user", "Runs without root", CheckStatus.Pass, "The server runs as an unprivileged user."));
            var loose = new List<string>();
            if (i.DataDirMode is { } d && (d & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
                loose.Add($"{o.DataDir} ({Octal(d)})");
            if (i.JwtKeyMode is { } k && (k & (UnixFileMode.GroupRead | UnixFileMode.OtherRead)) != 0)
                loose.Add($"{Path.Combine(o.DataDir, "jwt.key")} ({Octal(k)})");
            checks.Add(loose.Count > 0
                ? new("permissions", Group, CheckStatus.Fail, $"Other users can read {string.Join(" and ", loose)}: the database and session signing key.",
                    $"chmod 700 {o.DataDir} && chmod 600 {Path.Combine(o.DataDir, "jwt.key")}")
                : new("permissions", Group, CheckStatus.Pass, "The data directory and signing key are readable by the server's user only."));
        }
        return checks;
    }

    private static SelfCheck Listen(SelfCheckInputs i)
    {
        const string id = "listen", title = "Listening address";
        var publicNics = i.LocalAddresses.Where(AddressClassifier.IsPublic).ToList();
        var problems = new List<string>();
        var warnings = new List<string>();
        foreach (var url in i.ListenUrls)
        {
            var host = Host(url);
            if (host is "+" or "*" or "0.0.0.0" or "::" or "")
            {
                if (publicNics.Count > 0) problems.Add($"{url} (all addresses, including public {string.Join(", ", publicNics.Take(3))})");
                else warnings.Add($"{url} (all addresses; with a cloud provider's 1:1 NAT that can still be public)");
            }
            else if (host == "localhost" || IPAddress.TryParse(host, out _) && AddressClassifier.Classify(host) is AddressKind.Loopback or AddressKind.Tailnet or AddressKind.Private) { }
            else if (AddressClassifier.IsPublic(host)) problems.Add($"{url} (a public address)");
            else warnings.Add(url);
        }
        const string fix = "Listen on 127.0.0.1 behind Caddy or `tailscale serve`, or on the tailnet address: re-run the installer with --access tailscale (or set ASPNETCORE_URLS).";
        if (problems.Count > 0)
            return new(id, title, CheckStatus.Fail, $"The server answers on {string.Join("; ", problems)}.", fix);
        if (warnings.Count > 0)
            return new(id, title, CheckStatus.Warn, $"The server answers on {string.Join("; ", warnings)}.", fix);
        return new(id, title, CheckStatus.Pass, $"Only on {string.Join(", ", i.ListenUrls)}.");
    }

    /// <summary>Checks that need the database: users and enrolled agents.</summary>
    public static async Task<List<SelfCheck>> DatabaseAsync(AlastorDbContext db, CancellationToken ct)
    {
        var checks = new List<SelfCheck>();
        var users = await db.Users.AsNoTracking().Select(u => new { u.Username, u.PasswordChangedAt, u.TotpEnabledAt }).ToListAsync(ct);

        var initial = users.Where(u => u.PasswordChangedAt is null).Select(u => u.Username).ToList();
        checks.Add(initial.Count > 0
            ? new("initial-password", "Initial password replaced", CheckStatus.Warn,
                $"{string.Join(", ", initial)} still {(initial.Count == 1 ? "uses" : "use")} the password set at first start, which may be in the server log or installer output.",
                "Settings → Account → Change password.")
            : new("initial-password", "Initial password replaced", CheckStatus.Pass, "Every user has chosen their own password."));

        // Optional: reported, never nagged about.
        var withTotp = users.Count(u => u.TotpEnabledAt is not null);
        checks.Add(new("two-factor", "Two-factor sign-in", CheckStatus.Info,
            withTotp == users.Count ? "On for every user." : withTotp == 0 ? "Off. It's optional: turn it on under Settings → Account."
                : $"On for {withTotp} of {users.Count} users. It's optional."));

        var hosts = await db.Hosts.AsNoTracking().Where(h => h.ObservedScheme == "http" && h.ObservedAddress != null)
            .Select(h => new { h.Name, h.ObservedAddress }).ToListAsync(ct);
        var exposed = hosts.Where(h => AddressClassifier.IsPublic(h.ObservedAddress)).Select(h => h.Name).OrderBy(n => n).ToList();
        if (exposed.Count > 0)
            checks.Add(new("agent-http", "Agents connect encrypted", CheckStatus.Warn,
                $"{exposed.Count} agent{(exposed.Count == 1 ? "" : "s")} reach the server over plain HTTP from a public address: {string.Join(", ", exposed.Take(5))}{(exposed.Count > 5 ? ", …" : "")}.",
                "Serve the server over HTTPS or the tailnet, then re-enroll those hosts with the new URL."));
        else
            checks.Add(new("agent-http", "Agents connect encrypted", CheckStatus.Pass, "No agent sends its secret unencrypted across the internet."));
        return checks;
    }

    /// <summary>Addresses on this machine's network interfaces.</summary>
    public static List<string> LocalAddresses()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                .Select(a => a.Address)
                .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .Select(a => (a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a).ToString().Split('%')[0])
                .Distinct().ToList();
        }
        catch (NetworkInformationException) { return []; }
    }

    public static SelfCheckInputs Gather(IReadOnlyList<string> listenUrls, AlastorOptions options)
    {
        UnixFileMode? Mode(string path, bool dir)
        {
            if (OperatingSystem.IsWindows()) return null;
            try { return dir ? (Directory.Exists(path) ? File.GetUnixFileMode(path) : null) : (File.Exists(path) ? File.GetUnixFileMode(path) : null); }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
        }
        return new(listenUrls, LocalAddresses(), options, !OperatingSystem.IsWindows() && Environment.IsPrivilegedProcess,
            Mode(options.DataDir, true), Mode(Path.Combine(options.DataDir, "jwt.key"), false));
    }

    public static bool IsLoopbackOrTailnet(string host)
    {
        host = host.Trim('[', ']');
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".ts.net", StringComparison.OrdinalIgnoreCase)) return true;
        return IPAddress.TryParse(host, out _) && AddressClassifier.Classify(host) is AddressKind.Loopback or AddressKind.Tailnet;
    }

    private static string? Host(string url)
    {
        // Kestrel's wildcards (http://+:8080, http://*:8080) aren't valid URIs.
        var rest = url.Contains("://", StringComparison.Ordinal) ? url[(url.IndexOf("://", StringComparison.Ordinal) + 3)..] : url;
        if (rest.StartsWith('[')) return rest[1..rest.IndexOf(']')];
        var colon = rest.LastIndexOf(':');
        var host = colon >= 0 ? rest[..colon] : rest.TrimEnd('/');
        return host.Split('/')[0];
    }

    private static string Describe(NetworkAllowList list) =>
        string.Join(", ", list.Entries.Select(e => e switch { "loopback" => "this machine", "tailnet" => "your tailnet", "private" => "private networks", _ => e }));

    private static string Octal(UnixFileMode m) => Convert.ToString((int)m & 0x1FF, 8).PadLeft(3, '0');
}

/// <summary>Runs the self-check for the dashboard, and logs anything failing once the server has started.</summary>
public sealed class SelfCheckService(IServer server, IOptions<AlastorOptions> options, IServiceScopeFactory scopes)
{
    public async Task<List<SelfCheck>> RunAsync(CancellationToken ct)
    {
        var urls = server.Features.Get<IServerAddressesFeature>()?.Addresses.ToList() ?? [];
        var checks = SelfChecks.Static(SelfChecks.Gather(urls, options.Value));
        await using var scope = scopes.CreateAsyncScope();
        checks.AddRange(await SelfChecks.DatabaseAsync(scope.ServiceProvider.GetRequiredService<AlastorDbContext>(), ct));
        return checks;
    }
}

public sealed class SelfCheckStartupLogger(IHostApplicationLifetime lifetime, SelfCheckService checks, ILogger<SelfCheckStartupLogger> logger) : IHostedService
{
    public Task StartAsync(CancellationToken ct)
    {
        lifetime.ApplicationStarted.Register(() => _ = Task.Run(async () =>
        {
            try
            {
                foreach (var c in (await checks.RunAsync(CancellationToken.None)).Where(c => c.Status == CheckStatus.Fail))
                    logger.LogWarning("Security check failed: {Title}. {Detail} Fix: {Fix}", c.Title, c.Detail, c.Fix);
            }
            catch (Exception ex) { logger.LogDebug(ex, "Security self-check at startup failed"); }
        }));
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
