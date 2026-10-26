using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Options;
using Alastor.Core.Net;
using Alastor.Core.Network;

namespace Alastor.Server.Auth;

/// <summary>
/// Who may connect, as configured in <see cref="AlastorOptions.DashboardAllowFrom"/> and <see cref="AlastorOptions.AgentAllowFrom"/>:
/// <c>any</c>, <c>loopback</c>, <c>private</c> (RFC 1918 and fc00::/7), <c>tailnet</c> (Tailscale's ranges) and CIDRs.
/// </summary>
public sealed class NetworkAllowList
{
    public const string Any = "any";
    public static readonly string[] Keywords = [Any, "loopback", "private", "tailnet"];

    private readonly IpRangeSet _ranges;

    private NetworkAllowList(bool any, IpRangeSet ranges, IReadOnlyList<string> entries)
    {
        AllowsAny = any;
        _ranges = ranges;
        Entries = entries;
    }

    public bool AllowsAny { get; }
    public IReadOnlyList<string> Entries { get; }

    /// <summary>Any entry that lets in addresses on the public internet (<c>any</c>, or a CIDR with public addresses).</summary>
    public bool AllowsPublic => AllowsAny || Entries.Any(e => IpTarget.TryParse(e, out var t)
        && (AddressClassifier.IsPublic(t.Value.Network.BaseAddress.ToString()) || t.Value.Network.PrefixLength < 8));

    public static bool TryParse(string? value, out NetworkAllowList list, out string? error)
    {
        list = new NetworkAllowList(false, IpRangeSet.Empty, []);
        error = null;
        var entries = (value ?? "").Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(e => e.ToLowerInvariant()).Distinct().ToList();
        if (entries.Count == 0) { error = "is empty; use 'any' to allow everyone."; return false; }

        var any = false;
        var targets = new List<IpTarget>();
        foreach (var e in entries)
        {
            switch (e)
            {
                case Any: any = true; break;
                case "loopback": targets.AddRange(Parse("127.0.0.0/8", "::1/128")); break;
                case "private": targets.AddRange(Parse("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")); break;
                case "tailnet": targets.AddRange(Parse("100.64.0.0/10", "fd7a:115c:a1e0::/48")); break;
                default:
                    if (!IpTarget.TryParse(e, out var t)) { error = $"'{e}' is not {string.Join(", ", Keywords)} or an address/CIDR."; return false; }
                    targets.Add(t.Value);
                    break;
            }
        }
        list = new NetworkAllowList(any, IpRangeSet.From(targets), entries);
        return true;
    }

    public static NetworkAllowList Parse(string value) =>
        TryParse(value, out var list, out var error) ? list : throw new FormatException(error);

    /// <summary>A connection without an IP address (Unix socket, in-process test host) is local.</summary>
    public bool Allows(IPAddress? address) =>
        AllowsAny || address is null || _ranges.Contains(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address);

    private static IEnumerable<IpTarget> Parse(params string[] cidrs) =>
        cidrs.Select(c => IpTarget.TryParse(c, out var t) ? t.Value : throw new InvalidOperationException(c));
}

public static class NetworkAccess
{
    /// <summary>Paths agents use. Everything else belongs to the dashboard.</summary>
    public static bool IsAgentPath(PathString path) =>
        path.StartsWithSegments("/api/agent") || path.StartsWithSegments("/hubs/agent") || path.StartsWithSegments("/install");

    /// <summary>
    /// Answers requests from outside the configured networks with a bare 404, before authentication, so the dashboard
    /// gives nothing away to scanners. Runs after UseForwardedHeaders, so a local reverse proxy's client IP counts.
    /// </summary>
    public static IApplicationBuilder UseNetworkAllowLists(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetRequiredService<IOptions<AlastorOptions>>().Value;
        var dashboard = NetworkAllowList.Parse(options.DashboardAllowFrom);
        var agents = NetworkAllowList.Parse(options.AgentAllowFrom);
        var logger = app.ApplicationServices.GetRequiredService<ILoggerFactory>().CreateLogger("NetworkAccess");
        var time = app.ApplicationServices.GetRequiredService<TimeProvider>();
        var lastLogged = new ConcurrentDictionary<string, DateTimeOffset>();

        return app.Use(async (ctx, next) =>
        {
            var path = ctx.Request.Path;
            var ip = ctx.Connection.RemoteIpAddress;
            // Health checks from the box itself (installer, container HEALTHCHECK) always work.
            var allowed = path.StartsWithSegments("/healthz") && (ip is null || IPAddress.IsLoopback(ip))
                || (IsAgentPath(path) ? agents : dashboard).Allows(ip);
            if (allowed)
            {
                await next();
                return;
            }

            var key = ip?.ToString() ?? "unknown";
            var now = time.GetUtcNow();
            if (!lastLogged.TryGetValue(key, out var last) || now - last > TimeSpan.FromHours(1))
            {
                lastLogged[key] = now;
                if (lastLogged.Count > 10_000) lastLogged.Clear();
                logger.LogWarning("Refused {Path} from {Address}: not in {Setting}. Logged once an hour per address.",
                    path.Value, key, IsAgentPath(path) ? "AgentAllowFrom" : "DashboardAllowFrom");
            }
            ctx.Response.StatusCode = StatusCodes.Status404NotFound;
        });
    }

    /// <summary>Browser hardening headers on every response. The SPA loads only same-origin scripts, styles and fonts.</summary>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) => app.Use(async (ctx, next) =>
    {
        var h = ctx.Response.Headers;
        h.ContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; "
            + "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
        h.XContentTypeOptions = "nosniff";
        h.XFrameOptions = "DENY";
        h["Referrer-Policy"] = "no-referrer";
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
        h["Cross-Origin-Opener-Policy"] = "same-origin";
        if (ctx.Request.IsHttps) h.StrictTransportSecurity = "max-age=31536000";
        await next();
    });
}
