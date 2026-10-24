using System.Reflection;
using Sentinel.Core.Integrations;

namespace Sentinel.Server.Endpoints;

public static class MetaEndpoints
{
    public sealed record ToolLicense(string Id, string Name, string Capability, string License, string Homepage, bool Implemented, bool OptIn, string Description);
    public sealed record AboutDto(string Product, string Version, string License, string? Repository, IReadOnlyList<ToolLicense> BundledTools, IReadOnlyList<string> Notes);

    public static void MapMetaEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).AllowAnonymous().WithTags("Meta");

        // Public: the About page must work before login (license notices).
        app.MapGet("/api/about", () => new AboutDto(
            "SentinelVPS",
            Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "dev",
            "MIT",
            null,
            ToolCatalog.All.Select(e => new ToolLicense(e.Descriptor.Id, e.Descriptor.DisplayName, e.Descriptor.Capability.ToString(), e.Descriptor.License,
                e.Descriptor.Homepage, e.Implemented, e.OptIn, e.Descriptor.Description)).ToList(),
            [
                "Bundled tools are installed from your distribution's package repositories and keep their own licenses.",
                "SentinelVPS sends no telemetry. Agents only talk to this server; blocklist and threat feeds (NVD, CISA KEV, security news RSS) are fetched by the server.",
                "Alerts leave the server only through notification channels an admin sets up (SMTP, webhooks, ntfy).",
            ])).AllowAnonymous().WithTags("Meta");
    }
}
