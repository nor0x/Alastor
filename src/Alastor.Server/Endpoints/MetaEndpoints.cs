using System.Reflection;
using Alastor.Core.Integrations;

namespace Alastor.Server.Endpoints;

public static class MetaEndpoints
{
    public sealed record ToolLicense(string Id, string Name, string Capability, string License, string Homepage, bool Implemented, bool OptIn, string Description);
    public sealed record AboutDto(string Product, string? Version, string License, string? Repository, IReadOnlyList<ToolLicense> BundledTools, IReadOnlyList<string> Notes);

    public static void MapMetaEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).AllowAnonymous().WithTags("Meta");

        // Public: the About page must work before login (license notices). The exact version is for signed-in users only,
        // so a scanner can't match it against advisories.
        app.MapGet("/api/about", (System.Security.Claims.ClaimsPrincipal user) => new AboutDto(
            "Alastor",
            user.Identity?.IsAuthenticated == true
                ? Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "dev"
                : null,
            "MIT",
            null,
            ToolCatalog.All.Select(e => new ToolLicense(e.Descriptor.Id, e.Descriptor.DisplayName, e.Descriptor.Capability.ToString(), e.Descriptor.License,
                e.Descriptor.Homepage, e.Implemented, e.OptIn, e.Descriptor.Description)).ToList(),
            [
                "Bundled tools are installed from your distribution's package repositories and keep their own licenses.",
                "Trivy and Grype aren't in most distributions' repositories: the agent adopts whichever one you installed from its vendor's package repository, and scans against a database this server mirrors.",
                "Alastor sends no telemetry. Agents only talk to this server; blocklist and threat feeds (NVD, CISA KEV, security news RSS) are fetched by the server.",
                "Alerts leave the server only through notification channels an admin sets up (SMTP, webhooks, ntfy).",
            ])).AllowAnonymous().WithTags("Meta");
    }
}
