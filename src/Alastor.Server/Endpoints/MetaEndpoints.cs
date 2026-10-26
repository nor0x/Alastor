using Microsoft.Extensions.Options;
using Alastor.Core.Integrations;
using Alastor.Server.Auth;
using Alastor.Server.Services.Updates;

namespace Alastor.Server.Endpoints;

public static class MetaEndpoints
{
    public sealed record ToolLicense(string Id, string Name, string Capability, string License, string Homepage, bool Implemented, bool OptIn, string Description);
    public sealed record AboutDto(string Product, string? Version, string License, string? Repository, IReadOnlyList<ToolLicense> BundledTools, IReadOnlyList<string> Notes);
    public sealed record UpdateDto(bool Enabled, string Current, string? Latest, string? Url, DateTime? PublishedAt, DateTime? CheckedAt, bool Available);

    public static void MapMetaEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).AllowAnonymous().WithTags("Meta");

        // Public: the About page must work before login (license notices). The exact version is for signed-in users only,
        // so a scanner can't match it against advisories.
        app.MapGet("/api/about", (System.Security.Claims.ClaimsPrincipal user) => new AboutDto(
            "Alastor",
            user.Identity?.IsAuthenticated == true ? UpdateCheckService.CurrentVersion : null,
            "MIT",
            null,
            ToolCatalog.All.Select(e => new ToolLicense(e.Descriptor.Id, e.Descriptor.DisplayName, e.Descriptor.Capability.ToString(), e.Descriptor.License,
                e.Descriptor.Homepage, e.Implemented, e.OptIn, e.Descriptor.Description)).ToList(),
            [
                "Bundled tools are installed from your distribution's package repositories and keep their own licenses.",
                "Trivy and Grype aren't in most distributions' repositories: the agent adopts whichever one you installed from its vendor's package repository, and scans against a database this server mirrors.",
                "Alastor sends no telemetry. Agents only talk to this server; blocklist and threat feeds (NVD, CISA KEV, security news RSS) are fetched by the server.",
                "Twice a day the server asks GitHub for the latest Alastor release, to show when an update is available (turn off with ALASTOR_UPDATECHECKENABLED=false).",
                "Alerts leave the server only through notification channels an admin sets up (SMTP, webhooks, ntfy).",
            ])).AllowAnonymous().WithTags("Meta");

        // The newest release the update check has seen. Signed-in only, like the exact version.
        app.MapGet("/api/about/update", (UpdateCheckService updates, IOptions<AlastorOptions> options) =>
        {
            var latest = options.Value.UpdateCheckEnabled ? updates.Latest : null;
            return new UpdateDto(options.Value.UpdateCheckEnabled, UpdateCheckService.CurrentVersion, latest?.Tag, latest?.Url, latest?.PublishedAt, latest?.CheckedAt,
                latest is not null && UpdateCheckService.IsNewer(UpdateCheckService.CurrentVersion, latest.Tag));
        }).RequireAuthorization(AuthPolicies.Reader).WithTags("Meta");
    }
}
