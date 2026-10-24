using System.Reflection;

namespace Sentinel.Server.Endpoints;

/// <summary>Serves the installer scripts embedded from /install, so `curl https://server/install/agent.sh | bash` works with no other hosting.</summary>
public static class InstallEndpoints
{
    public static void MapInstallScripts(this IEndpointRouteBuilder app)
    {
        app.MapGet("/install/{name}", (string name) =>
        {
            var resource = name switch
            {
                "agent.sh" => "Sentinel.Server.install.agent-install.sh",
                "server.sh" => "Sentinel.Server.install.install.sh",
                _ => null,
            };
            var stream = resource is null ? null : Assembly.GetExecutingAssembly().GetManifestResourceStream(resource);
            return stream is null ? Results.NotFound() : Results.Stream(stream, "text/x-shellscript");
        }).AllowAnonymous().WithTags("Meta");
    }
}
