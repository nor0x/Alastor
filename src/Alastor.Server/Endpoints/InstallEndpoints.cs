using System.Reflection;
using Microsoft.Extensions.Options;

namespace Alastor.Server.Endpoints;

/// <summary>
/// Serves the installer scripts embedded from /install, so `curl https://server/install/agent.sh | bash` works with no other hosting,
/// and the agent binaries the server installer put in <see cref="AlastorOptions.AgentDownloadDir"/>, so hosts download the agent from their own server.
/// </summary>
public static class InstallEndpoints
{
    private static readonly string[] AgentFiles = ["alastor-agent-linux-x64", "alastor-agent-linux-arm64", "SHA256SUMS"];

    public static void MapInstallScripts(this IEndpointRouteBuilder app)
    {
        app.MapGet("/install/{name}", (string name) =>
        {
            var resource = name switch
            {
                "agent.sh" => "Alastor.Server.install.agent-install.sh",
                "server.sh" => "Alastor.Server.install.install.sh",
                "alastor.sh" => "Alastor.Server.install.alastor.sh",
                _ => null,
            };
            var stream = resource is null ? null : Assembly.GetExecutingAssembly().GetManifestResourceStream(resource);
            return stream is null ? Results.NotFound() : Results.Stream(stream, "text/x-shellscript");
        }).AllowAnonymous().WithTags("Meta");

        app.MapGet("/install/agent/{file}", (string file, IOptions<AlastorOptions> opt) =>
        {
            // Fixed names only, so the route can never reach outside the directory.
            if (!AgentFiles.Contains(file)) return Results.NotFound();
            var path = Path.Combine(opt.Value.AgentDownloadDir, file);
            return File.Exists(path)
                ? Results.File(path, file == "SHA256SUMS" ? "text/plain" : "application/octet-stream", file)
                : Results.NotFound();
        }).AllowAnonymous().WithTags("Meta");
    }
}
