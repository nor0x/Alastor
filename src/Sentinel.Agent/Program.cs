using Sentinel.Core.Baseline;
using Sentinel.Core.Blocklists;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Agent;
using Sentinel.Core.Contracts;
using Sentinel.Core.Integrations;
using Sentinel.Core.Integrations.Fail2Ban;
using Sentinel.Core.Platform;
using Serilog;

// sentinel-agent [run]                                        run the supervisor (systemd ExecStart)
// sentinel-agent enroll --server URL --token TOKEN [--pin SHA256] [--insecure] [--force]
// sentinel-agent status                                       print local tool detection
// sentinel-agent uninstall                                    remove everything the agent manages
// sentinel-agent version
var command = args.FirstOrDefault(a => !a.StartsWith('-')) ?? "run";
string? Arg(string name) { var i = Array.IndexOf(args, name); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
bool Flag(string name) => args.Contains(name);
var configPath = Arg("--config") ?? AgentConfig.DefaultPath;
var stateDir = Arg("--state-dir") ?? AgentConfig.DefaultStateDir;

switch (command)
{
    case "version":
        Console.WriteLine(AgentInfo.Version);
        return 0;
    case "enroll":
        return await EnrollAsync();
    case "status":
        return await StatusAsync();
    case "uninstall":
        return await UninstallAsync();
    case "run":
        break;
    default:
        Console.Error.WriteLine($"Unknown command '{command}'. Use: run | enroll | status | uninstall | version");
        return 2;
}

var config = AgentConfig.Load(configPath);
if (config is null)
{
    Console.Error.WriteLine($"Not enrolled: {configPath} not found. Run: sentinel-agent enroll --server https://… --token …");
    return 3;
}

if (config.ServerUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !config.AllowInsecureHttp)
{
    Console.Error.WriteLine("Server URL is plain HTTP but allowInsecureHttp is false. Refusing to send credentials unencrypted.");
    return 3;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSystemd();
builder.Services.AddSerilog((_, lc) => lc
    .MinimumLevel.Is(Enum.TryParse<Serilog.Events.LogEventLevel>(Environment.GetEnvironmentVariable("SENTINEL_AGENT_LOGLEVEL"), true, out var lvl) ? lvl : Serilog.Events.LogEventLevel.Information)
    .MinimumLevel.Override("Microsoft", Serilog.Events.LogEventLevel.Warning)
    .MinimumLevel.Override("System.Net.Http", Serilog.Events.LogEventLevel.Warning)
    // journald adds its own timestamps.
    .WriteTo.Console(outputTemplate: "{Level:u3} {SourceContext}: {Message:lj}{NewLine}{Exception}"));

var platform = await PlatformServices.CreateAsync(stateDir);
builder.Services.AddSingleton(config);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(platform.Os);
builder.Services.AddSingleton<IStateStore>(platform.State);
builder.Services.AddSingleton(new ServerClient(ServerClient.CreateHttpClient(config.ServerUrl, config.Credential, config.CertificatePin)));
builder.Services.AddSingleton<HostMetricsCollector>();
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateFail2Ban(sp.GetRequiredService<ILogger<Fail2BanIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateBaseline(sp.GetRequiredService<ILogger<BaselineIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateBlocklist(sp.GetRequiredService<ILogger<BlocklistIntegration>>()));
builder.Services.AddSingleton<Supervisor>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Supervisor>());
builder.Services.AddHostedService<HubListener>();

await builder.Build().RunAsync();
return 0;

async Task<int> EnrollAsync()
{
    var serverUrl = Arg("--server");
    var token = Arg("--token");
    if (serverUrl is null || token is null)
    {
        Console.Error.WriteLine("Usage: sentinel-agent enroll --server https://sentinel.example.com --token sve_… [--pin SHA256] [--insecure] [--force]");
        return 2;
    }
    if (AgentConfig.Load(configPath) is not null && !Flag("--force"))
    {
        Console.WriteLine($"Already enrolled ({configPath}). Use --force to enroll again as a new host.");
        return 0;
    }
    var insecure = Flag("--insecure");
    if (serverUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !insecure)
    {
        Console.Error.WriteLine("Refusing plain HTTP. Use https:// or pass --insecure for local testing.");
        return 2;
    }
    var pin = Arg("--pin");
    var os = await OsInfo.DetectAsync(new PhysicalFileSystem());
    var machineId = File.Exists("/etc/machine-id") ? (await File.ReadAllTextAsync("/etc/machine-id")).Trim() : null;
    var client = new ServerClient(ServerClient.CreateHttpClient(serverUrl, null, pin));
    try
    {
        var resp = await client.EnrollAsync(new EnrollRequest(token, Environment.MachineName, os.PrettyName, os.Id, os.VersionId, os.Architecture, AgentInfo.Version, machineId), CancellationToken.None);
        new AgentConfig
        {
            ServerUrl = serverUrl,
            AgentId = resp.AgentId,
            Credential = resp.AgentSecret,
            CertificatePin = pin,
            AllowInsecureHttp = insecure,
            HeartbeatIntervalSeconds = resp.HeartbeatIntervalSeconds,
        }.Save(configPath);
        Console.WriteLine($"Enrolled as {resp.AgentId}. Configuration written to {configPath}.");
        return 0;
    }
    catch (HttpRequestException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

async Task<int> StatusAsync()
{
    var platform = await PlatformServices.CreateAsync(stateDir);
    Console.WriteLine($"Agent {AgentInfo.Version} on {platform.Os.PrettyName} ({platform.Os.Family}, {platform.Os.Architecture})");
    Console.WriteLine($"Config: {configPath} ({(File.Exists(configPath) ? "enrolled" : "not enrolled")})");
    var tool = platform.CreateFail2Ban(NullLogger<Fail2BanIntegration>.Instance);
    var s = await tool.DetectAsync(CancellationToken.None);
    Console.WriteLine($"{s.ToolId,-10} installed={s.Installed} version={s.Version} running={s.Running} ownership={s.Ownership} config={s.ConfigState} rev={s.AppliedRevision}");
    if (s.UnavailableReason is not null) Console.WriteLine($"           unavailable: {s.UnavailableReason}");
    return 0;
}

async Task<int> UninstallAsync()
{
    var platform = await PlatformServices.CreateAsync(stateDir);
    IToolIntegration[] tools =
    [
        platform.CreateFail2Ban(NullLogger<Fail2BanIntegration>.Instance),
        platform.CreateBaseline(NullLogger<BaselineIntegration>.Instance),
        platform.CreateBlocklist(NullLogger<BlocklistIntegration>.Instance),
    ];
    foreach (var t in tools)
    {
        var r = await t.RemoveManagedStateAsync(CancellationToken.None);
        Console.WriteLine($"{t.Descriptor.Id}: removed managed configuration{(r.Error is null ? "" : $" ({r.Error})")}");
    }
    if (File.Exists(configPath)) File.Delete(configPath);
    if (Directory.Exists(stateDir)) Directory.Delete(stateDir, recursive: true);
    Console.WriteLine("Agent configuration and state removed. Bundled tools stay installed.");
    return 0;
}

/// <summary>Shared construction of OS-facing services for both the daemon and the CLI subcommands.</summary>
internal sealed record PlatformServices(OsInfo Os, ICommandRunner Runner, IFileSystem Fs, IStateStore State, string StateDir)
{
    public static async Task<PlatformServices> CreateAsync(string stateDir)
    {
        var fs = new PhysicalFileSystem();
        return new PlatformServices(await OsInfo.DetectAsync(fs), new ProcessCommandRunner(), fs, new JsonFileStateStore(stateDir), stateDir);
    }

    public BlocklistIntegration CreateBlocklist(ILogger<BlocklistIntegration> logger) =>
        new(Runner, Fs, PackageManagers.For(Os.Family, Runner), State, StateDir, logger, TimeProvider.System);

    public Fail2BanIntegration CreateFail2Ban(ILogger<Fail2BanIntegration> logger) =>
        new(Runner, Fs, PackageManagers.For(Os.Family, Runner), ServiceManagers.For(Runner), State, logger, TimeProvider.System);

    public BaselineIntegration CreateBaseline(ILogger<BaselineIntegration> logger) =>
        new(Runner, Fs, ServiceManagers.For(Runner), State, Os, logger, TimeProvider.System);
}
