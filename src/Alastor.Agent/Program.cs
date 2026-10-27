using Alastor.Core.Baseline;
using Alastor.Core.Blocklists;
using Alastor.Core.Hardening;
using Alastor.Core.Malware;
using Alastor.Core.Network;
using Alastor.Core.Updates;
using Alastor.Core.Vulnerabilities;
using Microsoft.Extensions.Logging.Abstractions;
using Alastor.Agent;
using Alastor.Core.Contracts;
using Alastor.Core.Integrations;
using Alastor.Core.Integrations.CrowdSec;
using Alastor.Core.Integrations.Fail2Ban;
using Alastor.Core.Platform;
using Serilog;

// alastor-agent [run]                                        run the supervisor (systemd ExecStart)
// alastor-agent enroll --server URL --token TOKEN [--pin SHA256] [--insecure] [--force]
// alastor-agent status                                       print local tool detection
// alastor-agent uninstall                                    remove everything the agent manages
// alastor-agent version
var command = args.FirstOrDefault(a => !a.StartsWith('-')) ?? "run";
string? Arg(string name) { var i = Array.IndexOf(args, name); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
bool Flag(string name) => args.Contains(name);
// Plain HTTP needs no --insecure when it never leaves this machine or travels inside Tailscale's WireGuard tunnel.
static bool IsPrivateTransport(string url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
    var host = uri.DnsSafeHost.TrimEnd('.');
    if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".ts.net", StringComparison.OrdinalIgnoreCase)) return true;
    if (!System.Net.IPAddress.TryParse(host, out var ip)) return false;
    return System.Net.IPAddress.IsLoopback(ip)
        || System.Net.IPNetwork.Parse("100.64.0.0/10").Contains(ip)
        || System.Net.IPNetwork.Parse("fd7a:115c:a1e0::/48").Contains(ip);
}
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
    Console.Error.WriteLine($"Not enrolled: {configPath} not found. Run: alastor-agent enroll --server https://… --token …");
    return 3;
}

if (config.ServerUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !config.AllowInsecureHttp && !IsPrivateTransport(config.ServerUrl))
{
    Console.Error.WriteLine("Server URL is plain HTTP to a host outside loopback and Tailscale, but allowInsecureHttp is false. Refusing to send credentials unencrypted.");
    return 3;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSystemd();
builder.Services.AddSerilog((_, lc) => lc
    .MinimumLevel.Is(Enum.TryParse<Serilog.Events.LogEventLevel>(Environment.GetEnvironmentVariable("ALASTOR_AGENT_LOGLEVEL"), true, out var lvl) ? lvl : Serilog.Events.LogEventLevel.Information)
    .MinimumLevel.Override("Microsoft", Serilog.Events.LogEventLevel.Warning)
    .MinimumLevel.Override("System.Net.Http", Serilog.Events.LogEventLevel.Warning)
    // journald adds its own timestamps.
    .WriteTo.Console(outputTemplate: "{Level:u3} {SourceContext}: {Message:lj}{NewLine}{Exception}"));

var platform = await PlatformServices.CreateAsync(stateDir);
builder.Services.AddSingleton(config);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(platform.Os);
builder.Services.AddSingleton<IStateStore>(platform.State);
builder.Services.AddSingleton<ICommandRunner>(platform.Runner);
builder.Services.AddSingleton(new ServerClient(ServerClient.CreateHttpClient(config.ServerUrl, config.Credential, config.CertificatePin)));
builder.Services.AddSingleton<HostMetricsCollector>();
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateFail2Ban(sp.GetRequiredService<ILogger<Fail2BanIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateCrowdSec(sp.GetRequiredService<ILogger<CrowdSecIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateBaseline(sp.GetRequiredService<ILogger<BaselineIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateBlocklist(sp.GetRequiredService<ILogger<BlocklistIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateUpdates(sp.GetRequiredService<ILogger<UpdatesIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateSoftware(sp.GetRequiredService<ILogger<Alastor.Core.Software.SoftwareIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateStorage(sp.GetRequiredService<ILogger<Alastor.Core.Storage.StorageIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateHardening(sp.GetRequiredService<ILogger<HardeningIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateNetwork(sp.GetRequiredService<ILogger<NetworkIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateLogins(sp.GetRequiredService<ILogger<Alastor.Core.Access.LoginIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateUfw(sp.GetRequiredService<ILogger<Alastor.Core.Firewall.UfwIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateAide(sp.GetRequiredService<ILogger<Alastor.Core.Integrity.AideIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateRkhunter(sp.GetRequiredService<ILogger<RkhunterIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateClamAv(sp.GetRequiredService<ServerClient>(), sp.GetRequiredService<ILogger<ClamAvIntegration>>()));
builder.Services.AddSingleton<IToolIntegration>(sp => platform.CreateVulnerabilities(sp.GetRequiredService<ServerClient>(), sp.GetRequiredService<ILogger<VulnerabilityIntegration>>()));
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
        Console.Error.WriteLine("Usage: alastor-agent enroll --server https://alastor.example.com --token sve_… [--pin SHA256] [--insecure] [--force]");
        return 2;
    }
    if (AgentConfig.Load(configPath) is not null && !Flag("--force"))
    {
        Console.WriteLine($"Already enrolled ({configPath}). Use --force to enroll again as a new host.");
        return 0;
    }
    var insecure = Flag("--insecure");
    if (serverUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !insecure && !IsPrivateTransport(serverUrl))
    {
        Console.Error.WriteLine("Refusing plain HTTP outside loopback and Tailscale. Use https:// or pass --insecure on a trusted network.");
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
        platform.CreateCrowdSec(NullLogger<CrowdSecIntegration>.Instance),
        platform.CreateBaseline(NullLogger<BaselineIntegration>.Instance),
        platform.CreateBlocklist(NullLogger<BlocklistIntegration>.Instance),
        platform.CreateVulnerabilities(null, NullLogger<VulnerabilityIntegration>.Instance),
        platform.CreateClamAv(null, NullLogger<ClamAvIntegration>.Instance),
        platform.CreateHardening(NullLogger<HardeningIntegration>.Instance),
        platform.CreateAide(NullLogger<Alastor.Core.Integrity.AideIntegration>.Instance),
        platform.CreateUfw(NullLogger<Alastor.Core.Firewall.UfwIntegration>.Instance),
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

    public UpdatesIntegration CreateUpdates(ILogger<UpdatesIntegration> logger) =>
        new(Runner, Fs, PackageManagers.For(Os.Family, Runner), State, Os, logger, TimeProvider.System);

    public Alastor.Core.Software.SoftwareIntegration CreateSoftware(ILogger<Alastor.Core.Software.SoftwareIntegration> logger) =>
        new(Runner, Fs, State, Os, logger, TimeProvider.System);

    public Alastor.Core.Storage.StorageIntegration CreateStorage(ILogger<Alastor.Core.Storage.StorageIntegration> logger) =>
        new(Runner, Fs, State, Os, StateDir, logger, TimeProvider.System);

    public HardeningIntegration CreateHardening(ILogger<HardeningIntegration> logger) =>
        new(Runner, Fs, PackageManagers.For(Os.Family, Runner), State, StateDir, logger, TimeProvider.System);

    public NetworkIntegration CreateNetwork(ILogger<NetworkIntegration> logger) => new(Runner, Fs, State, logger, TimeProvider.System);
    public Alastor.Core.Integrity.AideIntegration CreateAide(ILogger<Alastor.Core.Integrity.AideIntegration> logger) =>
        new(Runner, PackageManagers.For(Os.Family, Runner), ServiceManagers.For(Runner), State, StateDir, logger, TimeProvider.System);
    public Alastor.Core.Firewall.UfwIntegration CreateUfw(ILogger<Alastor.Core.Firewall.UfwIntegration> logger) =>
        new(Runner, PackageManagers.For(Os.Family, Runner), Os, logger, TimeProvider.System);
    public RkhunterIntegration CreateRkhunter(ILogger<RkhunterIntegration> logger) => new(Runner, PackageManagers.For(Os.Family, Runner), State, logger, TimeProvider.System);
    public Alastor.Core.Access.LoginIntegration CreateLogins(ILogger<Alastor.Core.Access.LoginIntegration> logger) => new(Runner, Fs, State, logger, TimeProvider.System);

    public VulnerabilityIntegration CreateVulnerabilities(IVulnDbSource? dbSource, ILogger<VulnerabilityIntegration> logger) =>
        new(Runner, PackageManagers.For(Os.Family, Runner), State, Os, StateDir, dbSource ?? NoVulnDb.Instance, logger, TimeProvider.System);

    public ClamAvIntegration CreateClamAv(IVulnDbSource? dbSource, ILogger<ClamAvIntegration> logger) =>
        new(Runner, Fs, PackageManagers.For(Os.Family, Runner), ServiceManagers.For(Runner), State, StateDir, dbSource ?? NoVulnDb.Instance, logger, TimeProvider.System);

    /// <summary>For CLI subcommands (uninstall) that never scan.</summary>
    private sealed class NoVulnDb : IVulnDbSource
    {
        public static readonly NoVulnDb Instance = new();
        public Task<VulnDbFetch> FetchAsync(string scanner, string? etag, string destinationPath, CancellationToken ct) =>
            Task.FromResult(new VulnDbFetch(VulnDbFetchStatus.Unavailable));
    }

    public BlocklistIntegration CreateBlocklist(ILogger<BlocklistIntegration> logger) =>
        new(Runner, Fs, PackageManagers.For(Os.Family, Runner), State, StateDir, logger, TimeProvider.System);

    public Fail2BanIntegration CreateFail2Ban(ILogger<Fail2BanIntegration> logger) =>
        new(Runner, Fs, PackageManagers.For(Os.Family, Runner), ServiceManagers.For(Runner), State, logger, TimeProvider.System);

    public CrowdSecIntegration CreateCrowdSec(ILogger<CrowdSecIntegration> logger) =>
        new(Runner, Fs, PackageManagers.For(Os.Family, Runner), ServiceManagers.For(Runner), State, logger, TimeProvider.System);

    public BaselineIntegration CreateBaseline(ILogger<BaselineIntegration> logger) =>
        new(Runner, Fs, ServiceManagers.For(Runner), State, Os, logger, TimeProvider.System);
}
