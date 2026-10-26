using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using Alastor.Core.Contracts;
using Alastor.Server;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Endpoints;
using Alastor.Server.Hubs;
using Alastor.Server.Services;
using Alastor.Server.Services.Alerts;
using Alastor.Server.Services.ThreatFeed;
using Alastor.Server.Services.Blocklists;
using Alastor.Server.Services.Vulnerabilities;
using Alastor.Server.Workers;
using Serilog;

// `alastor-server healthcheck`: for container HEALTHCHECKs, where the runtime image has no curl.
if (args is ["healthcheck", ..])
{
    var port = Environment.GetEnvironmentVariable("ALASTOR_HEALTHCHECKPORT") ?? "8080";
    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
    try
    {
        return (await http.GetAsync($"http://127.0.0.1:{port}/healthz")).IsSuccessStatusCode ? 0 : 1;
    }
    catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

Log.Logger = new LoggerConfiguration().WriteTo.Console().CreateBootstrapLogger();

var builder = WebApplication.CreateBuilder(args);

// ALASTOR_DATADIR, ALASTOR_ADMINPASSWORD, ... map onto AlastorOptions. So does the "Alastor" section of appsettings.json.
builder.Configuration.AddEnvironmentVariables("ALASTOR_");
var options = new AlastorOptions();
builder.Configuration.GetSection(AlastorOptions.Section).Bind(options);
builder.Configuration.Bind(options);
if (options.Validate() is { Count: > 0 } configErrors)
{
    foreach (var e in configErrors) Log.Fatal("Invalid configuration: {Error}", e);
    return 1;
}
// `alastor-server security-check`: the self-check's configuration checks (listen address, TLS, allowlists, file
// permissions) without starting the server. The installer prints it; exit code 1 when anything fails.
if (args is ["security-check", ..])
{
    var urls = builder.Configuration["urls"] is { Length: > 0 } u ? u : Environment.GetEnvironmentVariable("ASPNETCORE_URLS") ?? "http://127.0.0.1:8080";
    var checks = Alastor.Server.Services.Security.SelfChecks.Static(
        Alastor.Server.Services.Security.SelfChecks.Gather(urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), options));
    foreach (var c in checks)
    {
        Console.WriteLine($"{c.Status.ToString().ToLowerInvariant(),-5} {c.Title}: {c.Detail}");
        if (c.Fix is not null && c.Status is Alastor.Server.Services.Security.CheckStatus.Warn or Alastor.Server.Services.Security.CheckStatus.Fail)
            Console.WriteLine($"      fix: {c.Fix}");
    }
    return checks.Any(c => c.Status == Alastor.Server.Services.Security.CheckStatus.Fail) ? 1 : 0;
}

// The data dir holds the database, JWT key and data-protection keys: owner-only.
if (OperatingSystem.IsWindows()) Directory.CreateDirectory(options.DataDir);
else Directory.CreateDirectory(options.DataDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
builder.Services.AddSingleton(Options.Create(options));

if (string.IsNullOrEmpty(builder.Configuration["urls"]) && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ASPNETCORE_URLS")))
    builder.WebHost.UseUrls("http://127.0.0.1:8080"); // loopback unless told otherwise: put a TLS proxy or the tailnet in front

builder.Host.UseSerilog((ctx, lc) => lc
    // Sensible defaults baked in so the single binary needs no appsettings.json. Serilog config keys still override.
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft.AspNetCore", Serilog.Events.LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.EntityFrameworkCore", Serilog.Events.LogEventLevel.Warning)
    .MinimumLevel.Override("System.Net.Http.HttpClient", Serilog.Events.LogEventLevel.Warning)
    // Keys are stored in the owner-only data dir; the "unencrypted at rest" warning is expected on Linux.
    .MinimumLevel.Override("Microsoft.AspNetCore.DataProtection", Serilog.Events.LogEventLevel.Error)
    .ReadFrom.Configuration(ctx.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"));

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddDataProtection()
    .SetApplicationName("alastor")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(options.DataDir, "keys")));

// Compose files pass unset variables as empty strings; treat those as unset.
if (string.IsNullOrWhiteSpace(options.ConnectionString)) options.ConnectionString = null;
if (options.DatabaseProvider.Equals("postgres", StringComparison.OrdinalIgnoreCase))
{
    var cs = options.ConnectionString ?? throw new InvalidOperationException("ALASTOR_CONNECTIONSTRING is required for PostgreSQL.");
    builder.Services.AddDbContext<AlastorDbContext, PostgresAlastorDbContext>(o => o.UseNpgsql(cs));
}
else
{
    var cs = options.ConnectionString ?? $"Data Source={Path.Combine(options.DataDir, "alastor.db")}";
    builder.Services.AddDbContext<AlastorDbContext, SqliteAlastorDbContext>(o => o.UseSqlite(cs));
}

builder.Services.AddAlastorAuth(new JwtIssuer(JwtIssuer.LoadOrCreateKey(options.DataDir, builder.Configuration["JWTKEY"]), options.SessionLifetimeValue));
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = options.AuthRateLimitPerMinute, Window = TimeSpan.FromMinutes(1) }));
});

builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
    o.SerializerOptions.TypeInfoResolverChain.Insert(0, AgentJsonContext.Default);
});
builder.Services.AddSignalR().AddJsonProtocol(o => o.PayloadSerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    // Trust X-Forwarded-* from loopback only (Caddy/nginx on the same box). The remote IP feeds the self-ban guard.
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

builder.Services.AddScoped<PolicyService>();
builder.Services.AddScoped<CommandService>();
builder.Services.AddScoped<EventIngestService>();
builder.Services.AddScoped<IEventSink, AlertPipeline>();
builder.Services.AddSingleton<AlertQueue>();
builder.Services.AddSingleton<ChannelSecrets>();
builder.Services.AddSingleton<ISmtpTransport, MailKitSmtpTransport>();
builder.Services.AddSingleton<IChannelSender, EmailSender>();
builder.Services.AddSingleton<IChannelSender, WebhookSender>();
builder.Services.AddSingleton<IChannelSender, NtfySender>();
builder.Services.AddSingleton<NotificationDispatcher>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<NotificationDispatcher>());
builder.Services.AddHttpClient(WebhookSender.HttpClientName, c =>
{
    c.Timeout = TimeSpan.FromSeconds(15);
    c.DefaultRequestHeaders.UserAgent.ParseAdd($"Alastor/{typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "dev"} (notifications)");
});
builder.Services.AddSingleton<DashboardNotifier>();
builder.Services.AddHostedService<PresenceWorker>();
builder.Services.AddHostedService<RetentionWorker>();
builder.Services.AddScoped<Alastor.Server.Services.Posture.PostureService>();
builder.Services.AddScoped<Alastor.Server.Services.Issues.IssueService>();
builder.Services.AddScoped<HostStateService>();
builder.Services.AddScoped<Alastor.Server.Services.Access.LoginService>();
builder.Services.AddHostedService<PostureWorker>();
builder.Services.AddScoped<ThreatFeedService>();
builder.Services.AddHttpClient(ThreatFeedService.HttpClientName, c =>
{
    c.Timeout = TimeSpan.FromSeconds(90); // NVD pages of 2000 CVEs can be slow
    c.MaxResponseContentBufferSize = 64 * 1024 * 1024;
    c.DefaultRequestHeaders.UserAgent.ParseAdd($"Alastor/{typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "dev"} (self-hosted; threat feed)");
}).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AutomaticDecompression = System.Net.DecompressionMethods.All });
if (options.ThreatFeedEnabled) builder.Services.AddHostedService<ThreatFeedWorker>();
builder.Services.AddScoped<BlocklistService>();
builder.Services.AddSingleton<BlocklistMerger>();
builder.Services.AddHttpClient(BlocklistService.HttpClientName, c =>
{
    c.Timeout = TimeSpan.FromSeconds(60);
    c.MaxResponseContentBufferSize = 32 * 1024 * 1024;
    c.DefaultRequestHeaders.UserAgent.ParseAdd($"Alastor/{typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "dev"} (self-hosted; blocklists)");
}).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AutomaticDecompression = System.Net.DecompressionMethods.All });
if (options.BlocklistsEnabled) builder.Services.AddHostedService<BlocklistWorker>();
builder.Services.AddSingleton<VulnDbMirror>();
builder.Services.AddScoped<VulnerabilityService>();
builder.Services.AddScoped<Alastor.Server.Services.Hardening.HardeningService>();
builder.Services.AddScoped<Alastor.Server.Services.Network.NetworkService>();
builder.Services.AddScoped<Alastor.Server.Services.Malware.MalwareService>();
builder.Services.AddScoped<Alastor.Server.Services.Integrity.IntegrityService>();
builder.Services.AddHttpClient(VulnDbMirror.HttpClientName, c =>
{
    c.Timeout = Timeout.InfiniteTimeSpan; // 100-200 MB archives; each request is bounded by the worker's token
    c.DefaultRequestHeaders.UserAgent.ParseAdd($"Alastor/{typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "dev"} (self-hosted; vulnerability db mirror)");
});
if (options.VulnDbEnabled) builder.Services.AddHostedService<VulnDbWorker>();
builder.Services.AddScoped<Alastor.Server.Services.Software.SoftwareService>();
builder.Services.AddScoped<Alastor.Server.Services.Storage.StorageService>();
builder.Services.AddScoped<Alastor.Server.Services.Storage.ServerDataService>();
builder.Services.AddSingleton<Alastor.Server.Services.Security.SelfCheckService>();
builder.Services.AddHostedService<Alastor.Server.Services.Security.SelfCheckStartupLogger>();
builder.Services.AddScoped<Alastor.Server.Services.Osv.OsvService>();
builder.Services.AddHttpClient(Alastor.Server.Services.Osv.OsvService.HttpClientName, c =>
{
    c.Timeout = TimeSpan.FromSeconds(60);
    c.MaxResponseContentBufferSize = 32 * 1024 * 1024;
    c.DefaultRequestHeaders.UserAgent.ParseAdd($"Alastor/{typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "dev"} (self-hosted; software inventory)");
}).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AutomaticDecompression = System.Net.DecompressionMethods.All });
if (options.OsvEnabled) builder.Services.AddHostedService<OsvWorker>();
builder.Services.AddSingleton<Alastor.Server.Services.Updates.UpdateCheckService>();
builder.Services.AddHttpClient(Alastor.Server.Services.Updates.UpdateCheckService.HttpClientName, c =>
{
    c.Timeout = TimeSpan.FromSeconds(15);
    c.MaxResponseContentBufferSize = 1024 * 1024;
    c.DefaultRequestHeaders.UserAgent.ParseAdd($"Alastor/{typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "dev"} (self-hosted; update check)");
});
if (options.UpdateCheckEnabled) builder.Services.AddHostedService<UpdateCheckWorker>();

var app = builder.Build();

try
{
    await Bootstrap.RunAsync(app.Services);
}
catch (InvalidOperationException ex) when (ex.Message.StartsWith("ALASTOR_", StringComparison.Ordinal))
{
    Log.Fatal("Invalid configuration: {Error}", ex.Message);
    return 1;
}

app.UseForwardedHeaders();
app.UseNetworkAllowLists();
app.UseSecurityHeaders();
app.UseExceptionHandler();
app.UseSerilogRequestLogging(o => o.GetLevel = (ctx, _, ex) =>
    // A 503 with Retry-After is a planned "not yet" (vulnerability database still mirroring), not a failure.
    ex is null && ctx.Response.StatusCode == 503 && ctx.Response.Headers.RetryAfter.Count > 0 ? Serilog.Events.LogEventLevel.Debug
    : ex is not null || ctx.Response.StatusCode >= 500 ? Serilog.Events.LogEventLevel.Error
    : ctx.Request.Path.StartsWithSegments("/api/agent") ? Serilog.Events.LogEventLevel.Verbose
    : Serilog.Events.LogEventLevel.Debug);

// The SPA is embedded in the binary (see Alastor.Server.csproj), so the server ships as one file.
var web = new ManifestEmbeddedFileProvider(typeof(Program).Assembly, "wwwroot");
app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = web });
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = web,
    OnPrepareResponse = ctx =>
    {
        // Vite emits content-hashed file names under /assets, so they can be cached forever.
        if (ctx.Context.Request.Path.StartsWithSegments("/assets"))
            ctx.Context.Response.Headers.CacheControl = "public, max-age=31536000, immutable";
    },
});

app.UseRateLimiter();
app.UseAuthentication();
app.UseCsrfHeaderCheck();
app.UseAuthorization();

app.MapOpenApi("/openapi/{documentName}.json").RequireAuthorization(AuthPolicies.Reader);
app.MapMetaEndpoints();
app.MapAuthEndpoints();
app.MapAgentEndpoints();
app.MapHostEndpoints();
app.MapBaselineEndpoints();
app.MapAdminEndpoints();
app.MapBanEndpoints();
app.MapPolicyEndpoints();
app.MapEventEndpoints();
app.MapFeedEndpoints();
app.MapNotificationEndpoints();
app.MapBlocklistEndpoints();
app.MapReportEndpoints();
app.MapVulnerabilityEndpoints();
app.MapHardeningEndpoints();
app.MapNetworkEndpoints();
app.MapMalwareEndpoints();
app.MapStatsEndpoints();
app.MapIssueEndpoints();
app.MapAccessEndpoints();
app.MapIntegrityEndpoints();
app.MapSoftwareEndpoints();
app.MapStorageEndpoints();
app.MapSystemEndpoints();
app.MapHub<AgentHub>("/hubs/agent");
app.MapHub<DashboardHub>("/hubs/dashboard");
app.MapInstallScripts();

// Client-side routing: unknown non-API paths serve index.html.
app.MapFallback(async ctx =>
{
    if (ctx.Request.Path.StartsWithSegments("/api") || ctx.Request.Path.StartsWithSegments("/hubs"))
    {
        ctx.Response.StatusCode = StatusCodes.Status404NotFound;
        return;
    }
    var index = web.GetFileInfo("index.html");
    ctx.Response.ContentType = "text/html; charset=utf-8";
    ctx.Response.Headers.CacheControl = "no-cache";
    await using var s = index.CreateReadStream();
    await s.CopyToAsync(ctx.Response.Body);
});

app.Run();
return 0;

public partial class Program;
