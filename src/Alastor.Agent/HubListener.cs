using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Alastor.Core.Contracts;

namespace Alastor.Agent;

/// <summary>
/// Holds a SignalR connection to /hubs/agent and turns server "Wake" messages into immediate supervisor ticks.
/// SignalR negotiates WebSockets, then Server-Sent Events, then long polling. If even that fails, the
/// supervisor's 60 s heartbeat still delivers everything, only later.
/// </summary>
public sealed class HubListener(AgentConfig config, Supervisor supervisor, ILogger<HubListener> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var connection = new HubConnectionBuilder()
            .WithUrl(new Uri(new Uri(config.ServerUrl.TrimEnd('/') + "/"), "hubs/agent"), o =>
            {
                o.AccessTokenProvider = () => Task.FromResult<string?>(config.Credential);
                o.HttpMessageHandlerFactory = _ => ServerClient.CreateHandler(config.CertificatePin);
                o.WebSocketConfiguration = ws =>
                {
                    if (config.CertificatePin is { } pin)
                        ws.RemoteCertificateValidationCallback = (_, cert, _, _) => cert is not null &&
                            string.Equals(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cert.GetRawCertData())), pin.Replace(":", ""), StringComparison.OrdinalIgnoreCase);
                };
            })
            .AddJsonProtocol(o => o.PayloadSerializerOptions.TypeInfoResolverChain.Insert(0, AgentJsonContext.Default))
            .WithAutomaticReconnect(new ForeverRetryPolicy())
            .Build();

        connection.On<string>(AgentHubMethods.Wake, reason =>
        {
            logger.LogDebug("Wake from server: {Reason}", reason);
            supervisor.Wake(reason);
        });
        connection.Reconnected += _ =>
        {
            logger.LogInformation("Live channel reconnected");
            supervisor.Wake("reconnected");
            return Task.CompletedTask;
        };

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await connection.StartAsync(ct);
                logger.LogInformation("Live channel connected");
                break;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                logger.LogDebug("Live channel unavailable ({Message}); relying on heartbeat polling", ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
        }

        try { await Task.Delay(Timeout.Infinite, ct); }
        catch (OperationCanceledException) { }
        await connection.DisposeAsync();
    }

    private sealed class ForeverRetryPolicy : IRetryPolicy
    {
        public TimeSpan? NextRetryDelay(RetryContext ctx) =>
            TimeSpan.FromSeconds(Math.Min(60, Math.Pow(2, Math.Min(ctx.PreviousRetryCount, 6))) + Random.Shared.NextDouble() * 3);
    }
}
