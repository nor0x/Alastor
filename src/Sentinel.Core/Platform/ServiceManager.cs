namespace Sentinel.Core.Platform;

/// <summary>Starts and inspects bundled tools' daemons, using systemd on Debian/RHEL and OpenRC on Alpine.</summary>
public interface IServiceManager
{
    Task<bool> IsActiveAsync(string unit, CancellationToken ct);
    Task<bool> EnableAndStartAsync(string unit, CancellationToken ct);
    Task<bool> RestartAsync(string unit, CancellationToken ct);
    Task<bool> ReloadAsync(string unit, CancellationToken ct);
    Task<bool> DisableAndStopAsync(string unit, CancellationToken ct);
}

public static class ServiceManagers
{
    public static IServiceManager For(ICommandRunner runner) =>
        runner.Which("systemctl") is not null ? new SystemdServiceManager(runner) : new OpenRcServiceManager(runner);
}

public sealed class SystemdServiceManager(ICommandRunner runner) : IServiceManager
{
    public async Task<bool> IsActiveAsync(string unit, CancellationToken ct) =>
        (await runner.RunAsync("systemctl", ["is-active", "--quiet", unit], null, ct)).Success;

    public async Task<bool> EnableAndStartAsync(string unit, CancellationToken ct) =>
        (await runner.RunAsync("systemctl", ["enable", "--now", unit], null, ct)).Success;

    public async Task<bool> RestartAsync(string unit, CancellationToken ct) =>
        (await runner.RunAsync("systemctl", ["restart", unit], null, ct)).Success;

    public async Task<bool> ReloadAsync(string unit, CancellationToken ct) =>
        (await runner.RunAsync("systemctl", ["reload", unit], null, ct)).Success;

    public async Task<bool> DisableAndStopAsync(string unit, CancellationToken ct) =>
        (await runner.RunAsync("systemctl", ["disable", "--now", unit], null, ct)).Success;
}

public sealed class OpenRcServiceManager(ICommandRunner runner) : IServiceManager
{
    public async Task<bool> IsActiveAsync(string unit, CancellationToken ct) =>
        (await runner.RunAsync("rc-service", [unit, "status"], null, ct)).Success;

    public async Task<bool> EnableAndStartAsync(string unit, CancellationToken ct)
    {
        await runner.RunAsync("rc-update", ["add", unit, "default"], null, ct);
        return (await runner.RunAsync("rc-service", [unit, "start"], null, ct)).Success;
    }

    public async Task<bool> RestartAsync(string unit, CancellationToken ct) =>
        (await runner.RunAsync("rc-service", [unit, "restart"], null, ct)).Success;

    public async Task<bool> ReloadAsync(string unit, CancellationToken ct) =>
        (await runner.RunAsync("rc-service", [unit, "reload"], null, ct)).Success;

    public async Task<bool> DisableAndStopAsync(string unit, CancellationToken ct)
    {
        await runner.RunAsync("rc-update", ["del", unit, "default"], null, ct);
        return (await runner.RunAsync("rc-service", [unit, "stop"], null, ct)).Success;
    }
}
