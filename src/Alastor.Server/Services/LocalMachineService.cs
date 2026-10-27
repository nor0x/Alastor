using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Alastor.Server.Data;

namespace Alastor.Server.Services;

/// <summary>
/// The machine the server runs on: its Alastor server and agent services, and start/stop requests for them. The server runs
/// sandboxed as its own user and never changes services itself: it drops a request into <see cref="AlastorOptions.ControlDir"/>,
/// and the installer's root <c>alastor-control.path</c> unit hands it to <c>alastor apply-request</c>, which accepts only
/// <see cref="Requests"/>. The same list is in install/alastor.sh.
/// </summary>
public sealed class LocalMachineService(IOptions<AlastorOptions> options)
{
    public static readonly string[] Requests = ["server stop", "server restart", "agent start", "agent stop", "agent restart"];

    /// <param name="State">systemd's ActiveState (<c>active</c>, <c>inactive</c>, <c>failed</c>, …), or <c>unknown</c>.</param>
    public sealed record ServiceState(bool Installed, string State, bool StartsAtBoot);

    /// <param name="Controllable">Start/stop requests are carried out here (installed with install.sh under systemd).</param>
    /// <param name="AgentHostId">The host the local agent enrolled as (matched by /etc/machine-id).</param>
    public sealed record LocalMachineDto(
        string Hostname, bool Controllable, DateTime ServerStartedAt, ServiceState Server, ServiceState Agent,
        Guid? AgentHostId, string? AgentHostName, bool? AgentOnline);

    private static readonly DateTime StartedAt = Process.GetCurrentProcess().StartTime.ToUniversalTime();

    public bool Controllable => options.Value.ControlDir is { Length: > 0 } dir && Directory.Exists(dir);

    public static bool IsInstalled(string target) => File.Exists($"/etc/systemd/system/alastor-{target}.service");

    public async Task<LocalMachineDto> GetAsync(AlastorDbContext db, CancellationToken ct)
    {
        var machineId = File.Exists("/etc/machine-id") ? (await File.ReadAllTextAsync("/etc/machine-id", ct)).Trim() : null;
        var host = string.IsNullOrEmpty(machineId) ? null : await db.Hosts.AsNoTracking()
            .Where(h => h.MachineId == machineId)
            .OrderByDescending(h => h.LastSeenAt)
            .Select(h => new { h.Id, h.Name, h.IsOnline })
            .FirstOrDefaultAsync(ct);
        return new LocalMachineDto(Environment.MachineName, Controllable, StartedAt,
            await StateAsync("server", ct), await StateAsync("agent", ct), host?.Id, host?.Name, host?.IsOnline);
    }

    /// <summary>Hands a request to the control unit. The rename makes it appear whole, never half-written.</summary>
    public async Task RequestAsync(string request)
    {
        if (!Requests.Contains(request)) throw new ArgumentOutOfRangeException(nameof(request));
        var dir = options.Value.ControlDir;
        var tmp = Path.Combine(dir, "request.tmp");
        await File.WriteAllTextAsync(tmp, request + "\n");
        File.Move(tmp, Path.Combine(dir, "request"), overwrite: true);
    }

    private static async Task<ServiceState> StateAsync(string target, CancellationToken ct)
    {
        if (!IsInstalled(target)) return new(false, "not installed", false);
        var unit = "alastor-" + target;
        // Reading a unit's state needs no privileges.
        var state = await SystemctlAsync(ct, "is-active", unit) ?? "unknown";
        var boot = await SystemctlAsync(ct, "is-enabled", unit);
        return new(true, state, boot == "enabled");
    }

    private static async Task<string?> SystemctlAsync(CancellationToken ct, params string[] args)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var p = Process.Start(new ProcessStartInfo("systemctl", args) { RedirectStandardOutput = true, RedirectStandardError = true });
            if (p is null) return null;
            var output = (await p.StandardOutput.ReadToEndAsync(timeout.Token)).Trim();
            await p.WaitForExitAsync(timeout.Token);
            return output.Length > 0 ? output : null;
        }
        // No systemctl (Docker, Windows dev), or it hung.
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return null;
        }
    }
}
