using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Sentinel.Core.Contracts;

namespace Sentinel.Agent;

/// <summary>Reads host metrics straight from /proc. The values are cheap to read and need no extra tools.</summary>
public sealed class HostMetricsCollector
{
    private (ulong Idle, ulong Total)? _lastCpu;

    public async Task<HostMetrics> CollectAsync(CancellationToken ct)
    {
        var cpu = await ReadCpuPercentAsync(ct);
        var (memTotal, memAvail) = await ReadMemInfoAsync(ct);
        var root = new DriveInfo("/");
        var load = (await ReadAsync("/proc/loadavg", ct)).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var uptime = (await ReadAsync("/proc/uptime", ct)).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return new HostMetrics(
            cpu,
            memTotal,
            memTotal - memAvail,
            root.TotalSize,
            root.TotalSize - root.AvailableFreeSpace,
            Parse(load, 0), Parse(load, 1), Parse(load, 2),
            (long)Parse(uptime, 0));
    }

    public static async Task<string> KernelVersionAsync(CancellationToken ct) => (await ReadAsync("/proc/sys/kernel/osrelease", ct)).Trim();

    public static IReadOnlyList<string> IpAddresses() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Select(a => a.Address)
            .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6 && !a.IsIPv6LinkLocal)
            .Select(a => a.ToString())
            .Distinct()
            .ToList();

    private async Task<double> ReadCpuPercentAsync(CancellationToken ct)
    {
        // First line of /proc/stat: cpu user nice system idle iowait irq softirq steal ...
        var first = (await ReadAsync("/proc/stat", ct)).Split('\n')[0];
        var f = first.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(v => ulong.Parse(v, CultureInfo.InvariantCulture)).ToArray();
        if (f.Length < 5) return 0;
        var idle = f[3] + f[4];
        var total = f.Take(8).Aggregate(0UL, (a, b) => a + b);
        var prev = _lastCpu;
        _lastCpu = (idle, total);
        if (prev is not { } p || total <= p.Total) return 0;
        return Math.Round(100.0 * (1 - (double)(idle - p.Idle) / (total - p.Total)), 1);
    }

    private static async Task<(long Total, long Available)> ReadMemInfoAsync(CancellationToken ct)
    {
        long total = 0, avail = 0;
        foreach (var line in (await ReadAsync("/proc/meminfo", ct)).Split('\n'))
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            if (parts[0] == "MemTotal:") total = long.Parse(parts[1], CultureInfo.InvariantCulture) * 1024;
            else if (parts[0] == "MemAvailable:") avail = long.Parse(parts[1], CultureInfo.InvariantCulture) * 1024;
        }
        return (total, avail);
    }

    private static async Task<string> ReadAsync(string path, CancellationToken ct) =>
        File.Exists(path) ? await File.ReadAllTextAsync(path, ct) : "";

    private static double Parse(string[] parts, int i) =>
        parts.Length > i && double.TryParse(parts[i], NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : 0;
}

public static class AgentInfo
{
    public static string Version { get; } =
        typeof(AgentInfo).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion.Split('+')[0] ?? "dev";
}
