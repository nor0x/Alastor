using System.Diagnostics;
using System.Text;

namespace Sentinel.Core.Platform;

public sealed record CommandResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Success => ExitCode == 0;
    public string CombinedOutput => string.IsNullOrWhiteSpace(StdErr) ? StdOut : $"{StdOut}\n{StdErr}".Trim();
}

/// <summary>
/// Every call out to a bundled tool goes through this interface. Tests replace it with recorded outputs,
/// so integration logic can be checked without a real fail2ban, apt or systemd.
/// </summary>
public interface ICommandRunner
{
    /// <summary>Runs <paramref name="fileName"/> with literal arguments (never through a shell).</summary>
    Task<CommandResult> RunAsync(string fileName, IReadOnlyList<string> args, CommandOptions? options = null, CancellationToken ct = default);

    /// <summary>Resolves an executable on PATH, or returns null.</summary>
    string? Which(string fileName);
}

public sealed record CommandOptions
{
    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(2);
    public IReadOnlyDictionary<string, string>? Environment { get; init; }
}

public sealed class ProcessCommandRunner : ICommandRunner
{
    private static readonly string[] SearchPath =
        (System.Environment.GetEnvironmentVariable("PATH") ?? "")
        .Split(':', StringSplitOptions.RemoveEmptyEntries)
        .Concat(["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"])
        .Distinct()
        .ToArray();

    public async Task<CommandResult> RunAsync(string fileName, IReadOnlyList<string> args, CommandOptions? options = null, CancellationToken ct = default)
    {
        options ??= new CommandOptions();
        var psi = new ProcessStartInfo(Which(fileName) ?? fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        // Tools must produce stable, parseable output regardless of the host locale.
        psi.Environment["LC_ALL"] = "C";
        psi.Environment["LANG"] = "C";
        if (options.Environment is not null)
            foreach (var (k, v) in options.Environment) psi.Environment[k] = v;

        using var proc = new Process { StartInfo = psi };
        try
        {
            proc.Start();
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return new CommandResult(127, "", ex.Message);
        }
        proc.StandardInput.Close();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(options.Timeout);
        var stdout = proc.StandardOutput.ReadToEndAsync(timeout.Token);
        var stderr = proc.StandardError.ReadToEndAsync(timeout.Token);
        try
        {
            await proc.WaitForExitAsync(timeout.Token);
            return new CommandResult(proc.ExitCode, await stdout, await stderr);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            if (ct.IsCancellationRequested) throw;
            return new CommandResult(124, "", $"{fileName} timed out after {options.Timeout}");
        }
    }

    public string? Which(string fileName)
    {
        if (fileName.Contains('/')) return File.Exists(fileName) ? fileName : null;
        foreach (var dir in SearchPath)
        {
            var candidate = Path.Combine(dir, fileName);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
}

public static class CommandRunnerExtensions
{
    public static Task<CommandResult> RunAsync(this ICommandRunner runner, string fileName, params string[] args) =>
        runner.RunAsync(fileName, args, null, CancellationToken.None);

    public static string Describe(string fileName, IEnumerable<string> args)
    {
        var sb = new StringBuilder(fileName);
        foreach (var a in args) sb.Append(' ').Append(a.Contains(' ') ? $"'{a}'" : a);
        return sb.ToString();
    }
}
