using System.Text;
using Sentinel.Core.Platform;

namespace Sentinel.Tests;

/// <summary>Replays canned tool outputs. Unknown commands fail loudly so tests notice unexpected side effects.</summary>
public sealed class FakeCommandRunner : ICommandRunner
{
    private readonly Dictionary<string, Func<CommandResult>> _responses = new(StringComparer.Ordinal);
    public List<string> Calls { get; } = [];
    public HashSet<string> Installed { get; } = ["fail2ban-client"];

    public FakeCommandRunner On(string commandLine, string stdout, int exitCode = 0, string stderr = "")
    {
        _responses[commandLine] = () => new CommandResult(exitCode, stdout, stderr);
        return this;
    }

    public FakeCommandRunner On(string commandLine, Func<CommandResult> response)
    {
        _responses[commandLine] = response;
        return this;
    }

    public Task<CommandResult> RunAsync(string fileName, IReadOnlyList<string> args, CommandOptions? options = null, CancellationToken ct = default)
    {
        var line = string.Join(' ', new[] { fileName }.Concat(args));
        Calls.Add(line);
        return Task.FromResult(_responses.TryGetValue(line, out var r) ? r() : new CommandResult(127, "", $"unexpected command: {line}"));
    }

    public string? Which(string fileName) => Installed.Contains(fileName) ? "/usr/bin/" + fileName : null;
}

public sealed class FakeFileSystem : IFileSystem
{
    public Dictionary<string, string> Files { get; } = new(StringComparer.Ordinal);

    public bool FileExists(string path) => Files.ContainsKey(path);
    public bool DirectoryExists(string path) => Files.Keys.Any(k => k.StartsWith(path.TrimEnd('/') + "/", StringComparison.Ordinal));
    public Task<string?> ReadAllTextAsync(string path, CancellationToken ct = default) => Task.FromResult(Files.GetValueOrDefault(path));

    public Task WriteAllTextAtomicAsync(string path, string content, UnixFileMode mode, CancellationToken ct = default)
    {
        Files[path] = content;
        return Task.CompletedTask;
    }

    public void DeleteFile(string path) => Files.Remove(path);

    public IEnumerable<string> EnumerateFiles(string directory, string pattern)
    {
        var ext = pattern.TrimStart('*');
        return Files.Keys.Where(k => Path.GetDirectoryName(k) == directory.TrimEnd('/') && k.EndsWith(ext, StringComparison.Ordinal)).Order().ToList();
    }

    public void CreateDirectory(string path) { }
    public long GetFileLength(string path) => Encoding.UTF8.GetByteCount(Files[path]);
    public Stream OpenRead(string path) => new MemoryStream(Encoding.UTF8.GetBytes(Files[path]));
    public string? GetFileIdentity(string path) => Files.TryGetValue(path, out var c) ? Convert.ToHexString(Encoding.UTF8.GetBytes(c[..Math.Min(32, c.Length)])) : null;
}

public static class Fixture
{
    public static string Read(string relative) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", relative));
}

/// <summary>
/// Test classes that start the real server share this collection, so they never run in parallel: Program.cs replaces
/// Serilog's static bootstrap logger, and two hosts starting at once race to freeze it ("The logger is already frozen").
/// </summary>
[CollectionDefinition(Name)]
public sealed class ServerHostCollection
{
    public const string Name = "Server host";
}
