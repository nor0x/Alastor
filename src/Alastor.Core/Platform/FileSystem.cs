namespace Alastor.Core.Platform;

/// <summary>The small slice of file IO the integrations need, swappable with an in-memory fake in tests.</summary>
public interface IFileSystem
{
    bool FileExists(string path);
    bool DirectoryExists(string path);
    Task<string?> ReadAllTextAsync(string path, CancellationToken ct = default);

    /// <summary>Writes to a temp file next to the target, then renames over it, so readers never see a half-written file.</summary>
    Task WriteAllTextAtomicAsync(string path, string content, UnixFileMode mode, CancellationToken ct = default);
    void DeleteFile(string path);
    IEnumerable<string> EnumerateFiles(string directory, string pattern);
    void CreateDirectory(string path);
    long GetFileLength(string path);
    Stream OpenRead(string path);

    /// <summary>A value that changes when a file is replaced: a hex prefix of its first bytes, which grows while the file is young. Used to detect log rotation.</summary>
    string? GetFileIdentity(string path);

    /// <summary>Permission bits of a file, or null if it doesn't exist.</summary>
    UnixFileMode? GetUnixFileMode(string path);

    /// <summary>The path itself (not what it points to) is a symbolic link.</summary>
    bool IsSymbolicLink(string path);
}

public sealed class PhysicalFileSystem : IFileSystem
{
    public bool FileExists(string path) => File.Exists(path);
    public bool DirectoryExists(string path) => Directory.Exists(path);

    public async Task<string?> ReadAllTextAsync(string path, CancellationToken ct = default) =>
        File.Exists(path) ? await File.ReadAllTextAsync(path, ct) : null;

    public async Task WriteAllTextAtomicAsync(string path, string content, UnixFileMode mode, CancellationToken ct = default)
    {
        var dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        // The leading dot and .tmp suffix keep glob-based config loaders (jail.d/*.local) from picking this up.
        var tmp = Path.Combine(dir, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Options = FileOptions.Asynchronous };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = mode;
        await using (var fs = new FileStream(tmp, options))
        await using (var writer = new StreamWriter(fs))
        {
            await writer.WriteAsync(content.AsMemory(), ct);
            await writer.FlushAsync(ct);
            fs.Flush(flushToDisk: true);
        }
        File.Move(tmp, path, overwrite: true);
    }

    public void DeleteFile(string path)
    {
        if (File.Exists(path)) File.Delete(path);
    }

    public IEnumerable<string> EnumerateFiles(string directory, string pattern) =>
        Directory.Exists(directory) ? Directory.EnumerateFiles(directory, pattern).Order(StringComparer.Ordinal) : [];

    public void CreateDirectory(string path) => Directory.CreateDirectory(path);
    public long GetFileLength(string path) => new FileInfo(path).Length;

    public Stream OpenRead(string path) =>
        new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.Asynchronous);

    public string? GetFileIdentity(string path)
    {
        if (!File.Exists(path)) return null;
        // .NET has no inode API. The first bytes of a log (its first timestamped line) change when logrotate swaps the file.
        Span<byte> head = stackalloc byte[64];
        int read;
        using (var s = OpenRead(path)) read = s.Read(head);
        return Convert.ToHexString(head[..read]);
    }

    public UnixFileMode? GetUnixFileMode(string path) =>
        File.Exists(path) && !OperatingSystem.IsWindows() ? File.GetUnixFileMode(path) : null;

    // lstat-based: true for a dangling link too, and for a link to a directory.
    public bool IsSymbolicLink(string path) => new FileInfo(path).LinkTarget is not null;
}
