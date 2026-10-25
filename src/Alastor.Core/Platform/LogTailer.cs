using System.Text;

namespace Alastor.Core.Platform;

/// <summary>
/// Incrementally reads a log file. It persists its offset in <see cref="IStateStore"/>, handles rotation and
/// truncation, and never replays history on first start: the first read starts at the end of the file.
/// </summary>
public sealed class LogTailer(IFileSystem fs, IStateStore state, string stateKey)
{
    private const int MaxBytesPerRead = 4 * 1024 * 1024;

    public async Task<IReadOnlyList<string>> ReadNewLinesAsync(string path, CancellationToken ct)
    {
        if (!fs.FileExists(path)) return [];
        var identity = fs.GetFileIdentity(path);
        var length = fs.GetFileLength(path);
        var savedIdentity = state.Get($"{stateKey}.id");
        var offset = long.TryParse(state.Get($"{stateKey}.offset"), out var o) ? o : -1;

        if (offset < 0)
        {
            await SaveAsync(identity, length, ct);
            return [];
        }
        // Rotated (different file) or truncated: start from the top of the new file.
        if (!SameFile(savedIdentity, identity) || length < offset) offset = 0;
        if (length == offset) return [];

        var lines = new List<string>();
        await using var stream = fs.OpenRead(path);
        stream.Seek(offset, SeekOrigin.Begin);
        var toRead = (int)Math.Min(length - offset, MaxBytesPerRead);
        var buffer = new byte[toRead];
        var read = await stream.ReadAtLeastAsync(buffer, toRead, throwOnEndOfStream: false, ct);
        // Only consume complete lines. A partial trailing line is picked up on the next call.
        var lastNewline = Array.LastIndexOf(buffer, (byte)'\n', read - 1);
        if (lastNewline < 0) return [];
        var text = Encoding.UTF8.GetString(buffer, 0, lastNewline);
        lines.AddRange(text.Split('\n', StringSplitOptions.RemoveEmptyEntries));
        await SaveAsync(identity, offset + lastNewline + 1, ct);
        return lines;
    }

    // The identity is a prefix of the file's first bytes, so it can grow while a fresh file is under 64 bytes.
    private static bool SameFile(string? saved, string? current) =>
        saved is not null && current is not null &&
        (current.StartsWith(saved, StringComparison.Ordinal) || saved.StartsWith(current, StringComparison.Ordinal));

    private async Task SaveAsync(string? identity, long offset, CancellationToken ct)
    {
        await state.SetAsync($"{stateKey}.id", identity, ct);
        await state.SetAsync($"{stateKey}.offset", offset.ToString(System.Globalization.CultureInfo.InvariantCulture), ct);
    }
}
