namespace Alastor.Core.Platform;

/// <summary>Small persistent key/value store for agent-local state, such as log offsets, applied revisions and install provenance.</summary>
public interface IStateStore
{
    string? Get(string key);
    Task SetAsync(string key, string? value, CancellationToken ct = default);
}

public sealed class InMemoryStateStore : IStateStore
{
    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
    public string? Get(string key) { lock (_values) return _values.GetValueOrDefault(key); }

    public Task SetAsync(string key, string? value, CancellationToken ct = default)
    {
        lock (_values)
        {
            if (value is null) _values.Remove(key);
            else _values[key] = value;
        }
        return Task.CompletedTask;
    }
}
