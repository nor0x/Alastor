using System.Text.Json;
using Alastor.Core.Platform;

namespace Alastor.Agent;

/// <summary>Agent-local state (log offsets, applied revisions, install provenance) in one JSON file, written atomically.</summary>
public sealed class JsonFileStateStore : IStateStore
{
    private readonly string _path;
    private readonly Dictionary<string, string> _values;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public JsonFileStateStore(string stateDir)
    {
        Directory.CreateDirectory(stateDir);
        _path = Path.Combine(stateDir, "state.json");
        _values = File.Exists(_path)
            ? JsonSerializer.Deserialize(File.ReadAllText(_path), AgentConfigJson.Default.DictionaryStringString) ?? []
            : [];
    }

    public string? Get(string key)
    {
        lock (_values) return _values.GetValueOrDefault(key);
    }

    public async Task SetAsync(string key, string? value, CancellationToken ct = default)
    {
        string json;
        lock (_values)
        {
            if (value is null ? !_values.Remove(key) : _values.TryGetValue(key, out var old) && old == value) return;
            if (value is not null) _values[key] = value;
            json = JsonSerializer.Serialize(_values, AgentConfigJson.Default.DictionaryStringString);
        }
        await _lock.WaitAsync(ct);
        try
        {
            var tmp = _path + ".tmp";
            await File.WriteAllTextAsync(tmp, json, ct);
            File.Move(tmp, _path, overwrite: true);
        }
        finally { _lock.Release(); }
    }
}
