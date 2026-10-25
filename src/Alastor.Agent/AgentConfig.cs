using System.Text.Json;
using System.Text.Json.Serialization;

// The agent supervises Linux tools (systemd, /proc, distro packages) and only targets Linux.
[assembly: System.Runtime.Versioning.SupportedOSPlatform("linux")]

namespace Alastor.Agent;

/// <summary>Written by <c>alastor-agent enroll</c> to /etc/alastor-agent/agent.json (mode 0600).</summary>
public sealed class AgentConfig
{
    public required string ServerUrl { get; set; }
    public required Guid AgentId { get; set; }

    /// <summary>{agentId}.{secret}, sent as a Bearer token. The server stores only a hash.</summary>
    public required string Credential { get; set; }

    /// <summary>Optional SHA-256 fingerprint of the server's TLS certificate (hex). When set, only that certificate is accepted.</summary>
    public string? CertificatePin { get; set; }

    /// <summary>Plain HTTP is refused unless explicitly allowed (local development only).</summary>
    public bool AllowInsecureHttp { get; set; }

    public int HeartbeatIntervalSeconds { get; set; } = 60;

    public static string DefaultPath => Environment.GetEnvironmentVariable("ALASTOR_AGENT_CONFIG") ?? "/etc/alastor-agent/agent.json";
    public static string DefaultStateDir => Environment.GetEnvironmentVariable("ALASTOR_AGENT_STATE") ?? "/var/lib/alastor-agent";

    public static AgentConfig? Load(string path) =>
        File.Exists(path) ? JsonSerializer.Deserialize(File.ReadAllText(path), AgentConfigJson.Default.AgentConfig) : null;

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, AgentConfigJson.Default.AgentConfig));
        File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(tmp, path, overwrite: true);
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(AgentConfig))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class AgentConfigJson : JsonSerializerContext;
