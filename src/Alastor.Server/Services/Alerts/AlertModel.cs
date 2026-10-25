using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Alastor.Core.Events;
using Alastor.Core.Policy;
using Alastor.Server.Data;

namespace Alastor.Server.Services.Alerts;

/// <summary>
/// Leaky-bucket dedup. Each alert key (host + the event's dedup key) has a bucket that holds up to
/// <c>burst</c> notifications and drains at one per <c>window</c>. An event that fits in the bucket is sent; one that
/// doesn't is suppressed and counted, and the count rides along with the next notification for that key.
/// A more severe event than the last one sent always goes out, so escalation is never hidden.
/// </summary>
public static class AlertBucketMath
{
    public static bool Admit(AlertBucket bucket, Severity severity, DateTime now, TimeSpan window, int burst)
    {
        var elapsed = bucket.UpdatedAt == default ? TimeSpan.Zero : now - bucket.UpdatedAt;
        bucket.Level = Math.Max(0, bucket.Level - Math.Max(0, elapsed.TotalSeconds) / window.TotalSeconds);
        bucket.UpdatedAt = now;
        var escalation = bucket.LastNotifiedAt is not null && severity > bucket.LastSeverity;
        if (bucket.Level + 1 <= burst + 1e-9 || escalation)
        {
            bucket.Level = Math.Min(burst, bucket.Level + 1);
            bucket.LastNotifiedAt = now;
            bucket.LastSeverity = severity;
            return true;
        }
        bucket.Suppressed++;
        return false;
    }

    public static string Key(Guid? hostId, string dedupKey) => $"{hostId?.ToString("N") ?? "server"}|{dedupKey}";
}

/// <summary>Type-specific channel settings. Stored encrypted; secrets never leave the server (see <see cref="Masked"/>).</summary>
public sealed record ChannelConfig
{
    // email
    public string? SmtpHost { get; init; }
    public int? SmtpPort { get; init; }

    /// <summary><c>starttls</c> (default), <c>ssl</c> (implicit TLS, usually port 465) or <c>none</c>.</summary>
    public string? SmtpSecurity { get; init; }

    public string? SmtpUsername { get; init; }
    public string? SmtpPassword { get; init; }
    public string? From { get; init; }
    public List<string>? To { get; init; }

    // webhook
    public string? Url { get; init; }

    /// <summary><c>json</c> (Alastor payload), <c>slack</c> (Slack and Mattermost incoming webhooks) or <c>discord</c>.</summary>
    public string? Format { get; init; }

    /// <summary>HMAC-SHA256 key; when set, requests carry <c>X-Alastor-Signature: sha256=&lt;hex&gt;</c> of the body.</summary>
    public string? Secret { get; init; }

    // ntfy
    public string? NtfyServer { get; init; }
    public string? Topic { get; init; }
    public string? Token { get; init; }

    public static readonly string[] SecretFields = [nameof(SmtpPassword), nameof(Secret), nameof(Token)];
    public static readonly string[] WebhookFormats = ["json", "slack", "discord"];
    public static readonly string[] SmtpSecurityModes = ["starttls", "ssl", "none"];

    /// <summary>The config without secrets, for the dashboard.</summary>
    public ChannelConfig Masked() => this with { SmtpPassword = null, Secret = null, Token = null };

    /// <summary>An update from the dashboard: empty secret fields keep the stored value.</summary>
    public ChannelConfig MergeSecretsFrom(ChannelConfig stored) => this with
    {
        SmtpPassword = string.IsNullOrEmpty(SmtpPassword) ? stored.SmtpPassword : SmtpPassword,
        Secret = string.IsNullOrEmpty(Secret) ? stored.Secret : Secret,
        Token = string.IsNullOrEmpty(Token) ? stored.Token : Token,
    };

    public IReadOnlyDictionary<string, bool> SecretsSet() => new Dictionary<string, bool>
    {
        ["smtpPassword"] = !string.IsNullOrEmpty(SmtpPassword),
        ["secret"] = !string.IsNullOrEmpty(Secret),
        ["token"] = !string.IsNullOrEmpty(Token),
    };

    public Dictionary<string, string[]> Validate(string type)
    {
        var errors = new Dictionary<string, string[]>();
        void Err(string field, string msg) => errors[field] = [msg];
        switch (type)
        {
            case ChannelTypes.Email:
                if (string.IsNullOrWhiteSpace(SmtpHost)) Err("smtpHost", "SMTP server is required.");
                if (SmtpPort is < 1 or > 65535) Err("smtpPort", "Port must be 1-65535.");
                if (SmtpSecurity is not null && !SmtpSecurityModes.Contains(SmtpSecurity)) Err("smtpSecurity", "Use starttls, ssl or none.");
                if (!IsEmail(From)) Err("from", "A valid sender address is required.");
                if (To is not { Count: > 0 } || To.Any(t => !IsEmail(t))) Err("to", "At least one valid recipient address is required.");
                break;
            case ChannelTypes.Webhook:
                if (!IsHttpUrl(Url)) Err("url", "An http(s) URL is required.");
                if (Format is not null && !WebhookFormats.Contains(Format)) Err("format", "Use json, slack or discord.");
                break;
            case ChannelTypes.Ntfy:
                if (NtfyServer is not null && !IsHttpUrl(NtfyServer)) Err("ntfyServer", "An http(s) URL is required.");
                if (string.IsNullOrWhiteSpace(Topic) || Topic.Length > 64 || !Topic.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
                    Err("topic", "Topic: 1-64 letters, digits, '-' or '_'.");
                break;
            default:
                Err("type", $"Type must be one of: {string.Join(", ", ChannelTypes.All)}.");
                break;
        }
        return errors;
    }

    private static bool IsHttpUrl(string? s) =>
        Uri.TryCreate(s, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || u.Scheme == Uri.UriSchemeHttp);

    private static bool IsEmail(string? s) => s is { Length: > 3 and <= 254 } && System.Net.Mail.MailAddress.TryCreate(s, out _);

    public string ToJson() => JsonSerializer.Serialize(this, AlertJson.Default.ChannelConfig);
    public static ChannelConfig FromJson(string json) => JsonSerializer.Deserialize(json, AlertJson.Default.ChannelConfig) ?? new ChannelConfig();
}

/// <summary>One event as a channel sees it.</summary>
public sealed record AlertItem(
    Guid Id,
    Guid? HostId,
    string HostName,
    DateTime OccurredAt,
    Severity Severity,
    Capability Capability,
    string SourceTool,
    string Kind,
    string? Subject,
    string Message,
    int SuppressedBefore);

/// <summary>What a channel sends: a batch of alerts, a digest, or a test message.</summary>
public sealed record AlertMessage(string Kind, string Title, string Text, Severity Severity, IReadOnlyList<AlertItem> Items, string? Link)
{
    public const string KindAlert = "alert";
    public const string KindDigest = "digest";
    public const string KindTest = "test";

    public static AlertMessage ForAlerts(IReadOnlyList<AlertItem> items, string? baseUrl)
    {
        var worst = items.Max(i => i.Severity);
        var hosts = items.Select(i => i.HostName).Distinct().ToList();
        string title;
        if (items.Count == 1)
        {
            var i = items[0];
            title = $"[{i.Severity}] {i.HostName}: {Shorten(i.Message, 120)}";
        }
        else title = $"[{worst}] {items.Count} alerts from {(hosts.Count == 1 ? hosts[0] : $"{hosts.Count} hosts")}";

        var sb = new StringBuilder();
        foreach (var i in items.OrderByDescending(i => i.Severity).ThenBy(i => i.OccurredAt))
        {
            sb.Append($"{i.Severity,-8} {i.HostName}  {i.Message}").Append('\n');
            sb.Append($"         {i.Kind} · {i.SourceTool} · {i.OccurredAt:yyyy-MM-dd HH:mm:ss} UTC");
            if (i.SuppressedBefore > 0) sb.Append($" · {i.SuppressedBefore} similar suppressed since the last alert");
            sb.Append('\n');
        }
        var link = baseUrl is null ? null : items.Count == 1 && items[0].HostId is { } h ? $"{baseUrl}/hosts/{h}?tab=events" : $"{baseUrl}/events?minSeverity={worst}";
        if (link is not null) sb.Append('\n').Append(link).Append('\n');
        return new(KindAlert, title, sb.ToString(), worst, items, link);
    }

    public static AlertMessage ForDigest(IReadOnlyList<AlertItem> items, int total, DateTime since, DateTime until, string? baseUrl)
    {
        var worst = items.Count == 0 ? Severity.Info : items.Max(i => i.Severity);
        var title = total == 0 ? "Alastor digest: no alerts" : $"Alastor digest: {total} alert{(total == 1 ? "" : "s")} since {since:MMM d HH:mm} UTC";
        var sb = new StringBuilder();
        sb.Append($"Alerts from {since:yyyy-MM-dd HH:mm} to {until:yyyy-MM-dd HH:mm} UTC: {total}\n\n");
        if (total > 0)
        {
            foreach (var g in items.GroupBy(i => i.Severity).OrderByDescending(g => g.Key)) sb.Append($"  {g.Key}: {g.Count()}\n");
            sb.Append("\nBy host:\n");
            foreach (var g in items.GroupBy(i => i.HostName).OrderByDescending(g => g.Count()).Take(10)) sb.Append($"  {g.Key}: {g.Count()}\n");
            sb.Append("\nMost severe:\n");
            foreach (var i in items.OrderByDescending(i => i.Severity).ThenByDescending(i => i.OccurredAt).Take(20))
                sb.Append($"  {i.OccurredAt:MM-dd HH:mm} {i.Severity,-8} {i.HostName}  {Shorten(i.Message, 140)}\n");
            if (items.Count < total) sb.Append($"  … and {total - items.Count} more\n");
        }
        var link = baseUrl is null ? null : $"{baseUrl}/events";
        if (link is not null) sb.Append('\n').Append(link).Append('\n');
        return new(KindDigest, title, sb.ToString(), worst, items, link);
    }

    public static AlertMessage ForTest(string channelName, string? baseUrl) =>
        new(KindTest, "Alastor test notification", $"This is a test from Alastor for the channel \"{channelName}\". If you can read it, the channel works.\n" + (baseUrl is null ? "" : $"\n{baseUrl}\n"),
            Severity.Info, [], baseUrl);

    private static string Shorten(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";
}

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, UseStringEnumConverter = true)]
[JsonSerializable(typeof(ChannelConfig))]
[JsonSerializable(typeof(WebhookPayload))]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(string))]
internal sealed partial class AlertJson : JsonSerializerContext;

/// <summary>The <c>json</c> webhook format. Stable: integrations may depend on it.</summary>
public sealed record WebhookPayload(string Source, string Kind, string Title, string Text, Severity Severity, string? Link, IReadOnlyList<AlertItem> Events);

/// <summary>Whether a digest is due for a channel, using the shared <see cref="Schedule"/> type.</summary>
public static class DigestSchedule
{
    public static bool IsDue(NotificationChannel c, DateTime now, TimeZoneInfo zone)
    {
        if (!Schedule.TryParse(c.DigestSchedule, out var s, out _) || s.IsDisabled) return false;
        // The first digest covers the time since the channel was created.
        var last = c.LastDigestAt ?? c.CreatedAt;
        return s.IsDue(last, last, now, zone, TimeSpan.Zero);
    }
}
