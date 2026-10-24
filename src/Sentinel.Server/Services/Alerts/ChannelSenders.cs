using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Sentinel.Core.Events;
using Sentinel.Server.Data;

namespace Sentinel.Server.Services.Alerts;

/// <summary>Delivers one message to one channel. Throws on failure; the dispatcher retries and records the error.</summary>
public interface IChannelSender
{
    string Type { get; }
    Task SendAsync(ChannelConfig config, AlertMessage message, CancellationToken ct);
}

/// <summary>The SMTP conversation, behind a seam so tests don't need a mail server.</summary>
public interface ISmtpTransport
{
    Task SendAsync(ChannelConfig config, MimeMessage message, CancellationToken ct);
}

public sealed class MailKitSmtpTransport : ISmtpTransport
{
    public async Task SendAsync(ChannelConfig config, MimeMessage message, CancellationToken ct)
    {
        using var client = new SmtpClient { Timeout = 30_000 };
        var security = config.SmtpSecurity switch
        {
            "ssl" => SecureSocketOptions.SslOnConnect,
            "none" => SecureSocketOptions.None,
            _ => SecureSocketOptions.StartTls,
        };
        var port = config.SmtpPort ?? (security == SecureSocketOptions.SslOnConnect ? 465 : security == SecureSocketOptions.None ? 25 : 587);
        await client.ConnectAsync(config.SmtpHost!, port, security, ct);
        if (!string.IsNullOrEmpty(config.SmtpUsername)) await client.AuthenticateAsync(config.SmtpUsername, config.SmtpPassword ?? "", ct);
        await client.SendAsync(message, ct);
        await client.DisconnectAsync(true, ct);
    }
}

public sealed class EmailSender(ISmtpTransport transport) : IChannelSender
{
    public string Type => ChannelTypes.Email;

    public Task SendAsync(ChannelConfig config, AlertMessage message, CancellationToken ct) =>
        transport.SendAsync(config, Build(config, message), ct);

    public static MimeMessage Build(ChannelConfig config, AlertMessage message)
    {
        var mail = new MimeMessage();
        mail.From.Add(new MailboxAddress("SentinelVPS", config.From!));
        foreach (var to in config.To ?? []) mail.To.Add(MailboxAddress.Parse(to));
        mail.Subject = message.Title;
        // Mail clients use these to thread and filter; Priority helps people triage on their phone.
        mail.Headers.Add("X-SentinelVPS-Kind", message.Kind);
        if (message.Severity >= Severity.High) mail.Priority = MessagePriority.Urgent;
        mail.Body = new TextPart("plain") { Text = message.Text };
        return mail;
    }
}

public sealed class WebhookSender(IHttpClientFactory http) : IChannelSender
{
    public const string HttpClientName = "notifications";
    public string Type => ChannelTypes.Webhook;

    public async Task SendAsync(ChannelConfig config, AlertMessage message, CancellationToken ct)
    {
        var body = Body(config.Format ?? "json", message);
        using var req = new HttpRequestMessage(HttpMethod.Post, config.Url) { Content = new ByteArrayContent(body) };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        if (!string.IsNullOrEmpty(config.Secret)) req.Headers.Add("X-Sentinel-Signature", Signature(config.Secret, body));
        using var resp = await http.CreateClient(HttpClientName).SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Webhook returned {(int)resp.StatusCode} {resp.ReasonPhrase}: {Shorten(await resp.Content.ReadAsStringAsync(ct))}");
    }

    public static byte[] Body(string format, AlertMessage m) => format switch
    {
        // Slack and Mattermost incoming webhooks take {"text"}, Discord takes {"content"} (max 2000 chars).
        "slack" => JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object> { ["text"] = $"*{m.Title}*\n```{m.Text}```" }, AlertJson.Default.DictionaryStringObject),
        "discord" => JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object> { ["content"] = Shorten($"**{m.Title}**\n```{m.Text}```", 1990) }, AlertJson.Default.DictionaryStringObject),
        _ => JsonSerializer.SerializeToUtf8Bytes(new WebhookPayload("sentinel-vps", m.Kind, m.Title, m.Text, m.Severity, m.Link, m.Items), AlertJson.Default.WebhookPayload),
    };

    /// <summary>GitHub-style: <c>sha256=</c> + hex HMAC-SHA256 of the raw body with the shared secret.</summary>
    public static string Signature(string secret, byte[] body) =>
        "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), body));

    internal static string Shorten(string s, int max = 300) => s.Length <= max ? s : s[..max];
}

/// <summary>ntfy (https://ntfy.sh or self-hosted) via its JSON publish API, which handles non-ASCII titles unlike the header API.</summary>
public sealed class NtfySender(IHttpClientFactory http) : IChannelSender
{
    public const string DefaultServer = "https://ntfy.sh";
    public string Type => ChannelTypes.Ntfy;

    public async Task SendAsync(ChannelConfig config, AlertMessage message, CancellationToken ct)
    {
        var server = (config.NtfyServer ?? DefaultServer).TrimEnd('/');
        using var req = new HttpRequestMessage(HttpMethod.Post, server + "/") { Content = new ByteArrayContent(Body(config, message)) };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        if (!string.IsNullOrEmpty(config.Token)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", config.Token);
        using var resp = await http.CreateClient(WebhookSender.HttpClientName).SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"ntfy returned {(int)resp.StatusCode} {resp.ReasonPhrase}: {WebhookSender.Shorten(await resp.Content.ReadAsStringAsync(ct))}");
    }

    public static byte[] Body(ChannelConfig config, AlertMessage m)
    {
        var payload = new Dictionary<string, object>
        {
            ["topic"] = config.Topic!,
            ["title"] = m.Title,
            ["message"] = WebhookSender.Shorten(m.Text, 3500), // ntfy turns longer messages into attachments
            ["priority"] = Priority(m.Severity),
            ["tags"] = new[] { Tag(m) },
        };
        if (m.Link is not null) payload["click"] = m.Link;
        return JsonSerializer.SerializeToUtf8Bytes(payload, AlertJson.Default.DictionaryStringObject);
    }

    /// <summary>ntfy priorities: 1 min, 3 default, 5 max (bypasses do-not-disturb on phones).</summary>
    public static int Priority(Severity s) => s switch
    {
        Severity.Critical => 5,
        Severity.High => 4,
        Severity.Medium => 3,
        Severity.Low => 2,
        _ => 1,
    };

    private static string Tag(AlertMessage m) => m.Kind switch
    {
        AlertMessage.KindDigest => "clipboard",
        AlertMessage.KindTest => "white_check_mark",
        _ => m.Severity >= Severity.High ? "rotating_light" : "warning",
    };
}
