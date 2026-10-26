using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MimeKit;
using Alastor.Core.Events;
using Alastor.Server.Data;
using Alastor.Server.Services;
using Alastor.Server.Services.Alerts;

namespace Alastor.Tests;

public class AlertUnitTests
{
    private static readonly DateTime T0 = new(2026, 10, 24, 12, 0, 0, DateTimeKind.Utc);
    private static readonly TimeSpan Hour = TimeSpan.FromHours(1);

    [Fact]
    public void Leaky_bucket_sends_once_per_window_and_counts_repeats()
    {
        var b = new AlertBucket { Key = "k" };
        Assert.True(AlertBucketMath.Admit(b, Severity.Medium, T0, Hour, burst: 1));
        Assert.False(AlertBucketMath.Admit(b, Severity.Medium, T0.AddMinutes(5), Hour, 1));
        Assert.False(AlertBucketMath.Admit(b, Severity.Medium, T0.AddMinutes(30), Hour, 1));
        Assert.Equal(2, b.Suppressed);
        Assert.True(AlertBucketMath.Admit(b, Severity.Medium, T0.AddMinutes(61), Hour, 1)); // drained
    }

    [Fact]
    public void Burst_allows_several_before_suppressing()
    {
        var b = new AlertBucket { Key = "k" };
        var sent = Enumerable.Range(0, 5).Count(i => AlertBucketMath.Admit(b, Severity.Low, T0.AddSeconds(i), Hour, burst: 3));
        Assert.Equal(3, sent);
        // The bucket drains one slot per window.
        Assert.False(AlertBucketMath.Admit(b, Severity.Low, T0.AddMinutes(30), Hour, 3));
        Assert.True(AlertBucketMath.Admit(b, Severity.Low, T0.AddMinutes(61), Hour, 3));
    }

    [Fact]
    public void Escalation_is_never_suppressed()
    {
        var b = new AlertBucket { Key = "k" };
        Assert.True(AlertBucketMath.Admit(b, Severity.Medium, T0, Hour, 1));
        Assert.True(AlertBucketMath.Admit(b, Severity.Critical, T0.AddMinutes(1), Hour, 1));
        Assert.False(AlertBucketMath.Admit(b, Severity.Critical, T0.AddMinutes(2), Hour, 1));
    }

    private static AlertItem Item(Severity s = Severity.High, string msg = "Banned 203.0.113.9 in jail sshd", int suppressed = 0) =>
        new(Guid.Parse("11111111-2222-3333-4444-555555555555"), Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), "web-01", T0, s, Capability.Banning,
            "fail2ban", "ban.added", "203.0.113.9", msg, suppressed);

    [Fact]
    public void Single_alert_message_names_host_and_links_to_it()
    {
        var m = AlertMessage.ForAlerts([Item(suppressed: 4)], "https://alastor.example.com");
        Assert.Equal("[High] web-01: Banned 203.0.113.9 in jail sshd", m.Title);
        Assert.Contains("4 similar suppressed", m.Text);
        Assert.Equal("https://alastor.example.com/hosts/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee?tab=events", m.Link);
    }

    [Fact]
    public void Batch_title_counts_alerts_and_takes_the_worst_severity()
    {
        var m = AlertMessage.ForAlerts([Item(Severity.Medium), Item(Severity.Critical, "fail2ban stopped running")], null);
        Assert.Equal("[Critical] 2 alerts from web-01", m.Title);
        Assert.True(m.Text.IndexOf("fail2ban stopped", StringComparison.Ordinal) < m.Text.IndexOf("Banned", StringComparison.Ordinal)); // most severe first
        Assert.Null(m.Link);
    }

    [Fact]
    public void Webhook_signature_is_hmac_sha256_hex_of_the_body()
    {
        // Cross-checked against openssl, which is what receivers typically verify with.
        Assert.Equal(Hmac("s3cret", "{\"a\":1}"), WebhookSender.Signature("s3cret", "{\"a\":1}"u8.ToArray()));
    }

    private static string Hmac(string key, string body)
    {
        var psi = new System.Diagnostics.ProcessStartInfo("openssl", ["dgst", "-sha256", "-hmac", key]) { RedirectStandardInput = true, RedirectStandardOutput = true };
        using var p = System.Diagnostics.Process.Start(psi)!;
        p.StandardInput.Write(body);
        p.StandardInput.Close();
        var outText = p.StandardOutput.ReadToEnd().Trim();
        p.WaitForExit();
        return "sha256=" + outText[(outText.LastIndexOf(' ') + 1)..];
    }

    [Fact]
    public void Webhook_formats()
    {
        var m = AlertMessage.ForAlerts([Item()], null);
        var json = JsonDocument.Parse(WebhookSender.Body("json", m)).RootElement;
        Assert.Equal("alastor", json.GetProperty("source").GetString());
        Assert.Equal("High", json.GetProperty("severity").GetString());
        Assert.Equal("203.0.113.9", json.GetProperty("events")[0].GetProperty("subject").GetString());
        Assert.StartsWith("*[High] web-01", JsonDocument.Parse(WebhookSender.Body("slack", m)).RootElement.GetProperty("text").GetString());
        Assert.StartsWith("**[High] web-01", JsonDocument.Parse(WebhookSender.Body("discord", m)).RootElement.GetProperty("content").GetString());
    }

    [Fact]
    public void Ntfy_payload_maps_severity_to_priority()
    {
        var body = JsonDocument.Parse(NtfySender.Body(new ChannelConfig { Topic = "ops-alerts" }, AlertMessage.ForAlerts([Item(Severity.Critical)], "https://s.example"))).RootElement;
        Assert.Equal("ops-alerts", body.GetProperty("topic").GetString());
        Assert.Equal(5, body.GetProperty("priority").GetInt32());
        Assert.Equal("rotating_light", body.GetProperty("tags")[0].GetString());
        Assert.StartsWith("https://s.example/hosts/", body.GetProperty("click").GetString());
    }

    [Fact]
    public void Email_message_has_subject_recipients_and_urgent_priority()
    {
        var mail = EmailSender.Build(new ChannelConfig { From = "alastor@example.com", To = ["ops@example.com", "me@example.com"] }, AlertMessage.ForAlerts([Item()], null));
        Assert.Equal("[High] web-01: Banned 203.0.113.9 in jail sshd", mail.Subject);
        Assert.Equal(2, mail.To.Count);
        Assert.Equal(MessagePriority.Urgent, mail.Priority);
        Assert.Contains("ban.added", mail.TextBody);
    }

    [Theory]
    [InlineData("email", "{\"smtpHost\":\"\",\"from\":\"x\",\"to\":[]}", new[] { "smtpHost", "from", "to" })]
    [InlineData("webhook", "{\"url\":\"ftp://x\"}", new[] { "url" })]
    [InlineData("ntfy", "{\"topic\":\"bad topic!\"}", new[] { "topic" })]
    public void Channel_config_validation(string type, string json, string[] fields)
    {
        var errors = JsonSerializer.Deserialize<ChannelConfig>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web))!.Validate(type);
        Assert.Equal(fields.Order(), errors.Keys.Order());
    }

    [Fact]
    public void Digest_follows_the_schedule()
    {
        var c = new NotificationChannel { Name = "d", Type = "email", ConfigProtected = "", DigestSchedule = "every 1d", CreatedAt = T0 };
        Assert.False(DigestSchedule.IsDue(c, T0.AddHours(23), TimeZoneInfo.Utc));
        Assert.True(DigestSchedule.IsDue(c, T0.AddHours(24), TimeZoneInfo.Utc));
        c.DigestSchedule = "off";
        Assert.False(DigestSchedule.IsDue(c, T0.AddDays(3), TimeZoneInfo.Utc));
    }
}

/// <summary>Channels end to end in the real server: CRUD over the API, secrets at rest, dedup, delivery and the log.</summary>
[Collection(ServerHostCollection.Name)]
public sealed class AlertApiTests : IDisposable
{
    private readonly CapturingHandler _http = new();
    private readonly FakeSmtp _smtp = new();
    private readonly AlertFactory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public AlertApiTests() => _factory = new AlertFactory(_http, _smtp);
    public void Dispose() => _factory.Dispose();

    private sealed class AlertFactory(CapturingHandler http, FakeSmtp smtp) : WebApplicationFactory<Program>
    {
        public readonly string DataDir = Path.Combine(Path.GetTempPath(), "alastor-alert-test-" + Guid.NewGuid().ToString("N"));

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("DataDir", DataDir);
            builder.UseSetting("AdminPassword", "test-password-123");
            builder.UseSetting("SecureCookies", "false");
            builder.UseSetting("ThreatFeedEnabled", "false");
            builder.UseSetting("OsvEnabled", "false");
            builder.UseSetting("BlocklistsEnabled", "false"); // no list downloads in tests; BlocklistApiTests drives them itself
            builder.UseSetting("PublicUrl", "https://alastor.example.com");
            builder.ConfigureTestServices(s =>
            {
                s.AddHttpClient(WebhookSender.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => http);
                s.RemoveAll<ISmtpTransport>();
                s.AddSingleton<ISmtpTransport>(smtp);
            });
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try { Directory.Delete(DataDir, true); } catch (IOException) { }
        }
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public List<(HttpRequestMessage Request, string Body)> Requests { get; } = [];
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            lock (Requests) Requests.Add((request, body));
            return new HttpResponseMessage(Status) { Content = new StringContent(Status == HttpStatusCode.OK ? "ok" : "nope") };
        }
    }

    private sealed class FakeSmtp : ISmtpTransport
    {
        public List<MimeMessage> Sent { get; } = [];
        public Task SendAsync(ChannelConfig config, MimeMessage message, CancellationToken ct)
        {
            lock (Sent) Sent.Add(message);
            return Task.CompletedTask;
        }
    }

    private async Task<HttpClient> AdminAsync()
    {
        var c = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await c.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        c.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        return c;
    }

    private async Task<List<StoredEvent>> IngestAsync(params SecurityEvent[] events)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<EventIngestService>().IngestAsync(null, events, default);
        var ids = events.Select(e => e.Id).ToList();
        return await scope.ServiceProvider.GetRequiredService<AlastorDbContext>().Events.AsNoTracking().Where(e => ids.Contains(e.Id)).ToListAsync();
    }

    private static SecurityEvent Ban(string ip, Severity s = Severity.Medium) => new()
    {
        Id = Guid.NewGuid(), OccurredAt = DateTime.UtcNow, Capability = Capability.Banning, Severity = s, SourceTool = "fail2ban",
        Kind = EventKinds.BanAdded, Subject = ip, Message = $"Banned {ip} in jail sshd", DedupKey = $"fail2ban:ban.added:{ip}",
    };

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 100 && !condition(); i++) await Task.Delay(50);
        Assert.True(condition(), "timed out waiting for delivery");
    }

    [Fact]
    public async Task Webhook_channel_receives_signed_alerts_and_repeats_are_suppressed()
    {
        var admin = await AdminAsync();
        var create = await admin.PostAsJsonAsync("/api/notifications/channels", new
        {
            name = "ops webhook", type = "webhook", minSeverity = "Medium",
            config = new { url = "https://hooks.example.com/alastor", format = "json", secret = "s3cret" },
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var channel = await create.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(JsonValueKind.Null, channel.GetProperty("config").GetProperty("secret").ValueKind); // never sent back
        Assert.True(channel.GetProperty("secretsSet").GetProperty("secret").GetBoolean());

        // Stored encrypted: the secret isn't in the database file in clear text.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var row = await scope.ServiceProvider.GetRequiredService<AlastorDbContext>().NotificationChannels.SingleAsync();
            Assert.DoesNotContain("s3cret", row.ConfigProtected);
        }

        var first = await IngestAsync(Ban("203.0.113.9"), Ban("203.0.113.9"), Ban("198.51.100.4", Severity.Low));
        await WaitUntilAsync(() => _http.Requests.Count == 1);
        var (req, body) = _http.Requests[0];
        Assert.Equal(WebhookSender.Signature("s3cret", Encoding.UTF8.GetBytes(body)), req.Headers.GetValues("X-Alastor-Signature").Single());
        var payload = JsonDocument.Parse(body).RootElement;
        Assert.Equal(1, payload.GetProperty("events").GetArrayLength()); // the repeat was deduped, the Low event is below threshold
        Assert.Equal(1, first.Count(e => e.Alert == AlertDisposition.Notified));
        Assert.Equal(1, first.Count(e => e.Alert == AlertDisposition.Suppressed));
        Assert.Equal(1, first.Count(e => e.Alert == AlertDisposition.None));

        // A more severe event for the same key goes out despite the window.
        await IngestAsync(Ban("203.0.113.9", Severity.High));
        await WaitUntilAsync(() => _http.Requests.Count == 2);
        Assert.Contains("1 similar suppressed", JsonDocument.Parse(_http.Requests[1].Body).RootElement.GetProperty("text").GetString());

        var deliveries = await admin.GetFromJsonAsync<JsonElement>("/api/notifications/deliveries", Json);
        Assert.Equal(2, deliveries.GetArrayLength());
        Assert.True(deliveries[0].GetProperty("success").GetBoolean());

        var events = await admin.GetFromJsonAsync<JsonElement>("/api/events?limit=10", Json);
        Assert.Contains(events.GetProperty("items").EnumerateArray(), e => e.GetProperty("alert").GetString() == "Suppressed");
    }

    [Fact]
    public async Task Updating_without_a_secret_keeps_it_and_test_reports_errors()
    {
        var admin = await AdminAsync();
        var created = await (await admin.PostAsJsonAsync("/api/notifications/channels", new
        {
            name = "phone", type = "ntfy", config = new { topic = "alastor-ops", token = "tk_secret" },
        })).Content.ReadFromJsonAsync<JsonElement>();
        var id = created.GetProperty("id").GetGuid();

        var put = await admin.PutAsJsonAsync($"/api/notifications/channels/{id}", new
        {
            name = "phone", type = "ntfy", minSeverity = "High", config = new { topic = "alastor-ops", ntfyServer = "https://ntfy.example.com" },
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var test = await (await admin.PostAsync($"/api/notifications/channels/{id}/test", null)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(test.GetProperty("success").GetBoolean());
        var (req, body) = _http.Requests.Single();
        Assert.Equal("https://ntfy.example.com/", req.RequestUri!.ToString());
        Assert.Equal("Bearer tk_secret", req.Headers.Authorization!.ToString()); // kept from creation
        Assert.Equal("alastor-ops", JsonDocument.Parse(body).RootElement.GetProperty("topic").GetString());

        _http.Status = HttpStatusCode.Unauthorized;
        test = await (await admin.PostAsync($"/api/notifications/channels/{id}/test", null)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(test.GetProperty("success").GetBoolean());
        Assert.Contains("401", test.GetProperty("error").GetString());
        var list = await admin.GetFromJsonAsync<JsonElement>("/api/notifications/channels", Json);
        Assert.Contains("401", list[0].GetProperty("lastError").GetString());
    }

    [Fact]
    public async Task Email_channel_and_validation()
    {
        var admin = await AdminAsync();
        var bad = await admin.PostAsJsonAsync("/api/notifications/channels", new { name = "mail", type = "email", config = new { smtpHost = "smtp.example.com", from = "nope", to = Array.Empty<string>() } });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);

        var ok = await admin.PostAsJsonAsync("/api/notifications/channels", new
        {
            name = "mail", type = "email", minSeverity = "High", capabilities = new[] { "Agent" },
            config = new { smtpHost = "smtp.example.com", smtpPort = 587, smtpUsername = "u", smtpPassword = "p", from = "alastor@example.com", to = new[] { "ops@example.com" } },
        });
        Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        await IngestAsync(Ban("203.0.113.50", Severity.High)); // Banning, but the channel only wants Agent events
        await IngestAsync(new SecurityEvent
        {
            Id = Guid.NewGuid(), OccurredAt = DateTime.UtcNow, Capability = Capability.Agent, Severity = Severity.High, SourceTool = "alastor-server",
            Kind = EventKinds.HostOffline, Subject = "web-01", Message = "web-01 stopped sending heartbeats",
        });
        await WaitUntilAsync(() => _smtp.Sent.Count == 1);
        Assert.Equal("[High] server: web-01 stopped sending heartbeats", _smtp.Sent[0].Subject);

        var readOnly = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await readOnly.GetAsync("/api/notifications/channels")).StatusCode);
    }
}
