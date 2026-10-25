using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Events;
using Alastor.Core.Policy;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services.Alerts;

namespace Alastor.Server.Endpoints;

/// <summary>Notification channels (email, webhook, ntfy) and their delivery log. Admin only: channel configs hold credentials.</summary>
public static class NotificationEndpoints
{
    public sealed record ChannelRequest(
        string Name,
        string Type,
        bool? Enabled,
        Severity? MinSeverity,
        List<string>? Capabilities,
        bool? Immediate,
        string? DigestSchedule,
        ChannelConfig Config);

    public sealed record ChannelDto(
        Guid Id,
        string Name,
        string Type,
        bool Enabled,
        Severity MinSeverity,
        IReadOnlyList<string> Capabilities,
        bool Immediate,
        string DigestSchedule,
        DateTime? NextDigestAt,
        ChannelConfig Config,
        IReadOnlyDictionary<string, bool> SecretsSet,
        DateTime CreatedAt,
        DateTime? LastAttemptAt,
        DateTime? LastSuccessAt,
        string? LastError);

    public sealed record DeliveryDto(long Id, Guid ChannelId, string ChannelName, DateTime At, string Kind, string Title, int EventCount, bool Success, int Attempts, string? Error);

    public static void MapNotificationEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/notifications").WithTags("Notifications").RequireAuthorization(AuthPolicies.Admin);

        g.MapGet("/channels", async (AlastorDbContext db, ChannelSecrets secrets, TimeProvider time, CancellationToken ct) =>
            (await db.NotificationChannels.AsNoTracking().OrderBy(c => c.Name).ToListAsync(ct)).Select(c => ToDto(c, secrets, time)).ToList());

        g.MapPost("/channels", async (ChannelRequest req, ClaimsPrincipal user, AlastorDbContext db, ChannelSecrets secrets, TimeProvider time, CancellationToken ct) =>
        {
            if (Validate(req, req.Config) is { Count: > 0 } errors) return Results.ValidationProblem(errors);
            var c = new NotificationChannel { Name = req.Name.Trim(), Type = req.Type, ConfigProtected = secrets.Protect(Normalize(req.Config)), CreatedAt = time.GetUtcNow().UtcDateTime };
            Apply(c, req);
            db.NotificationChannels.Add(c);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "notification-channel.create", Target = c.Name, Details = c.Type });
            await db.SaveChangesAsync(ct);
            return Results.Created($"/api/notifications/channels/{c.Id}", ToDto(c, secrets, time));
        });

        g.MapPut("/channels/{id:guid}", async (Guid id, ChannelRequest req, ClaimsPrincipal user, AlastorDbContext db, ChannelSecrets secrets, TimeProvider time, CancellationToken ct) =>
        {
            var c = await db.NotificationChannels.FindAsync([id], ct);
            if (c is null) return Results.NotFound();
            if (req.Type != c.Type) return Results.ValidationProblem(new Dictionary<string, string[]> { ["type"] = ["The type of a channel can't change. Create a new channel instead."] });
            var config = Normalize(req.Config).MergeSecretsFrom(secrets.Unprotect(c.ConfigProtected));
            if (Validate(req, config) is { Count: > 0 } errors) return Results.ValidationProblem(errors);
            c.Name = req.Name.Trim();
            c.ConfigProtected = secrets.Protect(config);
            Apply(c, req);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "notification-channel.update", Target = c.Name });
            await db.SaveChangesAsync(ct);
            return Results.Ok(ToDto(c, secrets, time));
        });

        g.MapDelete("/channels/{id:guid}", async (Guid id, ClaimsPrincipal user, AlastorDbContext db, CancellationToken ct) =>
        {
            var c = await db.NotificationChannels.FindAsync([id], ct);
            if (c is null) return Results.NotFound();
            db.NotificationChannels.Remove(c);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "notification-channel.delete", Target = c.Name });
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        });

        // Sends right away (no retry) and returns the error, so the dashboard can show what's wrong with the settings.
        g.MapPost("/channels/{id:guid}/test", async (Guid id, AlastorDbContext db, NotificationDispatcher dispatcher, Microsoft.Extensions.Options.IOptions<AlastorOptions> opt, CancellationToken ct) =>
        {
            var c = await db.NotificationChannels.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
            if (c is null) return Results.NotFound();
            var error = await dispatcher.SendAsync(c, AlertMessage.ForTest(c.Name, opt.Value.PublicUrl?.TrimEnd('/')), retry: false, ct);
            return Results.Ok(new { success = error is null, error });
        });

        g.MapGet("/deliveries", async (Guid? channelId, int? limit, AlastorDbContext db, CancellationToken ct) =>
        {
            var q = db.NotificationDeliveries.AsNoTracking().AsQueryable();
            if (channelId is { } cid) q = q.Where(d => d.ChannelId == cid);
            var rows = await q.OrderByDescending(d => d.Id).Take(Math.Clamp(limit ?? 50, 1, 500)).ToListAsync(ct);
            var names = await db.NotificationChannels.AsNoTracking().ToDictionaryAsync(c => c.Id, c => c.Name, ct);
            return rows.Select(d => new DeliveryDto(d.Id, d.ChannelId, names.GetValueOrDefault(d.ChannelId, "?"), d.At, d.Kind, d.Title, d.EventCount, d.Success, d.Attempts, d.Error)).ToList();
        });
    }

    private static Dictionary<string, string[]> Validate(ChannelRequest req, ChannelConfig config)
    {
        var errors = config.Validate(req.Type);
        if (req.Name is not { Length: > 0 and <= 64 } || string.IsNullOrWhiteSpace(req.Name)) errors["name"] = ["1-64 characters."];
        if (req.DigestSchedule is not null && !Schedule.TryParse(req.DigestSchedule, out _, out var err)) errors["digestSchedule"] = [err!];
        if (req.Capabilities?.Any(c => !Enum.TryParse<Capability>(c, out _)) == true) errors["capabilities"] = ["Unknown capability."];
        if (req.Immediate == false && (req.DigestSchedule is null or "off")) errors["immediate"] = ["A channel needs immediate alerts, a digest schedule, or both."];
        return errors;
    }

    private static ChannelConfig Normalize(ChannelConfig c) => c with
    {
        SmtpHost = c.SmtpHost?.Trim(),
        From = c.From?.Trim(),
        To = c.To?.Select(t => t.Trim()).Where(t => t.Length > 0).Distinct().ToList(),
        Url = c.Url?.Trim(),
        NtfyServer = string.IsNullOrWhiteSpace(c.NtfyServer) ? null : c.NtfyServer.Trim(),
        Topic = c.Topic?.Trim(),
    };

    private static void Apply(NotificationChannel c, ChannelRequest req)
    {
        c.Enabled = req.Enabled ?? c.Enabled;
        c.MinSeverity = req.MinSeverity ?? c.MinSeverity;
        c.Capabilities = req.Capabilities?.Distinct().ToList() ?? c.Capabilities;
        c.Immediate = req.Immediate ?? c.Immediate;
        if (req.DigestSchedule is not null && req.DigestSchedule != c.DigestSchedule)
        {
            c.DigestSchedule = req.DigestSchedule.Trim();
            c.LastDigestAt ??= DateTime.UtcNow; // a new digest schedule starts counting now, not from channel creation
        }
    }

    private static ChannelDto ToDto(NotificationChannel c, ChannelSecrets secrets, TimeProvider time)
    {
        var config = secrets.Unprotect(c.ConfigProtected);
        DateTime? next = null;
        if (Schedule.TryParse(c.DigestSchedule, out var s, out _) && !s.IsDisabled)
        {
            var last = c.LastDigestAt ?? c.CreatedAt;
            next = s.NextDueUtc(last, last, TimeZoneInfo.Local, TimeSpan.Zero);
        }
        return new(c.Id, c.Name, c.Type, c.Enabled, c.MinSeverity, c.Capabilities, c.Immediate, c.DigestSchedule, next,
            config.Masked(), config.SecretsSet(), c.CreatedAt, c.LastAttemptAt, c.LastSuccessAt, c.LastError);
    }
}
