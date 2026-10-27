using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Access;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Policy;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;
using Alastor.Server.Services.Access;
using ScheduleDto = Alastor.Server.Endpoints.ReportEndpoints.ScheduleDto;

namespace Alastor.Server.Endpoints;

/// <summary>
/// Who logs in to a host over SSH: the learned (user, address) pairs and the latest logins; and with which keys: every
/// account's authorized keys, which admins can add to and remove from. A change names only the account and the key (or its
/// fingerprint); the agent picks the file and checks everything again.
/// </summary>
public static class AccessEndpoints
{
    public sealed record AddKeyRequest(string? User, string? Key);
    public sealed record RemoveKeyRequest(string? User, string? Fingerprint);

    public sealed record LoginSourceDto(string User, string Address, DateTime FirstSeenAt, DateTime LastSeenAt, string LastMethod, int Logins, bool Alerted);

    public sealed record HostLoginsDto(bool Monitor, bool AlertOnNewSource, IReadOnlyList<string> TrustedSources,
        IReadOnlyList<LoginSourceDto> Sources, IReadOnlyList<EventDto> Recent);

    public static void MapAccessEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/hosts/{id:guid}/logins", async (Guid id, AlastorDbContext db, PolicyService policies, CancellationToken ct) =>
        {
            if (!await db.Hosts.AnyAsync(h => h.Id == id, ct)) return Results.NotFound();
            var policy = (await policies.GetEffectiveAsync(id, ct)).Document.Logins;
            var sources = await db.LoginSources.AsNoTracking().Where(s => s.HostId == id).OrderByDescending(s => s.LastSeenAt).Take(200)
                .Select(s => new LoginSourceDto(s.User, s.Address, s.FirstSeenAt, s.LastSeenAt, s.LastMethod, s.Logins, s.Alerted)).ToListAsync(ct);
            var recent = await db.Events.AsNoTracking().Where(e => e.HostId == id && (e.Kind == EventKinds.Login || e.Kind == EventKinds.LoginNewSource))
                .OrderByDescending(e => e.OccurredAt).Take(30).ToListAsync(ct);
            return Results.Ok(new HostLoginsDto(policy?.Monitor != false, policy?.AlertOnNewSource != false, policy?.TrustedSources ?? [],
                sources, recent.Select(Dto.Event).ToList()));
        }).WithTags("Access").RequireAuthorization(AuthPolicies.Reader);

        app.MapGet("/api/hosts/{id:guid}/ssh-keys", async (Guid id, SshKeysService keys, PolicyService policies, CancellationToken ct) =>
        {
            var eff = await policies.GetEffectiveAsync(id, ct);
            var schedules = ScheduleDefaults.Resolve(eff.Document).Where(s => s.Path == "logins.keysSchedule")
                .Select(s => new ScheduleDto(s.Path, s.Value, s.IsDefault)).ToList();
            return await keys.HostAsync(id, schedules, ct) is { } dto ? Results.Ok(dto) : Results.NotFound();
        }).WithTags("Access").RequireAuthorization(AuthPolicies.Reader);

        app.MapPost("/api/hosts/{id:guid}/ssh-keys", async (Guid id, AddKeyRequest req, AlastorDbContext db, SshKeysService keys, CommandService commands,
            ClaimsPrincipal user, CancellationToken ct) =>
        {
            if (!await db.Hosts.AnyAsync(h => h.Id == id, ct)) return Results.NotFound();
            if (SshKeyParser.ParseNew(req.Key, out var error) is not { } key)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["key"] = [error!] });
            if (await AccountAsync(keys, id, req.User, ct) is not { } account)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["user"] = [$"{req.User} isn't an account that can log in over SSH on this host (as of its last key scan)."] });
            if (account.Keys.Any(k => k.Fingerprint == key.Fingerprint))
                return Results.Problem($"This key is already authorized for {account.User}.", statusCode: 409);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "ssh-key.add", Target = id.ToString(), Details = $"{account.User} {key.Fingerprint} {key.Comment}".TrimEnd() });
            var cmds = await commands.QueueAsync([id], AgentCommandTypes.SshKey,
                new() { ["op"] = "add", ["user"] = account.User, ["key"] = key.ToLine(), ["fingerprint"] = key.Fingerprint }, user.Actor(), ct);
            return Results.Accepted(value: Dto.Command(cmds[0]));
        }).WithTags("Access").RequireAuthorization(AuthPolicies.Admin);

        app.MapPost("/api/hosts/{id:guid}/ssh-keys/remove", async (Guid id, RemoveKeyRequest req, AlastorDbContext db, SshKeysService keys, CommandService commands,
            ClaimsPrincipal user, CancellationToken ct) =>
        {
            if (!await db.Hosts.AnyAsync(h => h.Id == id, ct)) return Results.NotFound();
            if (!SshKeyParser.IsFingerprint(req.Fingerprint))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["fingerprint"] = ["Expected a SHA256 fingerprint."] });
            var report = await keys.ReportAsync(id, ct);
            var account = report?.Accounts.FirstOrDefault(a => a.User == req.User);
            if (report is null || account is null || account.Keys.All(k => k.Fingerprint != req.Fingerprint))
                return Results.Problem("That key isn't authorized for this account (as of the host's last key scan).", statusCode: 404);
            if (SshKeysIntegration.LockoutReason(report, account.User, req.Fingerprint!) is { } lockout)
                return Results.Problem(lockout, statusCode: 409);
            db.Audit.Add(new AuditEntry { Actor = user.Actor(), Action = "ssh-key.remove", Target = id.ToString(), Details = $"{account.User} {req.Fingerprint}" });
            var cmds = await commands.QueueAsync([id], AgentCommandTypes.SshKey,
                new() { ["op"] = "remove", ["user"] = account.User, ["fingerprint"] = req.Fingerprint! }, user.Actor(), ct);
            return Results.Accepted(value: Dto.Command(cmds[0]));
        }).WithTags("Access").RequireAuthorization(AuthPolicies.Admin);
    }

    private static async Task<KeyAccount?> AccountAsync(SshKeysService keys, Guid hostId, string? user, CancellationToken ct) =>
        SshKeyParser.IsValidUser(user) && await keys.ReportAsync(hostId, ct) is { } report ? report.Accounts.FirstOrDefault(a => a.User == user) : null;
}
