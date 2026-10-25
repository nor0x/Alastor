using Microsoft.EntityFrameworkCore;
using Alastor.Core.Events;
using Alastor.Server.Auth;
using Alastor.Server.Data;
using Alastor.Server.Services;

namespace Alastor.Server.Endpoints;

/// <summary>Who logs in to a host over SSH: the learned (user, address) pairs and the latest logins.</summary>
public static class AccessEndpoints
{
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
    }
}
