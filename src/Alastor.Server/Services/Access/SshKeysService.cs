using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Alastor.Core.Access;
using Alastor.Core.Contracts;
using Alastor.Server.Data;
using ScheduleDto = Alastor.Server.Endpoints.ReportEndpoints.ScheduleDto;

namespace Alastor.Server.Services.Access;

public sealed record AuthorizedKeyDto(string File, int Line, string Type, string TypeName, string Fingerprint, int? Bits, string Comment, string Options, string? Weakness);

public sealed record KeyAccountDto(string User, int Uid, string Home, bool Admin, IReadOnlyList<string> Files, IReadOnlyList<AuthorizedKeyDto> Keys);

/// <summary>A key change the dashboard queued that the agent hasn't answered yet.</summary>
public sealed record PendingKeyChangeDto(Guid CommandId, string Op, string User, string? Fingerprint, DateTime CreatedAt);

public sealed record HostSshKeysDto(
    Guid HostId, string Name, bool Online, DateTime? ScannedAt, bool? Success, string? Error, bool KeysCommand, bool? PasswordLogin,
    IReadOnlyList<KeyAccountDto> Accounts, IReadOnlyList<PendingKeyChangeDto> Pending, IReadOnlyList<string> Notes, IReadOnlyList<ScheduleDto> Schedules);

/// <summary>
/// Keeps each host's latest SSH key scan (one <see cref="HostReport"/> row of kind <c>ssh-keys</c>) and builds the SSH keys
/// tab from it. The agent re-checks every change itself; the checks here only give the dashboard a clear answer up front.
/// </summary>
public sealed class SshKeysService(AlastorDbContext db, TimeProvider time)
{
    public const string ReportKind = "ssh-keys";

    /// <summary>A queued change that never reports back stops showing as pending after this long.</summary>
    private static readonly TimeSpan PendingFor = TimeSpan.FromHours(1);

    public static bool IsTooLarge(SshKeysReport r) =>
        r.Accounts.Count > SshKeysIntegration.MaxAccounts || r.Accounts.Any(a => a.Keys.Count > SshKeysIntegration.MaxKeysPerAccount || a.Files.Count > 20)
        || r.Notes.Count > 50;

    public async Task ReceiveAsync(Guid hostId, AgentReport report, CancellationToken ct)
    {
        var row = await db.HostReports.FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == ReportKind, ct);
        if (row is null) db.HostReports.Add(row = new HostReport { HostId = hostId, Kind = ReportKind, JobId = report.JobId, Json = "" });
        // A failed scan keeps showing the last good one, with the error.
        if (report.SshKeys is not null || row.Json.Length == 0) row.Json = JsonSerializer.Serialize(report, AgentJsonContext.Default.AgentReport);
        row.JobId = report.JobId;
        row.Success = report.Success;
        row.Error = report.Error;
        row.StartedAt = report.StartedAtUtc;
        row.FinishedAt = report.FinishedAtUtc;
        row.ReceivedAt = time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);
    }

    public async Task<SshKeysReport?> ReportAsync(Guid hostId, CancellationToken ct)
    {
        var row = await db.HostReports.AsNoTracking().FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == ReportKind, ct);
        return Parse(row?.Json);
    }

    public async Task<HostSshKeysDto?> HostAsync(Guid hostId, IReadOnlyList<ScheduleDto> schedules, CancellationToken ct)
    {
        var h = await db.Hosts.AsNoTracking().FirstOrDefaultAsync(x => x.Id == hostId, ct);
        if (h is null) return null;
        var row = await db.HostReports.AsNoTracking().FirstOrDefaultAsync(r => r.HostId == hostId && r.Kind == ReportKind, ct);
        var r = Parse(row?.Json);
        var since = time.GetUtcNow().UtcDateTime - PendingFor;
        var pending = await db.Commands.AsNoTracking()
            .Where(c => c.HostId == hostId && c.Type == AgentCommandTypes.SshKey && c.CreatedAt >= since && (c.Status == CommandStatus.Pending || c.Status == CommandStatus.Delivered))
            .OrderBy(c => c.CreatedAt).ToListAsync(ct);
        var accounts = (r?.Accounts ?? []).Select(a => new KeyAccountDto(a.User, a.Uid, a.Home, a.Admin, a.Files,
            a.Keys.Select(k => new AuthorizedKeyDto(k.File, k.Line, k.Type, SshKeysIntegration.TypeName(k.Type), k.Fingerprint, k.Bits, k.Comment, k.Options, k.Weakness)).ToList())).ToList();
        return new HostSshKeysDto(h.Id, h.Name, h.IsOnline, r is null ? null : row?.FinishedAt, row?.Success, row is { Success: false } ? row.Error : null,
            r?.KeysCommand ?? false, r?.PasswordLogin, accounts,
            pending.Select(c => new PendingKeyChangeDto(c.Id, c.Payload.GetValueOrDefault("op") ?? "", c.Payload.GetValueOrDefault("user") ?? "",
                c.Payload.GetValueOrDefault("fingerprint"), c.CreatedAt)).ToList(),
            r?.Notes ?? [], schedules);
    }

    private static SshKeysReport? Parse(string? json)
    {
        if (string.IsNullOrEmpty(json)) return null;
        try { return JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentReport)?.SshKeys; }
        catch (JsonException) { return null; }
    }
}
