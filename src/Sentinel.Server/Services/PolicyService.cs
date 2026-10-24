using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Integrations.Fail2Ban;
using Sentinel.Core.Policy;
using Sentinel.Server.Data;

namespace Sentinel.Server.Services;

public sealed record EffectivePolicy(PolicyDocument Document, string Revision, IReadOnlyList<PolicyLayerRef> Layers);

public sealed record PolicyLayerRef(Guid LayerId, PolicyScope Scope, Guid? TargetId, int Version);

public sealed class PolicyValidationException(IReadOnlyList<PolicyIssue> issues) : Exception("Policy is invalid")
{
    public IReadOnlyList<PolicyIssue> Issues { get; } = issues;
}

/// <summary>
/// Config-as-policy. Layers (global, then group, then host) are versioned YAML documents, merged per host,
/// plus the server-wide allowlist. Saving a layer creates a new immutable version. Reverting creates a new
/// version with old content, so history is never rewritten.
/// </summary>
public sealed class PolicyService(SentinelDbContext db, CommandService commands, TimeProvider time)
{
    public async Task<EffectivePolicy> GetEffectiveAsync(Guid hostId, CancellationToken ct)
    {
        var host = await db.Hosts.AsNoTracking().Where(h => h.Id == hostId).Select(h => new { h.Id, h.GroupId }).FirstAsync(ct);
        return await ComputeAsync(host.GroupId, host.Id, ct);
    }

    /// <summary>Computes the merged document for a group/host combination. Either may be null, as in a dashboard preview.</summary>
    public async Task<EffectivePolicy> ComputeAsync(Guid? groupId, Guid? hostId, CancellationToken ct, (PolicyScope Scope, Guid? Target, PolicyDocument Doc)? overrideLayer = null)
    {
        var layers = await db.PolicyLayers.AsNoTracking()
            .Where(l => l.Scope == PolicyScope.Global
                     || (l.Scope == PolicyScope.Group && l.TargetId == groupId && groupId != null)
                     || (l.Scope == PolicyScope.Host && l.TargetId == hostId && hostId != null))
            .ToListAsync(ct);
        var ordered = layers.OrderBy(l => l.Scope).ToList();

        var docs = new List<PolicyDocument>();
        var refs = new List<PolicyLayerRef>();
        foreach (var layer in ordered)
        {
            if (overrideLayer is { } o && o.Scope == layer.Scope && o.Target == layer.TargetId)
            {
                docs.Add(o.Doc);
                continue;
            }
            var yaml = await db.PolicyVersions.AsNoTracking()
                .Where(v => v.LayerId == layer.Id && v.Version == layer.CurrentVersion)
                .Select(v => v.Yaml).FirstOrDefaultAsync(ct);
            var parsed = PolicyYaml.Parse(yaml);
            if (parsed.Document is not null) docs.Add(parsed.Document);
            refs.Add(new PolicyLayerRef(layer.Id, layer.Scope, layer.TargetId, layer.CurrentVersion));
        }
        if (overrideLayer is { } ov && !ordered.Any(l => l.Scope == ov.Scope && l.TargetId == ov.Target))
            docs.Add(ov.Doc);

        var merged = PolicyMerger.MergeLayers(docs);

        // The server-wide allowlist (Bans & blocklist page) is part of every host's effective policy.
        var allow = await db.Allowlist.AsNoTracking().OrderBy(a => a.Target).Select(a => a.Target).ToListAsync(ct);
        if (allow.Count > 0)
        {
            merged.Banning ??= new BanningPolicy();
            merged.Banning.Allowlist = (merged.Banning.Allowlist ?? []).Concat(allow).Distinct(StringComparer.Ordinal).ToList();
        }
        return new EffectivePolicy(merged, PolicyYaml.Revision(merged), refs);
    }

    public async Task<PolicyLayer> GetOrCreateLayerAsync(PolicyScope scope, Guid? targetId, CancellationToken ct)
    {
        var layer = await db.PolicyLayers.FirstOrDefaultAsync(l => l.Scope == scope && l.TargetId == targetId, ct);
        if (layer is not null) return layer;
        layer = new PolicyLayer { Scope = scope, TargetId = targetId, CurrentVersion = 0 };
        db.PolicyLayers.Add(layer);
        return layer;
    }

    public async Task<PolicyVersion> SaveAsync(PolicyScope scope, Guid? targetId, string yaml, string? comment, string actor, CancellationToken ct)
    {
        var parsed = PolicyYaml.Parse(yaml);
        if (!parsed.IsValid) throw new PolicyValidationException(parsed.Issues);

        var layer = await GetOrCreateLayerAsync(scope, targetId, ct);
        var next = layer.CurrentVersion + 1;
        var version = new PolicyVersion { LayerId = layer.Id, Version = next, Yaml = yaml, Comment = comment, CreatedBy = actor, CreatedAt = time.GetUtcNow().UtcDateTime };
        db.PolicyVersions.Add(version);
        layer.CurrentVersion = next;
        db.Audit.Add(new AuditEntry { Actor = actor, Action = "policy.save", Target = $"{scope}:{targetId}", Details = $"v{next} {comment}" });
        // The unique (LayerId, Version) index turns concurrent saves into a conflict instead of a lost update.
        await db.SaveChangesAsync(ct);
        await commands.WakeAffectedAsync(scope, targetId, "policy", ct);
        return version;
    }

    public async Task<PolicyVersion> RevertAsync(Guid layerId, int toVersion, string actor, CancellationToken ct)
    {
        var layer = await db.PolicyLayers.FirstAsync(l => l.Id == layerId, ct);
        var old = await db.PolicyVersions.FirstAsync(v => v.LayerId == layerId && v.Version == toVersion, ct);
        return await SaveAsync(layer.Scope, layer.TargetId, old.Yaml, $"Revert to v{toVersion}", actor, ct);
    }

    /// <summary>A preview for the policy editor: validation issues, the merged result, and the exact fail2ban fragment agents will write.</summary>
    public async Task<PolicyPreview> PreviewAsync(PolicyScope scope, Guid? targetId, string yaml, CancellationToken ct)
    {
        var parsed = PolicyYaml.Parse(yaml);
        if (parsed.Document is null) return new PolicyPreview(parsed.Issues, null, null, null);

        Guid? groupId = scope == PolicyScope.Group ? targetId : null;
        Guid? hostId = scope == PolicyScope.Host ? targetId : null;
        if (hostId is { } h) groupId = await db.Hosts.Where(x => x.Id == h).Select(x => x.GroupId).FirstOrDefaultAsync(ct);

        var effective = await ComputeAsync(groupId, hostId, ct, (scope, targetId, parsed.Document));
        var issues = parsed.Issues.Concat(PolicyYaml.Validate(effective.Document)
            .Where(i => i.Level == IssueLevel.Warning)
            .Select(i => i with { Message = $"(effective) {i.Message}" }))
            .DistinctBy(i => (i.Path, i.Message.Replace("(effective) ", "")))
            .ToList();
        var fail2ban = effective.Document.Banning is { } b && b.Enabled != false
            ? Fail2BanConfigRenderer.RenderJails(b, new HashSet<string>())
            : null;
        return new PolicyPreview(issues, PolicyYaml.Serialize(effective.Document), effective.Revision, fail2ban, DescribeSchedules(effective.Document));
    }

    /// <summary>
    /// The next few runs of each schedule, as host-local wall-clock times, so the editor can show "0 3 * * *" as "03:00 tomorrow".
    /// They are computed in UTC: for cron that equals the host-local wall clock, apart from DST edges.
    /// </summary>
    public IReadOnlyList<ScheduleInfo> DescribeSchedules(PolicyDocument doc)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var result = new List<ScheduleInfo>();
        foreach (var (path, value, isDefault) in ScheduleDefaults.Resolve(doc))
        {
            if (!Schedule.TryParse(value, out var s, out _)) continue;
            var next = new List<DateTime>();
            DateTime? last = null;
            for (var i = 0; i < 3 && !s.IsDisabled; i++)
            {
                var due = s.NextDueUtc(last, now, TimeZoneInfo.Utc, TimeSpan.Zero);
                if (due is null) break;
                next.Add(DateTime.SpecifyKind(due.Value, DateTimeKind.Unspecified));
                last = due;
            }
            result.Add(new ScheduleInfo(path, s.Text, s.IsDisabled ? "off" : s.IsCron ? "cron" : "interval", isDefault, next));
        }
        return result;
    }
}

public sealed record PolicyPreview(IReadOnlyList<PolicyIssue> Issues, string? EffectiveYaml, string? Revision, string? Fail2BanConfig, IReadOnlyList<ScheduleInfo>? Schedules = null);

/// <summary><paramref name="NextRunsHostLocal"/> holds wall-clock times in the host's zone, with no UTC offset (DateTimeKind.Unspecified).</summary>
public sealed record ScheduleInfo(string Path, string Schedule, string Kind, bool IsDefault, IReadOnlyList<DateTime> NextRunsHostLocal);
