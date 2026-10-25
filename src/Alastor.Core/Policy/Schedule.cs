using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Cronos;

namespace Alastor.Core.Policy;

/// <summary>
/// The single schedule format for every recurring action: update checks, CVE scans, Lynis audits, ClamAV scans,
/// digests. A schedule is one of:
/// <list type="bullet">
/// <item><c>every 6h</c> (or just <c>6h</c>): a fixed interval since the last run.</item>
/// <item><c>0 3 * * *</c>: a standard 5-field cron expression, evaluated in the host's local time zone.</item>
/// <item><c>off</c>: disabled.</item>
/// </list>
/// Cron parsing uses Cronos (MIT): a small, reflection-free library, so it is safe in the Native AOT agent.
/// We don't write our own cron parser.
/// </summary>
public sealed class Schedule
{
    private readonly CronExpression? _cron;

    private Schedule(string text, TimeSpan? interval, CronExpression? cron)
    {
        Text = text;
        Interval = interval;
        _cron = cron;
    }

    public string Text { get; }
    public TimeSpan? Interval { get; }
    public bool IsCron => _cron is not null;
    public bool IsDisabled => Interval is null && _cron is null;

    public static readonly Schedule Off = new("off", null, null);

    public static bool TryParse(string? text, [NotNullWhen(true)] out Schedule? schedule, out string? error)
    {
        schedule = null;
        error = null;
        var t = text?.Trim() ?? "";
        if (t.Length == 0)
        {
            error = "Schedule is empty.";
            return false;
        }
        if (t is "off" or "never" or "disabled")
        {
            schedule = Off;
            return true;
        }

        var intervalText = t.StartsWith("every ", StringComparison.OrdinalIgnoreCase) ? t[6..].Trim() : t;
        if (!intervalText.Contains(' ') && Duration.TryParseSeconds(intervalText, out var seconds))
        {
            if (seconds == Duration.Permanent)
            {
                error = "Use 'off' to disable a schedule; 'permanent' is not an interval.";
                return false;
            }
            if (seconds < 60)
            {
                error = "Scheduled actions run at most once a minute (interval ≥ 1m).";
                return false;
            }
            schedule = new Schedule(t, TimeSpan.FromSeconds(seconds), null);
            return true;
        }

        if (t.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length != 5)
        {
            error = $"'{t}' is neither an interval (every 6h) nor a 5-field cron expression (0 3 * * *), nor 'off'.";
            return false;
        }
        try
        {
            schedule = new Schedule(t, null, CronExpression.Parse(t, CronFormat.Standard));
            return true;
        }
        catch (CronFormatException ex)
        {
            error = $"Invalid cron expression '{t}': {ex.Message}";
            return false;
        }
    }

    public static Schedule Parse(string text) =>
        TryParse(text, out var s, out var error) ? s : throw new FormatException(error);

    /// <summary>
    /// When the action is next due. A due time in the past means "run now": that is how a missed nightly run
    /// (agent down at 03:00) catches up once on startup instead of being skipped.
    /// </summary>
    /// <param name="lastRunUtc">Last successful run, or null if it has never run.</param>
    /// <param name="sinceUtc">When the schedule took effect (first enrollment, or the policy change). Used when it has never run.</param>
    /// <param name="spread">Per-host offset (see <see cref="HostSpread"/>) so a fleet doesn't run heavy scans in the same minute.</param>
    public DateTime? NextDueUtc(DateTime? lastRunUtc, DateTime sinceUtc, TimeZoneInfo zone, TimeSpan spread)
    {
        if (IsDisabled) return null;
        if (Interval is { } interval)
            return lastRunUtc is { } last ? last + interval : sinceUtc + spread;

        var from = DateTime.SpecifyKind(lastRunUtc ?? sinceUtc, DateTimeKind.Utc);
        // Offset the anchor back by the spread, so a run at 03:00+spread doesn't count as before the 03:00 occurrence.
        var next = _cron!.GetNextOccurrence(from - spread, zone);
        return next is null ? null : next.Value + spread;
    }

    public bool IsDue(DateTime? lastRunUtc, DateTime sinceUtc, DateTime nowUtc, TimeZoneInfo zone, TimeSpan spread) =>
        NextDueUtc(lastRunUtc, sinceUtc, zone, spread) is { } due && due <= nowUtc;

    /// <summary>A stable per-host offset in [0, maxSpread). Same host, same offset, every time, so schedules stay predictable.</summary>
    public static TimeSpan HostSpread(string hostKey, TimeSpan maxSpread)
    {
        if (maxSpread <= TimeSpan.Zero) return TimeSpan.Zero;
        var hash = BitConverter.ToUInt32(SHA256.HashData(Encoding.UTF8.GetBytes(hostKey)), 0);
        return TimeSpan.FromSeconds(hash % (uint)Math.Max(1, maxSpread.TotalSeconds));
    }

    public override string ToString() => Text;
}
