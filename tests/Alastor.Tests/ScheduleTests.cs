using Alastor.Core.Policy;
using Alastor.Server;

namespace Alastor.Tests;

public class ScheduleTests
{
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;
    private static DateTime T(string s) => DateTime.SpecifyKind(DateTime.Parse(s, System.Globalization.CultureInfo.InvariantCulture), DateTimeKind.Utc);

    [Theory]
    [InlineData("every 6h", "interval")]
    [InlineData("6h", "interval")]
    [InlineData("every 90m", "interval")]
    [InlineData("0 3 * * *", "cron")]
    [InlineData("*/15 * * * *", "cron")]
    [InlineData("0 5 * * 0", "cron")]
    [InlineData("off", "off")]
    public void Parses_interval_cron_and_off(string text, string kind)
    {
        Assert.True(Schedule.TryParse(text, out var s, out var err), err);
        Assert.Equal(kind, s.IsDisabled ? "off" : s.IsCron ? "cron" : "interval");
    }

    [Theory]
    [InlineData("")]
    [InlineData("every 30s")]          // more often than once a minute
    [InlineData("permanent")]
    [InlineData("0 3 * *")]            // 4 fields
    [InlineData("61 3 * * *")]         // minute out of range
    [InlineData("tomorrow at noon")]
    public void Rejects_bad_schedules_with_a_message(string text)
    {
        Assert.False(Schedule.TryParse(text, out _, out var err));
        Assert.False(string.IsNullOrWhiteSpace(err));
    }

    [Fact]
    public void Interval_is_measured_from_the_last_run()
    {
        var s = Schedule.Parse("every 6h");
        Assert.Equal(T("2026-10-24 06:00"), s.NextDueUtc(T("2026-10-24 00:00"), T("2026-10-01"), Utc, TimeSpan.Zero));
        Assert.False(s.IsDue(T("2026-10-24 00:00"), T("2026-10-01"), T("2026-10-24 05:59"), Utc, TimeSpan.Zero));
        Assert.True(s.IsDue(T("2026-10-24 00:00"), T("2026-10-01"), T("2026-10-24 06:00"), Utc, TimeSpan.Zero));
    }

    [Fact]
    public void Interval_never_run_starts_after_the_host_spread()
    {
        var s = Schedule.Parse("every 6h");
        Assert.Equal(T("2026-10-24 10:07"), s.NextDueUtc(null, T("2026-10-24 10:00"), Utc, TimeSpan.FromMinutes(7)));
    }

    [Fact]
    public void Cron_runs_at_the_next_occurrence_plus_spread()
    {
        var s = Schedule.Parse("0 3 * * *");
        var spread = TimeSpan.FromMinutes(12);
        // Enrolled at 14:00, never ran: the first run is tomorrow 03:12, not immediately.
        Assert.Equal(T("2026-10-25 03:12"), s.NextDueUtc(null, T("2026-10-24 14:00"), Utc, spread));
        // Ran at 03:12 today: the next run is tomorrow 03:12 (the spread doesn't make today's run count twice).
        Assert.Equal(T("2026-10-25 03:12"), s.NextDueUtc(T("2026-10-24 03:12"), T("2026-10-01"), Utc, spread));
    }

    [Fact]
    public void Missed_cron_run_catches_up_once()
    {
        var s = Schedule.Parse("0 3 * * *");
        // Last ran two days ago; the agent was down at 03:00 today → due now, then back on schedule.
        Assert.True(s.IsDue(T("2026-10-22 03:00"), T("2026-10-01"), T("2026-10-24 09:00"), Utc, TimeSpan.Zero));
        Assert.False(s.IsDue(T("2026-10-24 09:00"), T("2026-10-01"), T("2026-10-24 10:00"), Utc, TimeSpan.Zero));
    }

    [Fact]
    public void Cron_is_evaluated_in_the_host_time_zone()
    {
        var berlin = TimeZoneInfo.FindSystemTimeZoneById("Europe/Berlin");
        var s = Schedule.Parse("0 3 * * *");
        // A normal summer-time night: 03:00 CEST = 01:00 UTC.
        Assert.Equal(T("2026-10-21 01:00"), s.NextDueUtc(null, T("2026-10-20 14:00"), berlin, TimeSpan.Zero));
        // The night summer time ends (2026-10-25): 03:00 is already CET, so 02:00 UTC. The job still runs exactly once.
        Assert.Equal(T("2026-10-25 02:00"), s.NextDueUtc(null, T("2026-10-24 14:00"), berlin, TimeSpan.Zero));
    }

    [Fact]
    public void Off_is_never_due()
    {
        Assert.Null(Schedule.Off.NextDueUtc(null, T("2026-10-24"), Utc, TimeSpan.Zero));
        Assert.False(Schedule.Off.IsDue(null, T("2026-10-24"), T("2030-01-01"), Utc, TimeSpan.Zero));
    }

    [Fact]
    public void Host_spread_is_stable_and_bounded()
    {
        var max = TimeSpan.FromMinutes(30);
        var a = Schedule.HostSpread("host-a", max);
        Assert.Equal(a, Schedule.HostSpread("host-a", max));
        Assert.InRange(a, TimeSpan.Zero, max);
        var spreads = Enumerable.Range(0, 200).Select(i => Schedule.HostSpread($"h{i}", max)).Distinct().Count();
        Assert.True(spreads > 100, "hosts should be spread out, not bunched");
        Assert.Equal(TimeSpan.Zero, Schedule.HostSpread("x", TimeSpan.Zero));
    }

    // ---- policy keys ----

    [Fact]
    public void Default_policy_defines_every_schedule_and_agent_timing()
    {
        var doc = PolicyYaml.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "default.yaml"))).Document!;
        Assert.Equal("every 6h", doc.Updates!.CheckSchedule);
        Assert.Equal("off", doc.Updates.ApplySchedule);
        Assert.Equal("0 3 * * *", doc.Vulnerabilities!.ScanSchedule);
        Assert.Equal("0 5 * * 0", doc.Hardening!.AuditSchedule);
        Assert.Equal("off", doc.Malware!.ScanSchedule);
        var t = AgentTimings.From(doc);
        Assert.Equal(AgentTimings.Default, t);
    }

    [Fact]
    public void Default_yaml_and_code_defaults_agree()
    {
        // Servers whose stored global policy predates a key fall back to ScheduleDefaults. The two must never diverge.
        var doc = PolicyYaml.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "default.yaml"))).Document!;
        var fromYaml = ScheduleDefaults.Resolve(doc).Select(x => (x.Path, x.Value)).ToList();
        var builtIn = ScheduleDefaults.Resolve(new PolicyDocument()).Select(x => (x.Path, x.Value)).ToList();
        Assert.Equal(builtIn, fromYaml);
        Assert.All(ScheduleDefaults.Resolve(doc), x => Assert.False(x.IsDefault));
        Assert.Equal(AgentTimings.Default, AgentTimings.From(doc));
    }

    [Fact]
    public void Old_policies_without_schedule_keys_get_the_built_in_defaults()
    {
        var old = PolicyYaml.Parse("banning:\n  enabled: true\n").Document!;
        Assert.Equal(TimeSpan.FromHours(6), ScheduleDefaults.For(old, "updates.checkSchedule").Interval);
        Assert.True(ScheduleDefaults.For(old, "malware.scanSchedule").IsDisabled);
        Assert.Equal(AgentTimings.Default, AgentTimings.From(old));
    }

    [Fact]
    public void Unquoted_off_in_yaml_still_means_off()
    {
        // YAML 1.1 reads a bare `off` as a boolean. Make sure it reaches us as the text "off".
        var doc = PolicyYaml.Parse("malware:\n  scanSchedule: off\n");
        Assert.True(doc.IsValid, string.Join(";", doc.Issues.Select(i => i.Message)));
        Assert.True(Schedule.Parse(doc.Document!.Malware!.ScanSchedule!).IsDisabled);
    }

    [Theory]
    [InlineData("vulnerabilities:\n  scanSchedule: \"0 3 * *\"\n", "vulnerabilities.scanSchedule")]
    [InlineData("updates:\n  checkSchedule: every 10s\n", "updates.checkSchedule")]
    [InlineData("hardening:\n  auditSchedule: weekly\n", "hardening.auditSchedule")]
    [InlineData("agent:\n  heartbeatInterval: 2s\n", "agent.heartbeatInterval")]
    [InlineData("agent:\n  eventFlushInterval: 1h\n", "agent.eventFlushInterval")]
    [InlineData("agent:\n  driftCheckInterval: soon\n", "agent.driftCheckInterval")]
    public void Invalid_schedules_and_timings_are_errors(string yaml, string path)
    {
        var r = PolicyYaml.Parse(yaml);
        Assert.False(r.IsValid);
        Assert.Contains(r.Issues, i => i.Path == path);
    }

    [Fact]
    public void Host_layer_can_override_a_group_schedule()
    {
        var group = PolicyYaml.Parse("vulnerabilities:\n  scanSchedule: \"0 3 * * *\"\nagent:\n  heartbeatInterval: 2m\n").Document!;
        var host = PolicyYaml.Parse("vulnerabilities:\n  scanSchedule: every 12h\n").Document!;
        var merged = PolicyMerger.MergeLayers([group, host]);
        Assert.Equal("every 12h", merged.Vulnerabilities!.ScanSchedule);
        Assert.Equal(TimeSpan.FromMinutes(2), AgentTimings.From(merged).HeartbeatInterval);
    }

    [Fact]
    public void Permanent_grace_period_never_releases()
    {
        var doc = PolicyYaml.Parse("agent:\n  offlineGracePeriod: permanent\n").Document!;
        Assert.Equal(TimeSpan.MaxValue, AgentTimings.From(doc).OfflineGracePeriod);
    }

    // ---- server options ----

    [Fact]
    public void Server_options_defaults_are_valid_and_bad_values_are_named()
    {
        Assert.Empty(new AlastorOptions().Validate());
        var bad = new AlastorOptions { RetentionRunInterval = "fortnightly", PresenceCheckInterval = "1s", CommandMaxAttempts = 0 }.Validate();
        Assert.Contains(bad, e => e.StartsWith("RetentionRunInterval", StringComparison.Ordinal));
        Assert.Contains(bad, e => e.StartsWith("PresenceCheckInterval", StringComparison.Ordinal));
        Assert.Contains(bad, e => e.StartsWith("CommandMaxAttempts", StringComparison.Ordinal));
    }

    [Fact]
    public void Offline_threshold_scales_with_each_hosts_heartbeat()
    {
        var o = new AlastorOptions();
        Assert.Equal(TimeSpan.FromSeconds(195), o.OfflineAfter(TimeSpan.FromSeconds(60)));
        Assert.Equal(TimeSpan.FromSeconds(1815), o.OfflineAfter(TimeSpan.FromMinutes(10)));
    }
}
