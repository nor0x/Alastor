using Alastor.Core.Events;
using Alastor.Core.Integrations.Fail2Ban;

namespace Alastor.Tests;

public class Fail2BanNormalizationTests
{
    private static IReadOnlyList<SecurityEvent> NormalizeFixture() =>
        Fail2BanEventNormalizer.Normalize(Fixture.Read("fail2ban/fail2ban.log")
            .Split('\n')
            .Select(l => Fail2BanParsers.ParseLogLine(l, TimeZoneInfo.Utc))
            .OfType<Fail2BanLogRecord>());

    [Fact]
    public void Ban_unban_and_restore_lines_become_ban_events()
    {
        var events = NormalizeFixture();
        var bans = events.Where(e => e.Kind == EventKinds.BanAdded).ToList();
        Assert.Contains(bans, e => e.Subject == "192.0.2.10" && e.Metadata["jail"] == "sshd" && e.Severity == Severity.Low);
        Assert.Contains(bans, e => e.Subject == "203.0.113.0/24");
        Assert.Contains(events, e => e.Kind == EventKinds.BanRemoved && e.Subject == "203.0.113.45" && e.Metadata["jail"] == "sshd-file");
        Assert.Contains(events, e => e.Kind == EventKinds.BanRestored && e.Subject == "2001:db8::/48");
        Assert.All(events, e =>
        {
            Assert.Equal("fail2ban", e.SourceTool);
            Assert.Equal(Capability.Banning, e.Capability);
            Assert.Equal(DateTimeKind.Utc, e.OccurredAt.Kind);
            Assert.False(string.IsNullOrEmpty(e.Raw));
        });
    }

    [Fact]
    public void Manual_jail_bans_are_marked_manual_and_informational()
    {
        var manual = NormalizeFixture().First(e => e.Kind == EventKinds.BanAdded && e.Metadata["jail"] == "alastor-manual");
        Assert.Equal("true", manual.Metadata["manual"]);
        Assert.Equal(Severity.Info, manual.Severity);
    }

    [Fact]
    public void Found_lines_are_aggregated_per_jail_and_ip_not_one_event_per_line()
    {
        var events = NormalizeFixture();
        var failures = events.Where(e => e.Kind == EventKinds.AuthFailures).ToList();
        // The fixture contains 6 "Found 203.0.113.45" filter lines and 4 "Found 198.51.100.200" lines (sshd-file),
        // plus observer "Found ..., bad" lines, which come from a different logger and are ignored.
        Assert.Equal(2, failures.Count);
        var f = failures.Single(e => e.Subject == "203.0.113.45");
        Assert.Equal("6", f.Metadata["count"]);
        Assert.Equal("fail2ban:auth.failures:sshd-file:203.0.113.45", f.DedupKey);
    }

    [Fact]
    public void Failed_ban_action_becomes_one_high_severity_tool_error_and_stderr_detail_is_skipped()
    {
        var errors = NormalizeFixture().Where(e => e.Kind == EventKinds.ToolError).ToList();
        // One summary per failed ban (3 bans with a broken nftables action). The fail2ban.utils stderr lines add nothing.
        var actionFailures = errors.Where(e => e.Metadata.ContainsKey("action")).ToList();
        Assert.Equal(3, actionFailures.Count);
        Assert.All(actionFailures, e =>
        {
            Assert.Equal(Severity.High, e.Severity);
            Assert.Equal("nftables", e.Metadata["action"]);
        });
        Assert.Contains(actionFailures, e => e.Subject == "203.0.113.0/24");
        Assert.DoesNotContain(errors, e => e.Raw!.Contains("fail2ban.utils"));
    }

    [Fact]
    public void Event_ids_are_stable_so_rereading_a_log_is_idempotent()
    {
        var a = NormalizeFixture().Select(e => e.Id).ToList();
        var b = NormalizeFixture().Select(e => e.Id).ToList();
        Assert.Equal(a, b);
        Assert.Equal(a.Count, a.Distinct().Count());
    }

    [Fact]
    public void Increase_ban_lines_use_fail2ban_source_format()
    {
        // fail2ban/server/actions.py: logSys.notice("[%s] Increase Ban %s (%d # %s -> %s)", ...)
        // Synthetic: this line is hard to trigger in a container, so it is built from the source format above.
        var line = "2026-10-24 09:00:00,000 fail2ban.actions        [1116]: NOTICE  [sshd] Increase Ban 203.0.113.45 (2 # 2:00:00 -> 2026-10-24 11:00:00)";
        var e = Fail2BanEventNormalizer.NormalizeOne(Fail2BanParsers.ParseLogLine(line, TimeZoneInfo.Utc)!)!;
        Assert.Equal(EventKinds.BanIncreased, e.Kind);
        Assert.Equal(Severity.Medium, e.Severity);
        Assert.Equal("203.0.113.45", e.Subject);
        Assert.Equal("2 # 2:00:00 -> 2026-10-24 11:00:00", e.Metadata["detail"]);
    }
}
