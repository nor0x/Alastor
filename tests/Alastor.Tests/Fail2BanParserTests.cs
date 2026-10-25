using Alastor.Core.Integrations.Fail2Ban;

namespace Alastor.Tests;

/// <summary>Parsers run against outputs recorded from a real fail2ban 1.1.0 (Ubuntu 26.04), stored in Fixtures/fail2ban.</summary>
public class Fail2BanParserTests
{
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;

    [Fact]
    public void Parses_jail_list_from_client_status()
    {
        var jails = Fail2BanParsers.ParseJailList(Fixture.Read("fail2ban/client-status.txt"));
        Assert.Equal(["alastor-manual", "sshd", "sshd-file"], jails);
    }

    [Fact]
    public void Parses_ban_list_with_time_including_cidr_ipv6_and_permanent()
    {
        var bans = Fail2BanParsers.ParseBanList("sshd", Fixture.Read("fail2ban/client-banip-with-time.txt"), Utc);
        Assert.Equal(5, bans.Count);
        var first = bans[0];
        Assert.Equal("192.0.2.10", first.Target);
        Assert.Equal(new DateTime(2026, 10, 24, 8, 15, 32, DateTimeKind.Utc), first.BannedAtUtc);
        Assert.Equal(600, first.BanSeconds);
        Assert.Equal(first.BannedAtUtc.AddMinutes(10), first.ExpiresAtUtc);
        Assert.Contains(bans, b => b.Target == "203.0.113.0/24");
        var permanent = Assert.Single(bans, b => b.Target == "2001:db8::/48");
        Assert.Equal(-1, permanent.BanSeconds);
        Assert.Null(permanent.ExpiresAtUtc);
    }

    [Fact]
    public void Ban_times_are_converted_from_server_local_time_to_utc()
    {
        var berlin = TimeZoneInfo.FindSystemTimeZoneById("Europe/Berlin"); // UTC+2 on 2026-10-24 (CEST)
        var ban = Fail2BanParsers.ParseBanList("sshd", "192.0.2.10 \t2026-10-24 08:15:32 + 600 = 2026-10-24 08:25:32", berlin)[0];
        Assert.Equal(new DateTime(2026, 10, 24, 6, 15, 32, DateTimeKind.Utc), ban.BannedAtUtc);
    }

    [Theory]
    [InlineData("1.1.0\n", "1.1.0")]
    [InlineData("Fail2Ban v1.1.0\n", "1.1.0")]
    [InlineData("Fail2Ban v0.11.2", "0.11.2")]
    public void Parses_version(string output, string expected) => Assert.Equal(expected, Fail2BanParsers.ParseVersion(output));

    [Fact]
    public void Version_fixture() => Assert.Equal("1.1.0", Fail2BanParsers.ParseVersion(Fixture.Read("fail2ban/client-version.txt")));

    [Fact]
    public void Parses_logtarget_file_and_ignores_syslog_targets()
    {
        Assert.Equal("/var/log/fail2ban.log", Fail2BanParsers.ParseLogTarget(Fixture.Read("fail2ban/client-logtarget.txt")));
        Assert.Null(Fail2BanParsers.ParseLogTarget("Current logging target is:\n`- SYSTEMD-JOURNAL\n"));
    }

    [Fact]
    public void Extracts_errors_from_failed_config_test()
    {
        var errors = Fail2BanParsers.ParseTestErrors(Fixture.Read("fail2ban/client-test-failed.txt"));
        Assert.Equal(3, errors.Count);
        Assert.Contains(errors, e => e.Contains("Unable to read the filter 'nope'"));
        Assert.Empty(Fail2BanParsers.ParseTestErrors(Fixture.Read("fail2ban/client-test-ok.txt")));
    }

    [Fact]
    public void Every_line_of_the_real_log_parses()
    {
        var lines = Fixture.Read("fail2ban/fail2ban.log").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var parsed = lines.Select(l => Fail2BanParsers.ParseLogLine(l, Utc)).ToList();
        // Continuation lines (multi-line action scripts echoed on error) are the only non-matching lines.
        var unparsed = lines.Where((l, i) => parsed[i] is null).ToList();
        Assert.All(unparsed, l => Assert.False(char.IsDigit(l[0]) && l.Contains("fail2ban."), $"should have parsed: {l}"));
        var ban = parsed.First(r => r?.Message == "Ban 192.0.2.10")!;
        Assert.Equal("fail2ban.actions", ban.Logger);
        Assert.Equal("NOTICE", ban.Level);
        Assert.Equal("sshd", ban.Jail);
        Assert.Equal(1116, ban.Pid);
        Assert.Equal(new DateTime(2026, 10, 24, 8, 15, 31, 640, DateTimeKind.Utc), ban.TimestampUtc);
    }
}
