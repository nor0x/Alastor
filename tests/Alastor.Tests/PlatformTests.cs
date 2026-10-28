using Alastor.Core.Integrations;
using Alastor.Core.Logging;
using Alastor.Core.Net;
using Alastor.Core.Platform;

namespace Alastor.Tests;

public class PlatformTests
{
    [Theory]
    [InlineData("192.0.2.7", "192.0.2.7")]
    [InlineData("192.0.2.7/32", "192.0.2.7")]
    [InlineData("10.1.2.3/8", "10.0.0.0/8")]
    [InlineData("2001:db8::1/48", "2001:db8::/48")]
    [InlineData(" 203.0.113.0/24 ", "203.0.113.0/24")]
    public void IpTarget_normalizes(string input, string expected)
    {
        Assert.True(IpTarget.TryParse(input, out var t));
        Assert.Equal(expected, t.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("1.2.3")]
    [InlineData("1.2.3.4/33")]
    [InlineData("example.com")]
    [InlineData("1.2.3.4\n5.6.7.8")]
    public void IpTarget_rejects_garbage(string input) => Assert.False(IpTarget.TryParse(input, out _));

    [Fact]
    public void IpTarget_overlap()
    {
        IpTarget.TryParse("198.51.100.0/24", out var net);
        IpTarget.TryParse("198.51.100.99", out var inside);
        IpTarget.TryParse("198.51.101.1", out var outside);
        Assert.True(net!.Value.Overlaps(inside!.Value));
        Assert.True(inside.Value.Overlaps(net.Value));
        Assert.False(net.Value.Overlaps(outside!.Value));
    }

    [Fact]
    public void Managed_file_detects_hand_edits_and_foreign_files()
    {
        var rendered = ManagedFile.Render("[sshd]\nenabled = true\n", "rev1");
        var owned = ManagedFile.Inspect(rendered);
        Assert.Equal(ManagedFileState.Owned, owned.State);
        Assert.Equal("rev1", owned.Revision);
        Assert.Equal("[sshd]\nenabled = true\n", owned.Body);

        Assert.Equal(ManagedFileState.Drifted, ManagedFile.Inspect(rendered.Replace("enabled = true", "enabled = false")).State);
        Assert.Equal(ManagedFileState.Foreign, ManagedFile.Inspect("[sshd]\nenabled = true\n").State);
        Assert.Equal(ManagedFileState.Missing, ManagedFile.Inspect(null).State);
    }

    [Theory]
    [InlineData("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\nPRETTY_NAME=\"Ubuntu 26.04.1 LTS\"", DistroFamily.Debian)]
    [InlineData("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"", DistroFamily.RedHat)]
    [InlineData("ID=alpine\nVERSION_ID=3.20.0", DistroFamily.Alpine)]
    [InlineData("ID=arch", DistroFamily.Unknown)]
    public void Os_release_family(string osRelease, DistroFamily family) =>
        Assert.Equal(family, OsInfo.Parse(osRelease, "x64").Family);

    [Fact]
    public async Task Log_tailer_starts_at_end_then_reads_new_complete_lines_and_survives_rotation()
    {
        var fs = new FakeFileSystem();
        var state = new InMemoryStateStore();
        var tailer = new LogTailer(fs, state, "t");
        fs.Files["/log"] = "old line 1\nold line 2\n";
        Assert.Empty(await tailer.ReadNewLinesAsync("/log", default)); // no history replay

        fs.Files["/log"] += "new 1\nnew 2\npartial";
        Assert.Equal(["new 1", "new 2"], await tailer.ReadNewLinesAsync("/log", default));
        fs.Files["/log"] += " line\n";
        Assert.Equal(["partial line"], await tailer.ReadNewLinesAsync("/log", default));

        fs.Files["/log"] = "rotated first\n"; // logrotate: new file, different head
        Assert.Equal(["rotated first"], await tailer.ReadNewLinesAsync("/log", default));
    }

    [Fact]
    public void Log_buffer_keeps_the_newest_lines_and_hands_out_each_once()
    {
        var buffer = new LogBuffer(5);
        Assert.Empty(buffer.Since(0, 10));
        for (var i = 1; i <= 8; i++) buffer.Add(DateTime.UtcNow, "info", "Test", $"line {i}");

        Assert.Equal(["line 4", "line 5", "line 6", "line 7", "line 8"], buffer.Latest(10).Select(l => l.Message));
        Assert.Equal(["line 7", "line 8"], buffer.Latest(2).Select(l => l.Message));
        var sent = buffer.Since(6, 10);
        Assert.Equal(["line 7", "line 8"], sent.Select(l => l.Message));
        Assert.Empty(buffer.Since(sent[^1].Seq, 10));

        buffer.Add(DateTime.UtcNow, "error", "Test", new string('x', LogBuffer.MaxMessageLength + 50));
        Assert.Equal(LogBuffer.MaxMessageLength + 1, buffer.Since(8, 10).Single().Message.Length);
    }

    [Fact]
    public async Task Apt_install_waits_for_the_dpkg_lock()
    {
        // apt-daily or unattended-upgrades holding the lock must not fail the install outright.
        var runner = new FakeCommandRunner()
            .On("apt-get update -qq -o DPkg::Lock::Timeout=300", "")
            .On("apt-get install -y -qq --no-install-recommends -o DPkg::Lock::Timeout=300 lynis", "");

        var r = await new AptPackageManager(runner).InstallAsync("lynis", default);

        Assert.True(r.Success, r.Error);
    }
}
