using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging.Abstractions;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Storage;
using Alastor.Server.Data;
using Alastor.Server.Services.Issues;

namespace Alastor.Tests;

public class StorageParserTests
{
    [Fact]
    public void Df_keeps_disks_and_drops_memory_snap_and_overlay_mounts()
    {
        var list = StorageParsers.ParseDf(Fixture.Read("storage/df-PTk.ubuntu2404.txt"));
        Assert.Equal(["/", "/boot", "/boot/efi", "/mnt/data"], list.Select(f => f.Mount));
        var root = list[0];
        Assert.Equal(("/dev/vda1", "ext4"), (root.Device, root.Type));
        Assert.Equal(24676576L * 1024, root.TotalBytes);
        Assert.Equal(1095260L * 1024, root.AvailableBytes);
        Assert.Equal(["/", "/boot", "/mnt/data"], list.Where(StorageParsers.IsScannable).Select(f => f.Mount));
    }

    [Fact]
    public void Df_without_a_type_column_still_reads_busybox_output()
    {
        var list = StorageParsers.ParseDf("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda 10240000 9000000 1240000 88% /\n", hasType: false);
        var root = Assert.Single(list);
        Assert.Equal(("/", "?"), (root.Mount, root.Type));
    }

    [Fact]
    public void Df_inodes_skip_filesystems_without_counts()
    {
        var inodes = StorageParsers.ParseDfInodes(Fixture.Read("storage/df-Pi.ubuntu2404.txt"));
        Assert.Equal(26, inodes["/"]);
        Assert.False(inodes.ContainsKey("/boot/efi"));
    }

    [Fact]
    public void Folder_tree_keeps_the_biggest_children_breadth_first()
    {
        var sizes = StorageParsers.ParseDu(Fixture.Read("storage/du-xk-d3.ubuntu2404.txt"));
        var tree = StorageParsers.PruneTree(sizes, ["/"], 25L << 20, maxChildren: 2, maxTotal: 100);
        Assert.Equal("/", tree[0].Path);
        // Two children per folder, biggest first; /home (683 MiB) is the third-biggest top folder, so it's left out.
        Assert.Equal(["/var", "/usr"], tree.Where(d => StorageParsers.ParentOf(d.Path) == "/" && d.Path != "/").Select(d => d.Path));
        Assert.Equal(["/var/lib", "/var/log"], tree.Where(d => StorageParsers.ParentOf(d.Path) == "/var").Select(d => d.Path));
        Assert.Equal(["/var/lib/docker"], tree.Where(d => StorageParsers.ParentOf(d.Path) == "/var/lib").Select(d => d.Path));
        Assert.Equal(12582916L * 1024, tree.Single(d => d.Path == "/var/lib/docker").Bytes);
        Assert.DoesNotContain(tree, d => d.Path == "/var/lib/docker/tmp"); // 4 KiB, under the minimum

        var capped = StorageParsers.PruneTree(sizes, ["/"], 25L << 20, maxChildren: 15, maxTotal: 4);
        Assert.Equal(4, capped.Count);
        Assert.Equal(["/", "/var", "/usr", "/home"], capped.Select(d => d.Path));
    }

    [Fact]
    public void Large_files_are_sorted_and_keep_spaces_in_paths()
    {
        var files = StorageParsers.ParseLargeFiles(Fixture.Read("storage/find-large.ubuntu2404.txt"), 3);
        Assert.Equal(["/swapfile", "/var/backups/db dump.sql", "/root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/librustc_driver-a39fc8bf9e61dbb9.so"], files.Select(f => f.Path));
        Assert.Equal(4294967296, files[0].Bytes);
        Assert.Equal(DateTime.UnixEpoch.AddSeconds(1761480000), files[1].ModifiedUtc);
    }

    [Fact]
    public void Docker_df_reads_reclaimable_space_and_unused_counts()
    {
        var rows = StorageParsers.ParseDockerDf(Fixture.Read("storage/docker-system-df.docker29.txt")).ToDictionary(r => r.Type);
        Assert.Equal(0, rows["Images"].ReclaimableBytes); // the one image is used by a stopped container
        Assert.Equal(0, rows["Images"].Unused);
        Assert.Equal(20_980_000, rows["Containers"].ReclaimableBytes);
        Assert.Equal(1, rows["Containers"].Unused);
        Assert.Equal(15_730_000, rows["Local Volumes"].ReclaimableBytes);
        Assert.Equal(10_520_000, rows["Build Cache"].ReclaimableBytes);
    }

    [Theory]
    [InlineData("0B", 0L)]
    [InlineData("512kB", 512_000L)]
    [InlineData("1.2GB", 1_200_000_000L)]
    [InlineData("1.4G", 1503238554L)]
    [InlineData("88.0K", 90112L)]
    [InlineData("3MiB", 3145728L)]
    [InlineData("12", 12L)]
    public void Human_sizes_follow_each_tool_s_units(string text, long bytes) => Assert.Equal(bytes, StorageParsers.ParseHumanSize(text));

    [Fact]
    public void Journal_snap_and_cache_paths()
    {
        Assert.Equal(1503238554L, StorageParsers.ParseJournalUsage(Fixture.Read("storage/journalctl-disk-usage.txt")));
        Assert.Equal(0L, StorageParsers.ParseJournalUsage("No journal files were found.\nArchived and active journals take up 0B in the file system."));
        Assert.Equal([("core20", "2318"), ("lxd", "28463")], StorageParsers.ParseSnapDisabled(Fixture.Read("storage/snap-list-all.txt")));

        Assert.True(StorageParsers.IsDevCachePath("/root/.cache/pip"));
        Assert.True(StorageParsers.IsDevCachePath("/home/deploy/.npm/_cacache"));
        Assert.False(StorageParsers.IsDevCachePath("/home/deploy/.cache"));
        Assert.False(StorageParsers.IsDevCachePath("/home/deploy/app/.cache/pip"));
        Assert.False(StorageParsers.IsDevCachePath("/home/../etc/.cache/pip"));
        Assert.False(StorageParsers.IsDevCachePath("/var/www/.cache/pip"));
    }
}

public class StorageIntegrationTests
{
    private readonly FakeCommandRunner _runner = new();
    private readonly FakeFileSystem _fs = new();
    private readonly InMemoryStateStore _state = new();
    private static readonly OsInfo Ubuntu = new("ubuntu", "24.04", "Ubuntu 24.04.1 LTS", DistroFamily.Debian, "x64");

    private string _df = Fixture.Read("storage/df-PTk.ubuntu2404.txt");
    private string _dockerDf = Fixture.Read("storage/docker-system-df.docker29.txt");

    private const string AptAutoremove = "apt-get autoremove -y -q -o DPkg::Lock::Timeout=300";
    private const string RotatedFind = "find /var/log -xdev -type f ! -path /var/log/journal/* ( -name *.gz -o -name *.xz -o -name *.bz2 -o -name *.zst -o -name *.[0-9] -o -name *.[0-9].log -o -name *.old )";

    public StorageIntegrationTests()
    {
        _runner.Installed.UnionWith(["df", "du", "find", "apt-get", "dpkg-query", "journalctl", "docker", "snap"]);
        _fs.Files["/var/cache/apt/archives/curl.deb"] = "x";
        _fs.Files["/var/log/syslog"] = "x";
        _fs.Files["/var/lib/docker/containers/abc/abc-json.log"] = "x";
        _fs.Files["/var/lib/snapd/snaps/core20_2318.snap"] = "x";
        _fs.Files["/var/lib/snapd/snaps/lxd_28463.snap"] = "x";
        _fs.Files["/home/deploy/.bashrc"] = "x";
        _fs.Files["/tmp/x"] = "x";
        _fs.Files["/proc/sys/kernel/osrelease"] = "6.8.0-45-generic\n";
        _runner.On("df -PTk", () => new CommandResult(0, _df, ""))
            .On("df -Pi", Fixture.Read("storage/df-Pi.ubuntu2404.txt"))
            .On("du -xk -d 3 /", Fixture.Read("storage/du-xk-d3.ubuntu2404.txt"))
            .On("du -xk -d 3 /boot", "125000\t/boot\n")
            .On("du -xk -d 3 /mnt/data", "31457280\t/mnt/data\n30000000\t/mnt/data/backups\n")
            .On("find / -xdev -type f -size +100M -printf %s %T@ %p\n", Fixture.Read("storage/find-large.ubuntu2404.txt"))
            .On("find /boot -xdev -type f -size +100M -printf %s %T@ %p\n", "")
            .On("find /mnt/data -xdev -type f -size +100M -printf %s %T@ %p\n", "3000000000 1761000000 /mnt/data/backups/2026-10.tar\n")
            .On("du -sk /var/cache/apt", "870400\t/var/cache/apt\n")
            .On("journalctl --disk-usage", Fixture.Read("storage/journalctl-disk-usage.txt"))
            .On(RotatedFind + " -printf %s\n", "1000\n2000\n")
            .On("docker system df --format {{json .}}", () => new CommandResult(0, _dockerDf, ""))
            .On("find /var/lib/docker/containers -type f -name *-json.log -printf %s\n", "52428800\n")
            .On("apt-get -s -o Debug::NoLocking=1 autoremove", Fixture.Read("storage/apt-get-s-autoremove.ubuntu2404.txt"))
            .On("dpkg-query -W -f=${Installed-Size}\n linux-headers-6.8.0-40-generic linux-headers-6.8.0-40 linux-image-6.8.0-40-generic linux-modules-6.8.0-40-generic python3-netifaces",
                "1000\n100000\n15000\n90000\n50\n")
            .On("snap list --all", Fixture.Read("storage/snap-list-all.txt"))
            .On("du -sk /var/lib/snapd/snaps/core20_2318.snap /var/lib/snapd/snaps/lxd_28463.snap", "65536\t/var/lib/snapd/snaps/core20_2318.snap\n90000\t/var/lib/snapd/snaps/lxd_28463.snap\n")
            .On("find /home -mindepth 2 -maxdepth 3 -type d ( -path */.cache/pip -o -path */.npm/_cacache -o -path */.cache/yarn -o -path */.cache/go-build -o -path */.cache/composer -o -path */.composer/cache ) -prune -print",
                "/home/deploy/.cache/pip\n/home/deploy/.npm/_cacache\n/home/deploy/app/.cache/pip\n")
            .On("du -sk /home/deploy/.cache/pip /home/deploy/.npm/_cacache", "300000\t/home/deploy/.cache/pip\n200000\t/home/deploy/.npm/_cacache\n")
            .On("find /tmp -xdev -type f -mtime +10 -atime +10 -printf %s\n", "");
    }

    private StorageIntegration Integration() => new(_runner, _fs, _state, Ubuntu, NullLogger<StorageIntegration>.Instance, TimeProvider.System);

    private static async Task<List<SecurityEvent>> Drain(StorageIntegration s)
    {
        var list = new List<SecurityEvent>();
        await foreach (var e in s.CollectEventsAsync(default)) list.Add(e);
        return list;
    }

    [Fact]
    public async Task Scan_measures_folders_files_and_every_applicable_cleanup()
    {
        var s = Integration();
        var result = await s.ScanAsync(default);
        Assert.True(result.Success, result.Error);
        var r = result.Storage!;

        Assert.Equal(["/", "/boot", "/boot/efi", "/mnt/data"], r.Filesystems.Select(f => f.Mount));
        Assert.Equal(26, r.Filesystems[0].InodesUsedPercent);
        Assert.Equal("/", r.Directories[0].Path);
        Assert.Contains(r.Directories, d => d.Path == "/var/lib/docker");
        Assert.Contains(r.Directories, d => d.Path == "/mnt/data/backups");
        Assert.Equal("/swapfile", r.LargestFiles[0].Path);
        Assert.Equal("/mnt/data/backups/2026-10.tar", r.LargestFiles[1].Path);
        Assert.NotNull(r.ScannedAtUtc);

        var c = r.Cleanups.ToDictionary(x => x.Id);
        Assert.Equal(870400L * 1024, c[StorageCleanups.AptCache].Bytes);
        Assert.Equal(1503238554L - (200L << 20), c[StorageCleanups.JournalVacuum].Bytes);
        Assert.Equal((3000L, 2), (c[StorageCleanups.RotatedLogs].Bytes!.Value, c[StorageCleanups.RotatedLogs].Items!.Value));
        Assert.Equal(10_520_000, c[StorageCleanups.DockerBuildCache].Bytes);
        Assert.Equal((20_980_000L, 1), (c[StorageCleanups.DockerContainers].Bytes!.Value, c[StorageCleanups.DockerContainers].Items!.Value));
        Assert.Equal(0, c[StorageCleanups.DockerImages].Bytes);
        Assert.Equal(15_730_000, c[StorageCleanups.DockerVolumes].Bytes);
        Assert.Equal(52428800, c[StorageCleanups.DockerLogs].Bytes);
        // Old kernels may go; the running 6.8.0-45 isn't among them, so nothing blocks it.
        Assert.Equal(5, c[StorageCleanups.AptAutoremove].Items);
        Assert.Equal(206050L * 1024, c[StorageCleanups.AptAutoremove].Bytes);
        Assert.Null(c[StorageCleanups.AptAutoremove].Blocked);
        Assert.Equal((155536L * 1024, 2), (c[StorageCleanups.SnapRevisions].Bytes!.Value, c[StorageCleanups.SnapRevisions].Items!.Value));
        // Only the exact cache folders count; the project's own .cache/pip is left alone.
        Assert.Equal((500000L * 1024, 2), (c[StorageCleanups.DevCaches].Bytes!.Value, c[StorageCleanups.DevCaches].Items!.Value));
        Assert.Equal(0, c[StorageCleanups.OldTempFiles].Bytes);
        Assert.DoesNotContain(StorageCleanups.DnfCache, c.Keys);
        Assert.DoesNotContain(StorageCleanups.PodmanPrune, c.Keys);
        Assert.DoesNotContain(StorageCleanups.CrashDumps, c.Keys);

        // Volumes are destructive, so they don't count as reclaimable.
        Assert.Equal(r.Cleanups.Where(x => x.Id != StorageCleanups.DockerVolumes).Sum(x => x.Bytes ?? 0), r.ReclaimableBytes);
        var status = await s.DetectAsync(default);
        Assert.Equal(r.ReclaimableBytes.ToString(System.Globalization.CultureInfo.InvariantCulture), status.Details["reclaimableBytes"]);
    }

    [Fact]
    public async Task Scan_runs_at_low_priority_when_nice_and_ionice_exist()
    {
        _runner.Installed.UnionWith(["nice", "ionice"]);
        _runner.Fallback = (file, args) =>
            file == "nice" && args.Take(5).SequenceEqual(["-n", "19", "ionice", "-c", "3"]) ? new CommandResult(0, args[5] == "du" ? $"100\t{args[^1]}\n" : "", "") : null;
        await Integration().ScanAsync(default);
        Assert.Contains("nice -n 19 ionice -c 3 du -xk -d 3 /", _runner.Calls);
        Assert.DoesNotContain("du -xk -d 3 /", _runner.Calls);
    }

    [Fact]
    public async Task Busybox_find_falls_back_to_stat()
    {
        _runner.On("find / -xdev -type f -size +100M -printf %s %T@ %p\n", "", 1, "find: unrecognized: -printf")
            .On("find / -xdev -type f -size +204800 -exec stat -c %s %Y %n {} +", "200000000 1761000000 /var/lib/big.img\n");
        var r = (await Integration().ScanAsync(default)).Storage!;
        Assert.Contains(r.LargestFiles, f => f.Path == "/var/lib/big.img");
    }

    [Fact]
    public async Task Cleanup_runs_exactly_its_commands_and_reports_freed_space()
    {
        var s = Integration();
        await s.ScanAsync(default);
        _runner.On("docker builder prune -a -f", () =>
        {
            // 10 GiB more free on / afterwards.
            _df = _df.Replace("24676576 22547900   1095260", "24676576 12062140  11581020", StringComparison.Ordinal);
            _dockerDf = _dockerDf.Replace("\"Reclaimable\":\"10.52MB\"", "\"Reclaimable\":\"0B\"", StringComparison.Ordinal);
            return new CommandResult(0, "Total:\t10.52MB", "");
        });
        _runner.Calls.Clear();

        var result = await s.RunCleanupAsync(StorageCleanups.DockerBuildCache, default);
        Assert.True(result.Success, result.Error);
        Assert.Equal(StorageIntegration.CleanupJob, result.JobId);
        var done = result.Storage!.LastCleanup!;
        Assert.Equal((StorageCleanups.DockerBuildCache, true), (done.Id, done.Success));
        Assert.Equal((11581020L - 1095260L) * 1024, done.FreedBytes);
        Assert.Contains("docker builder prune -a -f", done.LogTail);
        Assert.Single(_runner.Calls, c => c.StartsWith("docker ", StringComparison.Ordinal) && c.Contains(" prune", StringComparison.Ordinal));
        Assert.Equal(0, result.Storage.Cleanups.Single(c => c.Id == StorageCleanups.DockerBuildCache).Bytes);
        // The folder tree from the scan is carried along until the next scan.
        Assert.NotEmpty(result.Storage.Directories);

        var e = Assert.Single(await Drain(s));
        Assert.Equal(EventKinds.StorageCleaned, e.Kind);
        Assert.Equal(Capability.Storage, e.Capability);
        Assert.Equal("Docker build cache: freed 10 GB", e.Message);
    }

    [Fact]
    public async Task Each_cleanup_runs_the_catalog_command()
    {
        var expected = new Dictionary<string, string[]>
        {
            [StorageCleanups.AptCache] = ["apt-get clean"],
            [StorageCleanups.JournalVacuum] = ["journalctl --vacuum-size=200M"],
            [StorageCleanups.RotatedLogs] = [RotatedFind + " -delete"],
            [StorageCleanups.DockerContainers] = ["docker container prune -f"],
            [StorageCleanups.DockerVolumes] = ["docker volume prune -a -f"],
            [StorageCleanups.DockerLogs] = ["find /var/lib/docker/containers -type f -name *-json.log -exec truncate -s 0 {} +"],
            [StorageCleanups.AptAutoremove] = [AptAutoremove],
            [StorageCleanups.SnapRevisions] = ["snap remove core20 --revision=2318", "snap remove lxd --revision=28463"],
            [StorageCleanups.DevCaches] = ["rm -rf -- /home/deploy/.cache/pip /home/deploy/.npm/_cacache"],
        };
        foreach (var (id, commands) in expected)
        {
            foreach (var cmd in commands) _runner.On(cmd, "ok");
            _runner.Calls.Clear();
            var result = await Integration().RunCleanupAsync(id, default);
            Assert.True(result.Success, $"{id}: {result.Error}");
            // This cleanup's commands ran, in order, and no other cleanup's did.
            Assert.Equal(commands, _runner.Calls.Where(c => expected.Values.SelectMany(v => v).Contains(c)));
            Assert.Equal(id, result.Storage!.LastCleanup!.Id);
        }
    }

    [Fact]
    public async Task Nothing_to_clean_succeeds_without_running_anything()
    {
        _runner.Calls.Clear();
        var result = await Integration().RunCleanupAsync(StorageCleanups.OldTempFiles, default);
        Assert.True(result.Success);
        Assert.DoesNotContain(_runner.Calls, c => c.Contains("-delete", StringComparison.Ordinal));
        Assert.Equal(0, result.Storage!.LastCleanup!.FreedBytes);
    }

    [Fact]
    public async Task Autoremove_that_would_take_the_running_kernel_is_refused()
    {
        _fs.Files["/proc/sys/kernel/osrelease"] = "6.8.0-40-generic\n";
        var s = Integration();
        var scan = (await s.ScanAsync(default)).Storage!;
        Assert.Contains("linux-image-6.8.0-40-generic", scan.Cleanups.Single(c => c.Id == StorageCleanups.AptAutoremove).Blocked);

        _runner.Calls.Clear();
        var result = await s.RunCleanupAsync(StorageCleanups.AptAutoremove, default);
        Assert.False(result.Success);
        Assert.StartsWith("Refused:", result.Error);
        Assert.DoesNotContain(AptAutoremove, _runner.Calls);
        Assert.Equal(EventKinds.StorageCleanupFailed, Assert.Single(await Drain(s)).Kind);
    }

    [Fact]
    public async Task Unknown_or_inapplicable_cleanups_run_nothing()
    {
        var s = Integration();
        var unknown = await s.RunCleanupAsync("rm-rf-slash", default);
        Assert.False(unknown.Success);
        Assert.Contains("Unknown cleanup", unknown.Error);

        _runner.Calls.Clear();
        var podman = await s.RunCleanupAsync(StorageCleanups.PodmanPrune, default);
        Assert.False(podman.Success);
        Assert.Contains("doesn't apply", podman.Error);
        Assert.DoesNotContain(_runner.Calls, c => c.StartsWith("podman", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Old_docker_without_volume_prune_all_falls_back()
    {
        _runner.On("docker volume prune -a -f", "", 125, "unknown shorthand flag: 'a' in -a")
            .On("docker volume prune -f", "Total reclaimed space: 15.73MB");
        var result = await Integration().RunCleanupAsync(StorageCleanups.DockerVolumes, default);
        Assert.True(result.Success, result.Error);
        Assert.Contains("docker volume prune -f", _runner.Calls);
    }

    [Theory]
    [InlineData("linux-image-6.8.0-40-generic", true)]
    [InlineData("linux-modules-6.8.0-40-generic", true)]
    [InlineData("linux-image-generic", false)]
    [InlineData("kernel-core", false)]
    [InlineData("kernel-6.11.4-301.fc41", true)]
    public void Versioned_kernels_are_told_apart_from_meta_packages(string name, bool versioned) =>
        Assert.Equal(versioned, StorageIntegration.IsVersionedKernel(name));
}

public class StorageIssueTests
{
    private static ManagedHost Host(long used, long total) =>
        new() { Name = "web-01", Hostname = "web-01", SecretHash = "x", IsOnline = true, PolicyApplySuccess = true, DiskUsedBytes = used, DiskTotalBytes = total };

    [Fact]
    public void A_nearly_full_root_filesystem_is_an_issue()
    {
        Assert.DoesNotContain(IssueRules.Evaluate(Host(89, 100), new([], [])), c => c.Rule == "storage.low");
        var medium = Assert.Single(IssueRules.Evaluate(Host(91L << 30, 100L << 30), new([], [])), c => c.Rule == "storage.low");
        Assert.Equal((Severity.Medium, "storage"), (medium.Severity, medium.Tab));
        Assert.Equal("The root filesystem is 91% full", medium.Title);
        Assert.StartsWith("9 GB free of 100 GB", medium.Detail);
        Assert.Equal(Severity.High, IssueRules.Evaluate(Host(96, 100), new([], [])).Single(c => c.Rule == "storage.low").Severity);
        Assert.DoesNotContain(IssueRules.Evaluate(Host(0, 0), new([], [])), c => c.Rule == "storage.low");
    }
}

[Collection(ServerHostCollection.Name)]
public sealed class StorageApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public StorageApiTests(ServerApiTests.Factory factory) => _factory = factory;

    [Fact]
    public async Task Reports_are_served_cleanups_are_checked_and_a_full_disk_alerts()
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "st" })).Content.ReadFromJsonAsync<JsonElement>();
        var resp = (await (await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "disk-01", "Ubuntu 24.04.1 LTS", "ubuntu", "24.04", "x64", "0.1.0", null))).Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);
        var id = resp.AgentId;

        // Before any scan there is nothing to clean.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/storage/cleanup", new { cleanup = StorageCleanups.AptCache })).StatusCode);

        var now = DateTime.UtcNow;
        var report = new StorageReport(
            StorageParsers.ParseDf(Fixture.Read("storage/df-PTk.ubuntu2404.txt")),
            [new DirectoryUsage("/", 23_000_000_000), new DirectoryUsage("/var", 16_000_000_000)],
            [new LargeFile("/swapfile", 4_294_967_296, null)],
            [
                new CleanupCandidate(StorageCleanups.AptCache, 891_289_600),
                new CleanupCandidate(StorageCleanups.DockerVolumes, 15_730_000, 1),
                new CleanupCandidate(StorageCleanups.AptAutoremove, 1000, 1, "linux-image-6.8.0-45-generic", "It would remove protected package linux-image-6.8.0-45-generic."),
            ],
            now, null);
        Assert.Equal(HttpStatusCode.NoContent,
            (await agent.PostAsJsonAsync("/api/agent/reports", new AgentReport(StorageIntegration.ScanJob, now, now, true, null) { Storage = report }, AgentJsonContext.Default.AgentReport)).StatusCode);

        var dto = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{id}/storage", Json);
        Assert.Equal(891_289_600 + 1000 - 1000, dto.GetProperty("reclaimableBytes").GetInt64());
        var cleanups = dto.GetProperty("cleanups").EnumerateArray().ToDictionary(c => c.GetProperty("id").GetString()!);
        Assert.Equal("sudo apt-get clean", cleanups[StorageCleanups.AptCache].GetProperty("command").GetString());
        Assert.Equal("Destructive", cleanups[StorageCleanups.DockerVolumes].GetProperty("risk").GetString());
        Assert.Equal("storage.scanSchedule", dto.GetProperty("schedules")[0].GetProperty("key").GetString());
        Assert.Equal("/swapfile", dto.GetProperty("largestFiles")[0].GetProperty("path").GetString());

        // Refused before anything reaches the agent: unknown ids, cleanups the agent blocked, destructive ones without the host name.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/storage/cleanup", new { cleanup = "rm -rf /" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/storage/cleanup", new { cleanup = StorageCleanups.AptAutoremove })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/storage/cleanup", new { cleanup = StorageCleanups.DnfCache })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/storage/cleanup", new { cleanup = StorageCleanups.DockerVolumes, confirm = "yes" })).StatusCode);
        Assert.Empty((await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json))!);

        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsJsonAsync($"/api/hosts/{id}/storage/cleanup", new { cleanup = StorageCleanups.DockerVolumes, confirm = "DISK-01" })).StatusCode);
        var cmd = Assert.Single((await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json))!);
        Assert.Equal((AgentCommandTypes.StorageCleanup, StorageCleanups.DockerVolumes), (cmd.Type, cmd.Payload["cleanup"]));
        await agent.PostAsJsonAsync($"/api/agent/commands/{cmd.Id}/result", new AgentCommandResult(true, "started"), AgentJsonContext.Default.AgentCommandResult);
        dto = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{id}/storage", Json);
        Assert.Equal(StorageCleanups.DockerVolumes, dto.GetProperty("running").GetProperty("id").GetString());

        // The cleanup's report ends "running".
        var done = DateTime.UtcNow.AddSeconds(1);
        var after = report with { LastCleanup = new CleanupResult(done, StorageCleanups.DockerVolumes, true, 15_730_000, null, "") };
        await agent.PostAsJsonAsync("/api/agent/reports", new AgentReport(StorageIntegration.CleanupJob, done, done, true, null) { Storage = after }, AgentJsonContext.Default.AgentReport);
        dto = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{id}/storage", Json);
        Assert.Equal(JsonValueKind.Null, dto.GetProperty("running").ValueKind);
        Assert.Equal(15_730_000, dto.GetProperty("lastCleanup").GetProperty("freedBytes").GetInt64());

        // Fleet: one command per selected host it applies to; destructive needs "delete".
        var fleet = await admin.GetFromJsonAsync<JsonElement>("/api/storage", Json);
        Assert.Contains(fleet.GetProperty("catalog").EnumerateArray(), c => c.GetProperty("id").GetString() == StorageCleanups.AptCache);
        Assert.Contains(fleet.GetProperty("hosts").EnumerateArray(), h => h.GetProperty("hostId").GetGuid() == id);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync("/api/storage/cleanup", new { cleanup = StorageCleanups.DockerVolumes, hostIds = new[] { id } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync("/api/storage/cleanup", new { cleanup = StorageCleanups.DnfCache, hostIds = new[] { id } })).StatusCode);
        var queued = await (await admin.PostAsJsonAsync("/api/storage/cleanup", new { cleanup = StorageCleanups.AptCache, hostIds = new[] { id, Guid.NewGuid() } })).Content.ReadFromJsonAsync<JsonElement>(Json);
        Assert.Single(queued.EnumerateArray());

        // A heartbeat past 90% opens the issue and raises one alert event; staying there doesn't raise another.
        HeartbeatRequest Hb(long used) => new("0.1.0", "disk-01", "Ubuntu 24.04.1 LTS", "6.8.0-45-generic",
            new HostMetrics(1, 1_000, 500, 100_000, used, 0, 0, 0, 60), [], null, []);
        (await agent.PostAsJsonAsync("/api/agent/heartbeat", Hb(50_000), Json)).EnsureSuccessStatusCode();
        (await agent.PostAsJsonAsync("/api/agent/heartbeat", Hb(93_000), Json)).EnsureSuccessStatusCode();
        (await agent.PostAsJsonAsync("/api/agent/heartbeat", Hb(93_500), Json)).EnsureSuccessStatusCode();
        var issues = await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={id}");
        var issue = Assert.Single(issues.GetProperty("items").EnumerateArray(), i => i.GetProperty("rule").GetString() == "storage.low");
        Assert.Equal("Medium", issue.GetProperty("severity").GetString());
        var events = await admin.GetFromJsonAsync<JsonElement>($"/api/events?hostId={id}&kind={EventKinds.StorageLow}");
        Assert.Single(events.GetProperty("items").EnumerateArray());

        (await agent.PostAsJsonAsync("/api/agent/heartbeat", Hb(40_000), Json)).EnsureSuccessStatusCode();
        issues = await admin.GetFromJsonAsync<JsonElement>($"/api/issues?hostId={id}");
        Assert.DoesNotContain(issues.GetProperty("items").EnumerateArray(), i => i.GetProperty("rule").GetString() == "storage.low");
    }
}
