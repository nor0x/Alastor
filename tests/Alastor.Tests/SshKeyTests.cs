using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging.Abstractions;
using Alastor.Core.Access;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Platform;

namespace Alastor.Tests;

public sealed class SshKeyParserTests
{
    // Throwaway keys from ssh-keygen; the fingerprints are what `ssh-keygen -lf` printed for them.
    public const string Ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATJOvZ4orz/ADKDm6uIWKhAZ70a5XSMCF9kKIxzQoeF alice@laptop";
    public const string Ed25519Fp = "SHA256:P3HYVlg8PrwPOJ4UAN5kWYC8tarFmHU1/MeRaGGtw50";
    public const string Rsa3072 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDk8Lg4xSZkGelkHGupwzOMsMxU5Y0OYWJ3VSQLCLmKZnaP0gTv/xjm9hxv4gMsyA7zWXSLF39obk6L/6lw45uxLPRwQnpxwg6RBl52Me0vaVxfSh7D6Az/KiaNAsh2162GHa3bfMjFSVOV1frmR0HfO2Q2X/Z1I9G+aQXViuP35tq46s0eoEPykra0P06G0AgstG8ag0ezcjgKQ9mJbeb6tcPVzXFn79dDPY0ilEbcgY3CwCkM7Jv0zW5LKSjtKreh8Ud9subU05Gphm+1OQD2JH/I9eDdGSXdjYLNQZdfapFntE3SpI0g9Re0alem2sq2lXMKgWEYvHl2vs3Td8Gp2+i2dKs7/W7VpP8/gAcQLzihOM2mJPb6idkEvWU7lQNXCOKSf5/HjG/u9s6E1xlbZ/iLwBPfzAdlo276xMuLPCMndQbZhmIJyDgHpOtmT7Qhae/72maRmmcuWGCzAi0as8RTYbTZwZRZ91zto43udJ3j60sdrZLw47dM6wOkF90= ci deploy";
    public const string Rsa3072Fp = "SHA256:5GcFufIXMmbZVzo581DySr3RX0JUC1tVCG1das/nakI";
    public const string Rsa1024 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDbAEveGwdjOpbBkKf4knrVhF6eQdQLp9m6v7m7/lzw3LxV4A6mZSVs5jhrl9hXmO0Q9RKFq15uMNlBYsWyOdoKdFNFDunb+fX9iyxaSi5Bjdk5ApSLhiByPoOIwNnaJ9SCh+U2N+2ZAUwYo2MKWjZHhzmIlHrcjxHzYQVnNVksFw== old";
    public const string Rsa1024Fp = "SHA256:8vMmB32GvYF9+I4gJ/+59OHi4qbWlzBdIPTe1ovNLMI";
    public const string Ecdsa384 = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBMmtWyNYb4mX9xwo28AnSI8uX7a5eJq6BNpKF/iuwVhr0G8kztIpYptEEpqBVR5FFvYXT1saGbFBG4Mk7ARPlP4xj+rlvW3oDlsLjT4NVWrkkaGNZFkoKn2Cn3SRPuikSA==";
    public const string Ecdsa384Fp = "SHA256:3VsD4oyle6lJfylgfMlo45hVJTBiwhR2jd+bxrOdh2o";

    [Theory]
    [InlineData(Ed25519, "ssh-ed25519", Ed25519Fp, 256, "alice@laptop")]
    [InlineData(Rsa3072, "ssh-rsa", Rsa3072Fp, 3072, "ci deploy")]
    [InlineData(Rsa1024, "ssh-rsa", Rsa1024Fp, 1024, "old")]
    [InlineData(Ecdsa384, "ecdsa-sha2-nistp384", Ecdsa384Fp, 384, "")]
    public void Fingerprints_and_sizes_match_ssh_keygen(string line, string type, string fingerprint, int bits, string comment)
    {
        var k = SshKeyParser.Parse(line)!;
        Assert.Equal((type, fingerprint, bits, comment, ""), (k.Type, k.Fingerprint, k.Bits, k.Comment, k.Options));
        Assert.True(SshKeyParser.IsFingerprint(k.Fingerprint));
    }

    [Fact]
    public void Options_with_quoted_spaces_are_kept_apart_from_the_key()
    {
        var k = SshKeyParser.Parse($"from=\"10.0.0.0/8, 192.168.1.1\",no-pty,command=\"echo \\\"hi there\\\"\" {Ed25519}")!;
        Assert.Equal("from=\"10.0.0.0/8, 192.168.1.1\",no-pty,command=\"echo \\\"hi there\\\"\"", k.Options);
        Assert.Equal(Ed25519Fp, k.Fingerprint);
        Assert.Equal("alice@laptop", k.Comment);
    }

    [Theory]
    [InlineData("")]
    [InlineData("# ssh-ed25519 AAAA comment")]
    [InlineData("ssh-ed25519 not-base64!")]
    [InlineData("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIATJOvZ4orz/ADKDm6uIWKhAZ70a5XSMCF9kKIxzQoeF")] // ed25519 blob labelled rsa
    [InlineData("ssh-xmss@openssh.com AAAA")]
    public void Non_keys_are_skipped(string line) => Assert.Null(SshKeyParser.Parse(line));

    [Theory]
    [InlineData("", "Paste a public key")]
    [InlineData(Ed25519 + "\n" + Rsa3072, "one key at a time")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----", "private key")]
    [InlineData("no-pty " + Ed25519, "without options")]
    [InlineData(Rsa1024, "weak keys")]
    [InlineData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATJOvZ4orz", "damaged")]
    [InlineData("hello world", "Not an OpenSSH public key")]
    public void New_keys_must_be_one_plain_strong_key(string text, string error)
    {
        Assert.Null(SshKeyParser.ParseNew(text, out var e));
        Assert.Contains(error, e);
    }

    [Fact]
    public void A_new_key_is_written_back_as_a_canonical_line()
    {
        var k = SshKeyParser.ParseNew($"  {Ed25519}  \r\n", out var e)!;
        Assert.Null(e);
        Assert.Equal(Ed25519, k.ToLine());
    }

    [Theory]
    [InlineData("root", true)]
    [InlineData("deploy-bot.2", true)]
    [InlineData("host$", true)]
    [InlineData("-rf", false)]
    [InlineData("../etc", false)]
    [InlineData("a b", false)]
    [InlineData("", false)]
    public void User_names_are_checked(string user, bool valid) => Assert.Equal(valid, SshKeyParser.IsValidUser(user));
}

public sealed class SshKeysIntegrationTests
{
    private const string Passwd = """
        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        alice:x:1000:1000:Alice:/home/alice:/bin/bash
        bob:x:1001:1001:Bob:/home/bob:/bin/zsh
        git:x:998:998::/srv/git:/usr/bin/git-shell
        """;

    private static (SshKeysIntegration Keys, FakeCommandRunner Runner, FakeFileSystem Fs, InMemoryStateStore State) Create(bool passwords = false)
    {
        var runner = new FakeCommandRunner();
        runner.Installed.UnionWith(["getent", "sshd"]);
        runner.On("sshd -T", $"passwordauthentication {(passwords ? "yes" : "no")}\nkbdinteractiveauthentication no\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\nauthorizedkeyscommand none\n")
            .On("getent passwd", Passwd)
            .On("getent group sudo wheel admin", "sudo:x:27:alice\n");
        runner.Fallback = (cmd, _) => cmd is "chown" or "chmod" ? new CommandResult(0, "", "") : null;
        var fs = new FakeFileSystem();
        fs.Files["/root/.ssh/authorized_keys"] = $"# managed by hand\n{SshKeyParserTests.Ed25519}\n";
        fs.Files["/home/alice/.ssh/authorized_keys"] = $"{SshKeyParserTests.Rsa3072}\nssh-ed25519-cert-v01@openssh.com AAAA cert\n";
        fs.Files["/srv/git/.ssh/authorized_keys"] = $"command=\"gitolite-shell bob\",no-pty {SshKeyParserTests.Ecdsa384}\n";
        fs.Files["/home/bob/.bashrc"] = "";
        var state = new InMemoryStateStore();
        return (new SshKeysIntegration(runner, fs, state, NullLogger<SshKeysIntegration>.Instance, TimeProvider.System), runner, fs, state);
    }

    private static async Task<List<SecurityEvent>> EventsAsync(SshKeysIntegration keys)
    {
        var list = new List<SecurityEvent>();
        await foreach (var e in keys.CollectEventsAsync(default)) list.Add(e);
        return list;
    }

    [Fact]
    public async Task Scan_lists_login_accounts_and_any_account_with_keys()
    {
        var (keys, _, _, _) = Create();
        var report = (await keys.ScanAsync(default)).SshKeys!;

        Assert.Equal(["root", "alice", "bob", "git"], report.Accounts.Select(a => a.User));
        Assert.False(report.PasswordLogin);
        var root = report.Accounts[0];
        Assert.True(root.Admin);
        Assert.Equal(["/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2"], root.Files);
        Assert.Equal((SshKeyParserTests.Ed25519Fp, 2), (root.Keys.Single().Fingerprint, root.Keys.Single().Line));
        Assert.True(report.Accounts[1].Admin); // sudo member
        Assert.Empty(report.Accounts[2].Keys);
        var git = report.Accounts[3]; // no login shell, but it has a key
        Assert.Equal("command=\"gitolite-shell bob\",no-pty", git.Keys.Single().Options);
        Assert.Contains(report.Notes, n => n.Contains("/home/alice/.ssh/authorized_keys: 1 line isn't a key", StringComparison.Ordinal));
        Assert.Empty(await EventsAsync(keys)); // the first scan learns
    }

    [Fact]
    public async Task Keys_added_behind_the_dashboards_back_raise_an_alert()
    {
        var (keys, _, fs, _) = Create();
        await keys.ScanAsync(default);
        fs.Files["/root/.ssh/authorized_keys"] += SshKeyParserTests.Rsa3072 + "\n";
        fs.Files["/home/alice/.ssh/authorized_keys"] = "";
        await keys.ScanAsync(default);

        var events = await EventsAsync(keys);
        var appeared = Assert.Single(events, e => e.Kind == EventKinds.KeyAppeared);
        Assert.Equal((Severity.Critical, "root"), (appeared.Severity, appeared.Subject));
        Assert.Contains(SshKeyParserTests.Rsa3072Fp, appeared.Message);
        var gone = Assert.Single(events, e => e.Kind == EventKinds.KeyDisappeared);
        Assert.Equal(("alice", SshKeyParserTests.Rsa3072Fp), (gone.Subject, gone.Metadata["fingerprint"]));
    }

    [Fact]
    public async Task Adding_a_key_creates_ssh_dir_and_file_owned_by_the_account_without_alerting()
    {
        var (keys, runner, fs, _) = Create();
        await keys.ScanAsync(default);

        var r = await keys.AddAsync("bob", SshKeyParserTests.Ed25519, default);
        Assert.True(r.Success, r.Message);
        Assert.Equal(SshKeyParserTests.Ed25519 + "\n", fs.Files["/home/bob/.ssh/authorized_keys"]);
        Assert.Contains("chmod 700 /home/bob/.ssh", runner.Calls);
        Assert.Contains("chown -h 1001:1001 /home/bob/.ssh", runner.Calls);
        Assert.Contains("chown -h 1001:1001 /home/bob/.ssh/authorized_keys", runner.Calls);

        Assert.False((await keys.AddAsync("bob", SshKeyParserTests.Ed25519, default)).Changed); // already there
        await keys.ScanAsync(default);
        var events = await EventsAsync(keys);
        Assert.Equal([EventKinds.KeyAdded], events.Select(e => e.Kind));
    }

    [Fact]
    public async Task A_dashboard_change_does_not_hide_a_key_someone_else_added_since_the_last_scan()
    {
        var (keys, _, fs, _) = Create();
        await keys.ScanAsync(default);
        fs.Files["/root/.ssh/authorized_keys"] += SshKeyParserTests.Rsa3072 + "\n"; // the attacker
        await keys.AddAsync("bob", SshKeyParserTests.Ed25519, default);
        await keys.ScanAsync(default);

        Assert.Contains(await EventsAsync(keys), e => e.Kind == EventKinds.KeyAppeared && e.Subject == "root");
    }

    [Fact]
    public async Task Adding_refuses_unknown_accounts_weak_keys_and_symlinks()
    {
        var (keys, _, fs, _) = Create();
        Assert.Contains("isn't an account", (await keys.AddAsync("daemon", SshKeyParserTests.Ed25519, default)).Message);
        Assert.Contains("weak", (await keys.AddAsync("bob", SshKeyParserTests.Rsa1024, default)).Message);
        fs.Links.Add("/home/alice/.ssh/authorized_keys");
        var r = await keys.AddAsync("alice", SshKeyParserTests.Ed25519, default);
        Assert.False(r.Success);
        Assert.Contains("symbolic link", r.Message);
    }

    [Fact]
    public async Task Removing_drops_only_that_key_and_gives_the_file_back()
    {
        var (keys, runner, fs, _) = Create();
        fs.Files["/home/alice/.ssh/authorized_keys"] = $"# laptop\n{SshKeyParserTests.Rsa3072}\nno-pty {SshKeyParserTests.Ed25519}\n";

        var r = await keys.RemoveAsync("alice", SshKeyParserTests.Ed25519Fp, default);
        Assert.True(r.Success, r.Message);
        Assert.Equal($"# laptop\n{SshKeyParserTests.Rsa3072}\n", fs.Files["/home/alice/.ssh/authorized_keys"]);
        Assert.Contains("chown -h 1000:1000 /home/alice/.ssh/authorized_keys", runner.Calls);
        Assert.Equal(EventKinds.KeyRemoved, Assert.Single(await EventsAsync(keys)).Kind);
    }

    [Fact]
    public async Task The_last_admin_key_stays_when_sshd_takes_no_passwords()
    {
        var (keys, _, fs, _) = Create();
        fs.Files["/home/alice/.ssh/authorized_keys"] = "";

        var r = await keys.RemoveAsync("root", SshKeyParserTests.Ed25519Fp, default);
        Assert.False(r.Success);
        Assert.Contains("lock everyone out", r.Message);
        Assert.Contains(SshKeyParserTests.Ed25519, fs.Files["/root/.ssh/authorized_keys"]);

        // With passwords on, or another admin key, it can go.
        var (withPasswords, _, fs2, _) = Create(passwords: true);
        fs2.Files["/home/alice/.ssh/authorized_keys"] = "";
        Assert.True((await withPasswords.RemoveAsync("root", SshKeyParserTests.Ed25519Fp, default)).Success);
        var (another, _, _, _) = Create();
        Assert.True((await another.RemoveAsync("root", SshKeyParserTests.Ed25519Fp, default)).Success);
    }
}

[Collection(ServerHostCollection.Name)]
public sealed class SshKeysApiTests : IClassFixture<ServerApiTests.Factory>
{
    private readonly ServerApiTests.Factory _factory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public SshKeysApiTests(ServerApiTests.Factory factory) => _factory = factory;

    [Fact]
    public async Task Keys_are_listed_and_changes_are_checked_before_they_reach_the_agent()
    {
        var admin = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        (await admin.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "test-password-123" })).EnsureSuccessStatusCode();
        admin.DefaultRequestHeaders.Add("X-Alastor-Request", "1");
        var token = await (await admin.PostAsJsonAsync("/api/enrollment-tokens", new { note = "keys" })).Content.ReadFromJsonAsync<JsonElement>();
        var resp = (await (await _factory.CreateClient().PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(token.GetProperty("secret").GetString()!, "keys-01", "Debian 13", "debian", "13", "x64", "0.1.0", null))).Content.ReadFromJsonAsync<EnrollResponse>(Json))!;
        var agent = _factory.CreateClient();
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", resp.AgentSecret);
        var id = resp.AgentId;

        // Before the first scan the server doesn't know the accounts.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/ssh-keys", new { user = "root", key = SshKeyParserTests.Ed25519 })).StatusCode);

        var report = new SshKeysReport(
        [
            new KeyAccount("root", 0, "/root", true, ["/root/.ssh/authorized_keys"],
                [new AuthorizedKey("/root/.ssh/authorized_keys", 1, "ssh-ed25519", SshKeyParserTests.Ed25519Fp, 256, "alice@laptop", "")]),
            new KeyAccount("deploy", 1001, "/home/deploy", false, ["/home/deploy/.ssh/authorized_keys"],
                [new AuthorizedKey("/home/deploy/.ssh/authorized_keys", 3, "ssh-rsa", SshKeyParserTests.Rsa1024Fp, 1024, "old", "")]),
        ], KeysCommand: false, PasswordLogin: false);
        var now = DateTime.UtcNow;
        Assert.Equal(HttpStatusCode.NoContent,
            (await agent.PostAsJsonAsync("/api/agent/reports", new AgentReport(SshKeysIntegration.ScanJob, now, now, true, null) { SshKeys = report }, AgentJsonContext.Default.AgentReport)).StatusCode);

        var dto = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{id}/ssh-keys", Json);
        Assert.Equal(["root", "deploy"], dto.GetProperty("accounts").EnumerateArray().Select(a => a.GetProperty("user").GetString()));
        var weak = dto.GetProperty("accounts")[1].GetProperty("keys")[0];
        Assert.Equal(("RSA", true), (weak.GetProperty("typeName").GetString(), weak.GetProperty("weakness").GetString()!.Contains("2048")));
        Assert.Equal("logins.keysSchedule", dto.GetProperty("schedules")[0].GetProperty("key").GetString());

        // Refused before anything reaches the agent: bad keys, unknown accounts, duplicates, the last admin key, unknown keys.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/ssh-keys", new { user = "deploy", key = "-----BEGIN OPENSSH PRIVATE KEY-----" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/hosts/{id}/ssh-keys", new { user = "nobody", key = SshKeyParserTests.Rsa3072 })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync($"/api/hosts/{id}/ssh-keys", new { user = "root", key = SshKeyParserTests.Ed25519 })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync($"/api/hosts/{id}/ssh-keys/remove", new { user = "root", fingerprint = SshKeyParserTests.Ed25519Fp })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsJsonAsync($"/api/hosts/{id}/ssh-keys/remove", new { user = "deploy", fingerprint = SshKeyParserTests.Ed25519Fp })).StatusCode);
        Assert.Empty((await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json))!);

        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsJsonAsync($"/api/hosts/{id}/ssh-keys", new { user = "deploy", key = SshKeyParserTests.Rsa3072 })).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsJsonAsync($"/api/hosts/{id}/ssh-keys/remove", new { user = "deploy", fingerprint = SshKeyParserTests.Rsa1024Fp })).StatusCode);
        dto = await admin.GetFromJsonAsync<JsonElement>($"/api/hosts/{id}/ssh-keys", Json);
        Assert.Equal(["add", "remove"], dto.GetProperty("pending").EnumerateArray().Select(p => p.GetProperty("op").GetString()));
        var cmds = (await agent.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", Json))!;
        Assert.All(cmds, c => Assert.Equal(AgentCommandTypes.SshKey, c.Type));
        Assert.Equal(SshKeyParserTests.Rsa3072, cmds[0].Payload["key"]);
        Assert.Equal(SshKeyParserTests.Rsa1024Fp, cmds[1].Payload["fingerprint"]);
    }
}
