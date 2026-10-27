using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Extensions.Logging;
using Alastor.Core.Baseline;
using Alastor.Core.Contracts;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Core.Access;

/// <summary>
/// Which keys let whom in over SSH, and changing that from the dashboard:
/// <list type="bullet">
/// <item>On <c>logins.keysSchedule</c>, reads the authorized_keys files sshd reads (<c>AuthorizedKeysFile</c> from <c>sshd -T</c>)
/// for every account that can log in (root, uid ≥ 1000 with a login shell) or already has keys.</item>
/// <item>Keys that appear or disappear between scans without going through the dashboard raise events: an unexpected new
/// key is High (Critical for root), because that's how attackers keep their way in. The first scan learns silently.</item>
/// <item>Adds a key to an account's first authorized_keys file (creating <c>~/.ssh</c> 0700 and the file 0600, owned by the
/// account), or removes one by fingerprint from all of them. It refuses to remove the last admin key when sshd
/// doesn't take passwords, so nobody gets locked out.</item>
/// </list>
/// The server sends only a user name and a key line or fingerprint; every path comes from here.
/// </summary>
public sealed class SshKeysIntegration(ICommandRunner runner, IFileSystem fs, IStateStore state, ILogger<SshKeysIntegration> logger, TimeProvider time)
    : IToolIntegration, IScheduledJobProvider
{
    public const string ScanJob = "access.keys";
    public const int MaxAccounts = 200;
    public const int MaxKeysPerAccount = 200;

    private const string StateKnown = "sshkeys.known";
    private const string DefaultKeysFiles = ".ssh/authorized_keys .ssh/authorized_keys2";
    private static readonly string[] NoLoginShells = ["nologin", "false", "sync", "shutdown", "halt"];

    private readonly ConcurrentQueue<SecurityEvent> _events = new();
    private readonly SemaphoreSlim _lock = new(1, 1);
    private volatile bool _alert = true;
    private SshKeysReport? _last;
    private string? _lastError;
    private DateTime? _lastSuccess;

    public static readonly ToolDescriptor Info = new(
        "ssh-keys",
        "SSH authorized keys",
        Capability.Access,
        "MIT",
        "https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT",
        new Dictionary<DistroFamily, string>(),
        "Built in. Lists every account's authorized SSH keys, adds and removes them from the dashboard, and alerts on keys added behind its back.");

    public ToolDescriptor Descriptor => Info;

    public IReadOnlyList<ScheduledJob> Jobs =>
    [
        new(ScanJob, "Scan SSH keys", "logins.keysSchedule", RunOnFirstStart: true, (policy, _, ct) =>
        {
            _alert = policy.Logins?.AlertOnNewKey != false;
            return ScanAsync(ct);
        }),
    ];

    public bool IsWanted(PolicyDocument policy)
    {
        _alert = policy.Logins?.AlertOnNewKey != false;
        return true;
    }

    public Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        if (runner.Which("getent") is null)
            return Task.FromResult(new ToolStatus { ToolId = Info.Id, Availability = Availability.Unavailable, UnavailableReason = "getent isn't available, so accounts can't be listed." });
        var details = new Dictionary<string, string>();
        if (_last is { } r)
        {
            details["keys"] = r.Accounts.Sum(a => a.Keys.Count).ToString(CultureInfo.InvariantCulture);
            details["accountsWithKeys"] = r.Accounts.Count(a => a.Keys.Count > 0).ToString(CultureInfo.InvariantCulture);
        }
        return Task.FromResult(new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Running = true,
            Ownership = Ownership.Adopted,
            ConfigState = ConfigState.InSync,
            LastError = _lastError,
            LastSuccessAt = _lastSuccess,
            Details = details,
        });
    }

    public Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct) => DetectAsync(ct);

    public Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct) =>
        Task.FromResult(new ReconcilePlan(Info.Id, request.Revision, [], [], ConfigState.InSync));

    public Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    public Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        await Task.CompletedTask;
        while (_events.TryDequeue(out var e)) yield return e;
    }

    // ---- scan ----

    public async Task<AgentReport> ScanAsync(CancellationToken ct)
    {
        var started = time.GetUtcNow().UtcDateTime;
        await _lock.WaitAsync(ct);
        try
        {
            var snap = await GatherAsync(ct);
            if (snap is null)
            {
                _lastError = "getent passwd returned no accounts.";
                return new AgentReport(ScanJob, started, time.GetUtcNow().UtcDateTime, false, _lastError);
            }
            await DiffAsync(snap.Report, ct);
            _last = snap.Report;
            _lastError = null;
            _lastSuccess = time.GetUtcNow().UtcDateTime;
            logger.LogInformation("SSH keys: {Keys} keys across {Accounts} accounts", snap.Report.Accounts.Sum(a => a.Keys.Count), snap.Report.Accounts.Count(a => a.Keys.Count > 0));
            return new AgentReport(ScanJob, started, _lastSuccess.Value, true, null) { SshKeys = snap.Report };
        }
        finally
        {
            _lock.Release();
        }
    }

    private sealed record Snapshot(SshKeysReport Report, IReadOnlyList<AccountInfo> Accounts);

    private async Task<Snapshot?> GatherAsync(CancellationToken ct)
    {
        var notes = new List<string>();
        Dictionary<string, string>? sshd = null;
        if (runner.Which("sshd") is null) notes.Add("No SSH server (sshd) found; these are the files it would read.");
        else
        {
            var r = await runner.RunAsync("sshd", ["-T"], null, ct);
            if (r.Success) sshd = BaselineParsers.ParseSshdT(r.StdOut);
            else notes.Add($"sshd -T failed, so the default key files are assumed: {FirstLine(r.CombinedOutput)}");
        }
        var accounts = BaselineParsers.ParseGetentPasswd((await runner.RunAsync("getent", ["passwd"], null, ct)).StdOut);
        if (accounts.Count == 0) return null;
        var members = BaselineParsers.ParseGetentGroupMembers((await runner.RunAsync("getent", ["group", "sudo", "wheel", "admin"], null, ct)).StdOut);
        var patterns = (sshd?.GetValueOrDefault("authorizedkeysfile") ?? DefaultKeysFiles).Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Where(p => p != "none").ToList();
        if (patterns.Count == 0) notes.Add("sshd reads no authorized_keys files (AuthorizedKeysFile none).");

        var list = new List<KeyAccount>();
        foreach (var account in accounts.DistinctBy(a => a.Name))
        {
            var files = patterns.Select(p => BaselineParsers.ExpandAuthorizedKeysPath(p, account)).Distinct(StringComparer.Ordinal).ToList();
            var keys = new List<AuthorizedKey>();
            foreach (var file in files)
            {
                string? content;
                try { content = await fs.ReadAllTextAsync(file, ct); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    notes.Add($"{file}: couldn't be read ({ex.Message})");
                    continue;
                }
                if (content is null) continue;
                var unreadable = 0;
                var lines = content.Split('\n');
                for (var i = 0; i < lines.Length && keys.Count < MaxKeysPerAccount; i++)
                {
                    var t = lines[i].Trim();
                    if (t.Length == 0 || t[0] == '#') continue;
                    if (SshKeyParser.Parse(t) is { } k) keys.Add(new AuthorizedKey(file, i + 1, k.Type, k.Fingerprint, k.Bits, Clip(k.Comment, SshKeyParser.MaxCommentLength), Clip(k.Options, 500)));
                    else unreadable++;
                }
                if (unreadable > 0) notes.Add($"{file}: {unreadable} line{(unreadable == 1 ? " isn't a key" : "s aren't keys")} Alastor understands (certificates or newer key types); they're left alone.");
            }
            var admin = account.Name == "root" || members.Contains(account.Name);
            if (keys.Count > 0 || (CanLogin(account) && (account.Uid == 0 || account.Uid is >= 1000 and < 65534)))
                list.Add(new KeyAccount(account.Name, account.Uid, account.Home, admin, files, keys));
            if (list.Count >= MaxAccounts) break;
        }
        var keysCommand = sshd is not null && sshd.GetValueOrDefault("authorizedkeyscommand", "none") is not ("none" or "");
        bool? passwords = sshd is null ? null
            : sshd.GetValueOrDefault("passwordauthentication") == "yes"
              || sshd.GetValueOrDefault("kbdinteractiveauthentication", sshd.GetValueOrDefault("challengeresponseauthentication", "no")) == "yes";
        var ordered = list.OrderBy(a => a.Uid == 0 ? 0 : 1).ThenBy(a => a.User, StringComparer.Ordinal).ToList();
        return new Snapshot(new SshKeysReport(ordered, keysCommand, passwords) { Notes = notes.Take(50).ToList() }, accounts);
    }

    /// <summary>Compares the keys with the last scan's and raises events for changes the dashboard didn't make.</summary>
    private async Task DiffAsync(SshKeysReport report, CancellationToken ct)
    {
        var current = report.Accounts.SelectMany(a => a.Keys.Select(k => (a.User, Key: k))).ToList();
        var stored = state.Get(StateKnown);
        await SaveKnownAsync(current.Select(c => Known(c.User, c.Key.Fingerprint)), ct);
        if (stored is null) return; // first scan: learn
        var known = stored.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        var now = time.GetUtcNow().UtcDateTime;
        foreach (var (user, key) in current.DistinctBy(c => Known(c.User, c.Key.Fingerprint)).Where(c => !known.Contains(Known(c.User, c.Key.Fingerprint))))
        {
            if (!_alert) continue;
            _events.Enqueue(KeyEvent(now, user, key.Fingerprint, EventKinds.KeyAppeared, user == "root" ? Severity.Critical : Severity.High,
                $"A new SSH key was authorized for {user} outside Alastor: {Describe(key.Type, key.Bits, key.Fingerprint, key.Comment)} in {key.File}. If nobody you know added it, remove it and treat the host as compromised.",
                key.File));
        }
        var currentSet = current.Select(c => Known(c.User, c.Key.Fingerprint)).ToHashSet(StringComparer.Ordinal);
        foreach (var gone in known.Where(k => !currentSet.Contains(k)))
        {
            var (user, fingerprint) = SplitKnown(gone);
            _events.Enqueue(KeyEvent(now, user, fingerprint, EventKinds.KeyDisappeared, Severity.Info,
                $"An SSH key of {user} was removed outside Alastor: {fingerprint}", null));
        }
    }

    // ---- changes ----

    /// <param name="Changed">False when there was nothing to do (the key was already there, or already gone).</param>
    public sealed record KeyChangeResult(bool Success, bool Changed, string Message);

    public async Task<KeyChangeResult> AddAsync(string user, string keyText, CancellationToken ct)
    {
        if (!SshKeyParser.IsValidUser(user)) return new(false, false, "Invalid user name");
        if (SshKeyParser.ParseNew(keyText, out var error) is not { } key) return new(false, false, error!);
        await _lock.WaitAsync(ct);
        try
        {
            if (await GatherAsync(ct) is not { } snap) return new(false, false, "Couldn't list the accounts on this host (getent passwd).");
            var account = snap.Report.Accounts.FirstOrDefault(a => a.User == user);
            var info = snap.Accounts.FirstOrDefault(a => a.Name == user);
            if (account is null || info is null) return new(false, false, $"{user} isn't an account that can log in over SSH on this host.");
            var described = Describe(key.Type, key.Bits, key.Fingerprint, key.Comment);
            if (account.Keys.Any(k => k.Fingerprint == key.Fingerprint)) return new(true, false, $"{described} is already authorized for {user}.");
            if (account.Files.Count == 0) return new(false, false, "sshd reads no authorized_keys files here (AuthorizedKeysFile none).");

            var path = account.Files[0];
            var dir = path[..Math.Max(1, path.LastIndexOf('/'))];
            var inHome = IsUnder(path, info.Home);
            if (fs.IsSymbolicLink(path) || (inHome && fs.IsSymbolicLink(dir)))
                return new(false, false, $"{(fs.IsSymbolicLink(path) ? path : dir)} is a symbolic link. Alastor doesn't write through links; change it by hand.");
            if (inHome && !fs.DirectoryExists(info.Home)) return new(false, false, $"{user}'s home directory {info.Home} doesn't exist.");
            if (!fs.DirectoryExists(dir))
            {
                fs.CreateDirectory(dir);
                if (inHome)
                {
                    if (await RunAsync("chmod", ["700", dir], ct) is { } e1) return new(false, false, e1);
                    if (await ChownAsync(info, dir, ct) is { } e2) return new(false, false, e2);
                }
            }
            var existing = await fs.ReadAllTextAsync(path, ct) ?? "";
            var content = existing.Length == 0 || existing.EndsWith('\n') ? existing : existing + "\n";
            await fs.WriteAllTextAtomicAsync(path, content + key.ToLine() + "\n", inHome ? UnixFileMode.UserRead | UnixFileMode.UserWrite : Readable, ct);
            var warning = inHome ? await ChownAsync(info, path, ct) : null;
            await UpdateKnownAsync(k => k.Add(Known(user, key.Fingerprint)), ct);
            _events.Enqueue(KeyEvent(time.GetUtcNow().UtcDateTime, user, key.Fingerprint, EventKinds.KeyAdded, Severity.Info,
                $"SSH key authorized for {user} from the dashboard: {described}", path));
            logger.LogInformation("Authorized {Fingerprint} for {User} in {Path}", key.Fingerprint, user, path);
            return new(true, true, $"Authorized {described} for {user} in {path}{(warning is null ? "" : $" ({warning})")}");
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<KeyChangeResult> RemoveAsync(string user, string fingerprint, CancellationToken ct)
    {
        if (!SshKeyParser.IsValidUser(user)) return new(false, false, "Invalid user name");
        if (!SshKeyParser.IsFingerprint(fingerprint)) return new(false, false, "Invalid fingerprint");
        await _lock.WaitAsync(ct);
        try
        {
            if (await GatherAsync(ct) is not { } snap) return new(false, false, "Couldn't list the accounts on this host (getent passwd).");
            var account = snap.Report.Accounts.FirstOrDefault(a => a.User == user);
            var info = snap.Accounts.FirstOrDefault(a => a.Name == user);
            var matches = account?.Keys.Where(k => k.Fingerprint == fingerprint).ToList() ?? [];
            if (account is null || info is null || matches.Count == 0) return new(true, false, $"{fingerprint} isn't authorized for {user} (any more).");
            if (LockoutReason(snap.Report, user, fingerprint) is { } lockout) return new(false, false, lockout);

            foreach (var file in matches.Select(k => k.File).Distinct(StringComparer.Ordinal))
            {
                if (fs.IsSymbolicLink(file)) return new(false, false, $"{file} is a symbolic link. Alastor doesn't write through links; change it by hand.");
                var content = await fs.ReadAllTextAsync(file, ct) ?? "";
                var kept = content.Split('\n').Where(l => SshKeyParser.Parse(l)?.Fingerprint != fingerprint);
                var mode = fs.GetUnixFileMode(file) ?? (UnixFileMode.UserRead | UnixFileMode.UserWrite);
                await fs.WriteAllTextAtomicAsync(file, string.Join('\n', kept), mode, ct);
                // The rewrite leaves the file owned by root; give it back.
                if (IsUnder(file, info.Home) && await ChownAsync(info, file, ct) is { } warning) logger.LogWarning("{Warning}", warning);
            }
            var described = Describe(matches[0].Type, matches[0].Bits, fingerprint, matches[0].Comment);
            await UpdateKnownAsync(k => k.Remove(Known(user, fingerprint)), ct);
            _events.Enqueue(KeyEvent(time.GetUtcNow().UtcDateTime, user, fingerprint, EventKinds.KeyRemoved, Severity.Info,
                $"SSH key removed from {user} from the dashboard: {described}", matches[0].File));
            logger.LogInformation("Removed {Fingerprint} from {User}", fingerprint, user);
            return new(true, true, $"Removed {described} from {user}");
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Removing this key would leave no admin account with a key while sshd takes no passwords (or that's unknown) and asks
    /// no AuthorizedKeysCommand: the reason to refuse, or null.
    /// </summary>
    public static string? LockoutReason(SshKeysReport report, string user, string fingerprint)
    {
        if (report.KeysCommand || report.PasswordLogin == true) return null;
        var target = report.Accounts.FirstOrDefault(a => a.User == user);
        if (target is null || !target.Admin) return null;
        var anyLeft = report.Accounts.Any(a => a.Admin && a.Keys.Any(k => a.User != user || k.Fingerprint != fingerprint));
        return anyLeft ? null
            : $"This is the last SSH key of any admin account, and the SSH server {(report.PasswordLogin is null ? "may not" : "doesn't")} accept passwords: removing it would lock everyone out. Add another admin key first.";
    }

    // ---- helpers ----

    private const UnixFileMode Readable = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    private async Task<string?> ChownAsync(AccountInfo account, string path, CancellationToken ct) =>
        await RunAsync("chown", ["-h", account.Gid >= 0 ? $"{account.Uid}:{account.Gid}" : account.Uid.ToString(CultureInfo.InvariantCulture), path], ct);

    private async Task<string?> RunAsync(string command, string[] args, CancellationToken ct)
    {
        var r = await runner.RunAsync(command, args, null, ct);
        return r.Success ? null : $"{command} {string.Join(' ', args)} failed: {FirstLine(r.CombinedOutput)}";
    }

    private static bool CanLogin(AccountInfo a) =>
        a.Shell.Length > 0 && !NoLoginShells.Any(s => a.Shell.EndsWith("/" + s, StringComparison.Ordinal) || a.Shell == s);

    private static bool IsUnder(string path, string home) =>
        home.Length > 1 && path.StartsWith(home.TrimEnd('/') + "/", StringComparison.Ordinal);

    private static string Known(string user, string fingerprint) => $"{user} {fingerprint}";

    private static (string User, string Fingerprint) SplitKnown(string s)
    {
        var i = s.IndexOf(' ');
        return i < 0 ? (s, "") : (s[..i], s[(i + 1)..]);
    }

    private Task SaveKnownAsync(IEnumerable<string> known, CancellationToken ct) =>
        state.SetAsync(StateKnown, string.Join('\n', known.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)), ct);

    /// <summary>
    /// Records one change the dashboard made, so the next scan doesn't report it. Only that entry changes: a key someone
    /// else added since the last scan must still be reported. Before the first scan there is nothing to update.
    /// </summary>
    private async Task UpdateKnownAsync(Action<HashSet<string>> change, CancellationToken ct)
    {
        if (state.Get(StateKnown) is not { } stored) return;
        var known = stored.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        change(known);
        await SaveKnownAsync(known, ct);
    }

    public static string Describe(string type, int? bits, string fingerprint, string comment)
    {
        var sb = new StringBuilder(TypeName(type));
        if (bits is { } b && type is "ssh-rsa" or "ssh-dss") sb.Append(CultureInfo.InvariantCulture, $" {b}");
        sb.Append(' ').Append(fingerprint);
        if (comment.Length > 0) sb.Append(" (").Append(comment).Append(')');
        return sb.ToString();
    }

    public static string TypeName(string type) => type switch
    {
        "ssh-ed25519" => "ED25519",
        "ssh-rsa" => "RSA",
        "ssh-dss" => "DSA",
        "sk-ssh-ed25519@openssh.com" => "ED25519-SK",
        "sk-ecdsa-sha2-nistp256@openssh.com" => "ECDSA-SK",
        _ when type.StartsWith("ecdsa-", StringComparison.Ordinal) => "ECDSA",
        _ => type,
    };

    private static SecurityEvent KeyEvent(DateTime at, string user, string fingerprint, string kind, Severity severity, string message, string? file) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = at,
        Capability = Capability.Access,
        Severity = severity,
        SourceTool = Info.Id,
        Kind = kind,
        Subject = user,
        Message = message,
        Metadata = new Dictionary<string, string> { ["user"] = user, ["fingerprint"] = fingerprint, ["file"] = file ?? "" },
        DedupKey = $"{kind}:{user}:{fingerprint}",
    };

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max];

    private static string FirstLine(string s) => s.Trim().Split('\n').FirstOrDefault()?.Trim() ?? "";
}
