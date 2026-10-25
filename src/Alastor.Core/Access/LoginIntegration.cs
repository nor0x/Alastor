using System.Globalization;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Alastor.Core.Events;
using Alastor.Core.Integrations;
using Alastor.Core.Platform;
using Alastor.Core.Policy;

namespace Alastor.Core.Access;

/// <summary>
/// Reports successful SSH logins (<c>logins.monitor</c>, on by default). It reads sshd's "Accepted …" messages from the
/// journal (<c>journalctl -o json -t sshd -t sshd-session</c>, resuming after a saved cursor) or, where journald isn't
/// readable, from <c>/var/log/auth.log</c> or <c>/var/log/secure</c>. It never replays history: the first read starts now.
/// Each login becomes an Info event; the server keeps every host's (user, address) pairs and alerts on new ones.
/// Nothing is installed or changed.
/// </summary>
public sealed class LoginIntegration(ICommandRunner runner, IFileSystem fs, IStateStore state, ILogger<LoginIntegration> logger, TimeProvider time)
    : IToolIntegration
{
    private const string StateCursor = "logins.cursor";
    private const string StateSince = "logins.since";
    private static readonly string[] LogFiles = ["/var/log/auth.log", "/var/log/secure"];

    /// <summary>Reading the journal is cheap but not free: at most once per interval, however often the supervisor asks.</summary>
    public static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);

    private readonly LogTailer _tailer = new(fs, state, "logins.log");
    private DateTime _lastPoll = DateTime.MinValue;
    private bool _enabled = true;
    private string? _source;

    public static readonly ToolDescriptor Info = new(
        "logins",
        "SSH login monitor",
        Capability.Access,
        "MIT",
        "https://www.freedesktop.org/software/systemd/man/latest/journalctl.html",
        new Dictionary<DistroFamily, string>(),
        "Built in. Reports successful SSH logins from the journal (or auth.log / secure); the server alerts on a user's first login from a new address.");

    public ToolDescriptor Descriptor => Info;

    public bool IsWanted(PolicyDocument policy) => policy.Logins?.Monitor != false;

    public Task<ToolStatus> DetectAsync(CancellationToken ct)
    {
        var journal = runner.Which("journalctl") is not null;
        var file = LogFiles.FirstOrDefault(fs.FileExists);
        if (!journal && file is null)
            return Task.FromResult(new ToolStatus
            {
                ToolId = Info.Id,
                Availability = Availability.Unavailable,
                UnavailableReason = "Neither journalctl nor /var/log/auth.log or /var/log/secure is available, so logins can't be read.",
            });
        return Task.FromResult(new ToolStatus
        {
            ToolId = Info.Id,
            Installed = true,
            Running = _enabled,
            Ownership = Ownership.Adopted,
            ConfigState = ConfigState.InSync,
            Availability = _enabled ? Availability.Available : Availability.Disabled,
            Details = new Dictionary<string, string> { ["source"] = _source ?? (journal ? "journald" : file!) },
        });
    }

    public Task<ToolStatus> EnsureInstalledAsync(ReconcileRequest request, CancellationToken ct) => DetectAsync(ct);

    public Task<ReconcilePlan> PlanAsync(ReconcileRequest request, CancellationToken ct)
    {
        _enabled = IsWanted(request.Policy);
        return Task.FromResult(new ReconcilePlan(Info.Id, request.Revision, [], [], ConfigState.InSync));
    }

    public Task<ReconcileResult> ApplyAsync(ReconcilePlan plan, CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    public Task<ReconcileResult> RemoveManagedStateAsync(CancellationToken ct) => Task.FromResult(ReconcileResult.Ok(ConfigState.InSync));

    public async IAsyncEnumerable<SecurityEvent> CollectEventsAsync([EnumeratorCancellation] CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        if (!_enabled || now - _lastPoll < PollInterval) yield break;
        _lastPoll = now;
        foreach (var login in await ReadAsync(now, ct))
            yield return new SecurityEvent
            {
                Id = SecurityEvent.StableId("login", login.Cursor),
                OccurredAt = login.AtUtc,
                Capability = Capability.Access,
                Severity = Severity.Info,
                SourceTool = Info.Id,
                Kind = EventKinds.Login,
                Subject = login.Address,
                Message = $"{login.User} logged in over SSH from {login.Address} ({login.Method}{(login.Key is null ? "" : $", {login.Key}")})",
                Metadata = new Dictionary<string, string>
                {
                    ["user"] = login.User,
                    ["method"] = login.Method,
                    ["port"] = login.Port.ToString(CultureInfo.InvariantCulture),
                    ["key"] = login.Key ?? "",
                },
                DedupKey = $"logins:{login.User}:{login.Address}",
            };
    }

    public async Task<IReadOnlyList<LoginRecord>> ReadAsync(DateTime now, CancellationToken ct)
    {
        if (runner.Which("journalctl") is not null)
        {
            var cursor = state.Get(StateCursor);
            var since = state.Get(StateSince);
            if (cursor is null && since is null)
            {
                // First run: start from now instead of replaying the journal.
                await state.SetAsync(StateSince, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ct);
                _source = "journald";
                return [];
            }
            string[] args = ["-o", "json", "--no-pager", "-q", "-t", "sshd", "-t", "sshd-session", "-n", "1000",
                cursor is not null ? $"--after-cursor={cursor}" : $"--since=@{since}"];
            var r = await runner.RunAsync("journalctl", args, new CommandOptions { Timeout = TimeSpan.FromSeconds(20) }, ct);
            if (r.Success)
            {
                _source = "journald";
                var (logins, last) = LoginParsers.ParseJournal(r.StdOut);
                if (last is not null) await state.SetAsync(StateCursor, last, ct);
                return logins;
            }
            logger.LogDebug("journalctl failed ({Exit}); reading log files instead", r.ExitCode);
        }
        if (LogFiles.FirstOrDefault(fs.FileExists) is not { } file) return [];
        _source = file;
        var lines = await _tailer.ReadNewLinesAsync(file, ct);
        return lines.Select(l => LoginParsers.ParseSyslogLine(l, now)).OfType<LoginRecord>().ToList();
    }
}
