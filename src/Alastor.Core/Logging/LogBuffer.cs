using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting.Display;

namespace Alastor.Core.Logging;

/// <summary>One log line as the dashboard shows it. <see cref="Seq"/> only orders lines within one process.</summary>
public sealed record LogLine(long Seq, DateTime At, string Level, string Source, string Message);

/// <summary>
/// The newest log lines of this process, kept in memory so the dashboard can show them without SSH and journalctl.
/// The agent sends what it has not sent yet with each heartbeat; the server keeps its own for the Settings page.
/// </summary>
public sealed class LogBuffer(int capacity)
{
    public const int MaxMessageLength = 4000;

    private readonly LogLine[] _ring = new LogLine[capacity];
    private readonly Lock _lock = new();
    private long _seq;

    public void Add(DateTime at, string level, string source, string message)
    {
        if (message.Length > MaxMessageLength) message = message[..MaxMessageLength] + "…";
        lock (_lock)
        {
            _seq++;
            _ring[_seq % capacity] = new LogLine(_seq, at, level, source, message);
        }
    }

    /// <summary>Lines after <paramref name="seq"/>, oldest first, at most <paramref name="max"/> (the newest ones when there are more).</summary>
    public IReadOnlyList<LogLine> Since(long seq, int max)
    {
        lock (_lock)
        {
            var from = Math.Max(Math.Max(seq, _seq - capacity), _seq - max) + 1;
            var lines = new List<LogLine>((int)Math.Max(0, _seq - from + 1));
            for (var s = from; s <= _seq; s++) lines.Add(_ring[s % capacity]);
            return lines;
        }
    }

    /// <summary>The newest lines, oldest first.</summary>
    public IReadOnlyList<LogLine> Latest(int max) => Since(0, max);
}

/// <summary>Feeds Serilog events into a <see cref="LogBuffer"/>, rendered like the console output.</summary>
public sealed class LogBufferSink(LogBuffer buffer) : ILogEventSink
{
    // ":l": strings and ids as plain text, not quoted like Serilog's default rendering.
    private static readonly MessageTemplateTextFormatter Text = new("{Message:l}");

    public void Emit(LogEvent e)
    {
        var source = e.Properties.TryGetValue("SourceContext", out var ctx) && ctx is ScalarValue { Value: string s } ? s[(s.LastIndexOf('.') + 1)..] : "";
        using var w = new StringWriter();
        Text.Format(e, w);
        var message = w.ToString();
        // The exception's own message, not its stack trace: the trace stays in the journal.
        if (e.Exception is { } ex) message += $" ({ex.GetType().Name}: {ex.Message})";
        buffer.Add(e.Timestamp.UtcDateTime, Level(e.Level), source, message);
    }

    public static string Level(LogEventLevel level) => level switch
    {
        LogEventLevel.Verbose or LogEventLevel.Debug => "debug",
        LogEventLevel.Information => "info",
        LogEventLevel.Warning => "warning",
        _ => "error",
    };
}
