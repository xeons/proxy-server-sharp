using Microsoft.Extensions.Logging;

namespace ProxyServerSharp.App;

/// <summary>One line of server output, ready to display.</summary>
/// <param name="Timestamp">When the line was written.</param>
/// <param name="Level">Its severity.</param>
/// <param name="Category">The logger it came from.</param>
/// <param name="Message">The rendered message.</param>
internal readonly record struct LogEntry(DateTime Timestamp, LogLevel Level, string Category, string Message)
{
    /// <inheritdoc />
    public override string ToString() =>
        $"{Timestamp:HH:mm:ss} {Level.ToString().ToUpperInvariant(),-5} {Message}";
}

/// <summary>
/// An <see cref="ILoggerProvider"/> that raises an event per log line instead of writing to a
/// console, so the desktop app can show the same output the console host prints.
/// </summary>
internal sealed class UiLoggerProvider : ILoggerProvider
{
    private LogLevel _minimum = LogLevel.Information;

    /// <summary>Raised, on a background thread, for every log line the server writes.</summary>
    internal event EventHandler<LogEntry>? EntryWritten;

    /// <summary>The lowest level that reaches <see cref="EntryWritten"/>.</summary>
    internal LogLevel MinimumLevel
    {
        get => _minimum;
        set => _minimum = value;
    }

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName) => new UiLogger(this, categoryName);

    /// <inheritdoc />
    public void Dispose() => EntryWritten = null;

    private void Write(LogLevel level, string category, string message) =>
        EntryWritten?.Invoke(this, new LogEntry(DateTime.Now, level, category, message));

    private sealed class UiLogger(UiLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) =>
            logLevel != LogLevel.None && logLevel >= provider.MinimumLevel;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            ArgumentNullException.ThrowIfNull(formatter);

            string message = formatter(state, exception);
            if (exception is not null)
            {
                message = $"{message} ({exception.GetType().Name}: {exception.Message})";
            }

            provider.Write(logLevel, category, message);
        }
    }
}
