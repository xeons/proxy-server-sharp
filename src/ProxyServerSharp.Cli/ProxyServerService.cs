using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Diagnostics;
using ProxyServerSharp.Server;

namespace ProxyServerSharp.Cli;

/// <summary>Runs a <see cref="ProxyServerHost"/> for the lifetime of the generic host.</summary>
internal sealed class ProxyServerService : IHostedService, IAsyncDisposable
{
    private readonly ProxyServerHost _server;
    private readonly ILogger<ProxyServerService> _logger;
    private readonly IHostApplicationLifetime _lifetime;

    public ProxyServerService(
        ProxyServerOptions options,
        ILoggerFactory loggerFactory,
        ILogger<ProxyServerService> logger,
        IHostApplicationLifetime lifetime)
    {
        ArgumentNullException.ThrowIfNull(options);

        _logger = logger;
        _lifetime = lifetime;
        _server = new ProxyServerHost(options, loggerFactory);

        _server.ListenerFailed += OnListenerFailed;
        _server.ConnectionRejected += OnConnectionRejected;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            IReadOnlyList<ProxyListener> listeners = await _server.StartAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Ready with {Count} listener(s). Press Ctrl+C to stop.", listeners.Count);
        }
        catch (InvalidOperationException exception)
        {
            _logger.LogCritical("{Message}", exception.Message);

            // Nothing bound, so there is no point staying alive; stop the host cleanly rather
            // than letting an unhandled exception unwind through the runtime.
            _lifetime.StopApplication();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation(
            "Shutting down after {Total} connection(s), {Active} still open.",
            _server.Connections.TotalAccepted,
            _server.Connections.Count);

        await _server.StopAsync().ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        _server.ListenerFailed -= OnListenerFailed;
        _server.ConnectionRejected -= OnConnectionRejected;
        await _server.DisposeAsync().ConfigureAwait(false);
    }

    private void OnListenerFailed(object? sender, ProxyListenerEventArgs e) =>
        _logger.LogError("Listener '{Name}' on port {Port} failed: {Error}", e.ListenerName, e.EndPoint.Port, e.Error);

    private void OnConnectionRejected(object? sender, ProxyAuthenticationEventArgs e) =>
        _logger.LogDebug("Rejected {Client} on '{Listener}': {Reason}", e.ClientEndPoint, e.ListenerName, e.Reason);
}
