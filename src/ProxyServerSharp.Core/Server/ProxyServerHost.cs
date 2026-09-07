using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Authentication.Http;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Diagnostics;
using ProxyServerSharp.Net;
using ProxyServerSharp.Protocol;

namespace ProxyServerSharp.Server;

/// <summary>
/// Runs every configured listener as one unit and exposes the events and live connection list a
/// front-end binds to.
/// </summary>
/// <remarks>
/// This is the whole public surface most callers need: construct it with
/// <see cref="ProxyServerOptions"/>, subscribe to the events, then
/// <see cref="StartAsync"/> and <see cref="StopAsync"/>.
/// </remarks>
public sealed class ProxyServerHost : IAsyncDisposable
{
    private readonly ProxyServerOptions _options;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;
    private readonly List<ProxyListener> _listeners = [];
    private readonly IUserStore _users;

    private CancellationTokenSource? _shutdown;

    /// <summary>Creates a host over bound configuration.</summary>
    /// <param name="options">The listeners, accounts and timeouts to run with.</param>
    /// <param name="loggerFactory">Where the host and its listeners log.</param>
    /// <param name="users">
    /// An account directory to use instead of the one implied by <paramref name="options"/>,
    /// for callers that keep accounts somewhere other than the configuration file.
    /// </param>
    public ProxyServerHost(ProxyServerOptions options, ILoggerFactory? loggerFactory = null, IUserStore? users = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
        _logger = _loggerFactory.CreateLogger<ProxyServerHost>();
        _users = users ?? new InMemoryUserStore(options.Users);

        Connections = new ProxyConnectionTracker(options.MaxConnections, options.MaxConnectionsPerClient);
    }

    /// <summary>Raised when any listener accepts a connection.</summary>
    public event EventHandler<ProxyConnectionEventArgs>? ConnectionAccepted;

    /// <summary>Raised when any connection finishes.</summary>
    public event EventHandler<ProxyConnectionEventArgs>? ConnectionClosed;

    /// <summary>Raised when a client is refused by an address filter or by failed credentials.</summary>
    public event EventHandler<ProxyAuthenticationEventArgs>? ConnectionRejected;

    /// <summary>Raised when a listener binds successfully.</summary>
    public event EventHandler<ProxyListenerEventArgs>? ListenerStarted;

    /// <summary>Raised when a listener fails to bind.</summary>
    public event EventHandler<ProxyListenerEventArgs>? ListenerFailed;

    /// <summary>The live connection list and its limits.</summary>
    public ProxyConnectionTracker Connections { get; }

    /// <summary>The account directory in use.</summary>
    public IUserStore Users => _users;

    /// <summary>The listeners that bound successfully.</summary>
    public IReadOnlyList<ProxyListener> Listeners => _listeners;

    /// <summary>Whether any listener is currently running.</summary>
    public bool IsRunning => _listeners.Exists(l => l.IsRunning);

    /// <summary>
    /// Binds and starts every enabled listener.
    /// </summary>
    /// <returns>The listeners that started. A listener that fails to bind raises
    /// <see cref="ListenerFailed"/> and is skipped, so one port collision does not stop the rest.</returns>
    /// <exception cref="InvalidOperationException">The configuration is not coherent, or nothing could be bound.</exception>
    public Task<IReadOnlyList<ProxyListener>> StartAsync(CancellationToken cancellationToken = default)
    {
        if (_shutdown is not null)
        {
            throw new InvalidOperationException("The proxy server host is already running.");
        }

        List<ListenerOptions> enabled = [.. _options.Listeners.Where(l => l.Enabled)];
        if (enabled.Count == 0)
        {
            throw new InvalidOperationException("No proxy listeners are enabled.");
        }

        // Validate everything before binding anything, so a typo in the last listener does not
        // leave the first few already accepting traffic.
        foreach (ListenerOptions listener in enabled)
        {
            ProxyHandlerFactory.Validate(listener);
        }

        WarnAboutRiskyConfiguration(enabled);

        _shutdown = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        DigestNonceManager nonces = new(_options.DigestNonceLifetime);
        ProxyHandlerFactory factory = new(_users, nonces, _loggerFactory);

        foreach (ListenerOptions options in enabled)
        {
            ProxyListener? listener = TryStartListener(options, factory, _shutdown.Token);
            if (listener is not null)
            {
                _listeners.Add(listener);
            }
        }

        if (_listeners.Count == 0)
        {
            throw new InvalidOperationException("No proxy listener could be bound; see the log for details.");
        }

        return Task.FromResult<IReadOnlyList<ProxyListener>>(_listeners);
    }

    /// <summary>Stops every listener and waits for in-flight connections to finish.</summary>
    public async Task StopAsync()
    {
        if (_shutdown is null)
        {
            return;
        }

        await _shutdown.CancelAsync().ConfigureAwait(false);
        await Task.WhenAll(_listeners.Select(l => l.StopAsync())).ConfigureAwait(false);

        foreach (ProxyListener listener in _listeners)
        {
            await listener.DisposeAsync().ConfigureAwait(false);
        }

        _listeners.Clear();
        _shutdown.Dispose();
        _shutdown = null;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);

    private ProxyListener? TryStartListener(
        ListenerOptions options,
        ProxyHandlerFactory factory,
        CancellationToken cancellationToken)
    {
        ProxyListener? listener = null;

        try
        {
            IProxyProtocolHandler handler = factory.Create(options);

            IRemoteConnector connector = new SocketRemoteConnector(
                new DestinationPolicy(options.Destinations),
                _options.ConnectTimeout,
                _options.EnableIPv6,
                _loggerFactory.CreateLogger($"ProxyServerSharp.{options.Name}"));

            listener = new ProxyListener(
                options,
                _options,
                handler,
                _users,
                connector,
                Connections,
                _loggerFactory.CreateLogger($"ProxyServerSharp.{options.Name}"));

            listener.ConnectionAccepted += (_, e) => ConnectionAccepted?.Invoke(this, e);
            listener.ConnectionClosed += (_, e) => ConnectionClosed?.Invoke(this, e);
            listener.ConnectionRejected += (_, e) => ConnectionRejected?.Invoke(this, e);

            listener.Start(cancellationToken);

            ListenerStarted?.Invoke(this, new ProxyListenerEventArgs(options.Name, options.Protocol, listener.EndPoint!));
            return listener;
        }
        catch (Exception exception) when (exception is System.Net.Sockets.SocketException
            or InvalidOperationException
            or IOException
            or System.Security.Cryptography.CryptographicException)
        {
            _logger.LogError(exception, "Listener '{Name}' could not start.", options.Name);

            ListenerFailed?.Invoke(
                this,
                new ProxyListenerEventArgs(
                    options.Name,
                    options.Protocol,
                    new System.Net.IPEndPoint(System.Net.IPAddress.None, options.Port),
                    exception.Message));

            listener?.DisposeAsync().AsTask().GetAwaiter().GetResult();
            return null;
        }
    }

    /// <summary>Points out configurations that turn the proxy into an open relay.</summary>
    private void WarnAboutRiskyConfiguration(IEnumerable<ListenerOptions> listeners)
    {
        foreach (ListenerOptions listener in listeners)
        {
            bool anonymous = listener.EffectiveAuthentication.Contains(AuthenticationMethod.Anonymous);
            bool loopbackOnly = listener.Address is "127.0.0.1" or "::1" or "localhost";
            bool restricted = listener.Access.Allow.Count > 0;

            if (anonymous && !loopbackOnly && !restricted)
            {
                _logger.LogWarning(
                    "Listener '{Name}' accepts anonymous clients on {Address}:{Port} with no address allow list. "
                    + "This is an open proxy; add an Authentication method or an Access:Allow entry.",
                    listener.Name,
                    listener.Address,
                    listener.Port);
            }

            if (listener.EffectiveAuthentication.Contains(AuthenticationMethod.Negotiate)
                && !NegotiateHttpAuthenticatorFactory.IsSupported)
            {
                _logger.LogWarning(
                    "Listener '{Name}' offers Negotiate, which this platform cannot serve.",
                    listener.Name);
            }

            if (listener.Protocol == ProxyProtocol.Http
                && !listener.Tls.Enabled
                && listener.EffectiveAuthentication.Contains(AuthenticationMethod.Basic)
                && !loopbackOnly)
            {
                _logger.LogWarning(
                    "Listener '{Name}' offers Basic over plaintext on {Address}. Credentials will be readable "
                    + "on the wire; enable Tls or switch to Digest.",
                    listener.Name,
                    listener.Address);
            }
        }
    }
}
