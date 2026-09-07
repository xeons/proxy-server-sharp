using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Diagnostics;
using ProxyServerSharp.Net;
using ProxyServerSharp.Protocol;

namespace ProxyServerSharp.Server;

/// <summary>
/// One bound socket and its accept loop. Owns connection admission — address filtering,
/// connection limits and TLS — and hands each accepted client to an
/// <see cref="IProxyProtocolHandler"/>.
/// </summary>
public sealed class ProxyListener : IAsyncDisposable
{
    private readonly ListenerOptions _options;
    private readonly ProxyServerOptions _serverOptions;
    private readonly IProxyProtocolHandler _handler;
    private readonly IUserStore _users;
    private readonly IRemoteConnector _connector;
    private readonly AccessControlList _access;
    private readonly ILogger _logger;
    private readonly ProxyConnectionTracker _tracker;
    private readonly X509Certificate2? _certificate;
    private readonly ConcurrentDictionary<Task, byte> _connections = new();

    private Socket? _socket;
    private CancellationTokenSource? _shutdown;
    private Task? _acceptLoop;

    internal ProxyListener(
        ListenerOptions options,
        ProxyServerOptions serverOptions,
        IProxyProtocolHandler handler,
        IUserStore users,
        IRemoteConnector connector,
        ProxyConnectionTracker tracker,
        ILogger logger)
    {
        _options = options;
        _serverOptions = serverOptions;
        _handler = handler;
        _users = users;
        _connector = connector;
        _tracker = tracker;
        _logger = logger;
        _access = options.Access.Build();
        _certificate = options.Tls.Enabled ? TlsCertificateLoader.Load(options.Tls, options.Name) : null;
    }

    /// <summary>Raised when a client connection is accepted.</summary>
    public event EventHandler<ProxyConnectionEventArgs>? ConnectionAccepted;

    /// <summary>Raised when a client connection finishes.</summary>
    public event EventHandler<ProxyConnectionEventArgs>? ConnectionClosed;

    /// <summary>Raised when a client is refused, by address filter or by failed credentials.</summary>
    public event EventHandler<ProxyAuthenticationEventArgs>? ConnectionRejected;

    /// <summary>The listener's configuration.</summary>
    public ListenerOptions Options => _options;

    /// <summary>The endpoint actually bound, which resolves a configured port of <c>0</c>.</summary>
    public IPEndPoint? EndPoint => _socket?.LocalEndPoint as IPEndPoint;

    /// <summary>Whether the accept loop is running.</summary>
    public bool IsRunning => _acceptLoop is { IsCompleted: false };

    /// <summary>Binds the socket and starts accepting.</summary>
    /// <exception cref="SocketException">The endpoint could not be bound.</exception>
    public void Start(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_shutdown?.IsCancellationRequested == true, this);

        if (IsRunning)
        {
            return;
        }

        IPAddress address = IPAddress.Parse(_options.Address);
        _socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

        // Binding to :: with dual mode covers IPv4 too, which is what an operator writing "::"
        // in a config file means.
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            _socket.DualMode = true;
        }

        _socket.Bind(new IPEndPoint(address, _options.Port));
        _socket.Listen(512);

        _shutdown = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _acceptLoop = AcceptLoopAsync(_shutdown.Token);

        _logger.LogInformation(
            "Listener '{Name}' bound {EndPoint} speaking {Protocol} with {Authentication}{Tls}.",
            _options.Name,
            EndPoint,
            _options.Protocol,
            string.Join(", ", _options.EffectiveAuthentication),
            _certificate is null ? "" : $" over TLS ({_certificate.Subject})");
    }

    /// <summary>Stops accepting and waits for in-flight connections to finish.</summary>
    public async Task StopAsync()
    {
        if (_shutdown is null)
        {
            return;
        }

        await _shutdown.CancelAsync().ConfigureAwait(false);
        _socket?.Close();

        if (_acceptLoop is not null)
        {
            await _acceptLoop.ConfigureAwait(false);
        }

        await Task.WhenAll(_connections.Keys).ConfigureAwait(false);
        _logger.LogInformation("Listener '{Name}' stopped.", _options.Name);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);

        _shutdown?.Dispose();
        _socket?.Dispose();
        _certificate?.Dispose();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        // Yield so Start() returns before the first blocking accept.
        await Task.Yield();

        while (!cancellationToken.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _socket!.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException exception)
            {
                _logger.LogWarning("Listener '{Name}' accept failed: {Error}.", _options.Name, exception.SocketErrorCode);
                continue;
            }

            Task connection = HandleClientAsync(client, cancellationToken);
            _connections[connection] = 0;
            _ = connection.ContinueWith(
                completed => _connections.TryRemove(completed, out _),
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }

    private async Task HandleClientAsync(Socket client, CancellationToken cancellationToken)
    {
        // Detach from the accept loop so a slow handshake never delays the next accept.
        await Task.Yield();

        IPEndPoint clientEndPoint = (IPEndPoint)(client.RemoteEndPoint ?? new IPEndPoint(IPAddress.None, 0));

        if (!_access.IsAllowed(clientEndPoint.Address))
        {
            _logger.LogWarning(
                "Listener '{Name}' refused {Client}: not in the address allow list.",
                _options.Name,
                clientEndPoint);

            ConnectionRejected?.Invoke(
                this,
                new ProxyAuthenticationEventArgs(_options.Name, clientEndPoint, null, "Address not allowed."));

            client.Dispose();
            return;
        }

        if (!_tracker.TryAdmit(clientEndPoint.Address, out string? limitReason))
        {
            _logger.LogWarning("Listener '{Name}' refused {Client}: {Reason}", _options.Name, clientEndPoint, limitReason);

            ConnectionRejected?.Invoke(
                this,
                new ProxyAuthenticationEventArgs(_options.Name, clientEndPoint, null, limitReason));

            client.Dispose();
            return;
        }

        ProxyConnection connection = _tracker.Register(_options.Name, _options.Protocol, clientEndPoint);

        try
        {
            client.NoDelay = true;

            using CancellationTokenSource handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshake.CancelAfter(_serverOptions.HandshakeTimeout);

            await using NetworkStream network = new(client, ownsSocket: false);
            Stream transport = network;
            SslStream? tls = null;

            if (_certificate is not null)
            {
                tls = new SslStream(network, leaveInnerStreamOpen: true);
                await tls.AuthenticateAsServerAsync(
                        new SslServerAuthenticationOptions
                        {
                            ServerCertificate = _certificate,
                            ClientCertificateRequired = _options.Tls.RequireClientCertificate,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        },
                        handshake.Token)
                    .ConfigureAwait(false);

                transport = tls;
            }

            try
            {
                await using BufferedReadStream buffered = new(transport, leaveOpen: true);

                ProxyConnectionContext context = new(
                    connection,
                    client,
                    buffered,
                    _options,
                    _serverOptions,
                    _users,
                    _connector,
                    _logger);

                ConnectionAccepted?.Invoke(this, new ProxyConnectionEventArgs(connection));

                // The handshake timeout guards the negotiation; the relay that follows is governed
                // by the idle timeout instead, so a long-lived tunnel is not cut off mid-transfer.
                await _handler.HandleAsync(context, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if (tls is not null)
                {
                    await tls.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
        catch (Exception exception) when (IsExpectedDisconnect(exception))
        {
            _logger.LogDebug(
                "Connection #{Id} from {Client} ended: {Reason}",
                connection.Id,
                clientEndPoint,
                exception.Message);
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Connection #{Id} from {Client} faulted.", connection.Id, clientEndPoint);
        }
        finally
        {
            connection.State = ProxyConnectionState.Closed;
            _tracker.Release(connection);
            ConnectionClosed?.Invoke(this, new ProxyConnectionEventArgs(connection));

            try
            {
                client.Dispose();
            }
            catch (SocketException)
            {
                // Already gone.
            }
        }
    }

    private static bool IsExpectedDisconnect(Exception exception) => exception switch
    {
        OperationCanceledException => true,
        ObjectDisposedException => true,
        EndOfStreamException => true,
        InvalidDataException => true,
        AuthenticationException => true,
        IOException => true,
        SocketException => true,
        _ => false,
    };
}
