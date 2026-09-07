using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace ProxyServerSharp.Net;

/// <summary>
/// The production <see cref="IRemoteConnector"/>: resolves the destination, applies the
/// listener's <see cref="DestinationPolicy"/> to every candidate address, then connects.
/// </summary>
public sealed class SocketRemoteConnector : IRemoteConnector
{
    private readonly DestinationPolicy _policy;
    private readonly TimeSpan _connectTimeout;
    private readonly bool _enableIPv6;
    private readonly ILogger _logger;

    /// <summary>Creates the connector.</summary>
    /// <param name="policy">Which destinations are permitted.</param>
    /// <param name="connectTimeout">How long to wait for the TCP handshake.</param>
    /// <param name="enableIPv6">Whether IPv6 candidate addresses are used.</param>
    /// <param name="logger">Where connection failures are reported.</param>
    public SocketRemoteConnector(
        DestinationPolicy policy,
        TimeSpan connectTimeout,
        bool enableIPv6 = true,
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(connectTimeout, TimeSpan.Zero);

        _policy = policy;
        _connectTimeout = connectTimeout;
        _enableIPv6 = enableIPv6;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
    }

    /// <inheritdoc />
    public async ValueTask<RemoteConnection> ConnectAsync(
        ProxyDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);

        IPAddress[] candidates = await ResolveAsync(destination, cancellationToken).ConfigureAwait(false);
        List<IPAddress> permitted = new(candidates.Length);

        DestinationRejection lastRejection = DestinationRejection.None;
        foreach (IPAddress candidate in candidates)
        {
            if (!_enableIPv6 && candidate.AddressFamily == AddressFamily.InterNetworkV6)
            {
                continue;
            }

            DestinationRejection rejection = _policy.Evaluate(candidate, destination.Port);
            if (rejection == DestinationRejection.None)
            {
                permitted.Add(candidate);
            }
            else
            {
                lastRejection = rejection;
            }
        }

        if (permitted.Count == 0)
        {
            throw lastRejection == DestinationRejection.None
                ? new ProxyDestinationException(
                    DestinationFailure.HostUnreachable,
                    $"'{destination}' resolved to no usable address.")
                : new ProxyDestinationException(
                    DestinationFailure.NotAllowed,
                    $"Destination '{destination}' refused by policy ({lastRejection}).");
        }

        SocketException? lastError = null;

        // Happy-eyeballs-lite: try each candidate in turn rather than giving up on the first.
        foreach (IPAddress address in permitted)
        {
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_connectTimeout);

            Socket socket = new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.NoDelay = true;
                IPEndPoint endPoint = new(address, destination.Port);
                await socket.ConnectAsync(endPoint, timeout.Token).ConfigureAwait(false);

                return new RemoteConnection(
                    socket,
                    (IPEndPoint)(socket.RemoteEndPoint ?? endPoint),
                    (IPEndPoint)(socket.LocalEndPoint ?? new IPEndPoint(IPAddress.Any, 0)));
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                socket.Dispose();
                lastError = new SocketException((int)SocketError.TimedOut);
                _logger.LogDebug("Timed out connecting to {Address}:{Port}.", address, destination.Port);
            }
            catch (SocketException exception)
            {
                socket.Dispose();
                lastError = exception;
                _logger.LogDebug(
                    "Failed to connect to {Address}:{Port}: {Error}.",
                    address,
                    destination.Port,
                    exception.SocketErrorCode);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw new ProxyDestinationException(
            Map(lastError!.SocketErrorCode),
            $"Could not connect to '{destination}': {lastError.SocketErrorCode}.",
            lastError);
    }

    private static async ValueTask<IPAddress[]> ResolveAsync(
        ProxyDestination destination,
        CancellationToken cancellationToken)
    {
        if (!destination.RequiresResolution)
        {
            return [destination.Address];
        }

        try
        {
            return await Dns.GetHostAddressesAsync(destination.Host, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException exception)
        {
            throw new ProxyDestinationException(
                DestinationFailure.HostUnreachable,
                $"Could not resolve '{destination.Host}': {exception.SocketErrorCode}.",
                exception);
        }
    }

    /// <summary>Maps a socket error onto the protocol-independent failure kinds.</summary>
    public static DestinationFailure Map(SocketError error) => error switch
    {
        SocketError.ConnectionRefused => DestinationFailure.ConnectionRefused,
        SocketError.HostUnreachable or SocketError.HostNotFound or SocketError.NoData =>
            DestinationFailure.HostUnreachable,
        SocketError.NetworkUnreachable or SocketError.NetworkDown => DestinationFailure.NetworkUnreachable,
        SocketError.TimedOut => DestinationFailure.TimedOut,
        SocketError.AddressFamilyNotSupported or SocketError.OperationNotSupported =>
            DestinationFailure.AddressTypeNotSupported,
        _ => DestinationFailure.GeneralFailure,
    };
}
