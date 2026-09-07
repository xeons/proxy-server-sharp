using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using ProxyServerSharp.Net;

namespace ProxyServerSharp.Protocol.Socks;

/// <summary>
/// The datagram half of a SOCKS5 <c>UDP ASSOCIATE</c> (RFC 1928 §7): one socket carrying both
/// the client's outbound datagrams and the replies coming back.
/// </summary>
/// <remarks>
/// Datagrams from the client are unwrapped and forwarded; datagrams from anywhere else are only
/// accepted if they come from an endpoint this association has already sent to, and are wrapped
/// back up before being handed to the client. Fragmented datagrams are dropped, which the RFC
/// permits and every mainstream client already assumes.
/// </remarks>
internal sealed class Socks5UdpRelay
{
    private const int MaxDatagram = 65_535;
    private const int HeaderReserved = 2;

    private readonly Socket _socket;
    private readonly IPAddress _clientAddress;
    private readonly DestinationPolicy _policy;
    private readonly RelayCounters _counters;
    private readonly ILogger _logger;
    private readonly ConcurrentDictionary<IPEndPoint, byte> _peers = new();

    private IPEndPoint? _clientEndPoint;
    private long _lastActivityTicks = Environment.TickCount64;

    internal Socks5UdpRelay(
        Socket socket,
        IPAddress clientAddress,
        IPEndPoint? clientEndPoint,
        DestinationPolicy policy,
        RelayCounters counters,
        ILogger logger)
    {
        _socket = socket;
        _clientAddress = clientAddress;
        _clientEndPoint = clientEndPoint;
        _policy = policy;
        _counters = counters;
        _logger = logger;
    }

    /// <summary>Pumps datagrams until the association is cancelled or goes idle.</summary>
    internal async Task RunAsync(TimeSpan idleTimeout, CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxDatagram);
        using CancellationTokenSource idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task watchdog = WatchIdleAsync(idleTimeout, idle);

        try
        {
            EndPoint any = new IPEndPoint(
                _socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any,
                0);

            while (!idle.Token.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, any, idle.Token)
                        .ConfigureAwait(false);
                }
                catch (SocketException exception) when (exception.SocketErrorCode == SocketError.ConnectionReset)
                {
                    // Windows reports an ICMP port-unreachable for a previous send as a receive
                    // error; the association survives it.
                    continue;
                }

                Interlocked.Exchange(ref _lastActivityTicks, Environment.TickCount64);

                if (received.RemoteEndPoint is not IPEndPoint sender)
                {
                    continue;
                }

                ReadOnlyMemory<byte> datagram = buffer.AsMemory(0, received.ReceivedBytes);

                if (IsFromClient(sender))
                {
                    await ForwardFromClientAsync(datagram, sender, idle.Token).ConfigureAwait(false);
                }
                else
                {
                    await ForwardToClientAsync(datagram, sender, idle.Token).ConfigureAwait(false);
                }
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException)
        {
            // The association was torn down.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            await idle.CancelAsync().ConfigureAwait(false);
            await watchdog.ConfigureAwait(false);
        }
    }

    private bool IsFromClient(IPEndPoint sender)
    {
        if (_clientEndPoint is not null)
        {
            return sender.Equals(_clientEndPoint);
        }

        // The client did not declare its source port, so latch onto the first datagram that
        // arrives from the address that opened the control connection.
        if (!sender.Address.Equals(_clientAddress))
        {
            return false;
        }

        _clientEndPoint = sender;
        _logger.LogDebug("UDP association latched onto client endpoint {Client}.", sender);
        return true;
    }

    private async ValueTask ForwardFromClientAsync(
        ReadOnlyMemory<byte> datagram,
        IPEndPoint sender,
        CancellationToken cancellationToken)
    {
        // RSV(2) | FRAG(1) | ATYP | DST.ADDR | DST.PORT | DATA
        if (datagram.Length < HeaderReserved + 1)
        {
            return;
        }

        ReadOnlySpan<byte> span = datagram.Span;

        if (span[2] != 0)
        {
            _logger.LogDebug("Dropped a fragmented UDP datagram from {Client}; reassembly is not supported.", sender);
            return;
        }

        if (!Socks5Address.TryRead(span[(HeaderReserved + 1)..], out ProxyDestination? destination, out int consumed)
            || destination is null)
        {
            _logger.LogDebug("Dropped a UDP datagram from {Client} with an unreadable address header.", sender);
            return;
        }

        IPEndPoint? target = await ResolveAsync(destination, cancellationToken).ConfigureAwait(false);
        if (target is null)
        {
            return;
        }

        DestinationRejection rejection = _policy.Evaluate(target.Address, target.Port);
        if (rejection != DestinationRejection.None)
        {
            _logger.LogDebug("Dropped a UDP datagram to {Target}: {Rejection}.", target, rejection);
            return;
        }

        int payloadOffset = HeaderReserved + 1 + consumed;
        ReadOnlyMemory<byte> payload = datagram[payloadOffset..];

        _peers[target] = 0;
        await _socket.SendToAsync(payload, SocketFlags.None, target, cancellationToken).ConfigureAwait(false);
        _counters.Add(RelayDirection.ClientToRemote, payload.Length);
    }

    private async ValueTask ForwardToClientAsync(
        ReadOnlyMemory<byte> datagram,
        IPEndPoint sender,
        CancellationToken cancellationToken)
    {
        if (_clientEndPoint is null)
        {
            return;
        }

        // Only echo back datagrams from somewhere this association actually sent to, so the port
        // cannot be used to inject traffic into the client.
        if (!_peers.ContainsKey(sender))
        {
            _logger.LogDebug("Dropped an unsolicited UDP datagram from {Sender}.", sender);
            return;
        }

        int headerLength = HeaderReserved + 1 + (sender.AddressFamily == AddressFamily.InterNetworkV6 ? 19 : 7);
        byte[] wrapped = ArrayPool<byte>.Shared.Rent(headerLength + datagram.Length);
        try
        {
            wrapped[0] = 0;
            wrapped[1] = 0;
            wrapped[2] = 0; // FRAG
            int written = Socks5Address.Write(wrapped.AsSpan(HeaderReserved + 1), sender);
            datagram.Span.CopyTo(wrapped.AsSpan(HeaderReserved + 1 + written));

            int total = HeaderReserved + 1 + written + datagram.Length;
            await _socket
                .SendToAsync(wrapped.AsMemory(0, total), SocketFlags.None, _clientEndPoint, cancellationToken)
                .ConfigureAwait(false);

            _counters.Add(RelayDirection.RemoteToClient, datagram.Length);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(wrapped);
        }
    }

    private async ValueTask<IPEndPoint?> ResolveAsync(ProxyDestination destination, CancellationToken cancellationToken)
    {
        if (!destination.RequiresResolution)
        {
            return new IPEndPoint(destination.Address, destination.Port);
        }

        try
        {
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(destination.Host, cancellationToken)
                .ConfigureAwait(false);

            // The relay socket has one address family; only a matching address can be sent to.
            foreach (IPAddress address in addresses)
            {
                if (address.AddressFamily == _socket.AddressFamily)
                {
                    return new IPEndPoint(address, destination.Port);
                }
            }

            return null;
        }
        catch (SocketException)
        {
            _logger.LogDebug("Dropped a UDP datagram for '{Host}', which did not resolve.", destination.Host);
            return null;
        }
    }

    private async Task WatchIdleAsync(TimeSpan idleTimeout, CancellationTokenSource association)
    {
        if (idleTimeout <= TimeSpan.Zero)
        {
            return;
        }

        TimeSpan interval = TimeSpan.FromMilliseconds(Math.Max(1000, idleTimeout.TotalMilliseconds / 4));
        using PeriodicTimer timer = new(interval);

        try
        {
            while (await timer.WaitForNextTickAsync(association.Token).ConfigureAwait(false))
            {
                if (Environment.TickCount64 - Interlocked.Read(ref _lastActivityTicks) >= idleTimeout.TotalMilliseconds)
                {
                    _logger.LogDebug("UDP association went idle after {Timeout}.", idleTimeout);
                    await association.CancelAsync().ConfigureAwait(false);
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // The association ended on its own.
        }
    }
}
