using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Authentication.Socks;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Diagnostics;
using ProxyServerSharp.Net;
using ProxyServerSharp.Server;

namespace ProxyServerSharp.Protocol.Socks;

/// <summary>
/// SOCKS5 (RFC 1928) with the <c>CONNECT</c>, <c>BIND</c> and <c>UDP ASSOCIATE</c> commands, and
/// RFC 1929 username/password authentication.
/// </summary>
/// <remarks>
/// GSSAPI (method <c>0x01</c>, RFC 1961) is deliberately not offered: its per-message wrapping
/// would apply to the tunnelled payload as well as the handshake. Clients that need a Windows
/// domain login should use an HTTP listener with <c>Negotiate</c>.
/// </remarks>
public sealed class Socks5ProxyHandler : IProxyProtocolHandler
{
    private const int MaxMethods = 255;

    private readonly ISocks5Authenticator[] _authenticators;

    /// <summary>Creates the handler for one listener.</summary>
    /// <param name="authenticators">The methods to advertise, in server preference order.</param>
    public Socks5ProxyHandler(IEnumerable<ISocks5Authenticator> authenticators)
    {
        ArgumentNullException.ThrowIfNull(authenticators);
        _authenticators = [.. authenticators];

        if (_authenticators.Length == 0)
        {
            throw new ArgumentException("A SOCKS5 listener must offer at least one method.", nameof(authenticators));
        }
    }

    /// <inheritdoc />
    public ProxyProtocol Protocol => ProxyProtocol.Socks5;

    /// <inheritdoc />
    public async Task HandleAsync(ProxyConnectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        Stream client = context.ClientStream;

        ISocks5Authenticator? method = await NegotiateMethodAsync(context, cancellationToken).ConfigureAwait(false);
        if (method is null)
        {
            return;
        }

        AuthenticationResult authentication = await method
            .AuthenticateAsync(client, context.StoreContext, cancellationToken)
            .ConfigureAwait(false);

        if (!authentication.Succeeded)
        {
            context.Logger.LogWarning(
                "Connection #{Id} from {Client} failed {Method} authentication: {Reason}",
                context.Connection.Id,
                context.ClientEndPoint,
                method.Method,
                authentication.FailureReason);
            return;
        }

        context.SetIdentity(authentication.Identity!);

        // VER | CMD | RSV | ATYP ...
        byte[] header = new byte[3];
        await client.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

        if (header[0] != SocksConstants.Version5)
        {
            throw new InvalidDataException($"Expected SOCKS version 5 in request, got 0x{header[0]:X2}.");
        }

        Socks5Command command = (Socks5Command)header[1];

        try
        {
            ProxyDestination destination = await Socks5Address.ReadAsync(client, cancellationToken).ConfigureAwait(false);
            context.Connection.Destination = destination;

            switch (command)
            {
                case Socks5Command.Connect:
                    await ConnectAsync(context, destination, cancellationToken).ConfigureAwait(false);
                    break;

                case Socks5Command.Bind when context.Listener.AllowBind:
                    await BindAsync(context, destination, cancellationToken).ConfigureAwait(false);
                    break;

                case Socks5Command.UdpAssociate when context.Listener.AllowUdpAssociate:
                    await UdpAssociateAsync(context, destination, cancellationToken).ConfigureAwait(false);
                    break;

                default:
                    context.Logger.LogWarning(
                        "Connection #{Id} requested SOCKS5 command {Command}, which this listener does not offer.",
                        context.Connection.Id,
                        command);
                    await ReplyAsync(client, Socks5Reply.CommandNotSupported, cancellationToken).ConfigureAwait(false);
                    break;
            }
        }
        catch (Socks5ProtocolException exception)
        {
            context.Logger.LogInformation("Connection #{Id}: {Reason}", context.Connection.Id, exception.Message);
            await ReplyAsync(client, exception.Reply, cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask<ISocks5Authenticator?> NegotiateMethodAsync(
        ProxyConnectionContext context,
        CancellationToken cancellationToken)
    {
        Stream client = context.ClientStream;

        // VER | NMETHODS | METHODS
        byte[] greeting = new byte[2];
        await client.ReadExactlyAsync(greeting, cancellationToken).ConfigureAwait(false);

        if (greeting[0] != SocksConstants.Version5)
        {
            throw new InvalidDataException($"Expected SOCKS version 5, got 0x{greeting[0]:X2}.");
        }

        int count = greeting[1];
        if (count is 0 or > MaxMethods)
        {
            throw new InvalidDataException($"SOCKS5 greeting offered {count} methods.");
        }

        byte[] offered = new byte[count];
        await client.ReadExactlyAsync(offered, cancellationToken).ConfigureAwait(false);

        // Server preference wins: the client's list says what it can do, not what it prefers.
        foreach (ISocks5Authenticator authenticator in _authenticators)
        {
            if (Array.IndexOf(offered, authenticator.MethodCode) < 0)
            {
                continue;
            }

            await client
                .WriteAsync(new byte[] { SocksConstants.Version5, authenticator.MethodCode }, cancellationToken)
                .ConfigureAwait(false);
            await client.FlushAsync(cancellationToken).ConfigureAwait(false);
            return authenticator;
        }

        context.Logger.LogWarning(
            "Connection #{Id} from {Client} offered no acceptable SOCKS5 method; this listener requires {Methods}.",
            context.Connection.Id,
            context.ClientEndPoint,
            string.Join(", ", _authenticators.Select(a => a.Method)));

        await client
            .WriteAsync(new byte[] { SocksConstants.Version5, SocksConstants.NoAcceptableMethods }, cancellationToken)
            .ConfigureAwait(false);
        await client.FlushAsync(cancellationToken).ConfigureAwait(false);
        return null;
    }

    private static async Task ConnectAsync(
        ProxyConnectionContext context,
        ProxyDestination destination,
        CancellationToken cancellationToken)
    {
        Stream client = context.ClientStream;

        RemoteConnection remote;
        try
        {
            remote = await context.Connector.ConnectAsync(destination, cancellationToken).ConfigureAwait(false);
        }
        catch (ProxyDestinationException exception)
        {
            context.Logger.LogInformation(
                "Connection #{Id} to {Destination} failed: {Reason}",
                context.Connection.Id,
                destination,
                exception.Message);

            await ReplyAsync(client, SocksConstants.ToSocks5Reply(exception.Failure), cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        await using (remote.ConfigureAwait(false))
        {
            await ReplyAsync(client, Socks5Reply.Succeeded, remote.LocalEndPoint, cancellationToken)
                .ConfigureAwait(false);

            context.Connection.State = ProxyConnectionState.Relaying;
            context.Logger.LogInformation(
                "Connection #{Id} {Identity} tunnelling {Client} -> {Destination}",
                context.Connection.Id,
                context.Connection.Identity,
                context.ClientEndPoint,
                remote.RemoteEndPoint);

            await TunnelRelay.RunAsync(
                    client,
                    remote.Stream,
                    context.CreateRelayOptions(),
                    context.ClientSocket,
                    remote.Socket,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static async Task BindAsync(
        ProxyConnectionContext context,
        ProxyDestination expectedPeer,
        CancellationToken cancellationToken)
    {
        Stream client = context.ClientStream;
        IPAddress bindAddress = LocalAddress(context);

        using Socket listener = new(bindAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(bindAddress, 0));
        listener.Listen(1);

        IPEndPoint bound = (IPEndPoint)listener.LocalEndPoint!;

        // First reply: where the peer should connect.
        await ReplyAsync(client, Socks5Reply.Succeeded, bound, cancellationToken).ConfigureAwait(false);

        context.Logger.LogInformation(
            "Connection #{Id} {Identity} listening on {Bound} for an inbound connection from {Peer}",
            context.Connection.Id,
            context.Connection.Identity,
            bound,
            expectedPeer);

        using CancellationTokenSource bindTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bindTimeout.CancelAfter(context.Options.BindTimeout);

        Socket inbound;
        try
        {
            inbound = await listener.AcceptAsync(bindTimeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            context.Logger.LogInformation(
                "Connection #{Id} BIND timed out after {Timeout}.",
                context.Connection.Id,
                context.Options.BindTimeout);

            await ReplyAsync(client, Socks5Reply.TtlExpired, cancellationToken).ConfigureAwait(false);
            return;
        }

        using (inbound)
        {
            IPEndPoint peer = (IPEndPoint)inbound.RemoteEndPoint!;

            // RFC 1928 leaves peer verification to the implementation. Checking the address the
            // client named keeps a BIND port from being hijacked by whoever connects first.
            if (!expectedPeer.RequiresResolution
                && !expectedPeer.Address.Equals(IPAddress.Any)
                && !expectedPeer.Address.Equals(IPAddress.IPv6Any)
                && !expectedPeer.Address.Equals(peer.Address))
            {
                context.Logger.LogWarning(
                    "Connection #{Id} BIND refused {Actual}; the client expected {Expected}.",
                    context.Connection.Id,
                    peer.Address,
                    expectedPeer.Address);

                await ReplyAsync(client, Socks5Reply.NotAllowed, cancellationToken).ConfigureAwait(false);
                return;
            }

            // Second reply: who actually connected.
            await ReplyAsync(client, Socks5Reply.Succeeded, peer, cancellationToken).ConfigureAwait(false);

            context.Connection.State = ProxyConnectionState.Relaying;
            await using NetworkStream inboundStream = new(inbound, ownsSocket: false);

            await TunnelRelay.RunAsync(
                    client,
                    inboundStream,
                    context.CreateRelayOptions(),
                    context.ClientSocket,
                    inbound,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static async Task UdpAssociateAsync(
        ProxyConnectionContext context,
        ProxyDestination requestedClientEndPoint,
        CancellationToken cancellationToken)
    {
        Stream client = context.ClientStream;
        IPAddress bindAddress = LocalAddress(context);

        using Socket relay = new(bindAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        relay.Bind(new IPEndPoint(bindAddress, 0));

        IPEndPoint bound = (IPEndPoint)relay.LocalEndPoint!;
        await ReplyAsync(client, Socks5Reply.Succeeded, bound, cancellationToken).ConfigureAwait(false);

        // A client may say 0.0.0.0:0 when it does not yet know its own source port, in which case
        // the association latches onto the first datagram that arrives from the client's address.
        IPEndPoint? clientUdp = requestedClientEndPoint.RequiresResolution
            || requestedClientEndPoint.Port == 0
            || requestedClientEndPoint.Address.Equals(IPAddress.Any)
            || requestedClientEndPoint.Address.Equals(IPAddress.IPv6Any)
                ? null
                : new IPEndPoint(requestedClientEndPoint.Address, requestedClientEndPoint.Port);

        context.Connection.State = ProxyConnectionState.Relaying;
        context.Logger.LogInformation(
            "Connection #{Id} {Identity} opened a UDP association on {Bound} for {Client}",
            context.Connection.Id,
            context.Connection.Identity,
            bound,
            context.ClientEndPoint);

        using CancellationTokenSource association = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        Socks5UdpRelay udpRelay = new(
            relay,
            context.ClientEndPoint.Address,
            clientUdp,
            new DestinationPolicy(context.Listener.Destinations),
            context.Connection.Counters,
            context.Logger);

        Task relayTask = udpRelay.RunAsync(context.Options.UdpAssociationTimeout, association.Token);
        Task controlTask = WaitForControlCloseAsync(client, association);

        await Task.WhenAny(relayTask, controlTask).ConfigureAwait(false);
        await association.CancelAsync().ConfigureAwait(false);

        // Both tasks swallow cancellation, so this only surfaces genuine faults.
        await Task.WhenAll(relayTask, controlTask).ConfigureAwait(false);
    }

    /// <summary>
    /// The UDP association lives exactly as long as the TCP control connection (RFC 1928 §7), so
    /// this reads the control stream purely to notice when the client hangs up.
    /// </summary>
    private static async Task WaitForControlCloseAsync(Stream client, CancellationTokenSource association)
    {
        byte[] scratch = new byte[256];

        try
        {
            while (await client.ReadAsync(scratch, association.Token).ConfigureAwait(false) > 0)
            {
                // A conforming client sends nothing here; anything that arrives is discarded.
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or IOException or SocketException or ObjectDisposedException)
        {
            // The control connection dropped, which ends the association.
        }
        finally
        {
            await association.CancelAsync().ConfigureAwait(false);
        }
    }

    /// <summary>The address the client reached this proxy on, which is what replies must advertise.</summary>
    private static IPAddress LocalAddress(ProxyConnectionContext context) =>
        context.ClientSocket.LocalEndPoint is IPEndPoint local ? local.Address : IPAddress.Loopback;

    private static ValueTask ReplyAsync(Stream stream, Socks5Reply reply, CancellationToken cancellationToken) =>
        ReplyAsync(stream, reply, new IPEndPoint(IPAddress.Any, 0), cancellationToken);

    private static async ValueTask ReplyAsync(
        Stream stream,
        Socks5Reply reply,
        IPEndPoint boundEndPoint,
        CancellationToken cancellationToken)
    {
        byte[] response = new byte[4 + Socks5Address.MaxEncodedLength];
        response[0] = SocksConstants.Version5;
        response[1] = (byte)reply;
        response[2] = 0x00;

        int addressLength = Socks5Address.Write(response.AsSpan(3), boundEndPoint);

        await stream.WriteAsync(response.AsMemory(0, 3 + addressLength), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads a big-endian port, kept here so the wire layout stays in one place.</summary>
    internal static int ReadPort(ReadOnlySpan<byte> buffer) => BinaryPrimitives.ReadUInt16BigEndian(buffer);
}
