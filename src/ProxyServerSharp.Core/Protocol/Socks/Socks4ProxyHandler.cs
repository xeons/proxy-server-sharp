using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Authentication.Socks;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Diagnostics;
using ProxyServerSharp.Net;
using ProxyServerSharp.Server;

namespace ProxyServerSharp.Protocol.Socks;

/// <summary>
/// SOCKS4 with the SOCKS4a host name extension.
/// </summary>
/// <remarks>
/// SOCKS4 has no credential exchange of its own: the only thing a client can assert is the
/// <c>USERID</c> field, which this server matches against the account directory when the listener
/// is not anonymous. There is no password, so treat it as an identifier rather than a secret and
/// pair it with the listener's address allow list.
/// </remarks>
public sealed class Socks4ProxyHandler : IProxyProtocolHandler
{
    private const int MaxUserIdLength = 255;
    private const int MaxHostNameLength = 255;
    private const byte CommandConnect = 0x01;
    private const byte CommandBind = 0x02;

    private readonly Socks4Authenticator _authenticator;

    /// <summary>Creates the handler for one listener.</summary>
    public Socks4ProxyHandler(Socks4Authenticator authenticator)
    {
        ArgumentNullException.ThrowIfNull(authenticator);
        _authenticator = authenticator;
    }

    /// <inheritdoc />
    public ProxyProtocol Protocol => ProxyProtocol.Socks4;

    /// <inheritdoc />
    public async Task HandleAsync(ProxyConnectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        Stream client = context.ClientStream;

        // VN | CD | DSTPORT | DSTIP
        byte[] header = new byte[8];
        await client.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

        if (header[0] != SocksConstants.Version4)
        {
            throw new InvalidDataException($"Expected SOCKS version 4, got 0x{header[0]:X2}.");
        }

        byte command = header[1];
        int port = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2, 2));
        byte[] rawAddress = header[4..8];

        string userId = await ReadNullTerminatedAsync(client, MaxUserIdLength, cancellationToken).ConfigureAwait(false);

        // SOCKS4a marks "resolve this name for me" with an address of 0.0.0.x where x is non-zero.
        bool isSocks4a = rawAddress[0] == 0 && rawAddress[1] == 0 && rawAddress[2] == 0 && rawAddress[3] != 0;

        ProxyDestination destination;
        if (isSocks4a)
        {
            string host = await ReadNullTerminatedAsync(client, MaxHostNameLength, cancellationToken).ConfigureAwait(false);
            if (host.Length == 0)
            {
                await ReplyAsync(client, Socks4Reply.Rejected, rawAddress, port, cancellationToken).ConfigureAwait(false);
                throw new InvalidDataException("SOCKS4a request carried an empty host name.");
            }

            destination = ProxyDestination.FromHost(host, port);
        }
        else
        {
            destination = ProxyDestination.FromAddress(new IPAddress(rawAddress), port);
        }

        context.Connection.Destination = destination;

        AuthenticationResult authentication = await _authenticator
            .AuthenticateAsync(userId, context.StoreContext, cancellationToken)
            .ConfigureAwait(false);

        if (!authentication.Succeeded)
        {
            context.Logger.LogWarning(
                "Connection #{Id} from {Client} rejected: {Reason}",
                context.Connection.Id,
                context.ClientEndPoint,
                authentication.FailureReason);

            // 0x5D is the closest SOCKS4 has to "your identity was not accepted".
            await ReplyAsync(client, Socks4Reply.IdentdMismatch, rawAddress, port, cancellationToken).ConfigureAwait(false);
            return;
        }

        context.SetIdentity(authentication.Identity!);

        if (command == CommandBind)
        {
            if (!context.Listener.AllowBind)
            {
                context.Logger.LogWarning(
                    "Connection #{Id} requested SOCKS4 BIND, which this listener does not offer.",
                    context.Connection.Id);

                await ReplyAsync(client, Socks4Reply.Rejected, rawAddress, port, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            await BindAsync(context, destination, rawAddress, port, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (command != CommandConnect)
        {
            context.Logger.LogWarning(
                "Connection #{Id} requested unsupported SOCKS4 command 0x{Command:X2}.",
                context.Connection.Id,
                command);

            await ReplyAsync(client, Socks4Reply.Rejected, rawAddress, port, cancellationToken).ConfigureAwait(false);
            return;
        }

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

            await ReplyAsync(client, Socks4Reply.Rejected, rawAddress, port, cancellationToken).ConfigureAwait(false);
            return;
        }

        await using (remote.ConfigureAwait(false))
        {
            // SOCKS4 replies can only carry an IPv4 address; echo the request's own bytes when the
            // connection landed somewhere that will not fit, which is what clients expect.
            byte[] replyAddress = remote.RemoteEndPoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? remote.RemoteEndPoint.Address.GetAddressBytes()
                : rawAddress;

            await ReplyAsync(client, Socks4Reply.Granted, replyAddress, remote.RemoteEndPoint.Port, cancellationToken)
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

    /// <summary>
    /// The SOCKS4 <c>BIND</c> command: listen for one inbound connection on the client's behalf.
    /// </summary>
    /// <remarks>
    /// Two replies are sent. The first carries the address and port the peer should connect to;
    /// the second, once someone does, carries that peer's address. The address the client named
    /// in the request is the peer it expects, and anyone else is refused, so a bind port cannot
    /// be taken over by whoever connects first.
    /// </remarks>
    private static async Task BindAsync(
        ProxyConnectionContext context,
        ProxyDestination expectedPeer,
        byte[] rawAddress,
        int requestedPort,
        CancellationToken cancellationToken)
    {
        Stream client = context.ClientStream;
        IPAddress bindAddress = context.ClientSocket.LocalEndPoint is IPEndPoint local
            ? local.Address
            : IPAddress.Loopback;

        // A SOCKS4 reply can only carry an IPv4 address, so BIND is IPv4 only.
        if (bindAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            context.Logger.LogWarning(
                "Connection #{Id} requested SOCKS4 BIND on {Address}, which is not IPv4.",
                context.Connection.Id,
                bindAddress);

            await ReplyAsync(client, Socks4Reply.Rejected, rawAddress, requestedPort, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        using Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(bindAddress, 0));
        listener.Listen(1);

        IPEndPoint bound = (IPEndPoint)listener.LocalEndPoint!;

        await ReplyAsync(client, Socks4Reply.Granted, bound.Address.GetAddressBytes(), bound.Port, cancellationToken)
            .ConfigureAwait(false);

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
                "Connection #{Id} SOCKS4 BIND timed out after {Timeout}.",
                context.Connection.Id,
                context.Options.BindTimeout);

            await ReplyAsync(client, Socks4Reply.Rejected, rawAddress, requestedPort, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        using (inbound)
        {
            IPEndPoint peer = (IPEndPoint)inbound.RemoteEndPoint!;

            if (!expectedPeer.RequiresResolution
                && !expectedPeer.Address.Equals(IPAddress.Any)
                && !expectedPeer.Address.Equals(peer.Address))
            {
                context.Logger.LogWarning(
                    "Connection #{Id} SOCKS4 BIND refused {Actual}; the client expected {Expected}.",
                    context.Connection.Id,
                    peer.Address,
                    expectedPeer.Address);

                await ReplyAsync(client, Socks4Reply.Rejected, rawAddress, requestedPort, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            byte[] peerAddress = peer.AddressFamily == AddressFamily.InterNetwork
                ? peer.Address.GetAddressBytes()
                : rawAddress;

            await ReplyAsync(client, Socks4Reply.Granted, peerAddress, peer.Port, cancellationToken)
                .ConfigureAwait(false);

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

    private static async ValueTask ReplyAsync(
        Stream stream,
        Socks4Reply reply,
        byte[] address,
        int port,
        CancellationToken cancellationToken)
    {
        // VN in a reply is 0x00, not 0x04. The original implementation sent 0x04 on the failure
        // path, which made rejections look like garbage to conforming clients.
        byte[] response = new byte[8];
        response[0] = 0x00;
        response[1] = (byte)reply;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), (ushort)port);
        address.AsSpan(0, 4).CopyTo(response.AsSpan(4));

        await stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<string> ReadNullTerminatedAsync(
        Stream stream,
        int maxLength,
        CancellationToken cancellationToken)
    {
        byte[] one = new byte[1];
        StringBuilder builder = new();

        while (true)
        {
            await stream.ReadExactlyAsync(one, cancellationToken).ConfigureAwait(false);

            if (one[0] == 0)
            {
                return builder.ToString();
            }

            if (builder.Length >= maxLength)
            {
                throw new InvalidDataException($"SOCKS4 string exceeded {maxLength} bytes.");
            }

            builder.Append((char)one[0]);
        }
    }
}
