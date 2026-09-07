using System.Buffers.Binary;
using System.Net;
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

        if (command != (byte)Socks5Command.Connect)
        {
            // BIND is the only other SOCKS4 command, and this server does not offer it;
            // SOCKS5 listeners can be configured for BIND instead.
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
