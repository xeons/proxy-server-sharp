using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ProxyServerSharp.Tests;

/// <summary>
/// A hand-rolled SOCKS client that speaks the wire format directly, so tests assert on actual
/// bytes rather than on whatever a client library decides to send.
/// </summary>
internal sealed class SocksClient : IAsyncDisposable
{
    private readonly Socket _socket;
    private readonly NetworkStream _stream;

    private SocksClient(Socket socket)
    {
        _socket = socket;
        _stream = new NetworkStream(socket, ownsSocket: false);
    }

    /// <summary>The stream carrying the proxy conversation, and then the tunnel.</summary>
    internal NetworkStream Stream => _stream;

    /// <summary>Connects to a proxy listener.</summary>
    internal static async Task<SocksClient> ConnectAsync(IPEndPoint proxy)
    {
        Socket socket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        return new SocksClient(socket);
    }

    // ---- SOCKS5 -----------------------------------------------------------

    /// <summary>Sends the greeting and returns the method byte the server selected.</summary>
    internal async Task<byte> GreetAsync(params byte[] methods)
    {
        byte[] greeting = new byte[2 + methods.Length];
        greeting[0] = 0x05;
        greeting[1] = (byte)methods.Length;
        methods.CopyTo(greeting, 2);

        await _stream.WriteAsync(greeting);

        byte[] reply = new byte[2];
        await _stream.ReadExactlyAsync(reply);

        Assert.Equal(0x05, reply[0]);
        return reply[1];
    }

    /// <summary>Runs the RFC 1929 username/password sub-negotiation, returning the status byte.</summary>
    internal async Task<byte> AuthenticateAsync(string username, string password)
    {
        byte[] user = Encoding.UTF8.GetBytes(username);
        byte[] pass = Encoding.UTF8.GetBytes(password);

        byte[] request = new byte[3 + user.Length + pass.Length];
        request[0] = 0x01;
        request[1] = (byte)user.Length;
        user.CopyTo(request, 2);
        request[2 + user.Length] = (byte)pass.Length;
        pass.CopyTo(request, 3 + user.Length);

        await _stream.WriteAsync(request);

        byte[] reply = new byte[2];
        await _stream.ReadExactlyAsync(reply);
        return reply[1];
    }

    /// <summary>Sends a SOCKS5 request and returns the reply code plus the bound endpoint.</summary>
    internal async Task<(byte Reply, IPEndPoint Bound)> RequestAsync(byte command, IPEndPoint destination)
    {
        byte[] request = new byte[10];
        request[0] = 0x05;
        request[1] = command;
        request[2] = 0x00;
        request[3] = 0x01; // IPv4
        destination.Address.GetAddressBytes().CopyTo(request, 4);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(8), (ushort)destination.Port);

        await _stream.WriteAsync(request);
        return await ReadReplyAsync();
    }

    /// <summary>Sends a SOCKS5 request naming the destination by host name.</summary>
    internal async Task<(byte Reply, IPEndPoint Bound)> RequestAsync(byte command, string host, int port)
    {
        byte[] name = Encoding.UTF8.GetBytes(host);
        byte[] request = new byte[7 + name.Length];
        request[0] = 0x05;
        request[1] = command;
        request[2] = 0x00;
        request[3] = 0x03; // domain name
        request[4] = (byte)name.Length;
        name.CopyTo(request, 5);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(5 + name.Length), (ushort)port);

        await _stream.WriteAsync(request);
        return await ReadReplyAsync();
    }

    /// <summary>Reads one SOCKS5 reply, including its variable-length bound address.</summary>
    internal async Task<(byte Reply, IPEndPoint Bound)> ReadReplyAsync()
    {
        byte[] header = new byte[4];
        await _stream.ReadExactlyAsync(header);

        Assert.Equal(0x05, header[0]);

        int addressLength = header[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            0x03 => await ReadDomainLengthAsync(),
            _ => throw new InvalidDataException($"Unexpected ATYP 0x{header[3]:X2}."),
        };

        byte[] rest = new byte[addressLength + 2];
        await _stream.ReadExactlyAsync(rest);

        IPAddress address = header[3] == 0x03
            ? IPAddress.Any
            : new IPAddress(rest.AsSpan(0, addressLength));

        int port = BinaryPrimitives.ReadUInt16BigEndian(rest.AsSpan(addressLength));
        return (header[1], new IPEndPoint(address, port));
    }

    // ---- SOCKS4 -----------------------------------------------------------

    /// <summary>Sends a SOCKS4 CONNECT and returns the reply code.</summary>
    internal async Task<byte> Socks4ConnectAsync(IPEndPoint destination, string userId)
    {
        byte[] user = Encoding.ASCII.GetBytes(userId);
        byte[] request = new byte[9 + user.Length];
        request[0] = 0x04;
        request[1] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), (ushort)destination.Port);
        destination.Address.GetAddressBytes().CopyTo(request, 4);
        user.CopyTo(request, 8);
        request[8 + user.Length] = 0x00;

        await _stream.WriteAsync(request);
        return await ReadSocks4ReplyAsync();
    }

    /// <summary>Sends a SOCKS4a CONNECT naming the destination by host name.</summary>
    internal async Task<byte> Socks4aConnectAsync(string host, int port, string userId)
    {
        byte[] user = Encoding.ASCII.GetBytes(userId);
        byte[] name = Encoding.ASCII.GetBytes(host);

        byte[] request = new byte[9 + user.Length + name.Length + 1];
        request[0] = 0x04;
        request[1] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), (ushort)port);

        // 0.0.0.x with a non-zero last octet is the SOCKS4a "resolve this name" marker.
        request[4] = 0;
        request[5] = 0;
        request[6] = 0;
        request[7] = 1;

        user.CopyTo(request, 8);
        request[8 + user.Length] = 0x00;
        name.CopyTo(request, 9 + user.Length);
        request[9 + user.Length + name.Length] = 0x00;

        await _stream.WriteAsync(request);
        return await ReadSocks4ReplyAsync();
    }

    private async Task<byte> ReadSocks4ReplyAsync()
    {
        byte[] reply = new byte[8];
        await _stream.ReadExactlyAsync(reply);

        // A SOCKS4 reply always begins with a zero version byte, never 0x04.
        Assert.Equal(0x00, reply[0]);
        return reply[1];
    }

    private async Task<int> ReadDomainLengthAsync()
    {
        byte[] length = new byte[1];
        await _stream.ReadExactlyAsync(length);
        return length[0];
    }

    // ---- payload ----------------------------------------------------------

    /// <summary>Sends a payload through the established tunnel and reads the same number of bytes back.</summary>
    internal async Task<string> RoundTripAsync(string payload)
    {
        byte[] sent = Encoding.UTF8.GetBytes(payload);
        await _stream.WriteAsync(sent);

        byte[] received = new byte[sent.Length];
        await _stream.ReadExactlyAsync(received);
        return Encoding.UTF8.GetString(received);
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync();
        _socket.Dispose();
    }
}
