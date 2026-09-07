using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyServerSharp.Net;

namespace ProxyServerSharp.Protocol.Socks;

/// <summary>
/// Reads and writes the <c>ATYP / DST.ADDR / DST.PORT</c> triple that appears in SOCKS5 requests,
/// replies and UDP datagram headers.
/// </summary>
public static class Socks5Address
{
    /// <summary>The largest an encoded address can be: type + length + 255 name bytes + port.</summary>
    public const int MaxEncodedLength = 1 + 1 + 255 + 2;

    /// <summary>Reads an address and port from <paramref name="stream"/>.</summary>
    /// <exception cref="Socks5ProtocolException">The address type is not one this server supports.</exception>
    public static async ValueTask<ProxyDestination> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        byte[] header = new byte[1];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

        return (Socks5AddressType)header[0] switch
        {
            Socks5AddressType.IPv4 => await ReadIpAsync(stream, 4, cancellationToken).ConfigureAwait(false),
            Socks5AddressType.IPv6 => await ReadIpAsync(stream, 16, cancellationToken).ConfigureAwait(false),
            Socks5AddressType.DomainName => await ReadDomainAsync(stream, cancellationToken).ConfigureAwait(false),
            _ => throw new Socks5ProtocolException(
                Socks5Reply.AddressTypeNotSupported,
                $"Unsupported SOCKS5 address type 0x{header[0]:X2}."),
        };
    }

    /// <summary>Writes an endpoint into <paramref name="destination"/>, returning the bytes used.</summary>
    public static int Write(Span<byte> destination, IPEndPoint endPoint)
    {
        ArgumentNullException.ThrowIfNull(endPoint);

        bool isIPv6 = endPoint.AddressFamily == AddressFamily.InterNetworkV6;
        int addressLength = isIPv6 ? 16 : 4;

        destination[0] = (byte)(isIPv6 ? Socks5AddressType.IPv6 : Socks5AddressType.IPv4);
        if (!endPoint.Address.TryWriteBytes(destination[1..], out int written) || written != addressLength)
        {
            throw new ArgumentException($"Could not encode {endPoint.Address}.", nameof(endPoint));
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination[(1 + addressLength)..], (ushort)endPoint.Port);
        return 1 + addressLength + 2;
    }

    /// <summary>Writes a destination that may still be a host name, returning the bytes used.</summary>
    public static int Write(Span<byte> destination, ProxyDestination proxyDestination)
    {
        ArgumentNullException.ThrowIfNull(proxyDestination);

        if (!proxyDestination.RequiresResolution)
        {
            return Write(destination, new IPEndPoint(proxyDestination.Address, proxyDestination.Port));
        }

        byte[] host = Encoding.UTF8.GetBytes(proxyDestination.Host);
        if (host.Length > 255)
        {
            throw new ArgumentException("Host name exceeds the 255 byte SOCKS5 limit.", nameof(proxyDestination));
        }

        destination[0] = (byte)Socks5AddressType.DomainName;
        destination[1] = (byte)host.Length;
        host.CopyTo(destination[2..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[(2 + host.Length)..], (ushort)proxyDestination.Port);
        return 2 + host.Length + 2;
    }

    /// <summary>Reads an address and port from an in-memory buffer, e.g. a UDP datagram header.</summary>
    public static bool TryRead(ReadOnlySpan<byte> buffer, out ProxyDestination? destination, out int consumed)
    {
        destination = null;
        consumed = 0;

        if (buffer.Length < 1)
        {
            return false;
        }

        switch ((Socks5AddressType)buffer[0])
        {
            case Socks5AddressType.IPv4 when buffer.Length >= 7:
                destination = ProxyDestination.FromAddress(new IPAddress(buffer.Slice(1, 4)), ReadPort(buffer[5..]));
                consumed = 7;
                return true;

            case Socks5AddressType.IPv6 when buffer.Length >= 19:
                destination = ProxyDestination.FromAddress(new IPAddress(buffer.Slice(1, 16)), ReadPort(buffer[17..]));
                consumed = 19;
                return true;

            case Socks5AddressType.DomainName when buffer.Length >= 2 && buffer.Length >= 2 + buffer[1] + 2:
            {
                int length = buffer[1];
                string host = Encoding.UTF8.GetString(buffer.Slice(2, length));
                destination = ProxyDestination.FromHost(host, ReadPort(buffer[(2 + length)..]));
                consumed = 2 + length + 2;
                return true;
            }

            default:
                return false;
        }
    }

    private static async ValueTask<ProxyDestination> ReadIpAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[length + 2];
        await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);

        IPAddress address = new(buffer.AsSpan(0, length));
        return ProxyDestination.FromAddress(address, ReadPort(buffer.AsSpan(length)));
    }

    private static async ValueTask<ProxyDestination> ReadDomainAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] lengthByte = new byte[1];
        await stream.ReadExactlyAsync(lengthByte, cancellationToken).ConfigureAwait(false);

        if (lengthByte[0] == 0)
        {
            throw new Socks5ProtocolException(Socks5Reply.GeneralFailure, "SOCKS5 request carried an empty host name.");
        }

        byte[] buffer = new byte[lengthByte[0] + 2];
        await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);

        string host = Encoding.UTF8.GetString(buffer, 0, lengthByte[0]);
        return ProxyDestination.FromHost(host, ReadPort(buffer.AsSpan(lengthByte[0])));
    }

    private static int ReadPort(ReadOnlySpan<byte> buffer) => BinaryPrimitives.ReadUInt16BigEndian(buffer);
}

/// <summary>A SOCKS5 request could not be honoured, carrying the reply code to send back.</summary>
public sealed class Socks5ProtocolException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <param name="reply">The reply code the client should receive.</param>
    /// <param name="message">A description for the log.</param>
    public Socks5ProtocolException(Socks5Reply reply, string message)
        : base(message) => Reply = reply;

    /// <summary>Creates the exception with a general-failure reply code.</summary>
    public Socks5ProtocolException()
        : this(Socks5Reply.GeneralFailure, "The SOCKS5 request could not be honoured.")
    {
    }

    /// <summary>Creates the exception with a general-failure reply code.</summary>
    public Socks5ProtocolException(string message)
        : this(Socks5Reply.GeneralFailure, message)
    {
    }

    /// <summary>Creates the exception with a general-failure reply code and an inner exception.</summary>
    public Socks5ProtocolException(string message, Exception innerException)
        : base(message, innerException) => Reply = Socks5Reply.GeneralFailure;

    /// <summary>The reply code the client should receive.</summary>
    public Socks5Reply Reply { get; }
}
