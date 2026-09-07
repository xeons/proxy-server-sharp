using System.Buffers.Binary;

namespace ProxyServerSharp.Authentication.Socks;

/// <summary>The message types in the RFC 1961 sub-negotiation.</summary>
public enum GssapiMessageType : byte
{
    /// <summary>A GSS-API context-establishment token.</summary>
    Authentication = 0x01,

    /// <summary>A protection-level negotiation message.</summary>
    ProtectionLevel = 0x02,

    /// <summary>Encapsulated user data, once a protection level above none is in force.</summary>
    EncapsulatedData = 0x03,

    /// <summary>The server refuses the context; the client must close the connection.</summary>
    Abort = 0xFF,
}

/// <summary>
/// The per-message protection RFC 1961 §4.3 negotiates.
/// </summary>
public enum GssapiProtectionLevel : byte
{
    /// <summary>GSS-API is used for the handshake only; what follows is a raw byte stream.</summary>
    None = 0,

    /// <summary>Every subsequent message carries an integrity token.</summary>
    Integrity = 1,

    /// <summary>Every subsequent message is encrypted as well as integrity protected.</summary>
    Confidentiality = 2,
}

/// <summary>
/// Reads and writes the RFC 1961 sub-negotiation frame:
/// <c>VER(1) | MTYP(1) | LEN(2) | TOKEN</c>, with <c>VER</c> fixed at <c>0x01</c>.
/// </summary>
/// <remarks>
/// Note that this <c>VER</c> is the sub-negotiation version, not the SOCKS version — it is
/// <c>0x01</c> here even though the outer protocol is SOCKS5.
/// </remarks>
public static class GssapiMessage
{
    /// <summary>The sub-negotiation version byte.</summary>
    public const byte Version = 0x01;

    /// <summary>The largest token a single frame can carry, from the 16-bit length field.</summary>
    public const int MaxTokenLength = 65535;

    /// <summary>Reads one frame, returning its type and token.</summary>
    /// <exception cref="InvalidDataException">The frame is not a valid RFC 1961 message.</exception>
    public static async ValueTask<(GssapiMessageType Type, byte[] Token)> ReadAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

        if (header[0] != Version)
        {
            throw new InvalidDataException(
                $"Expected RFC 1961 version 0x01, got 0x{header[0]:X2}.");
        }

        int length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2, 2));
        byte[] token = new byte[length];

        if (length > 0)
        {
            await stream.ReadExactlyAsync(token, cancellationToken).ConfigureAwait(false);
        }

        return ((GssapiMessageType)header[1], token);
    }

    /// <summary>Writes one frame.</summary>
    /// <exception cref="ArgumentException">The token does not fit the 16-bit length field.</exception>
    public static async ValueTask WriteAsync(
        Stream stream,
        GssapiMessageType type,
        ReadOnlyMemory<byte> token,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (token.Length > MaxTokenLength)
        {
            throw new ArgumentException(
                $"A GSSAPI token of {token.Length} bytes exceeds the {MaxTokenLength} byte frame limit.",
                nameof(token));
        }

        byte[] frame = new byte[4 + token.Length];
        frame[0] = Version;
        frame[1] = (byte)type;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2, 2), (ushort)token.Length);
        token.Span.CopyTo(frame.AsSpan(4));

        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Writes an abort message, telling the client the context was refused.</summary>
    public static ValueTask WriteAbortAsync(Stream stream, CancellationToken cancellationToken) =>
        WriteAsync(stream, GssapiMessageType.Abort, ReadOnlyMemory<byte>.Empty, cancellationToken);
}
