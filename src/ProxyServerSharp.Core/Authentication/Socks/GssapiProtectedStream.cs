using System.Buffers;
using System.Net.Security;

namespace ProxyServerSharp.Authentication.Socks;

/// <summary>
/// Wraps a connection so that everything crossing it is encapsulated in RFC 1961
/// <see cref="GssapiMessageType.EncapsulatedData"/> frames, with each frame's payload passed
/// through GSS-API per-message protection.
/// </summary>
/// <remarks>
/// Installed only when the negotiated protection level is
/// <see cref="GssapiProtectionLevel.Integrity"/> or
/// <see cref="GssapiProtectionLevel.Confidentiality"/>. At
/// <see cref="GssapiProtectionLevel.None"/> the connection stays a raw byte stream and this type
/// is not used at all, which is what most clients negotiate.
/// </remarks>
internal sealed class GssapiProtectedStream : Stream
{
    /// <summary>
    /// The most plaintext put into one frame. Wrapping adds a header and, for confidentiality,
    /// padding; keeping the plaintext well under the 64 KiB frame limit leaves room for both.
    /// </summary>
    private const int MaxPlaintextPerFrame = 16 * 1024;

    private readonly Stream _inner;
    private readonly NegotiateAuthentication _context;
    private readonly bool _encrypt;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    private byte[] _pending = [];
    private int _pendingOffset;
    private bool _disposed;

    internal GssapiProtectedStream(Stream inner, NegotiateAuthentication context, GssapiProtectionLevel level)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(context);

        _inner = inner;
        _context = context;
        _encrypt = level == GssapiProtectionLevel.Confidentiality;
    }

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => true;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
        {
            return 0;
        }

        while (_pendingOffset == _pending.Length)
        {
            if (!await ReadFrameAsync(cancellationToken).ConfigureAwait(false))
            {
                return 0;
            }
        }

        int count = Math.Min(buffer.Length, _pending.Length - _pendingOffset);
        _pending.AsMemory(_pendingOffset, count).CopyTo(buffer);
        _pendingOffset += count;
        return count;
    }

    /// <inheritdoc />
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        // One logical write can span several frames, and the relay writes from two directions;
        // the lock keeps frames from interleaving on the wire.
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            while (!buffer.IsEmpty)
            {
                int chunk = Math.Min(buffer.Length, MaxPlaintextPerFrame);
                await WriteFrameAsync(buffer[..chunk], cancellationToken).ConfigureAwait(false);
                buffer = buffer[chunk..];
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <inheritdoc />
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override void Flush() => _inner.Flush();

    /// <inheritdoc />
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            _writeLock.Dispose();
        }

        base.Dispose(disposing);
    }

    private async ValueTask<bool> ReadFrameAsync(CancellationToken cancellationToken)
    {
        GssapiMessageType type;
        byte[] token;

        try
        {
            (type, token) = await GssapiMessage.ReadAsync(_inner, cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException)
        {
            // The peer closed cleanly between frames.
            return false;
        }

        if (type == GssapiMessageType.Abort)
        {
            return false;
        }

        if (type != GssapiMessageType.EncapsulatedData)
        {
            throw new InvalidDataException($"Expected encapsulated data, got GSSAPI message type 0x{(byte)type:X2}.");
        }

        ArrayBufferWriter<byte> plaintext = new(token.Length);
        NegotiateAuthenticationStatusCode status = _context.Unwrap(token, plaintext, out _);

        if (status != NegotiateAuthenticationStatusCode.Completed)
        {
            throw new InvalidDataException($"GSSAPI unwrap failed: {status}.");
        }

        _pending = plaintext.WrittenSpan.ToArray();
        _pendingOffset = 0;

        // A frame carrying no plaintext is legal; the caller's loop simply reads the next one.
        return true;
    }

    private async ValueTask WriteFrameAsync(ReadOnlyMemory<byte> plaintext, CancellationToken cancellationToken)
    {
        ArrayBufferWriter<byte> wrapped = new(plaintext.Length + 128);
        NegotiateAuthenticationStatusCode status = _context.Wrap(plaintext.Span, wrapped, _encrypt, out _);

        if (status != NegotiateAuthenticationStatusCode.Completed)
        {
            throw new IOException($"GSSAPI wrap failed: {status}.");
        }

        await GssapiMessage
            .WriteAsync(_inner, GssapiMessageType.EncapsulatedData, wrapped.WrittenMemory, cancellationToken)
            .ConfigureAwait(false);
    }
}
