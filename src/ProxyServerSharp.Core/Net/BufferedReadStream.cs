using System.Text;

namespace ProxyServerSharp.Net;

/// <summary>
/// A read-buffering stream wrapper that can also pull CRLF-delimited lines.
/// </summary>
/// <remarks>
/// The HTTP handler has to read a request head before it knows whether the connection becomes a
/// tunnel. Buffering inside the stream itself means the bytes that arrived alongside the head are
/// still there for the relay, instead of being stranded in a separate parser buffer.
/// </remarks>
public sealed class BufferedReadStream : Stream
{
    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private readonly byte[] _buffer;
    private int _start;
    private int _end;

    /// <summary>Wraps <paramref name="inner"/> with a read buffer.</summary>
    /// <param name="inner">The stream to read from and write to.</param>
    /// <param name="bufferSize">The buffer capacity, which also caps a single header line.</param>
    /// <param name="leaveOpen">Whether disposing this leaves <paramref name="inner"/> open.</param>
    public BufferedReadStream(Stream inner, int bufferSize = 8192, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentOutOfRangeException.ThrowIfLessThan(bufferSize, 256);

        _inner = inner;
        _leaveOpen = leaveOpen;
        _buffer = new byte[bufferSize];
    }

    /// <summary>The stream being buffered.</summary>
    public Stream Inner => _inner;

    /// <summary>Bytes read ahead of the current position and not yet consumed.</summary>
    public int BufferedCount => _end - _start;

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => _inner.CanWrite;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>
    /// Reads one CRLF- or LF-terminated line, returning it without the terminator, or
    /// <see langword="null"/> at end of stream.
    /// </summary>
    /// <exception cref="InvalidDataException">The line is longer than the buffer.</exception>
    public async ValueTask<string?> ReadLineAsync(CancellationToken cancellationToken = default)
    {
        int searched = 0;
        while (true)
        {
            int newline = Array.IndexOf(_buffer, (byte)'\n', _start + searched, _end - _start - searched);
            if (newline >= 0)
            {
                int length = newline - _start;
                if (length > 0 && _buffer[newline - 1] == (byte)'\r')
                {
                    length--;
                }

                // Header field values are ASCII by spec; Latin-1 keeps stray high bytes
                // round-trippable instead of turning them into replacement characters.
                string line = Encoding.Latin1.GetString(_buffer, _start, length);
                _start = newline + 1;
                return line;
            }

            searched = _end - _start;
            if (!await FillAsync(cancellationToken).ConfigureAwait(false))
            {
                return searched == 0 ? null : throw new InvalidDataException("Stream ended mid-line.");
            }
        }
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_start == _end)
        {
            // Nothing buffered: go straight to the source rather than paying for a copy.
            return await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        int count = Math.Min(buffer.Length, _end - _start);
        _buffer.AsMemory(_start, count).CopyTo(buffer);
        _start += count;
        return count;
    }

    /// <inheritdoc />
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateBufferArguments(buffer, offset, count);

        if (_start == _end)
        {
            return _inner.Read(buffer, offset, count);
        }

        int read = Math.Min(count, _end - _start);
        Buffer.BlockCopy(_buffer, _start, buffer, offset, read);
        _start += read;
        return read;
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

    /// <inheritdoc />
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        _inner.WriteAsync(buffer, cancellationToken);

    /// <inheritdoc />
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _inner.WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

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
        if (disposing && !_leaveOpen)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc />
    public override async ValueTask DisposeAsync()
    {
        if (!_leaveOpen)
        {
            await _inner.DisposeAsync().ConfigureAwait(false);
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    private async ValueTask<bool> FillAsync(CancellationToken cancellationToken)
    {
        Compact();

        if (_end == _buffer.Length)
        {
            throw new InvalidDataException(
                $"A single line exceeded the {_buffer.Length} byte header buffer.");
        }

        int read = await _inner
            .ReadAsync(_buffer.AsMemory(_end, _buffer.Length - _end), cancellationToken)
            .ConfigureAwait(false);

        _end += read;
        return read > 0;
    }

    private void Compact()
    {
        if (_start == 0)
        {
            return;
        }

        Buffer.BlockCopy(_buffer, _start, _buffer, 0, _end - _start);
        _end -= _start;
        _start = 0;
    }
}
