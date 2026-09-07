using System.Buffers;
using System.Globalization;
using System.Text;
using ProxyServerSharp.Net;

namespace ProxyServerSharp.Protocol.Http;

/// <summary>How a message body is delimited.</summary>
public enum HttpBodyKind
{
    /// <summary>There is no body.</summary>
    None,

    /// <summary>The body is exactly <see cref="HttpBodyFraming.Length"/> bytes.</summary>
    ContentLength,

    /// <summary>The body uses chunked transfer coding.</summary>
    Chunked,

    /// <summary>The body runs until the sender closes the connection.</summary>
    UntilClose,
}

/// <summary>The delimiting rule for one message body.</summary>
/// <param name="Kind">How the body is delimited.</param>
/// <param name="Length">The byte count, for <see cref="HttpBodyKind.ContentLength"/>.</param>
public readonly record struct HttpBodyFraming(HttpBodyKind Kind, long Length = 0)
{
    /// <summary>A message with no body.</summary>
    public static HttpBodyFraming None => new(HttpBodyKind.None);

    /// <summary>Whether the connection must close for the recipient to know the body ended.</summary>
    public bool RequiresClose => Kind == HttpBodyKind.UntilClose;
}

/// <summary>
/// Determines how a message body is framed and copies it verbatim from one connection to the
/// other.
/// </summary>
/// <remarks>
/// Getting this right is what lets the proxy keep connections alive. The original implementation
/// forced <c>Connection: close</c> on every forwarded request precisely because it could not tell
/// where one message ended and the next began.
/// </remarks>
public static class HttpMessageBody
{
    private const int MaxChunkLineLength = 64;

    /// <summary>Determines how a request body is framed (RFC 9112 §6).</summary>
    /// <exception cref="InvalidDataException">The framing headers conflict or are malformed.</exception>
    public static HttpBodyFraming ForRequest(HttpRequestHead request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (IsChunked(request.Headers))
        {
            return new HttpBodyFraming(HttpBodyKind.Chunked);
        }

        long? length = ContentLength(request.Headers);

        // A request with neither header has no body; "until close" is not available to a request,
        // since the server would never know when to start responding.
        return length is { } value ? new HttpBodyFraming(HttpBodyKind.ContentLength, value) : HttpBodyFraming.None;
    }

    /// <summary>Determines how a response body is framed (RFC 9112 §6.3).</summary>
    /// <param name="response">The response head.</param>
    /// <param name="requestMethod">The method of the request being answered.</param>
    /// <exception cref="InvalidDataException">The framing headers conflict or are malformed.</exception>
    public static HttpBodyFraming ForResponse(HttpResponseHead response, string requestMethod)
    {
        ArgumentNullException.ThrowIfNull(response);

        // A HEAD response and the bodiless status codes carry framing headers that describe the
        // body the request would have produced, not one that is actually sent.
        if (string.Equals(requestMethod, "HEAD", StringComparison.OrdinalIgnoreCase)
            || response.IsInformational
            || response.Status is 204 or 304)
        {
            return HttpBodyFraming.None;
        }

        if (IsChunked(response.Headers))
        {
            return new HttpBodyFraming(HttpBodyKind.Chunked);
        }

        long? length = ContentLength(response.Headers);
        return length is { } value
            ? new HttpBodyFraming(HttpBodyKind.ContentLength, value)
            : new HttpBodyFraming(HttpBodyKind.UntilClose);
    }

    /// <summary>Copies a body from <paramref name="source"/> to <paramref name="destination"/>.</summary>
    /// <returns>The number of body bytes copied, excluding chunked framing overhead.</returns>
    public static async ValueTask<long> CopyAsync(
        BufferedReadStream source,
        Stream destination,
        HttpBodyFraming framing,
        int bufferSize,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(destination);

        return framing.Kind switch
        {
            HttpBodyKind.None => 0,
            HttpBodyKind.ContentLength =>
                await CopyExactAsync(source, destination, framing.Length, bufferSize, cancellationToken)
                    .ConfigureAwait(false),
            HttpBodyKind.Chunked =>
                await CopyChunkedAsync(source, destination, bufferSize, cancellationToken).ConfigureAwait(false),
            _ => await CopyUntilCloseAsync(source, destination, bufferSize, cancellationToken).ConfigureAwait(false),
        };
    }

    /// <summary>Reads a body into memory, refusing anything larger than <paramref name="maximum"/>.</summary>
    /// <remarks>Used only by Digest <c>qop=auth-int</c>, which cannot verify a streamed body.</remarks>
    public static async ValueTask<byte[]?> ReadAsync(
        BufferedReadStream source,
        HttpBodyFraming framing,
        int maximum,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);

        if (framing.Kind == HttpBodyKind.None)
        {
            return [];
        }

        if (framing.Kind == HttpBodyKind.ContentLength && framing.Length > maximum)
        {
            return null;
        }

        using MemoryStream buffer = new();
        long copied = await CopyAsync(source, buffer, framing, 8192, cancellationToken).ConfigureAwait(false);

        return copied > maximum ? null : buffer.ToArray();
    }

    /// <summary>Whether the header block requests the chunked transfer coding.</summary>
    public static bool IsChunked(HttpHeaders headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        foreach (string value in headers.GetAll("Transfer-Encoding"))
        {
            // RFC 9112 §6.1: chunked must be the final coding, and it is the only one this
            // proxy needs to understand because it re-emits the body verbatim.
            string[] codings = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (codings.Length > 0 && string.Equals(codings[^1], "chunked", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Reads the <c>Content-Length</c> field, or <see langword="null"/> when absent.</summary>
    /// <exception cref="InvalidDataException">The field is malformed or repeated with different values.</exception>
    public static long? ContentLength(HttpHeaders headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        long? result = null;

        foreach (string value in headers.GetAll("Content-Length"))
        {
            if (!long.TryParse(value.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long parsed))
            {
                throw new InvalidDataException($"Malformed Content-Length '{value}'.");
            }

            // Conflicting Content-Length fields are a request-smuggling vector, so reject rather
            // than pick one.
            if (result is { } existing && existing != parsed)
            {
                throw new InvalidDataException("Conflicting Content-Length header fields.");
            }

            result = parsed;
        }

        return result;
    }

    private static async ValueTask<long> CopyExactAsync(
        Stream source,
        Stream destination,
        long length,
        int bufferSize,
        CancellationToken cancellationToken)
    {
        if (length == 0)
        {
            return 0;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            long remaining = length;

            while (remaining > 0)
            {
                int wanted = (int)Math.Min(remaining, buffer.Length);
                int read = await source.ReadAsync(buffer.AsMemory(0, wanted), cancellationToken).ConfigureAwait(false);

                if (read == 0)
                {
                    throw new EndOfStreamException(
                        $"The body ended {remaining} bytes short of its declared Content-Length.");
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                remaining -= read;
            }

            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            return length;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async ValueTask<long> CopyUntilCloseAsync(
        Stream source,
        Stream destination,
        int bufferSize,
        CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            long total = 0;

            while (true)
            {
                int read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                total += read;
            }

            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            return total;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Copies a chunked body, re-emitting the chunk framing exactly as it arrived.
    /// </summary>
    private static async ValueTask<long> CopyChunkedAsync(
        BufferedReadStream source,
        Stream destination,
        int bufferSize,
        CancellationToken cancellationToken)
    {
        long total = 0;

        while (true)
        {
            string? line = await source.ReadLineAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new EndOfStreamException("The chunked body ended before its terminating chunk.");

            if (line.Length > MaxChunkLineLength)
            {
                throw new InvalidDataException($"Chunk size line exceeded {MaxChunkLineLength} bytes.");
            }

            // A chunk-size line may carry extensions after a semicolon; they are forwarded as-is.
            int semicolon = line.IndexOf(';', StringComparison.Ordinal);
            string sizeToken = (semicolon < 0 ? line : line[..semicolon]).Trim();

            if (!long.TryParse(sizeToken, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long size)
                || size < 0)
            {
                throw new InvalidDataException($"Malformed chunk size '{sizeToken}'.");
            }

            await WriteLineAsync(destination, line, cancellationToken).ConfigureAwait(false);

            if (size == 0)
            {
                // The terminating chunk is followed by optional trailer fields, then a blank line.
                while (true)
                {
                    string? trailer = await source.ReadLineAsync(cancellationToken).ConfigureAwait(false)
                        ?? throw new EndOfStreamException("The chunked body ended inside its trailer section.");

                    await WriteLineAsync(destination, trailer, cancellationToken).ConfigureAwait(false);

                    if (trailer.Length == 0)
                    {
                        break;
                    }
                }

                await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
                return total;
            }

            await CopyExactAsync(source, destination, size, bufferSize, cancellationToken).ConfigureAwait(false);
            total += size;

            // Each chunk's data is followed by its own CRLF.
            string? terminator = await source.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (terminator is not { Length: 0 })
            {
                throw new InvalidDataException("A chunk was not terminated by CRLF.");
            }

            await WriteLineAsync(destination, "", cancellationToken).ConfigureAwait(false);
        }
    }

    private static ValueTask WriteLineAsync(Stream destination, string line, CancellationToken cancellationToken) =>
        destination.WriteAsync(Encoding.Latin1.GetBytes(line + "\r\n"), cancellationToken);
}
