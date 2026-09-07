using ProxyServerSharp.Net;

namespace ProxyServerSharp.Protocol.Http;

/// <summary>
/// Holds a request body in memory when something needs to see all of it before the request can be
/// forwarded.
/// </summary>
/// <remarks>
/// Only Digest <c>qop=auth-int</c> needs this: its response hash covers the entity body, so the
/// body cannot simply be streamed through. Buffering is therefore opt-in and capped — an
/// unbounded buffer on an unauthenticated request would be a denial-of-service vector, which is
/// most of the reason <c>auth-int</c> is off by default.
/// </remarks>
internal sealed class RequestBodyBuffer
{
    private readonly BufferedReadStream _source;
    private readonly HttpBodyFraming _framing;
    private readonly int _maximum;

    private byte[]? _content;
    private bool _attempted;

    internal RequestBodyBuffer(BufferedReadStream source, HttpBodyFraming framing, int maximum)
    {
        _source = source;
        _framing = framing;
        _maximum = maximum;
    }

    /// <summary>The buffered body, once <see cref="EnsureAsync"/> has succeeded.</summary>
    internal byte[]? Content => _content;

    /// <summary>Whether the body is held in memory and should be forwarded from there.</summary>
    internal bool IsBuffered => _content is not null;

    /// <summary>
    /// Buffers the body, returning <see langword="null"/> if it is larger than the cap or the
    /// stream ended early. Reading happens once; later calls return the same result.
    /// </summary>
    internal async ValueTask<byte[]?> EnsureAsync(CancellationToken cancellationToken)
    {
        if (_attempted)
        {
            return _content;
        }

        _attempted = true;

        try
        {
            _content = await HttpMessageBody
                .ReadAsync(_source, _framing, _maximum, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or EndOfStreamException)
        {
            _content = null;
        }

        return _content;
    }
}
