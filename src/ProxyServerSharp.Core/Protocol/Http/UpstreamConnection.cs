using System.Net;
using System.Net.Sockets;
using ProxyServerSharp.Net;
using ProxyServerSharp.Server;

namespace ProxyServerSharp.Protocol.Http;

/// <summary>
/// The proxy's connection to the origin server, reused across requests on one client connection
/// while the destination stays the same and both ends want to persist.
/// </summary>
/// <remarks>
/// Reuse has a race: the origin may close an idle connection at the moment the next request goes
/// out. Because the request head is already in memory, this retries it once on a fresh connection
/// before any of the body is streamed, which is the only point where a retry is safe.
/// </remarks>
internal sealed class UpstreamConnection : IAsyncDisposable
{
    private readonly ProxyConnectionContext _context;

    private RemoteConnection? _connection;
    private BufferedReadStream? _stream;
    private ProxyDestination? _destination;

    internal UpstreamConnection(ProxyConnectionContext context) => _context = context;

    /// <summary>Whether the origin indicated the connection may carry another request.</summary>
    internal bool KeepAlive { get; set; } = true;

    /// <summary>The endpoint currently connected to, for logging.</summary>
    internal IPEndPoint? EndPoint => _connection?.RemoteEndPoint;

    /// <summary>The underlying socket, for half-close once a connection becomes a tunnel.</summary>
    internal Socket? Socket => _connection?.Socket;

    /// <summary>
    /// Ensures a connection to <paramref name="destination"/>, writes <paramref name="head"/>, and
    /// returns the stream to read the response from.
    /// </summary>
    /// <exception cref="ProxyDestinationException">The destination could not be reached.</exception>
    internal async ValueTask<BufferedReadStream> SendHeadAsync(
        ProxyDestination destination,
        byte[] head,
        CancellationToken cancellationToken)
    {
        bool reused = await EnsureConnectedAsync(destination, cancellationToken).ConfigureAwait(false);

        try
        {
            await _stream!.WriteAsync(head, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return _stream;
        }
        catch (Exception exception) when (reused && exception is IOException or SocketException or ObjectDisposedException)
        {
            // The pooled connection had already been closed by the origin. Nothing of this
            // request has reached the wire yet, so opening a new one and starting over is safe.
            await CloseAsync().ConfigureAwait(false);
            await EnsureConnectedAsync(destination, cancellationToken).ConfigureAwait(false);

            await _stream!.WriteAsync(head, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return _stream;
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync() => await CloseAsync().ConfigureAwait(false);

    /// <summary>Connects if needed, returning whether an existing connection was reused.</summary>
    private async ValueTask<bool> EnsureConnectedAsync(ProxyDestination destination, CancellationToken cancellationToken)
    {
        if (_connection is not null && KeepAlive && destination.Equals(_destination))
        {
            return true;
        }

        await CloseAsync().ConfigureAwait(false);

        _connection = await _context.Connector.ConnectAsync(destination, cancellationToken).ConfigureAwait(false);
        _stream = new BufferedReadStream(_connection.Stream, leaveOpen: true);
        _destination = destination;
        KeepAlive = true;
        return false;
    }

    private async ValueTask CloseAsync()
    {
        if (_stream is not null)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
            _stream = null;
        }

        if (_connection is not null)
        {
            await _connection.DisposeAsync().ConfigureAwait(false);
            _connection = null;
        }

        _destination = null;
    }
}
