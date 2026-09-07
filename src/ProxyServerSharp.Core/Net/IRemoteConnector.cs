using System.Net;
using System.Net.Sockets;

namespace ProxyServerSharp.Net;

/// <summary>Opens the outbound half of a proxied connection.</summary>
/// <remarks>
/// An interface rather than a direct <see cref="Socket"/> call so that the destination policy has
/// one place to sit, and so tests can stand in a loopback endpoint without a real network.
/// </remarks>
public interface IRemoteConnector
{
    /// <summary>Connects to <paramref name="destination"/>, resolving it first if needed.</summary>
    /// <exception cref="ProxyDestinationException">Policy refused the destination, or it could not be reached.</exception>
    ValueTask<RemoteConnection> ConnectAsync(
        ProxyDestination destination,
        CancellationToken cancellationToken);
}

/// <summary>An established outbound connection and the endpoint it actually landed on.</summary>
public sealed class RemoteConnection : IAsyncDisposable
{
    private readonly Socket _socket;
    private readonly NetworkStream _stream;

    internal RemoteConnection(Socket socket, IPEndPoint remoteEndPoint, IPEndPoint localEndPoint)
    {
        _socket = socket;
        _stream = new NetworkStream(socket, ownsSocket: false);
        RemoteEndPoint = remoteEndPoint;
        LocalEndPoint = localEndPoint;
    }

    /// <summary>The endpoint the connection reached.</summary>
    public IPEndPoint RemoteEndPoint { get; }

    /// <summary>The local endpoint the connection was made from.</summary>
    public IPEndPoint LocalEndPoint { get; }

    /// <summary>The byte stream carrying the connection.</summary>
    public Stream Stream => _stream;

    /// <summary>The underlying socket, for half-close and socket options.</summary>
    public Socket Socket => _socket;

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync().ConfigureAwait(false);
        _socket.Dispose();
    }
}

/// <summary>A destination could not be used, with the reply code the protocol should send.</summary>
public sealed class ProxyDestinationException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <param name="failure">Why the destination failed, so handlers can map it to a reply code.</param>
    /// <param name="message">A description for the log.</param>
    /// <param name="innerException">The underlying failure, if any.</param>
    public ProxyDestinationException(DestinationFailure failure, string message, Exception? innerException = null)
        : base(message, innerException) => Failure = failure;

    /// <summary>Creates the exception with no specific failure kind.</summary>
    public ProxyDestinationException()
        : this(DestinationFailure.GeneralFailure, "The destination could not be reached.")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public ProxyDestinationException(string message)
        : this(DestinationFailure.GeneralFailure, message)
    {
    }

    /// <summary>Creates the exception with a message and inner exception.</summary>
    public ProxyDestinationException(string message, Exception innerException)
        : this(DestinationFailure.GeneralFailure, message, innerException)
    {
    }

    /// <summary>Why the destination failed.</summary>
    public DestinationFailure Failure { get; }
}

/// <summary>The protocol-independent reasons an outbound connection fails.</summary>
public enum DestinationFailure
{
    /// <summary>An unspecified failure.</summary>
    GeneralFailure,

    /// <summary>Policy refused the destination.</summary>
    NotAllowed,

    /// <summary>The host name did not resolve.</summary>
    HostUnreachable,

    /// <summary>No route to the destination network.</summary>
    NetworkUnreachable,

    /// <summary>The destination refused the connection.</summary>
    ConnectionRefused,

    /// <summary>The connection attempt timed out.</summary>
    TimedOut,

    /// <summary>The address family is not supported by this listener.</summary>
    AddressTypeNotSupported,
}
