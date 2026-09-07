using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Diagnostics;
using ProxyServerSharp.Net;

namespace ProxyServerSharp.Server;

/// <summary>
/// Everything a protocol handler needs for one accepted connection: the streams, the listener's
/// configuration, and the services it shares with every other connection on that listener.
/// </summary>
public sealed class ProxyConnectionContext
{
    internal ProxyConnectionContext(
        ProxyConnection connection,
        Socket clientSocket,
        BufferedReadStream clientStream,
        ListenerOptions listener,
        ProxyServerOptions options,
        IUserStore users,
        IRemoteConnector connector,
        ILogger logger)
    {
        Connection = connection;
        ClientSocket = clientSocket;
        ClientStream = clientStream;
        Listener = listener;
        Options = options;
        Users = users;
        Connector = connector;
        Logger = logger;
    }

    /// <summary>The live view of this connection.</summary>
    public ProxyConnection Connection { get; }

    /// <summary>The accepted socket, for half-close and socket options.</summary>
    public Socket ClientSocket { get; }

    /// <summary>
    /// The client byte stream: a buffered <see cref="NetworkStream"/>, or a buffered
    /// <see cref="System.Net.Security.SslStream"/> when the listener terminates TLS.
    /// </summary>
    public BufferedReadStream ClientStream { get; }

    /// <summary>The listener's configuration.</summary>
    public ListenerOptions Listener { get; }

    /// <summary>The server-wide configuration.</summary>
    public ProxyServerOptions Options { get; }

    /// <summary>The account directory.</summary>
    public IUserStore Users { get; }

    /// <summary>Opens the outbound half of the connection.</summary>
    public IRemoteConnector Connector { get; }

    /// <summary>The logger, already scoped to this listener.</summary>
    public ILogger Logger { get; }

    /// <summary>Where the client connected from.</summary>
    public IPEndPoint ClientEndPoint => Connection.ClientEndPoint;

    /// <summary>The listener and client identity used for per-account grants.</summary>
    public UserStoreContext StoreContext => new(Listener.Name, ClientEndPoint.Address);

    /// <summary>Records the authenticated principal on the connection.</summary>
    public void SetIdentity(ProxyIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        Connection.Identity = identity;
        Connection.State = ProxyConnectionState.Authenticated;
    }

    /// <summary>Builds the relay options for this connection, wired to its live counters.</summary>
    public RelayOptions CreateRelayOptions() => new(
        Options.BufferSize,
        Options.IdleTimeout,
        Connection.Counters);
}
