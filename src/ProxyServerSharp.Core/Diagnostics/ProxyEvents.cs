using System.Net;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Net;

namespace ProxyServerSharp.Diagnostics;

/// <summary>The lifecycle stage of a proxied connection.</summary>
public enum ProxyConnectionState
{
    /// <summary>Accepted, still negotiating the protocol handshake.</summary>
    Handshaking,

    /// <summary>Credentials accepted; the destination has not been opened yet.</summary>
    Authenticated,

    /// <summary>Bytes are flowing between the client and the destination.</summary>
    Relaying,

    /// <summary>The connection has finished.</summary>
    Closed,
}

/// <summary>A live view of one proxied connection, safe to read from a UI thread.</summary>
public sealed class ProxyConnection
{
    private int _state;

    internal ProxyConnection(long id, string listenerName, ProxyProtocol protocol, IPEndPoint clientEndPoint)
    {
        Id = id;
        ListenerName = listenerName;
        Protocol = protocol;
        ClientEndPoint = clientEndPoint;
        StartedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>A process-unique identifier, used in log messages.</summary>
    public long Id { get; }

    /// <summary>The listener that accepted the connection.</summary>
    public string ListenerName { get; }

    /// <summary>The protocol spoken to the client.</summary>
    public ProxyProtocol Protocol { get; }

    /// <summary>Where the client connected from.</summary>
    public IPEndPoint ClientEndPoint { get; }

    /// <summary>When the connection was accepted.</summary>
    public DateTimeOffset StartedAt { get; }

    /// <summary>Live byte counters for the tunnel.</summary>
    public RelayCounters Counters { get; } = new();

    /// <summary>The authenticated principal, once the handshake has established one.</summary>
    public ProxyIdentity? Identity { get; internal set; }

    /// <summary>Where the client asked to go, once it has said.</summary>
    public ProxyDestination? Destination { get; internal set; }

    /// <summary>The lifecycle stage.</summary>
    public ProxyConnectionState State
    {
        get => (ProxyConnectionState)Volatile.Read(ref _state);
        internal set => Volatile.Write(ref _state, (int)value);
    }

    /// <summary>How long the connection has been open.</summary>
    public TimeSpan Duration => DateTimeOffset.UtcNow - StartedAt;

    /// <inheritdoc />
    public override string ToString() =>
        $"#{Id} {Protocol} {ClientEndPoint} -> {Destination?.ToString() ?? "(none)"} [{State}]";
}

/// <summary>Carries a <see cref="ProxyConnection"/> to an event handler.</summary>
public sealed class ProxyConnectionEventArgs(ProxyConnection connection) : EventArgs
{
    /// <summary>The connection the event is about.</summary>
    public ProxyConnection Connection { get; } = connection;
}

/// <summary>Reports a rejected credential or a refused client.</summary>
public sealed class ProxyAuthenticationEventArgs(
    string listenerName,
    IPEndPoint clientEndPoint,
    string? username,
    string reason) : EventArgs
{
    /// <summary>The listener the attempt arrived on.</summary>
    public string ListenerName { get; } = listenerName;

    /// <summary>Where the attempt came from.</summary>
    public IPEndPoint ClientEndPoint { get; } = clientEndPoint;

    /// <summary>The name presented, when the scheme carried one.</summary>
    public string? Username { get; } = username;

    /// <summary>Why the attempt was refused.</summary>
    public string Reason { get; } = reason;
}

/// <summary>Reports a listener changing state.</summary>
public sealed class ProxyListenerEventArgs(string listenerName, ProxyProtocol protocol, IPEndPoint endPoint, string? error = null)
    : EventArgs
{
    /// <summary>The listener's configured name.</summary>
    public string ListenerName { get; } = listenerName;

    /// <summary>The protocol it speaks.</summary>
    public ProxyProtocol Protocol { get; } = protocol;

    /// <summary>The endpoint it bound, or tried to.</summary>
    public IPEndPoint EndPoint { get; } = endPoint;

    /// <summary>Why the listener stopped, when it stopped because of a fault.</summary>
    public string? Error { get; } = error;
}
