using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Diagnostics;

namespace ProxyServerSharp.Server;

/// <summary>
/// Enforces the global and per-client connection limits and keeps the live connection list the
/// desktop UI displays.
/// </summary>
/// <remarks>
/// The original implementation kept a plain <c>List&lt;ConnectionInfo&gt;</c> that was mutated
/// under a lock from several threads and never enforced any limit, so a client could open
/// connections until the process ran out of sockets.
/// </remarks>
public sealed class ProxyConnectionTracker
{
    private readonly int _maxConnections;
    private readonly int _maxPerClient;
    private readonly ConcurrentDictionary<long, ProxyConnection> _connections = new();
    private readonly ConcurrentDictionary<IPAddress, int> _perClient = new();

    private long _nextId;
    private int _total;

    /// <summary>Creates the tracker.</summary>
    /// <param name="maxConnections">The global cap; zero means unlimited.</param>
    /// <param name="maxConnectionsPerClient">The per-address cap; zero means unlimited.</param>
    public ProxyConnectionTracker(int maxConnections, int maxConnectionsPerClient)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxConnections);
        ArgumentOutOfRangeException.ThrowIfNegative(maxConnectionsPerClient);

        _maxConnections = maxConnections;
        _maxPerClient = maxConnectionsPerClient;
    }

    /// <summary>The connections currently open, newest last.</summary>
    public IReadOnlyCollection<ProxyConnection> Active => [.. _connections.Values.OrderBy(c => c.Id)];

    /// <summary>How many connections are open right now.</summary>
    public int Count => Volatile.Read(ref _total);

    /// <summary>How many connections have been accepted since the server started.</summary>
    public long TotalAccepted => Interlocked.Read(ref _nextId);

    /// <summary>Reserves a slot for a new connection, or explains why it cannot be admitted.</summary>
    public bool TryAdmit(IPAddress clientAddress, [NotNullWhen(false)] out string? reason)
    {
        ArgumentNullException.ThrowIfNull(clientAddress);

        int total = Interlocked.Increment(ref _total);
        if (_maxConnections > 0 && total > _maxConnections)
        {
            Interlocked.Decrement(ref _total);
            reason = $"The server is at its limit of {_maxConnections} connections.";
            return false;
        }

        if (_maxPerClient > 0)
        {
            int perClient = _perClient.AddOrUpdate(clientAddress, 1, (_, current) => current + 1);
            if (perClient > _maxPerClient)
            {
                DecrementClient(clientAddress);
                Interlocked.Decrement(ref _total);
                reason = $"{clientAddress} is at its limit of {_maxPerClient} connections.";
                return false;
            }
        }

        reason = null;
        return true;
    }

    /// <summary>Creates the live view for an admitted connection.</summary>
    public ProxyConnection Register(string listenerName, ProxyProtocol protocol, IPEndPoint clientEndPoint)
    {
        ArgumentNullException.ThrowIfNull(clientEndPoint);

        long id = Interlocked.Increment(ref _nextId);
        ProxyConnection connection = new(id, listenerName, protocol, clientEndPoint);
        _connections[id] = connection;
        return connection;
    }

    /// <summary>Releases the slot held by a finished connection.</summary>
    public void Release(ProxyConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        if (!_connections.TryRemove(connection.Id, out _))
        {
            return;
        }

        Interlocked.Decrement(ref _total);

        if (_maxPerClient > 0)
        {
            DecrementClient(connection.ClientEndPoint.Address);
        }
    }

    private void DecrementClient(IPAddress address)
    {
        // Drop the entry entirely at zero so the dictionary does not accumulate an entry per
        // address that ever connected.
        _perClient.AddOrUpdate(address, 0, (_, current) => current - 1);
        _perClient.TryRemove(new KeyValuePair<IPAddress, int>(address, 0));
    }
}
