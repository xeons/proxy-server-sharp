using System.Net;
using System.Net.Sockets;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Server;

namespace ProxyServerSharp.Tests;

/// <summary>
/// Spins up a real <see cref="ProxyServerHost"/> on an ephemeral loopback port, plus an origin
/// server for it to reach, so the tests exercise actual sockets rather than mocks.
/// </summary>
internal sealed class ProxyServerFixture : IAsyncDisposable
{
    private readonly ProxyServerHost _host;

    private ProxyServerFixture(ProxyServerHost host, IReadOnlyList<ProxyListener> listeners)
    {
        _host = host;
        Listeners = listeners;
    }

    /// <summary>The bound listeners, in configuration order.</summary>
    internal IReadOnlyList<ProxyListener> Listeners { get; }

    /// <summary>The endpoint of the first listener.</summary>
    internal IPEndPoint EndPoint => Listeners[0].EndPoint!;

    /// <summary>The port of the first listener.</summary>
    internal int Port => EndPoint.Port;

    /// <summary>The live connection tracker, for asserting on server-side state.</summary>
    internal ProxyConnectionTracker Connections => _host.Connections;

    /// <summary>Starts a host with the given listeners and accounts.</summary>
    internal static async Task<ProxyServerFixture> StartAsync(
        IEnumerable<ListenerOptions> listeners,
        IEnumerable<ProxyUserOptions>? users = null,
        Action<ProxyServerOptions>? configure = null)
    {
        ProxyServerOptions options = new()
        {
            // Tests connect to loopback origin servers, so the default loopback block is off.
            HandshakeTimeout = TimeSpan.FromSeconds(10),
            ConnectTimeout = TimeSpan.FromSeconds(10),
            IdleTimeout = TimeSpan.FromSeconds(30),
        };

        foreach (ListenerOptions listener in listeners)
        {
            listener.Destinations.BlockLoopback = false;
            listener.Destinations.BlockLinkLocal = false;
            options.Listeners.Add(listener);
        }

        foreach (ProxyUserOptions user in users ?? [])
        {
            options.Users.Add(user);
        }

        configure?.Invoke(options);

        ProxyServerHost host = new(options);
        IReadOnlyList<ProxyListener> started = await host.StartAsync();
        return new ProxyServerFixture(host, started);
    }

    /// <summary>Starts a host with a single listener.</summary>
    internal static Task<ProxyServerFixture> StartAsync(
        ListenerOptions listener,
        IEnumerable<ProxyUserOptions>? users = null,
        Action<ProxyServerOptions>? configure = null) =>
        StartAsync([listener], users, configure);

    /// <summary>Builds a listener bound to an ephemeral loopback port.</summary>
    internal static ListenerOptions Listener(ProxyProtocol protocol, params AuthenticationMethod[] methods)
    {
        ListenerOptions listener = new()
        {
            Name = $"test-{protocol}",
            Protocol = protocol,
            Address = "127.0.0.1",
            Port = FreePort(),
        };

        foreach (AuthenticationMethod method in methods)
        {
            listener.Authentication.Add(method);
        }

        return listener;
    }

    /// <summary>
    /// Reserves an ephemeral port by binding and releasing it. There is a race in principle, but
    /// binding a port the OS just handed out is reliable enough for a test run.
    /// </summary>
    internal static int FreePort()
    {
        using Socket probe = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();
}
