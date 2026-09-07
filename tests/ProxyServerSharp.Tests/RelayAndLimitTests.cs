using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Diagnostics;
using ProxyServerSharp.Net;
using ProxyServerSharp.Server;

namespace ProxyServerSharp.Tests;

/// <summary>Tests for the bidirectional relay.</summary>
public sealed class TunnelRelayTests
{
    [Fact]
    public async Task HalfClose_LetsTheResponseFinishAfterTheClientStopsSending()
    {
        // The original implementation tore both sockets down as soon as either direction ended,
        // which truncated any response that arrived after the client half-closed.
        await using SocketPair clientSide = await SocketPair.CreateAsync();
        await using SocketPair remoteSide = await SocketPair.CreateAsync();

        RelayOptions options = new(BufferSize: 4096, IdleTimeout: TimeSpan.FromSeconds(10));

        Task<RelayCounters> relay = TunnelRelay.RunAsync(
            clientSide.ServerStream,
            remoteSide.ServerStream,
            options,
            clientSide.Server,
            remoteSide.Server);

        // The client sends a request, then half-closes its send channel.
        await clientSide.ClientStream.WriteAsync("request"u8.ToArray());
        clientSide.Client.Shutdown(SocketShutdown.Send);

        byte[] atRemote = new byte[7];
        await remoteSide.ClientStream.ReadExactlyAsync(atRemote);
        Assert.Equal("request", Encoding.UTF8.GetString(atRemote));

        // The far side answers only after that half-close; the relay must still carry it.
        await remoteSide.ClientStream.WriteAsync("late response"u8.ToArray());
        remoteSide.Client.Shutdown(SocketShutdown.Send);

        byte[] atClient = new byte[13];
        await clientSide.ClientStream.ReadExactlyAsync(atClient);
        Assert.Equal("late response", Encoding.UTF8.GetString(atClient));

        RelayCounters counters = await relay.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(7, counters.ClientToRemote);
        Assert.Equal(13, counters.RemoteToClient);
    }

    [Fact]
    public async Task IdleTimeout_TearsDownASilentTunnel()
    {
        await using SocketPair clientSide = await SocketPair.CreateAsync();
        await using SocketPair remoteSide = await SocketPair.CreateAsync();

        RelayOptions options = new(BufferSize: 4096, IdleTimeout: TimeSpan.FromMilliseconds(600));

        Task<RelayCounters> relay = TunnelRelay.RunAsync(
            clientSide.ServerStream,
            remoteSide.ServerStream,
            options,
            clientSide.Server,
            remoteSide.Server);

        // Neither side ever speaks, so the watchdog should end it well inside this wait.
        await relay.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task Counters_TrackBothDirections()
    {
        await using SocketPair clientSide = await SocketPair.CreateAsync();
        await using SocketPair remoteSide = await SocketPair.CreateAsync();

        RelayCounters counters = new();
        RelayOptions options = new(4096, TimeSpan.FromSeconds(10), counters);

        Task<RelayCounters> relay = TunnelRelay.RunAsync(
            clientSide.ServerStream,
            remoteSide.ServerStream,
            options,
            clientSide.Server,
            remoteSide.Server);

        await clientSide.ClientStream.WriteAsync(new byte[100]);
        byte[] drain = new byte[100];
        await remoteSide.ClientStream.ReadExactlyAsync(drain);

        await remoteSide.ClientStream.WriteAsync(new byte[250]);
        byte[] back = new byte[250];
        await clientSide.ClientStream.ReadExactlyAsync(back);

        clientSide.Client.Shutdown(SocketShutdown.Send);
        remoteSide.Client.Shutdown(SocketShutdown.Send);
        await relay.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(100, counters.ClientToRemote);
        Assert.Equal(250, counters.RemoteToClient);
        Assert.Equal(350, counters.Total);
    }

    /// <summary>A connected pair of loopback sockets and their streams.</summary>
    private sealed class SocketPair : IAsyncDisposable
    {
        private SocketPair(Socket client, Socket server)
        {
            Client = client;
            Server = server;
            ClientStream = new NetworkStream(client, ownsSocket: false);
            ServerStream = new NetworkStream(server, ownsSocket: false);
        }

        public Socket Client { get; }

        public Socket Server { get; }

        public NetworkStream ClientStream { get; }

        public NetworkStream ServerStream { get; }

        public static async Task<SocketPair> CreateAsync()
        {
            using Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(1);

            Socket client = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Task<Socket> accept = listener.AcceptAsync();
            await client.ConnectAsync((IPEndPoint)listener.LocalEndPoint!);

            return new SocketPair(client, await accept);
        }

        public async ValueTask DisposeAsync()
        {
            await ClientStream.DisposeAsync();
            await ServerStream.DisposeAsync();
            Client.Dispose();
            Server.Dispose();
        }
    }
}

/// <summary>Tests for the connection limits the original implementation never enforced.</summary>
public sealed class ProxyConnectionTrackerTests
{
    [Fact]
    public void GlobalLimit_RefusesOnceItIsReached()
    {
        ProxyConnectionTracker tracker = new(maxConnections: 2, maxConnectionsPerClient: 0);
        IPAddress client = IPAddress.Loopback;

        Assert.True(tracker.TryAdmit(client, out _));
        Assert.True(tracker.TryAdmit(client, out _));
        Assert.False(tracker.TryAdmit(client, out string? reason));
        Assert.Contains("limit of 2", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void PerClientLimit_IsIndependentPerAddress()
    {
        ProxyConnectionTracker tracker = new(maxConnections: 0, maxConnectionsPerClient: 1);

        Assert.True(tracker.TryAdmit(IPAddress.Parse("10.0.0.1"), out _));
        Assert.False(tracker.TryAdmit(IPAddress.Parse("10.0.0.1"), out _));
        Assert.True(tracker.TryAdmit(IPAddress.Parse("10.0.0.2"), out _));
    }

    [Fact]
    public void Release_FreesTheSlotAgain()
    {
        ProxyConnectionTracker tracker = new(maxConnections: 1, maxConnectionsPerClient: 1);
        IPEndPoint endPoint = new(IPAddress.Loopback, 5000);

        Assert.True(tracker.TryAdmit(endPoint.Address, out _));
        ProxyConnection connection = tracker.Register("listener", ProxyProtocol.Socks5, endPoint);

        Assert.False(tracker.TryAdmit(endPoint.Address, out _));

        tracker.Release(connection);

        Assert.True(tracker.TryAdmit(endPoint.Address, out _));
        Assert.Equal(0, tracker.Count - 1);
    }

    [Fact]
    public void ZeroMeansUnlimited()
    {
        ProxyConnectionTracker tracker = new(maxConnections: 0, maxConnectionsPerClient: 0);

        for (int i = 0; i < 1000; i++)
        {
            Assert.True(tracker.TryAdmit(IPAddress.Loopback, out _));
        }
    }

    [Fact]
    public void Register_AssignsIncreasingIdsAndTracksTotals()
    {
        ProxyConnectionTracker tracker = new(maxConnections: 0, maxConnectionsPerClient: 0);
        IPEndPoint endPoint = new(IPAddress.Loopback, 5000);

        ProxyConnection first = tracker.Register("a", ProxyProtocol.Http, endPoint);
        ProxyConnection second = tracker.Register("a", ProxyProtocol.Http, endPoint);

        Assert.True(second.Id > first.Id);
        Assert.Equal(2, tracker.TotalAccepted);
        Assert.Equal(2, tracker.Active.Count);
    }
}

/// <summary>Tests for the line-oriented buffered stream the HTTP handler reads through.</summary>
public sealed class BufferedReadStreamTests
{
    [Fact]
    public async Task ReadLine_SplitsOnCrLfAndStripsTheTerminator()
    {
        await using BufferedReadStream stream = Wrap("GET / HTTP/1.1\r\nHost: a\r\n\r\nbody");

        Assert.Equal("GET / HTTP/1.1", await stream.ReadLineAsync());
        Assert.Equal("Host: a", await stream.ReadLineAsync());
        Assert.Equal("", await stream.ReadLineAsync());
    }

    [Fact]
    public async Task ReadLine_AlsoAcceptsBareLf()
    {
        await using BufferedReadStream stream = Wrap("one\ntwo\n");

        Assert.Equal("one", await stream.ReadLineAsync());
        Assert.Equal("two", await stream.ReadLineAsync());
    }

    [Fact]
    public async Task ReadLine_ReturnsNullAtEndOfStream()
    {
        await using BufferedReadStream stream = Wrap("");

        Assert.Null(await stream.ReadLineAsync());
    }

    [Fact]
    public async Task BufferedBytes_RemainReadableAfterTheHeaderBlock()
    {
        // Whatever arrived alongside the head must still be there for the relay.
        await using BufferedReadStream stream = Wrap("head\r\n\r\nthe body bytes");

        Assert.Equal("head", await stream.ReadLineAsync());
        Assert.Equal("", await stream.ReadLineAsync());

        byte[] rest = new byte[14];
        await stream.ReadExactlyAsync(rest);

        Assert.Equal("the body bytes", Encoding.UTF8.GetString(rest));
    }

    [Fact]
    public async Task OverlongLine_IsRejectedRatherThanGrowingTheBuffer()
    {
        await using BufferedReadStream stream = new(
            new MemoryStream(Encoding.ASCII.GetBytes(new string('x', 2000))),
            bufferSize: 256);

        await Assert.ThrowsAsync<InvalidDataException>(async () => await stream.ReadLineAsync());
    }

    private static BufferedReadStream Wrap(string content) =>
        new(new MemoryStream(Encoding.ASCII.GetBytes(content)));
}
