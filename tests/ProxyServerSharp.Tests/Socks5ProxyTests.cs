using System.Net;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Tests;

/// <summary>End-to-end SOCKS5 tests over real loopback sockets.</summary>
public sealed class Socks5ProxyTests
{
    private const byte NoAuth = 0x00;
    private const byte UsernamePassword = 0x02;
    private const byte NoAcceptableMethods = 0xFF;
    private const byte Connect = 0x01;
    private const byte Bind = 0x02;
    private const byte UdpAssociate = 0x03;

    [Fact]
    public async Task AnonymousListener_RelaysTrafficBothWays()
    {
        await using EchoServer origin = EchoServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.Anonymous));

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(NoAuth, await client.GreetAsync(NoAuth));

        (byte reply, _) = await client.RequestAsync(Connect, origin.EndPoint);
        Assert.Equal(0x00, reply);

        Assert.Equal("round trip", await client.RoundTripAsync("round trip"));
    }

    [Fact]
    public async Task UsernamePassword_AcceptsCorrectCredentials()
    {
        await using EchoServer origin = EchoServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.UsernamePassword),
            [Account("alice", "hunter2")]);

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(UsernamePassword, await client.GreetAsync(NoAuth, UsernamePassword));
        Assert.Equal(0x00, await client.AuthenticateAsync("alice", "hunter2"));

        (byte reply, _) = await client.RequestAsync(Connect, origin.EndPoint);
        Assert.Equal(0x00, reply);
        Assert.Equal("payload", await client.RoundTripAsync("payload"));
    }

    [Fact]
    public async Task UsernamePassword_RejectsWrongPassword()
    {
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.UsernamePassword),
            [Account("alice", "hunter2")]);

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(UsernamePassword, await client.GreetAsync(UsernamePassword));
        Assert.Equal(0x01, await client.AuthenticateAsync("alice", "wrong"));
    }

    [Fact]
    public async Task UsernamePassword_RejectsUnknownUser()
    {
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.UsernamePassword),
            [Account("alice", "hunter2")]);

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(UsernamePassword, await client.GreetAsync(UsernamePassword));
        Assert.Equal(0x01, await client.AuthenticateAsync("mallory", "hunter2"));
    }

    [Fact]
    public async Task ServerPreferenceWins_WhenClientOffersBothMethods()
    {
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(
                ProxyProtocol.Socks5,
                AuthenticationMethod.Anonymous,
                AuthenticationMethod.UsernamePassword),
            [Account("alice", "hunter2")]);

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        // The client lists no-auth first, but the listener offers both and prefers the stronger.
        Assert.Equal(UsernamePassword, await client.GreetAsync(NoAuth, UsernamePassword));
    }

    [Fact]
    public async Task NoAcceptableMethods_WhenClientCannotAuthenticate()
    {
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.UsernamePassword),
            [Account("alice", "hunter2")]);

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(NoAcceptableMethods, await client.GreetAsync(NoAuth));
    }

    [Fact]
    public async Task ConnectByHostName_ResolvesAndRelays()
    {
        await using EchoServer origin = EchoServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.Anonymous));

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);
        await client.GreetAsync(NoAuth);

        (byte reply, _) = await client.RequestAsync(Connect, "localhost", origin.EndPoint.Port);

        Assert.Equal(0x00, reply);
        Assert.Equal("by name", await client.RoundTripAsync("by name"));
    }

    [Fact]
    public async Task ConnectionRefused_MapsToReplyCode5()
    {
        int deadPort = ProxyServerFixture.FreePort();

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.Anonymous));

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);
        await client.GreetAsync(NoAuth);

        (byte reply, _) = await client.RequestAsync(Connect, new IPEndPoint(IPAddress.Loopback, deadPort));

        Assert.Equal(0x05, reply);
    }

    [Fact]
    public async Task BlockedDestination_MapsToReplyCode2()
    {
        await using EchoServer origin = EchoServer.Start();

        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.Anonymous);
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            listener,
            configure: _ => listener.Destinations.BlockLoopback = true);

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);
        await client.GreetAsync(NoAuth);

        (byte reply, _) = await client.RequestAsync(Connect, origin.EndPoint);

        Assert.Equal(0x02, reply);
    }

    [Fact]
    public async Task DisabledCommand_MapsToReplyCode7()
    {
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.Anonymous));

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);
        await client.GreetAsync(NoAuth);

        // AllowBind and AllowUdpAssociate both default to false.
        (byte reply, _) = await client.RequestAsync(Bind, new IPEndPoint(IPAddress.Loopback, 9));

        Assert.Equal(0x07, reply);
    }

    [Fact]
    public async Task Bind_AcceptsAnInboundConnectionAndRelays()
    {
        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.Anonymous);
        listener.AllowBind = true;

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(listener);
        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);
        await client.GreetAsync(NoAuth);

        // 0.0.0.0 means "I do not know which peer will connect", which skips the peer check.
        (byte first, IPEndPoint bound) = await client.RequestAsync(Bind, new IPEndPoint(IPAddress.Any, 0));
        Assert.Equal(0x00, first);
        Assert.NotEqual(0, bound.Port);

        using System.Net.Sockets.Socket peer = new(
            System.Net.Sockets.AddressFamily.InterNetwork,
            System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Tcp);

        await peer.ConnectAsync(new IPEndPoint(IPAddress.Loopback, bound.Port));

        (byte second, _) = await client.ReadReplyAsync();
        Assert.Equal(0x00, second);

        // The tunnel now joins the SOCKS client to the peer that connected.
        await peer.SendAsync("from peer"u8.ToArray());

        byte[] received = new byte[9];
        await client.Stream.ReadExactlyAsync(received);
        Assert.Equal("from peer", System.Text.Encoding.UTF8.GetString(received));
    }

    [Fact]
    public async Task UdpAssociate_RelaysDatagramsBothWays()
    {
        using System.Net.Sockets.UdpClient origin = new(new IPEndPoint(IPAddress.Loopback, 0));
        IPEndPoint originEndPoint = (IPEndPoint)origin.Client.LocalEndPoint!;

        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.Anonymous);
        listener.AllowUdpAssociate = true;

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(listener);
        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);
        await client.GreetAsync(NoAuth);

        (byte reply, IPEndPoint relay) = await client.RequestAsync(UdpAssociate, new IPEndPoint(IPAddress.Any, 0));
        Assert.Equal(0x00, reply);

        using System.Net.Sockets.UdpClient clientUdp = new(new IPEndPoint(IPAddress.Loopback, 0));
        IPEndPoint relayEndPoint = new(IPAddress.Loopback, relay.Port);

        // RSV(2) | FRAG | ATYP | DST.ADDR | DST.PORT | DATA
        byte[] payload = "datagram"u8.ToArray();
        byte[] datagram = new byte[10 + payload.Length];
        datagram[3] = 0x01; // IPv4
        originEndPoint.Address.GetAddressBytes().CopyTo(datagram, 4);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(8), (ushort)originEndPoint.Port);
        payload.CopyTo(datagram, 10);

        await clientUdp.SendAsync(datagram, relayEndPoint);

        System.Net.Sockets.UdpReceiveResult atOrigin = await origin.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal("datagram", System.Text.Encoding.UTF8.GetString(atOrigin.Buffer));

        // The reply comes back wrapped in the same header shape.
        await origin.SendAsync("answer"u8.ToArray(), atOrigin.RemoteEndPoint);

        System.Net.Sockets.UdpReceiveResult atClient = await clientUdp.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(0x01, atClient.Buffer[3]);
        Assert.Equal("answer", System.Text.Encoding.UTF8.GetString(atClient.Buffer.AsSpan(10).ToArray()));
    }

    [Fact]
    public async Task PerListenerGrant_RefusesAccountOnAnotherListener()
    {
        ProxyUserOptions account = Account("alice", "hunter2");
        account.Listeners.Add("some-other-listener");

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.UsernamePassword),
            [account]);

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);
        await client.GreetAsync(UsernamePassword);

        Assert.Equal(0x01, await client.AuthenticateAsync("alice", "hunter2"));
    }

    private static ProxyUserOptions Account(string username, string password) => new()
    {
        Username = username,
        PasswordHash = PasswordHasher.Hash(password, iterations: 1000),
    };
}
