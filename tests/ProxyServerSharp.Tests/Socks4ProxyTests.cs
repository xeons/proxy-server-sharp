using ProxyServerSharp.Authentication;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Tests;

/// <summary>End-to-end SOCKS4 and SOCKS4a tests.</summary>
public sealed class Socks4ProxyTests
{
    private const byte Granted = 0x5A;
    private const byte Rejected = 0x5B;
    private const byte IdentdMismatch = 0x5D;

    [Fact]
    public async Task AnonymousListener_RelaysTraffic()
    {
        await using EchoServer origin = EchoServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks4, AuthenticationMethod.Anonymous));

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(Granted, await client.Socks4ConnectAsync(origin.EndPoint, "anyone"));
        Assert.Equal("socks4 payload", await client.RoundTripAsync("socks4 payload"));
    }

    [Fact]
    public async Task UserId_AcceptsKnownAccount()
    {
        await using EchoServer origin = EchoServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks4, AuthenticationMethod.UserId),
            [Account("alice")]);

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(Granted, await client.Socks4ConnectAsync(origin.EndPoint, "alice"));
        Assert.Equal("hello", await client.RoundTripAsync("hello"));
    }

    [Fact]
    public async Task UserId_RejectsUnknownAccount()
    {
        await using EchoServer origin = EchoServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks4, AuthenticationMethod.UserId),
            [Account("alice")]);

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(IdentdMismatch, await client.Socks4ConnectAsync(origin.EndPoint, "mallory"));
    }

    [Fact]
    public async Task UserId_RejectsEmptyUserId()
    {
        await using EchoServer origin = EchoServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks4, AuthenticationMethod.UserId),
            [Account("alice")]);

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(IdentdMismatch, await client.Socks4ConnectAsync(origin.EndPoint, ""));
    }

    [Fact]
    public async Task Socks4a_ResolvesHostName()
    {
        await using EchoServer origin = EchoServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks4, AuthenticationMethod.Anonymous));

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(Granted, await client.Socks4aConnectAsync("localhost", origin.EndPoint.Port, "anyone"));
        Assert.Equal("via 4a", await client.RoundTripAsync("via 4a"));
    }

    [Fact]
    public async Task UnreachableDestination_IsRejected()
    {
        int deadPort = ProxyServerFixture.FreePort();

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Socks4, AuthenticationMethod.Anonymous));

        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        byte reply = await client.Socks4ConnectAsync(
            new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, deadPort),
            "anyone");

        Assert.Equal(Rejected, reply);
    }

    private static ProxyUserOptions Account(string username) => new()
    {
        Username = username,
        PasswordHash = PasswordHasher.Hash("unused", iterations: 1000),
    };
}
