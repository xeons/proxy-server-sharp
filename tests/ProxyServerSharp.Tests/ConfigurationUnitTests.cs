using System.Net;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Net;
using ProxyServerSharp.Server;

namespace ProxyServerSharp.Tests;

/// <summary>Unit tests for the client address allow/deny list.</summary>
public sealed class AccessControlListTests
{
    [Fact]
    public void EmptyAllowList_PermitsEveryAddress()
    {
        AccessControlList acl = AccessControlList.Parse([], []);

        Assert.True(acl.IsAllowed(IPAddress.Parse("8.8.8.8")));
    }

    [Fact]
    public void AllowList_PermitsOnlyListedBlocks()
    {
        AccessControlList acl = AccessControlList.Parse(["192.168.1.0/24"], []);

        Assert.True(acl.IsAllowed(IPAddress.Parse("192.168.1.50")));
        Assert.False(acl.IsAllowed(IPAddress.Parse("192.168.2.50")));
    }

    [Fact]
    public void DenyList_OverridesTheAllowList()
    {
        AccessControlList acl = AccessControlList.Parse(["10.0.0.0/8"], ["10.1.0.0/16"]);

        Assert.True(acl.IsAllowed(IPAddress.Parse("10.2.0.1")));
        Assert.False(acl.IsAllowed(IPAddress.Parse("10.1.0.1")));
    }

    [Fact]
    public void BareAddress_IsTreatedAsASingleHost()
    {
        AccessControlList acl = AccessControlList.Parse(["127.0.0.1"], []);

        Assert.True(acl.IsAllowed(IPAddress.Loopback));
        Assert.False(acl.IsAllowed(IPAddress.Parse("127.0.0.2")));
    }

    [Fact]
    public void Ipv4MappedAddress_MatchesIpv4Rules()
    {
        // A dual-mode listener reports IPv4 clients as ::ffff:a.b.c.d, which must still match.
        AccessControlList acl = AccessControlList.Parse(["192.168.1.0/24"], []);

        Assert.True(acl.IsAllowed(IPAddress.Parse("::ffff:192.168.1.50")));
        Assert.False(acl.IsAllowed(IPAddress.Parse("::ffff:192.168.2.50")));
    }

    [Fact]
    public void Ipv6Blocks_AreMatchedIndependentlyOfIpv4()
    {
        AccessControlList acl = AccessControlList.Parse(["2001:db8::/32"], []);

        Assert.True(acl.IsAllowed(IPAddress.Parse("2001:db8::1")));
        Assert.False(acl.IsAllowed(IPAddress.Parse("2001:dba::1")));
        Assert.False(acl.IsAllowed(IPAddress.Parse("192.168.1.1")));
    }

    [Fact]
    public void MalformedEntry_IsRejectedAtParseTime()
    {
        Assert.ThrowsAny<FormatException>(() => AccessControlList.Parse(["not-an-address"], []));
    }
}

/// <summary>Unit tests for the destination policy.</summary>
public sealed class DestinationPolicyTests
{
    [Fact]
    public void BlockLoopback_RefusesLoopbackDestinations()
    {
        DestinationPolicy policy = new(new DestinationPolicyOptions { BlockLoopback = true });

        Assert.Equal(DestinationRejection.LoopbackBlocked, policy.Evaluate(IPAddress.Loopback, 80));
        Assert.Equal(DestinationRejection.LoopbackBlocked, policy.Evaluate(IPAddress.Parse("127.5.5.5"), 80));
        Assert.Equal(DestinationRejection.LoopbackBlocked, policy.Evaluate(IPAddress.IPv6Loopback, 80));
    }

    [Fact]
    public void BlockLinkLocal_RefusesTheCloudMetadataAddress()
    {
        DestinationPolicy policy = new(new DestinationPolicyOptions { BlockLinkLocal = true });

        Assert.Equal(DestinationRejection.LinkLocalBlocked, policy.Evaluate(IPAddress.Parse("169.254.169.254"), 80));
    }

    [Fact]
    public void BlockPrivateNetworks_RefusesRfc1918Ranges()
    {
        DestinationPolicy policy = new(new DestinationPolicyOptions
        {
            BlockLoopback = false,
            BlockLinkLocal = false,
            BlockPrivateNetworks = true,
        });

        Assert.Equal(DestinationRejection.PrivateNetworkBlocked, policy.Evaluate(IPAddress.Parse("10.1.2.3"), 80));
        Assert.Equal(DestinationRejection.PrivateNetworkBlocked, policy.Evaluate(IPAddress.Parse("192.168.1.1"), 80));
        Assert.Equal(DestinationRejection.PrivateNetworkBlocked, policy.Evaluate(IPAddress.Parse("172.16.0.1"), 80));
        Assert.Equal(DestinationRejection.None, policy.Evaluate(IPAddress.Parse("8.8.8.8"), 80));
    }

    [Fact]
    public void DeniedPorts_AreRefused()
    {
        DestinationPolicyOptions options = new() { BlockLoopback = false, BlockLinkLocal = false };
        options.DeniedPorts.Add(25);

        DestinationPolicy policy = new(options);

        Assert.Equal(DestinationRejection.PortBlocked, policy.Evaluate(IPAddress.Parse("8.8.8.8"), 25));
        Assert.Equal(DestinationRejection.None, policy.Evaluate(IPAddress.Parse("8.8.8.8"), 443));
    }

    [Fact]
    public void AllowedPorts_RestrictToTheListedSet()
    {
        DestinationPolicyOptions options = new() { BlockLoopback = false, BlockLinkLocal = false };
        options.AllowedPorts.Add(443);

        DestinationPolicy policy = new(options);

        Assert.Equal(DestinationRejection.None, policy.Evaluate(IPAddress.Parse("8.8.8.8"), 443));
        Assert.Equal(DestinationRejection.PortBlocked, policy.Evaluate(IPAddress.Parse("8.8.8.8"), 80));
    }
}

/// <summary>Unit tests for destination parsing.</summary>
public sealed class ProxyDestinationTests
{
    [Theory]
    [InlineData("example.com:8080", "example.com", 8080)]
    [InlineData("example.com", "example.com", 443)]
    [InlineData("[2001:db8::1]:8080", "2001:db8::1", 8080)]
    [InlineData("[2001:db8::1]", "2001:db8::1", 443)]
    [InlineData("2001:db8::1", "2001:db8::1", 443)]
    [InlineData("192.168.1.1:1234", "192.168.1.1", 1234)]
    public void TryParseAuthority_HandlesTheUsualForms(string authority, string host, int port)
    {
        Assert.True(ProxyDestination.TryParseAuthority(authority, 443, out ProxyDestination? destination));
        Assert.Equal(host, destination!.Host);
        Assert.Equal(port, destination.Port);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("example.com:notaport")]
    [InlineData("[2001:db8::1")]
    [InlineData("example.com:99999")]
    [InlineData("example.com:0")]
    public void TryParseAuthority_RejectsMalformedInput(string authority)
    {
        Assert.False(ProxyDestination.TryParseAuthority(authority, 443, out _));
    }

    [Fact]
    public void FromHost_CollapsesAnAddressLiteralToAnAddress()
    {
        ProxyDestination destination = ProxyDestination.FromHost("192.168.1.1", 80);

        Assert.False(destination.RequiresResolution);
        Assert.Equal(IPAddress.Parse("192.168.1.1"), destination.Address);
    }

    [Fact]
    public void FromHost_KeepsANameForResolution()
    {
        ProxyDestination destination = ProxyDestination.FromHost("example.com", 80);

        Assert.True(destination.RequiresResolution);
        Assert.Null(destination.Address);
    }

    [Fact]
    public void ToString_BracketsIpv6Literals()
    {
        Assert.Equal("[2001:db8::1]:443", ProxyDestination.FromHost("2001:db8::1", 443).ToString());
        Assert.Equal("example.com:443", ProxyDestination.FromHost("example.com", 443).ToString());
    }

    [Fact]
    public void PortZero_IsAllowedForBindAndUdpAssociate()
    {
        // SOCKS5 BIND and UDP ASSOCIATE send 0.0.0.0:0 when the peer is not yet known.
        ProxyDestination destination = ProxyDestination.FromAddress(IPAddress.Any, 0);

        Assert.Equal(0, destination.Port);
    }
}

/// <summary>Unit tests for listener configuration validation.</summary>
public sealed class ProxyHandlerFactoryTests
{
    [Theory]
    [InlineData(ProxyProtocol.Socks4, AuthenticationMethod.Basic)]
    [InlineData(ProxyProtocol.Socks4, AuthenticationMethod.UsernamePassword)]
    [InlineData(ProxyProtocol.Socks5, AuthenticationMethod.Digest)]
    [InlineData(ProxyProtocol.Socks5, AuthenticationMethod.UserId)]
    [InlineData(ProxyProtocol.Http, AuthenticationMethod.UserId)]
    [InlineData(ProxyProtocol.Http, AuthenticationMethod.UsernamePassword)]
    public void Validate_RejectsMethodsTheProtocolCannotExpress(
        ProxyProtocol protocol,
        AuthenticationMethod method)
    {
        ListenerOptions listener = new() { Name = "x", Protocol = protocol, Port = 1080 };
        listener.Authentication.Add(method);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => ProxyHandlerFactory.Validate(listener));

        Assert.Contains(method.ToString(), exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(ProxyProtocol.Socks4, AuthenticationMethod.UserId)]
    [InlineData(ProxyProtocol.Socks5, AuthenticationMethod.UsernamePassword)]
    [InlineData(ProxyProtocol.Http, AuthenticationMethod.Digest)]
    [InlineData(ProxyProtocol.Http, AuthenticationMethod.Negotiate)]
    public void Validate_AcceptsMethodsTheProtocolSupports(ProxyProtocol protocol, AuthenticationMethod method)
    {
        ListenerOptions listener = new() { Name = "x", Protocol = protocol, Port = 1080 };
        listener.Authentication.Add(method);

        ProxyHandlerFactory.Validate(listener);
    }

    [Fact]
    public void Validate_RejectsTlsOnASocksListener()
    {
        ListenerOptions listener = new() { Name = "x", Protocol = ProxyProtocol.Socks5, Port = 1080 };
        listener.Tls.Enabled = true;

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => ProxyHandlerFactory.Validate(listener));

        Assert.Contains("TLS", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsAnOutOfRangePort()
    {
        ListenerOptions listener = new() { Name = "x", Protocol = ProxyProtocol.Socks5, Port = 70000 };

        Assert.Throws<InvalidOperationException>(() => ProxyHandlerFactory.Validate(listener));
    }

    [Fact]
    public void EffectiveAuthentication_DefaultsToAnonymous()
    {
        ListenerOptions listener = new() { Name = "x", Protocol = ProxyProtocol.Socks5, Port = 1080 };

        Assert.Equal([AuthenticationMethod.Anonymous], listener.EffectiveAuthentication);
    }
}
