namespace ProxyServerSharp.Configuration;

/// <summary>Root configuration for a <see cref="Server.ProxyServerHost"/>.</summary>
public sealed class ProxyServerOptions
{
    /// <summary>The configuration section this binds to by convention.</summary>
    public const string SectionName = "ProxyServer";

    /// <summary>The sockets to bind.</summary>
    public IList<ListenerOptions> Listeners { get; init; } = [];

    /// <summary>The accounts credential schemes are checked against.</summary>
    public IList<ProxyUserOptions> Users { get; init; } = [];

    /// <summary>Relay buffer size, per direction, in bytes.</summary>
    public int BufferSize { get; set; } = 32 * 1024;

    /// <summary>How long a client has to finish the handshake before it is dropped.</summary>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>How long to wait for the outbound TCP connection to the destination.</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>How long an established tunnel may sit with no traffic in either direction.</summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Maximum simultaneous client connections across all listeners. Zero means unlimited.</summary>
    public int MaxConnections { get; set; } = 512;

    /// <summary>Maximum simultaneous connections from any single client address. Zero means unlimited.</summary>
    public int MaxConnectionsPerClient { get; set; } = 64;

    /// <summary>How long a SOCKS5 <c>BIND</c> listener waits for the inbound connection.</summary>
    public TimeSpan BindTimeout { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>How long an idle SOCKS5 UDP association is kept alive.</summary>
    public TimeSpan UdpAssociationTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Whether destination host names are resolved to IPv6 as well as IPv4.</summary>
    public bool EnableIPv6 { get; set; } = true;

    /// <summary>
    /// The largest request body buffered for Digest <c>qop=auth-int</c>. A larger body is
    /// refused rather than held in memory.
    /// </summary>
    public int MaxBufferedRequestBody { get; set; } = 256 * 1024;

    /// <summary>How long a Digest nonce stays valid before the client must re-handshake.</summary>
    public TimeSpan DigestNonceLifetime { get; set; } = TimeSpan.FromMinutes(5);
}
