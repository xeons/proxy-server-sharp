namespace ProxyServerSharp.Configuration;

/// <summary>The wire protocol a listener speaks to its clients.</summary>
public enum ProxyProtocol
{
    /// <summary>SOCKS4 and the SOCKS4a hostname extension.</summary>
    Socks4,

    /// <summary>SOCKS5 as defined by RFC 1928.</summary>
    Socks5,

    /// <summary>An HTTP proxy: absolute-URI forwarding plus <c>CONNECT</c> tunnelling.</summary>
    Http,
}
