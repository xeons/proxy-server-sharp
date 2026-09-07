using System.Net.Sockets;
using ProxyServerSharp.Net;

namespace ProxyServerSharp.Protocol.Socks;

/// <summary>SOCKS5 request commands (RFC 1928 §4).</summary>
public enum Socks5Command : byte
{
    /// <summary>Open a TCP connection to the destination.</summary>
    Connect = 0x01,

    /// <summary>Listen for one inbound TCP connection on the proxy's behalf.</summary>
    Bind = 0x02,

    /// <summary>Open a UDP relay for the client.</summary>
    UdpAssociate = 0x03,
}

/// <summary>SOCKS5 address types (RFC 1928 §5).</summary>
public enum Socks5AddressType : byte
{
    /// <summary>A four-byte IPv4 address.</summary>
    IPv4 = 0x01,

    /// <summary>A length-prefixed host name.</summary>
    DomainName = 0x03,

    /// <summary>A sixteen-byte IPv6 address.</summary>
    IPv6 = 0x04,
}

/// <summary>SOCKS5 reply codes (RFC 1928 §6).</summary>
public enum Socks5Reply : byte
{
    /// <summary>The request succeeded.</summary>
    Succeeded = 0x00,

    /// <summary>An unspecified server failure.</summary>
    GeneralFailure = 0x01,

    /// <summary>The ruleset forbids the destination.</summary>
    NotAllowed = 0x02,

    /// <summary>The destination network is unreachable.</summary>
    NetworkUnreachable = 0x03,

    /// <summary>The destination host is unreachable.</summary>
    HostUnreachable = 0x04,

    /// <summary>The destination refused the connection.</summary>
    ConnectionRefused = 0x05,

    /// <summary>The TTL expired.</summary>
    TtlExpired = 0x06,

    /// <summary>The command is not supported by this listener.</summary>
    CommandNotSupported = 0x07,

    /// <summary>The address type is not supported by this listener.</summary>
    AddressTypeNotSupported = 0x08,
}

/// <summary>SOCKS4 reply codes.</summary>
public enum Socks4Reply : byte
{
    /// <summary>Request granted.</summary>
    Granted = 0x5A,

    /// <summary>Request rejected or failed.</summary>
    Rejected = 0x5B,

    /// <summary>Rejected because the identd lookup failed.</summary>
    IdentdUnreachable = 0x5C,

    /// <summary>Rejected because the reported user id did not match.</summary>
    IdentdMismatch = 0x5D,
}

/// <summary>Shared SOCKS wire constants and mappings.</summary>
public static class SocksConstants
{
    /// <summary>The SOCKS4 version byte.</summary>
    public const byte Version4 = 0x04;

    /// <summary>The SOCKS5 version byte.</summary>
    public const byte Version5 = 0x05;

    /// <summary>The method identifier meaning "no acceptable methods" (RFC 1928 §3).</summary>
    public const byte NoAcceptableMethods = 0xFF;

    /// <summary>Maps an outbound failure onto its SOCKS5 reply code.</summary>
    public static Socks5Reply ToSocks5Reply(DestinationFailure failure) => failure switch
    {
        DestinationFailure.NotAllowed => Socks5Reply.NotAllowed,
        DestinationFailure.HostUnreachable => Socks5Reply.HostUnreachable,
        DestinationFailure.NetworkUnreachable => Socks5Reply.NetworkUnreachable,
        DestinationFailure.ConnectionRefused => Socks5Reply.ConnectionRefused,
        DestinationFailure.TimedOut => Socks5Reply.TtlExpired,
        DestinationFailure.AddressTypeNotSupported => Socks5Reply.AddressTypeNotSupported,
        _ => Socks5Reply.GeneralFailure,
    };

    /// <summary>Maps a socket error onto its SOCKS5 reply code.</summary>
    public static Socks5Reply ToSocks5Reply(SocketError error) =>
        ToSocks5Reply(SocketRemoteConnector.Map(error));
}
