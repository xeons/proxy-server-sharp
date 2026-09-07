using System.ComponentModel.DataAnnotations;
using ProxyServerSharp.Authentication.Socks;

namespace ProxyServerSharp.Configuration;

/// <summary>One bound socket: a protocol, an endpoint, and the credentials it accepts.</summary>
public sealed class ListenerOptions
{
    /// <summary>A human-readable name used in logs and in per-user listener grants.</summary>
    public string Name { get; set; } = "";

    /// <summary>Whether the host should bind this listener at startup.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>The proxy protocol spoken on this socket.</summary>
    public ProxyProtocol Protocol { get; set; } = ProxyProtocol.Socks5;

    /// <summary>
    /// The local address to bind. Defaults to loopback so a fresh install is never
    /// an open relay; use <c>0.0.0.0</c> or <c>::</c> to accept remote clients.
    /// </summary>
    public string Address { get; set; } = "127.0.0.1";

    /// <summary>The local TCP port to bind.</summary>
    [Range(1, 65535)]
    public int Port { get; set; } = 1080;

    /// <summary>
    /// The credential schemes offered, in configuration order. A client that satisfies any
    /// one of them is authenticated; listing <see cref="AuthenticationMethod.Anonymous"/>
    /// makes the listener open.
    /// </summary>
    public IList<AuthenticationMethod> Authentication { get; init; } = [];

    /// <summary>The protection space advertised for HTTP Basic and Digest challenges.</summary>
    public string Realm { get; set; } = "ProxyServerSharp";

    /// <summary>
    /// The Digest algorithms offered, strongest first. One challenge is sent per algorithm and
    /// the client picks; the default keeps MD5 in the list because Windows SSPI-backed clients
    /// still implement nothing else. Valid values are <c>SHA-256</c>, <c>SHA-512-256</c> and <c>MD5</c>.
    /// </summary>
    public IList<string> DigestAlgorithms { get; init; } = [];

    /// <summary>
    /// Whether HTTP Digest offers <c>qop=auth-int</c>, whose response hash covers the request
    /// body. Off by default: verifying it means buffering the body of an as-yet unauthenticated
    /// request, and essentially no client implements it.
    /// </summary>
    public bool AllowDigestAuthInt { get; set; }

    /// <summary>Which client addresses may connect at all.</summary>
    public AccessControlOptions Access { get; init; } = new();

    /// <summary>Which destinations authenticated clients may reach.</summary>
    public DestinationPolicyOptions Destinations { get; init; } = new();

    /// <summary>Server-side TLS, turning an HTTP listener into an HTTPS proxy.</summary>
    public TlsOptions Tls { get; init; } = new();

    /// <summary>
    /// The strongest per-message protection a SOCKS5 GSSAPI client may negotiate (RFC 1961 §4.3).
    /// The client proposes a level and the server lowers it to this cap;
    /// <c>None</c> authenticates with GSSAPI but leaves the relayed traffic unencapsulated,
    /// which is what most clients ask for.
    /// </summary>
    public GssapiProtectionLevel GssapiProtection { get; set; } = GssapiProtectionLevel.Confidentiality;

    /// <summary>Whether the SOCKS4 and SOCKS5 <c>BIND</c> command is honoured. Off by default.</summary>
    public bool AllowBind { get; set; }

    /// <summary>Whether the SOCKS5 <c>UDP ASSOCIATE</c> command is honoured. Off by default.</summary>
    public bool AllowUdpAssociate { get; set; }

    /// <summary>Whether plain HTTP absolute-URI requests are forwarded, in addition to <c>CONNECT</c>.</summary>
    public bool AllowPlainHttpForwarding { get; set; } = true;

    /// <summary>Returns the effective methods, defaulting to anonymous when nothing is configured.</summary>
    public IReadOnlyList<AuthenticationMethod> EffectiveAuthentication =>
        Authentication.Count == 0 ? [AuthenticationMethod.Anonymous] : [.. Authentication];
}
