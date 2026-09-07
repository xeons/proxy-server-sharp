namespace ProxyServerSharp.Configuration;

/// <summary>
/// A credential scheme a listener may offer. Not every method is valid for every
/// <see cref="ProxyProtocol"/>; see <see cref="AuthenticationMethodExtensions.IsValidFor"/>.
/// </summary>
public enum AuthenticationMethod
{
    /// <summary>Accept every client without asking for credentials.</summary>
    Anonymous,

    /// <summary>SOCKS4 <c>USERID</c>, matched against the user store (RFC-less, ident style).</summary>
    UserId,

    /// <summary>SOCKS5 username/password sub-negotiation (RFC 1929).</summary>
    UsernamePassword,

    /// <summary>HTTP <c>Basic</c> proxy authentication (RFC 7617).</summary>
    Basic,

    /// <summary>HTTP <c>Digest</c> proxy authentication (RFC 7616).</summary>
    Digest,

    /// <summary>HTTP <c>Bearer</c> proxy authentication with a shared token (RFC 6750 style).</summary>
    Bearer,

    /// <summary>HTTP <c>Negotiate</c>/NTLM using the host's SSPI or GSSAPI stack.</summary>
    Negotiate,
}

/// <summary>Protocol compatibility rules for <see cref="AuthenticationMethod"/>.</summary>
public static class AuthenticationMethodExtensions
{
    /// <summary>Returns <see langword="true"/> when <paramref name="method"/> can be offered by <paramref name="protocol"/>.</summary>
    public static bool IsValidFor(this AuthenticationMethod method, ProxyProtocol protocol) => protocol switch
    {
        ProxyProtocol.Socks4 => method is AuthenticationMethod.Anonymous or AuthenticationMethod.UserId,
        ProxyProtocol.Socks5 => method is AuthenticationMethod.Anonymous or AuthenticationMethod.UsernamePassword,
        ProxyProtocol.Http => method is AuthenticationMethod.Anonymous
            or AuthenticationMethod.Basic
            or AuthenticationMethod.Digest
            or AuthenticationMethod.Bearer
            or AuthenticationMethod.Negotiate,
        _ => false,
    };

    /// <summary>The methods <paramref name="protocol"/> understands, strongest first.</summary>
    public static IReadOnlyList<AuthenticationMethod> SupportedBy(ProxyProtocol protocol) => protocol switch
    {
        ProxyProtocol.Socks4 => [AuthenticationMethod.UserId, AuthenticationMethod.Anonymous],
        ProxyProtocol.Socks5 => [AuthenticationMethod.UsernamePassword, AuthenticationMethod.Anonymous],
        ProxyProtocol.Http =>
        [
            AuthenticationMethod.Negotiate,
            AuthenticationMethod.Digest,
            AuthenticationMethod.Bearer,
            AuthenticationMethod.Basic,
            AuthenticationMethod.Anonymous,
        ],
        _ => [],
    };
}
