using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication.Socks;

/// <summary>
/// One SOCKS5 authentication method (RFC 1928 §3): a method byte the server can advertise
/// and the sub-negotiation that follows once the client selects it.
/// </summary>
public interface ISocks5Authenticator
{
    /// <summary>The configured method this implements.</summary>
    AuthenticationMethod Method { get; }

    /// <summary>The RFC 1928 method identifier sent in the method-selection reply.</summary>
    byte MethodCode { get; }

    /// <summary>
    /// Runs the method-specific sub-negotiation on <paramref name="stream"/>, which is positioned
    /// immediately after the server's method-selection reply.
    /// </summary>
    /// <param name="stream">The client connection.</param>
    /// <param name="context">The listener and client the connection arrived on.</param>
    /// <param name="cancellationToken">Cancels a stalled handshake.</param>
    ValueTask<AuthenticationResult> AuthenticateAsync(
        Stream stream,
        UserStoreContext context,
        CancellationToken cancellationToken);
}
