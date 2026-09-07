using ProxyServerSharp.Authentication;
using ProxyServerSharp.Authentication.Http;
using ProxyServerSharp.Authentication.Socks;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Protocol;
using ProxyServerSharp.Protocol.Http;
using ProxyServerSharp.Protocol.Socks;

namespace ProxyServerSharp.Server;

/// <summary>
/// Builds the protocol handler for a listener, wiring in exactly the authentication schemes that
/// listener is configured to offer.
/// </summary>
/// <remarks>
/// The successor to the original <c>ProxyCoreFactory</c>, which mapped a protocol enum onto a
/// core that owned its own sockets and threw <see cref="NotImplementedException"/> for everything
/// but SOCKS4.
/// </remarks>
public sealed class ProxyHandlerFactory
{
    private readonly IUserStore _users;
    private readonly DigestNonceManager _nonces;

    /// <summary>Creates the factory.</summary>
    /// <param name="users">The account directory every scheme checks against.</param>
    /// <param name="nonces">The Digest nonce manager, shared so nonces survive across connections.</param>
    public ProxyHandlerFactory(IUserStore users, DigestNonceManager nonces)
    {
        ArgumentNullException.ThrowIfNull(users);
        ArgumentNullException.ThrowIfNull(nonces);

        _users = users;
        _nonces = nonces;
    }

    /// <summary>Builds the handler for <paramref name="listener"/>.</summary>
    /// <exception cref="InvalidOperationException">The listener's configuration is not coherent.</exception>
    public IProxyProtocolHandler Create(ListenerOptions listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        Validate(listener);

        return listener.Protocol switch
        {
            ProxyProtocol.Socks4 => new Socks4ProxyHandler(Socks4Authenticator.ForListener(_users, listener)),
            ProxyProtocol.Socks5 => new Socks5ProxyHandler(CreateSocks5Authenticators(listener)),
            ProxyProtocol.Http => new HttpProxyHandler(CreateHttpAuthentication(listener)),
            _ => throw new InvalidOperationException($"Unknown proxy protocol '{listener.Protocol}'."),
        };
    }

    /// <summary>Rejects configurations that would silently do the wrong thing.</summary>
    public static void Validate(ListenerOptions listener)
    {
        ArgumentNullException.ThrowIfNull(listener);

        if (listener.Port is < 1 or > 65535)
        {
            throw new InvalidOperationException($"Listener '{listener.Name}' has invalid port {listener.Port}.");
        }

        foreach (AuthenticationMethod method in listener.EffectiveAuthentication)
        {
            if (!method.IsValidFor(listener.Protocol))
            {
                throw new InvalidOperationException(
                    $"Listener '{listener.Name}' offers {method}, which {listener.Protocol} cannot express. "
                    + $"Valid methods are {string.Join(", ", AuthenticationMethodExtensions.SupportedBy(listener.Protocol))}.");
            }
        }

        if (listener.Tls.Enabled && listener.Protocol != ProxyProtocol.Http)
        {
            throw new InvalidOperationException(
                $"Listener '{listener.Name}' enables TLS, which only the HTTP protocol supports. "
                + "SOCKS has no TLS handshake of its own.");
        }
    }

    private IEnumerable<ISocks5Authenticator> CreateSocks5Authenticators(ListenerOptions listener)
    {
        // Ordered strongest-first so the server's preference, not the client's, decides.
        foreach (AuthenticationMethod method in AuthenticationMethodExtensions.SupportedBy(ProxyProtocol.Socks5))
        {
            if (!listener.EffectiveAuthentication.Contains(method))
            {
                continue;
            }

            yield return method switch
            {
                AuthenticationMethod.UsernamePassword => new Socks5UsernamePasswordAuthenticator(_users),
                _ => new Socks5NoAuthenticator(),
            };
        }
    }

    private HttpProxyAuthentication CreateHttpAuthentication(ListenerOptions listener)
    {
        List<IHttpProxyAuthenticatorFactory> factories = [];
        bool allowAnonymous = false;

        foreach (AuthenticationMethod method in AuthenticationMethodExtensions.SupportedBy(ProxyProtocol.Http))
        {
            if (!listener.EffectiveAuthentication.Contains(method))
            {
                continue;
            }

            switch (method)
            {
                case AuthenticationMethod.Anonymous:
                    allowAnonymous = true;
                    break;

                case AuthenticationMethod.Basic:
                    factories.Add(new BasicHttpAuthenticator(_users));
                    break;

                case AuthenticationMethod.Digest:
                    factories.Add(new DigestHttpAuthenticator(
                        _users,
                        _nonces,
                        listener.DigestAlgorithms.Count > 0 ? listener.DigestAlgorithms : null));
                    break;

                case AuthenticationMethod.Bearer:
                    factories.Add(new BearerHttpAuthenticator(_users));
                    break;

                case AuthenticationMethod.Negotiate:
                    // Requiring a matching account only makes sense when there are accounts to
                    // match; otherwise any principal the OS authenticates is accepted.
                    factories.Add(new NegotiateHttpAuthenticatorFactory(_users, requireKnownAccount: !_users.IsEmpty));
                    break;

                default:
                    throw new InvalidOperationException($"Method {method} is not an HTTP scheme.");
            }
        }

        return new HttpProxyAuthentication(factories, allowAnonymous);
    }
}
