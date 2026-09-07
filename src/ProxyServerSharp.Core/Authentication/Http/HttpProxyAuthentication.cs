using ProxyServerSharp.Configuration;
using ProxyServerSharp.Protocol.Http;

namespace ProxyServerSharp.Authentication.Http;

/// <summary>
/// The set of schemes one HTTP listener offers. Built once per listener and shared by every
/// connection it accepts.
/// </summary>
public sealed class HttpProxyAuthentication
{
    private readonly IHttpProxyAuthenticatorFactory[] _factories;

    /// <summary>Creates the scheme set.</summary>
    /// <param name="factories">The schemes to offer, strongest first.</param>
    /// <param name="allowAnonymous">Whether unauthenticated clients are accepted.</param>
    public HttpProxyAuthentication(IEnumerable<IHttpProxyAuthenticatorFactory> factories, bool allowAnonymous)
    {
        ArgumentNullException.ThrowIfNull(factories);
        _factories = [.. factories];
        AllowAnonymous = allowAnonymous;
    }

    /// <summary>Whether unauthenticated clients are accepted.</summary>
    public bool AllowAnonymous { get; }

    /// <summary>Whether any credential scheme is offered at all.</summary>
    public bool RequiresCredentials => !AllowAnonymous && _factories.Length > 0;

    /// <summary>The methods offered, for logging and the desktop UI.</summary>
    public IReadOnlyList<AuthenticationMethod> Methods => [.. _factories.Select(f => f.Method)];

    /// <summary>Creates the authenticator state for one client connection.</summary>
    public HttpConnectionAuthenticator CreateConnectionAuthenticator() =>
        new([.. _factories.Select(f => f.Create())], AllowAnonymous);
}

/// <summary>
/// Per-connection HTTP authentication state. Holds the scheme instances for one client so that
/// multi-leg schemes such as Negotiate can carry a security context across <c>407</c> round trips.
/// </summary>
public sealed class HttpConnectionAuthenticator : IDisposable
{
    private readonly IHttpProxyAuthenticator[] _schemes;
    private readonly bool _allowAnonymous;

    internal HttpConnectionAuthenticator(IHttpProxyAuthenticator[] schemes, bool allowAnonymous)
    {
        _schemes = schemes;
        _allowAnonymous = allowAnonymous;
    }

    /// <summary>The identity established on this connection, once one has been.</summary>
    /// <remarks>
    /// HTTP proxy authentication is nominally per-request, but Negotiate binds to the connection,
    /// and re-verifying a Basic or Digest credential on every request of a pipelined connection
    /// buys nothing. Once a connection is authenticated it stays authenticated.
    /// </remarks>
    public ProxyIdentity? Identity { get; private set; }

    /// <summary>Checks the credential on <paramref name="request"/>, if the listener needs one.</summary>
    public async ValueTask<HttpAuthenticationOutcome> AuthenticateAsync(
        HttpRequestHead request,
        HttpAuthenticationContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (Identity is not null)
        {
            return HttpAuthenticationOutcome.Success(Identity);
        }

        if (_allowAnonymous)
        {
            Identity = ProxyIdentity.Anonymous;
            return HttpAuthenticationOutcome.Success(Identity);
        }

        if (_schemes.Length == 0)
        {
            return HttpAuthenticationOutcome.Fail("The listener requires credentials but offers no scheme.");
        }

        // A client may send several Proxy-Authorization fields; take the first one naming a
        // scheme this listener actually offers.
        foreach (string value in request.Headers.GetAll("Proxy-Authorization"))
        {
            if (!HttpCredential.TryParse(value, out HttpCredential credential))
            {
                continue;
            }

            IHttpProxyAuthenticator? scheme = FindScheme(credential.Scheme);
            if (scheme is null)
            {
                continue;
            }

            HttpAuthenticationOutcome outcome = await scheme
                .AuthenticateAsync(credential, context, cancellationToken)
                .ConfigureAwait(false);

            if (outcome.Succeeded)
            {
                Identity = outcome.Identity;
            }

            return outcome;
        }

        return HttpAuthenticationOutcome.Fail("No supported proxy credential was presented.");
    }

    /// <summary>
    /// Builds the <c>Proxy-Authenticate</c> values for a <c>407</c> response.
    /// </summary>
    /// <param name="outcome">The outcome that triggered the challenge, if any.</param>
    /// <param name="context">The realm and request the challenge belongs to.</param>
    public IReadOnlyList<string> BuildChallenges(HttpAuthenticationOutcome? outcome, in HttpAuthenticationContext context)
    {
        // Mid-handshake, the continuation token is the only thing the client should act on;
        // offering alternatives alongside it makes several clients restart the exchange.
        if (outcome?.Status == HttpAuthenticationStatus.Continue)
        {
            return outcome.Challenges;
        }

        List<string> challenges = [.. outcome?.Challenges ?? []];

        foreach (IHttpProxyAuthenticator scheme in _schemes)
        {
            // Skip a scheme the outcome already spoke for, so a stale=true Digest challenge is
            // not immediately followed by a fresh one for the same scheme.
            if (challenges.Exists(c => StartsWithScheme(c, scheme.SchemeName)))
            {
                continue;
            }

            challenges.AddRange(scheme.CreateChallenges(context));
        }

        return challenges;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (IHttpProxyAuthenticator scheme in _schemes)
        {
            if (scheme is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }

    private IHttpProxyAuthenticator? FindScheme(string schemeName)
    {
        foreach (IHttpProxyAuthenticator scheme in _schemes)
        {
            if (string.Equals(scheme.SchemeName, schemeName, StringComparison.OrdinalIgnoreCase))
            {
                return scheme;
            }
        }

        return null;
    }

    private static bool StartsWithScheme(string challenge, string schemeName) =>
        challenge.StartsWith(schemeName, StringComparison.OrdinalIgnoreCase)
        && (challenge.Length == schemeName.Length || challenge[schemeName.Length] == ' ');
}
