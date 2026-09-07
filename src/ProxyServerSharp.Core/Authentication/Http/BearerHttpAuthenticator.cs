using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication.Http;

/// <summary>
/// HTTP <c>Bearer</c> proxy authentication: a single opaque token that names its own account,
/// matched against the PBKDF2 token verifiers in the user store.
/// </summary>
/// <remarks>
/// Handy for scripts and headless clients that would otherwise have to carry a username too.
/// Like Basic, the token is only as private as the transport carrying it.
/// </remarks>
public sealed class BearerHttpAuthenticator : IHttpProxyAuthenticator, IHttpProxyAuthenticatorFactory
{
    /// <summary>The scheme token.</summary>
    public const string Scheme = "Bearer";

    private readonly IUserStore _users;

    /// <summary>Creates the scheme over an account directory.</summary>
    public BearerHttpAuthenticator(IUserStore users)
    {
        ArgumentNullException.ThrowIfNull(users);
        _users = users;
    }

    /// <inheritdoc />
    public AuthenticationMethod Method => AuthenticationMethod.Bearer;

    /// <inheritdoc />
    public string SchemeName => Scheme;

    /// <inheritdoc cref="IHttpProxyAuthenticatorFactory.Create" />
    public IHttpProxyAuthenticator Create() => this;

    /// <inheritdoc />
    public IReadOnlyList<string> CreateChallenges(in HttpAuthenticationContext context) =>
        [$"{Scheme} realm={HttpAuthenticationHelpers.Quote(context.Realm)}"];

    /// <inheritdoc />
    public async ValueTask<HttpAuthenticationOutcome> AuthenticateAsync(
        HttpCredential credential,
        HttpAuthenticationContext context,
        CancellationToken cancellationToken)
    {
        if (credential.Parameter.Length == 0)
        {
            return HttpAuthenticationOutcome.Fail("Bearer credential carried no token.");
        }

        AuthenticationResult result = await _users
            .ValidateTokenAsync(credential.Parameter, context.StoreContext, cancellationToken)
            .ConfigureAwait(false);

        return result.Succeeded
            ? HttpAuthenticationOutcome.Success(result.Identity!)
            : HttpAuthenticationOutcome.Fail(result.FailureReason ?? "Bearer token rejected.");
    }
}
