using System.Text;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication.Http;

/// <summary>HTTP <c>Basic</c> proxy authentication, RFC 7617.</summary>
/// <remarks>
/// Basic hands the password to the server in a reversible encoding, so it pairs with the
/// PBKDF2 verifier in the user store and needs no plaintext on disk. It should only be used
/// on a loopback listener or one wrapped in TLS.
/// </remarks>
public sealed class BasicHttpAuthenticator : IHttpProxyAuthenticator, IHttpProxyAuthenticatorFactory
{
    /// <summary>The scheme token.</summary>
    public const string Scheme = "Basic";

    private readonly IUserStore _users;

    /// <summary>Creates the scheme over an account directory.</summary>
    public BasicHttpAuthenticator(IUserStore users)
    {
        ArgumentNullException.ThrowIfNull(users);
        _users = users;
    }

    /// <inheritdoc />
    public AuthenticationMethod Method => AuthenticationMethod.Basic;

    /// <inheritdoc />
    public string SchemeName => Scheme;

    /// <inheritdoc cref="IHttpProxyAuthenticatorFactory.Create" />
    public IHttpProxyAuthenticator Create() => this;

    /// <inheritdoc />
    public IReadOnlyList<string> CreateChallenges(in HttpAuthenticationContext context) =>
        [$"{Scheme} realm={HttpAuthenticationHelpers.Quote(context.Realm)}, charset=\"UTF-8\""];

    /// <inheritdoc />
    public async ValueTask<HttpAuthenticationOutcome> AuthenticateAsync(
        HttpCredential credential,
        HttpAuthenticationContext context,
        CancellationToken cancellationToken)
    {
        if (!HttpAuthenticationHelpers.TryDecodeBase64(credential.Parameter, out byte[]? decoded))
        {
            return HttpAuthenticationOutcome.Fail("Basic credential was not valid base64.");
        }

        string userPass = Encoding.UTF8.GetString(decoded);
        int separator = userPass.IndexOf(':', StringComparison.Ordinal);
        if (separator < 0)
        {
            return HttpAuthenticationOutcome.Fail("Basic credential had no ':' separator.");
        }

        AuthenticationResult result = await _users
            .ValidatePasswordAsync(
                userPass[..separator],
                userPass[(separator + 1)..],
                context.StoreContext,
                cancellationToken)
            .ConfigureAwait(false);

        return result.Succeeded
            ? HttpAuthenticationOutcome.Success(result.Identity! with { Method = AuthenticationMethod.Basic })
            : HttpAuthenticationOutcome.Fail(result.FailureReason ?? "Basic credential rejected.");
    }
}
