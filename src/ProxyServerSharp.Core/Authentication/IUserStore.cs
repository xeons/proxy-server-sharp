using System.Net;

namespace ProxyServerSharp.Authentication;

/// <summary>The account directory credential schemes are checked against.</summary>
public interface IUserStore
{
    /// <summary>Whether the store holds any account at all.</summary>
    bool IsEmpty { get; }

    /// <summary>Validates a username and password.</summary>
    /// <param name="username">The account name.</param>
    /// <param name="password">The presented password.</param>
    /// <param name="context">The listener and client the credential arrived on.</param>
    ValueTask<AuthenticationResult> ValidatePasswordAsync(
        string username,
        string password,
        UserStoreContext context,
        CancellationToken cancellationToken = default);

    /// <summary>Validates a bearer token that carries no username of its own.</summary>
    ValueTask<AuthenticationResult> ValidateTokenAsync(
        string token,
        UserStoreContext context,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a name on its own, with no secret: the SOCKS4 <c>USERID</c> case, and the
    /// post-handshake authorisation check for Negotiate.
    /// </summary>
    ValueTask<AuthenticationResult> ValidateNameAsync(
        string username,
        UserStoreContext context,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the Digest <c>HA1</c> for an account, either precomputed or derived from a stored
    /// plaintext password, or <see langword="null"/> when Digest is impossible for this account.
    /// </summary>
    /// <param name="username">The account name.</param>
    /// <param name="realm">The protection space from the challenge.</param>
    /// <param name="algorithm">The Digest algorithm, e.g. <c>SHA-256</c> or <c>MD5</c>.</param>
    /// <param name="context">The listener and client the credential arrived on.</param>
    ValueTask<string?> GetDigestHa1Async(
        string username,
        string realm,
        string algorithm,
        UserStoreContext context,
        CancellationToken cancellationToken = default);
}

/// <summary>Where a credential arrived from, so per-account grants can be enforced.</summary>
/// <param name="ListenerName">The listener the client connected to.</param>
/// <param name="ClientAddress">The client's address.</param>
public readonly record struct UserStoreContext(string ListenerName, IPAddress? ClientAddress)
{
    /// <summary>A context with no listener or client restriction, for tests and tooling.</summary>
    public static UserStoreContext None => new("", null);
}
