using System.Security.Cryptography;
using System.Text;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication.Http;

/// <summary>
/// HTTP <c>Digest</c> proxy authentication, RFC 7616, with <c>qop=auth</c> and the SHA-256,
/// SHA-512-256 and MD5 algorithms.
/// </summary>
/// <remarks>
/// Digest never puts the password on the wire, which makes it the strongest option here for a
/// listener that is not wrapped in TLS. The trade-off is on the server side: verifying a
/// response requires <c>HA1</c>, so an account must store either a plaintext password or a
/// precomputed <c>HA1</c> rather than the one-way PBKDF2 verifier the other schemes use.
/// </remarks>
public sealed class DigestHttpAuthenticator : IHttpProxyAuthenticator, IHttpProxyAuthenticatorFactory
{
    /// <summary>The scheme token.</summary>
    public const string Scheme = "Digest";

    private readonly IUserStore _users;
    private readonly DigestNonceManager _nonces;
    private readonly string[] _algorithms;

    /// <summary>Creates the scheme.</summary>
    /// <param name="users">The account directory.</param>
    /// <param name="nonces">The shared nonce manager.</param>
    /// <param name="algorithms">
    /// The algorithms to advertise, strongest first. RFC 7616 §3.7 has the server offer one
    /// challenge per algorithm and the client pick the strongest it implements, so the default
    /// offers SHA-256 and then MD5 — several mainstream clients, including anything using the
    /// Windows SSPI digest package, still only understand MD5.
    /// </param>
    public DigestHttpAuthenticator(IUserStore users, DigestNonceManager nonces, IEnumerable<string>? algorithms = null)
    {
        ArgumentNullException.ThrowIfNull(users);
        ArgumentNullException.ThrowIfNull(nonces);

        _users = users;
        _nonces = nonces;
        _algorithms = algorithms is null
            ? [DigestHash.Sha256, DigestHash.Md5]
            : [.. algorithms.Select(Normalize).Distinct(StringComparer.Ordinal)];

        if (_algorithms.Length == 0)
        {
            throw new ArgumentException("At least one digest algorithm must be offered.", nameof(algorithms));
        }
    }

    /// <inheritdoc />
    public AuthenticationMethod Method => AuthenticationMethod.Digest;

    /// <inheritdoc />
    public string SchemeName => Scheme;

    /// <inheritdoc cref="IHttpProxyAuthenticatorFactory.Create" />
    public IHttpProxyAuthenticator Create() => this;

    /// <inheritdoc />
    public IReadOnlyList<string> CreateChallenges(in HttpAuthenticationContext context) =>
        BuildChallenges(context.Realm, stale: false);

    /// <inheritdoc />
    public async ValueTask<HttpAuthenticationOutcome> AuthenticateAsync(
        HttpCredential credential,
        HttpAuthenticationContext context,
        CancellationToken cancellationToken)
    {
        DigestParameters parameters = DigestParameters.Parse(credential.Parameter);

        string? username = parameters["username"];
        string? response = parameters["response"];
        string? uri = parameters["uri"];
        string? nonce = parameters["nonce"];

        if (username is null || response is null || uri is null || nonce is null)
        {
            return Reject("Digest credential was missing a required parameter.", context, stale: false);
        }

        if (!DigestHash.TryNormalize(parameters["algorithm"], out string algorithm, out bool isSession))
        {
            return Reject($"Unsupported digest algorithm '{parameters["algorithm"]}'.", context, stale: false);
        }

        NonceValidation nonceState = _nonces.Validate(nonce, DigestNonceManager.ParseNonceCount(parameters["nc"]));
        if (nonceState != NonceValidation.Valid)
        {
            // A stale nonce is not a credential failure: the client is told to retry with a fresh
            // one and, per RFC 7616 §3.3, should do so without re-prompting the user.
            return Reject(
                $"Digest nonce was {nonceState.ToString().ToLowerInvariant()}.",
                context,
                stale: nonceState == NonceValidation.Stale);
        }

        string? ha1 = await _users
            .GetDigestHa1Async(username, context.Realm, algorithm, context.StoreContext, cancellationToken)
            .ConfigureAwait(false);

        if (ha1 is null)
        {
            return Reject($"No digest-capable account '{username}'.", context, stale: false);
        }

        string? qop = parameters["qop"];
        string? cnonce = parameters["cnonce"];
        string? nc = parameters["nc"];

        if (isSession)
        {
            if (cnonce is null)
            {
                return Reject("Session digest requires a cnonce.", context, stale: false);
            }

            ha1 = DigestHash.Compute(algorithm, $"{ha1}:{nonce}:{cnonce}");
        }

        string ha2 = DigestHash.Compute(algorithm, $"{context.Method}:{uri}");

        string expected;
        if (string.IsNullOrEmpty(qop))
        {
            // RFC 2069 compatibility for clients that never learned qop.
            expected = DigestHash.Compute(algorithm, $"{ha1}:{nonce}:{ha2}");
        }
        else if (string.Equals(qop, "auth", StringComparison.OrdinalIgnoreCase))
        {
            if (cnonce is null || nc is null)
            {
                return Reject("Digest qop=auth requires both cnonce and nc.", context, stale: false);
            }

            expected = DigestHash.Compute(algorithm, $"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}");
        }
        else
        {
            // qop=auth-int would require hashing the entity body, which this proxy streams
            // rather than buffers.
            return Reject($"Unsupported digest qop '{qop}'.", context, stale: false);
        }

        if (!FixedTimeEquals(expected, response))
        {
            return Reject($"Incorrect digest response for '{username}'.", context, stale: false);
        }

        AuthenticationResult authorization = await _users
            .ValidateNameAsync(username, context.StoreContext, cancellationToken)
            .ConfigureAwait(false);

        return authorization.Succeeded
            ? HttpAuthenticationOutcome.Success(new ProxyIdentity(username, AuthenticationMethod.Digest))
            : Reject(authorization.FailureReason ?? "Digest account rejected.", context, stale: false);
    }

    private HttpAuthenticationOutcome Reject(string reason, in HttpAuthenticationContext context, bool stale) =>
        HttpAuthenticationOutcome.Fail(reason, BuildChallenges(context.Realm, stale));

    private List<string> BuildChallenges(string realm, bool stale)
    {
        List<string> challenges = new(_algorithms.Length);

        foreach (string algorithm in _algorithms)
        {
            StringBuilder builder = new(192);
            builder.Append(Scheme)
                .Append(" realm=").Append(HttpAuthenticationHelpers.Quote(realm))
                .Append(", qop=\"auth\"")
                .Append(", algorithm=").Append(algorithm)
                .Append(", nonce=").Append(HttpAuthenticationHelpers.Quote(_nonces.Create()))
                .Append(", opaque=").Append(HttpAuthenticationHelpers.Quote(_nonces.Opaque))
                .Append(", charset=UTF-8");

            if (stale)
            {
                builder.Append(", stale=true");
            }

            challenges.Add(builder.ToString());
        }

        return challenges;
    }

    private static string Normalize(string algorithm) =>
        DigestHash.TryNormalize(algorithm, out string normalized, out _)
            ? normalized
            : throw new ArgumentOutOfRangeException(
                nameof(algorithm),
                algorithm,
                $"Supported digest algorithms are {string.Join(", ", DigestHash.SupportedAlgorithms)}.");

    private static bool FixedTimeEquals(string expected, string actual) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(actual.Trim().ToLowerInvariant()));
}
