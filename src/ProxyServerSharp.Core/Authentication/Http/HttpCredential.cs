using System.Diagnostics.CodeAnalysis;

namespace ProxyServerSharp.Authentication.Http;

/// <summary>A parsed <c>Proxy-Authorization</c> field: a scheme token and its raw parameters.</summary>
/// <param name="Scheme">The scheme token, e.g. <c>Basic</c>.</param>
/// <param name="Parameter">Everything after the scheme token, trimmed. May be empty.</param>
public readonly record struct HttpCredential(string Scheme, string Parameter)
{
    /// <summary>Parses a <c>Proxy-Authorization</c> or <c>Authorization</c> field value.</summary>
    public static bool TryParse(string? value, out HttpCredential credential)
    {
        credential = default;

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string trimmed = value.Trim();
        int space = trimmed.IndexOf(' ', StringComparison.Ordinal);

        credential = space < 0
            ? new HttpCredential(trimmed, "")
            : new HttpCredential(trimmed[..space], trimmed[(space + 1)..].Trim());

        return credential.Scheme.Length > 0;
    }

    /// <summary>Whether this credential uses <paramref name="scheme"/>, ignoring case.</summary>
    public bool Is(string scheme) => string.Equals(Scheme, scheme, StringComparison.OrdinalIgnoreCase);
}

/// <summary>How far a scheme got with the credential it was handed.</summary>
public enum HttpAuthenticationStatus
{
    /// <summary>The client is authenticated and the request may proceed.</summary>
    Succeeded,

    /// <summary>The credential was rejected.</summary>
    Failed,

    /// <summary>
    /// A multi-leg scheme needs another round trip: the server must answer <c>407</c> with
    /// <see cref="HttpAuthenticationOutcome.Challenge"/> and keep the connection open.
    /// </summary>
    Continue,
}

/// <summary>The result of running one HTTP authentication scheme.</summary>
public sealed class HttpAuthenticationOutcome
{
    private HttpAuthenticationOutcome(
        HttpAuthenticationStatus status,
        ProxyIdentity? identity,
        IReadOnlyList<string> challenges,
        string? failureReason)
    {
        Status = status;
        Identity = identity;
        Challenges = challenges;
        FailureReason = failureReason;
    }

    /// <summary>How far the scheme got.</summary>
    public HttpAuthenticationStatus Status { get; }

    /// <summary>The authenticated principal, when <see cref="Status"/> is <see cref="HttpAuthenticationStatus.Succeeded"/>.</summary>
    public ProxyIdentity? Identity { get; }

    /// <summary>
    /// The <c>Proxy-Authenticate</c> values this scheme wants sent back. A scheme may offer
    /// several, which is how Digest advertises one challenge per algorithm.
    /// </summary>
    public IReadOnlyList<string> Challenges { get; }

    /// <summary>Why the credential was rejected, for the log. Never sent to the client.</summary>
    public string? FailureReason { get; }

    /// <summary>Whether the request may proceed.</summary>
    public bool Succeeded => Status == HttpAuthenticationStatus.Succeeded;

    /// <summary>The client is authenticated.</summary>
    public static HttpAuthenticationOutcome Success(ProxyIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return new HttpAuthenticationOutcome(HttpAuthenticationStatus.Succeeded, identity, [], null);
    }

    /// <summary>The credential was rejected; any <paramref name="challenges"/> given are sent back.</summary>
    public static HttpAuthenticationOutcome Fail(string reason, params string[] challenges) =>
        new(HttpAuthenticationStatus.Failed, null, challenges, reason);

    /// <summary>The credential was rejected, with a list of challenges to send back.</summary>
    public static HttpAuthenticationOutcome Fail(string reason, IReadOnlyList<string> challenges) =>
        new(HttpAuthenticationStatus.Failed, null, challenges, reason);

    /// <summary>The scheme needs another leg on the same connection.</summary>
    public static HttpAuthenticationOutcome Continue(string challenge)
    {
        ArgumentException.ThrowIfNullOrEmpty(challenge);
        return new HttpAuthenticationOutcome(HttpAuthenticationStatus.Continue, null, [challenge], null);
    }
}

/// <summary>Everything a scheme needs beyond the credential itself.</summary>
/// <param name="StoreContext">The listener and client the credential arrived on.</param>
/// <param name="Realm">The protection space advertised by the listener.</param>
/// <param name="Method">The HTTP method, which Digest folds into its response hash.</param>
/// <param name="Target">The request-target, which Digest compares against its <c>uri</c> parameter.</param>
/// <param name="EntityBody">
/// Buffers the request body on demand, for the one scheme that needs it: Digest
/// <c>qop=auth-int</c> hashes the body into its response. Returns <see langword="null"/> when no
/// body is available or it exceeds the configured cap. Left unset by callers that do not support
/// <c>auth-int</c>.
/// </param>
public readonly record struct HttpAuthenticationContext(
    UserStoreContext StoreContext,
    string Realm,
    string Method,
    string Target,
    Func<CancellationToken, ValueTask<byte[]?>>? EntityBody = null);

/// <summary>One HTTP proxy authentication scheme.</summary>
public interface IHttpProxyAuthenticator
{
    /// <summary>The configured method this implements.</summary>
    Configuration.AuthenticationMethod Method { get; }

    /// <summary>The scheme token used in <c>Proxy-Authenticate</c> and <c>Proxy-Authorization</c>.</summary>
    string SchemeName { get; }

    /// <summary>
    /// Builds the <c>Proxy-Authenticate</c> values offered when no credential was presented.
    /// Most schemes return one; Digest returns one per algorithm it will accept.
    /// </summary>
    IReadOnlyList<string> CreateChallenges(in HttpAuthenticationContext context);

    /// <summary>Checks a credential the client presented under <see cref="SchemeName"/>.</summary>
    ValueTask<HttpAuthenticationOutcome> AuthenticateAsync(
        HttpCredential credential,
        HttpAuthenticationContext context,
        CancellationToken cancellationToken);
}

/// <summary>Creates the per-connection scheme instances a listener offers.</summary>
/// <remarks>
/// Negotiate carries state across the legs of a single connection, so schemes are built per
/// connection rather than shared. Stateless schemes just return themselves.
/// </remarks>
public interface IHttpProxyAuthenticatorFactory
{
    /// <summary>The configured method the created schemes implement.</summary>
    Configuration.AuthenticationMethod Method { get; }

    /// <summary>Creates a scheme instance scoped to one client connection.</summary>
    IHttpProxyAuthenticator Create();
}

/// <summary>Small helpers shared by the HTTP schemes.</summary>
internal static class HttpAuthenticationHelpers
{
    /// <summary>Quotes a value for an <c>auth-param</c>, escaping backslashes and quotes.</summary>
    internal static string Quote(string value) =>
        "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    /// <summary>Tries to base64-decode a credential parameter.</summary>
    internal static bool TryDecodeBase64(string value, [NotNullWhen(true)] out byte[]? bytes)
    {
        bytes = null;
        Span<byte> buffer = value.Length <= 1024 ? stackalloc byte[value.Length] : new byte[value.Length];

        if (!Convert.TryFromBase64String(value, buffer, out int written))
        {
            return false;
        }

        bytes = buffer[..written].ToArray();
        return true;
    }
}
