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
    ValueTask<Socks5AuthenticationOutcome> AuthenticateAsync(
        Stream stream,
        UserStoreContext context,
        CancellationToken cancellationToken);
}

/// <summary>
/// The result of a SOCKS5 sub-negotiation, including any replacement stream the method installs.
/// </summary>
/// <remarks>
/// Most methods just authenticate and leave the connection alone. GSSAPI (RFC 1961) can negotiate
/// per-message integrity or confidentiality, after which every SOCKS message and all relayed
/// traffic is encapsulated — so it hands back a stream that does that framing, and the handler
/// uses it for everything that follows.
/// </remarks>
public sealed class Socks5AuthenticationOutcome
{
    private Socks5AuthenticationOutcome(AuthenticationResult result, Stream? protectedStream)
    {
        Result = result;
        ProtectedStream = protectedStream;
    }

    /// <summary>Whether the client proved its identity, and as whom.</summary>
    public AuthenticationResult Result { get; }

    /// <summary>
    /// The stream to use for everything after the sub-negotiation, or <see langword="null"/> to
    /// carry on with the raw connection.
    /// </summary>
    public Stream? ProtectedStream { get; }

    /// <summary>Whether the request may proceed.</summary>
    public bool Succeeded => Result.Succeeded;

    /// <summary>The client authenticated; subsequent traffic is unchanged.</summary>
    public static Socks5AuthenticationOutcome Success(ProxyIdentity identity) =>
        new(AuthenticationResult.Success(identity), null);

    /// <summary>The client authenticated and installed a stream that encapsulates what follows.</summary>
    public static Socks5AuthenticationOutcome Protected(ProxyIdentity identity, Stream protectedStream)
    {
        ArgumentNullException.ThrowIfNull(protectedStream);
        return new Socks5AuthenticationOutcome(AuthenticationResult.Success(identity), protectedStream);
    }

    /// <summary>The client failed the check.</summary>
    public static Socks5AuthenticationOutcome Fail(string reason) =>
        new(AuthenticationResult.Fail(reason), null);

    /// <summary>Lifts a plain <see cref="AuthenticationResult"/> into an outcome.</summary>
    public static Socks5AuthenticationOutcome From(AuthenticationResult result) => new(result, null);
}
