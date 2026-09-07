using System.Net.Security;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication.Http;

/// <summary>
/// Creates the per-connection <see cref="NegotiateHttpAuthenticator"/> instances a listener offers.
/// </summary>
public sealed class NegotiateHttpAuthenticatorFactory : IHttpProxyAuthenticatorFactory
{
    private readonly IUserStore _users;
    private readonly bool _requireKnownAccount;

    /// <summary>Creates the factory.</summary>
    /// <param name="users">The account directory used for post-authentication authorisation.</param>
    /// <param name="requireKnownAccount">
    /// When <see langword="true"/>, an OS-authenticated principal must also match an account in
    /// <paramref name="users"/>. When <see langword="false"/>, any principal the platform
    /// authenticates is accepted.
    /// </param>
    public NegotiateHttpAuthenticatorFactory(IUserStore users, bool requireKnownAccount)
    {
        ArgumentNullException.ThrowIfNull(users);
        _users = users;
        _requireKnownAccount = requireKnownAccount;
    }

    /// <summary>Whether the platform can act as a Negotiate server at all.</summary>
    /// <remarks>
    /// Backed by SSPI on Windows and GSSAPI elsewhere; a Linux host without a keytab will
    /// construct fine and then fail every handshake, so listeners log this at startup.
    /// </remarks>
    public static bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    /// <inheritdoc />
    public AuthenticationMethod Method => AuthenticationMethod.Negotiate;

    /// <inheritdoc />
    public IHttpProxyAuthenticator Create() => new NegotiateHttpAuthenticator(_users, _requireKnownAccount);
}

/// <summary>
/// HTTP <c>Negotiate</c> (Kerberos, falling back to NTLM) proxy authentication, backed by the
/// host's SSPI or GSSAPI stack.
/// </summary>
/// <remarks>
/// Unlike the other schemes this one is a multi-leg exchange bound to a single TCP connection:
/// the security context is built up across two or three <c>407</c> round trips, so the instance
/// is created per connection and the handler must keep that connection open between legs.
/// </remarks>
public sealed class NegotiateHttpAuthenticator : IHttpProxyAuthenticator, IDisposable
{
    /// <summary>The scheme token.</summary>
    public const string Scheme = "Negotiate";

    private readonly IUserStore _users;
    private readonly bool _requireKnownAccount;
    private NegotiateAuthentication? _negotiate;
    private bool _disposed;

    /// <summary>Creates a scheme instance for one client connection.</summary>
    public NegotiateHttpAuthenticator(IUserStore users, bool requireKnownAccount)
    {
        ArgumentNullException.ThrowIfNull(users);
        _users = users;
        _requireKnownAccount = requireKnownAccount;
    }

    /// <inheritdoc />
    public AuthenticationMethod Method => AuthenticationMethod.Negotiate;

    /// <inheritdoc />
    public string SchemeName => Scheme;

    /// <inheritdoc />
    public IReadOnlyList<string> CreateChallenges(in HttpAuthenticationContext context) => [Scheme];

    /// <inheritdoc />
    public async ValueTask<HttpAuthenticationOutcome> AuthenticateAsync(
        HttpCredential credential,
        HttpAuthenticationContext context,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (credential.Parameter.Length == 0)
        {
            return HttpAuthenticationOutcome.Fail("Negotiate credential carried no token.", Scheme);
        }

        _negotiate ??= new NegotiateAuthentication(new NegotiateAuthenticationServerOptions
        {
            // "Negotiate" lets the client pick Kerberos and fall back to NTLM on its own.
            Package = Scheme,
            RequiredProtectionLevel = ProtectionLevel.None,
        });

        string? outgoing;
        NegotiateAuthenticationStatusCode status;
        try
        {
            outgoing = _negotiate.GetOutgoingBlob(credential.Parameter, out status);
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or NotSupportedException)
        {
            Reset();
            return HttpAuthenticationOutcome.Fail($"Negotiate is unavailable on this host: {exception.Message}");
        }

        switch (status)
        {
            case NegotiateAuthenticationStatusCode.ContinueNeeded when outgoing is not null:
                return HttpAuthenticationOutcome.Continue($"{Scheme} {outgoing}");

            case NegotiateAuthenticationStatusCode.Completed:
                return await CompleteAsync(outgoing, context, cancellationToken).ConfigureAwait(false);

            default:
                string reason = $"Negotiate handshake failed: {status}.";
                Reset();
                return HttpAuthenticationOutcome.Fail(reason, Scheme);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _negotiate?.Dispose();
        _negotiate = null;
    }

    private async ValueTask<HttpAuthenticationOutcome> CompleteAsync(
        string? finalBlob,
        HttpAuthenticationContext context,
        CancellationToken cancellationToken)
    {
        string? name = _negotiate!.RemoteIdentity.Name;
        if (string.IsNullOrEmpty(name))
        {
            Reset();
            return HttpAuthenticationOutcome.Fail("Negotiate completed without a remote identity.");
        }

        if (_requireKnownAccount)
        {
            AuthenticationResult result = await AuthorizeAsync(name, context, cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                Reset();
                return HttpAuthenticationOutcome.Fail(result.FailureReason ?? $"'{name}' is not a permitted account.");
            }
        }

        // The last leg may carry a mutual-authentication token; the client is entitled to it,
        // but this proxy has nothing more to say once the context is complete.
        _ = finalBlob;

        return HttpAuthenticationOutcome.Success(new ProxyIdentity(name, AuthenticationMethod.Negotiate));
    }

    private async ValueTask<AuthenticationResult> AuthorizeAsync(
        string name,
        HttpAuthenticationContext context,
        CancellationToken cancellationToken)
    {
        AuthenticationResult result = await _users
            .ValidateNameAsync(name, context.StoreContext, cancellationToken)
            .ConfigureAwait(false);

        if (result.Succeeded)
        {
            return result;
        }

        // Windows reports principals as DOMAIN\user or user@realm; try the bare account name too
        // so operators do not have to write the domain into every config entry.
        string bare = BareName(name);
        return bare.Length == name.Length
            ? result
            : await _users.ValidateNameAsync(bare, context.StoreContext, cancellationToken).ConfigureAwait(false);
    }

    private static string BareName(string name)
    {
        int backslash = name.LastIndexOf('\\');
        if (backslash >= 0)
        {
            return name[(backslash + 1)..];
        }

        int at = name.IndexOf('@', StringComparison.Ordinal);
        return at > 0 ? name[..at] : name;
    }

    private void Reset()
    {
        // A failed leg poisons the security context; drop it so the next attempt starts clean.
        _negotiate?.Dispose();
        _negotiate = null;
    }
}
