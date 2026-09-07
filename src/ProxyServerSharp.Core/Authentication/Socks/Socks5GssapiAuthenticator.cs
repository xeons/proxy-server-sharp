using System.Buffers;
using System.Net.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication.Socks;

/// <summary>
/// SOCKS5 GSS-API authentication, RFC 1961, advertised as RFC 1928 method <c>0x01</c>.
/// </summary>
/// <remarks>
/// <para>
/// The exchange has three stages: a multi-leg context establishment, a protection-level
/// negotiation, and then — only if a level above <see cref="GssapiProtectionLevel.None"/> was
/// agreed — encapsulation of every subsequent SOCKS message and all relayed traffic.
/// </para>
/// <para>
/// Backed by the host's SSPI or GSSAPI stack, so in practice this authenticates against Kerberos
/// or NTLM. Client support is thin: curl implements it, most SOCKS libraries and every browser do
/// not. An HTTP listener with <c>Negotiate</c> reaches far more clients for the same purpose.
/// </para>
/// </remarks>
public sealed class Socks5GssapiAuthenticator : ISocks5Authenticator
{
    /// <summary>The RFC 1928 method identifier for GSS-API.</summary>
    public const byte Code = 0x01;

    private readonly IUserStore _users;
    private readonly bool _requireKnownAccount;
    private readonly GssapiProtectionLevel _maximumProtection;
    private readonly ILogger _logger;

    /// <summary>Creates the authenticator.</summary>
    /// <param name="users">The account directory used for post-authentication authorisation.</param>
    /// <param name="requireKnownAccount">
    /// When <see langword="true"/>, the authenticated principal must also match an account;
    /// when <see langword="false"/>, any principal the platform authenticates is accepted.
    /// </param>
    /// <param name="maximumProtection">
    /// The strongest per-message protection this listener will agree to. The client asks for a
    /// level and the server may lower it, so capping at <see cref="GssapiProtectionLevel.None"/>
    /// keeps the relay a raw byte pipe.
    /// </param>
    /// <param name="logger">Where handshake failures are reported.</param>
    public Socks5GssapiAuthenticator(
        IUserStore users,
        bool requireKnownAccount,
        GssapiProtectionLevel maximumProtection = GssapiProtectionLevel.Confidentiality,
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(users);

        _users = users;
        _requireKnownAccount = requireKnownAccount;
        _maximumProtection = maximumProtection;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <inheritdoc />
    public AuthenticationMethod Method => AuthenticationMethod.Gssapi;

    /// <inheritdoc />
    public byte MethodCode => Code;

    /// <inheritdoc />
    public async ValueTask<Socks5AuthenticationOutcome> AuthenticateAsync(
        Stream stream,
        UserStoreContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        NegotiateAuthentication negotiate = new(new NegotiateAuthenticationServerOptions
        {
            Package = "Negotiate",

            // The SOCKS protection level is negotiated separately, below; asking SSPI for the
            // strongest level here keeps Wrap able to encrypt if the client requests it.
            RequiredProtectionLevel = _maximumProtection == GssapiProtectionLevel.None
                ? ProtectionLevel.None
                : ProtectionLevel.EncryptAndSign,
        });

        bool keep = false;
        try
        {
            string? principal = await EstablishContextAsync(stream, negotiate, cancellationToken)
                .ConfigureAwait(false);

            if (principal is null)
            {
                return Socks5AuthenticationOutcome.Fail("GSSAPI context establishment failed.");
            }

            AuthenticationResult authorization = await AuthorizeAsync(principal, context, cancellationToken)
                .ConfigureAwait(false);

            if (!authorization.Succeeded)
            {
                await GssapiMessage.WriteAbortAsync(stream, cancellationToken).ConfigureAwait(false);
                return Socks5AuthenticationOutcome.From(authorization);
            }

            GssapiProtectionLevel level = await NegotiateProtectionAsync(stream, negotiate, cancellationToken)
                .ConfigureAwait(false);

            ProxyIdentity identity = new(principal, AuthenticationMethod.Gssapi);

            if (level == GssapiProtectionLevel.None)
            {
                // Nothing further is encapsulated, so the context is no longer needed.
                return Socks5AuthenticationOutcome.Success(identity);
            }

            _logger.LogDebug("GSSAPI negotiated {Level} protection for '{Principal}'.", level, principal);

            keep = true;
            return Socks5AuthenticationOutcome.Protected(
                identity,
                new GssapiProtectedStream(stream, negotiate, level));
        }
        finally
        {
            // The protected stream keeps using the context, so it only gets disposed when the
            // connection ends up unprotected or the handshake failed.
            if (!keep)
            {
                negotiate.Dispose();
            }
        }
    }

    /// <summary>Runs the multi-leg token exchange, returning the authenticated principal name.</summary>
    private async ValueTask<string?> EstablishContextAsync(
        Stream stream,
        NegotiateAuthentication negotiate,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            (GssapiMessageType type, byte[] token) = await GssapiMessage
                .ReadAsync(stream, cancellationToken)
                .ConfigureAwait(false);

            if (type == GssapiMessageType.Abort)
            {
                _logger.LogDebug("Client aborted the GSSAPI exchange.");
                return null;
            }

            if (type != GssapiMessageType.Authentication)
            {
                await GssapiMessage.WriteAbortAsync(stream, cancellationToken).ConfigureAwait(false);
                throw new InvalidDataException(
                    $"Expected a GSSAPI authentication token, got message type 0x{(byte)type:X2}.");
            }

            byte[]? outgoing;
            NegotiateAuthenticationStatusCode status;
            try
            {
                outgoing = negotiate.GetOutgoingBlob(token, out status);
            }
            catch (Exception exception) when (exception is PlatformNotSupportedException or NotSupportedException)
            {
                _logger.LogWarning("GSSAPI is unavailable on this host: {Message}", exception.Message);
                await GssapiMessage.WriteAbortAsync(stream, cancellationToken).ConfigureAwait(false);
                return null;
            }

            switch (status)
            {
                case NegotiateAuthenticationStatusCode.ContinueNeeded:
                    await GssapiMessage
                        .WriteAsync(stream, GssapiMessageType.Authentication, outgoing ?? [], cancellationToken)
                        .ConfigureAwait(false);
                    continue;

                case NegotiateAuthenticationStatusCode.Completed:
                    // RFC 1961 §4.2: the final leg is still answered, even with an empty token,
                    // so the client knows the context is complete.
                    await GssapiMessage
                        .WriteAsync(stream, GssapiMessageType.Authentication, outgoing ?? [], cancellationToken)
                        .ConfigureAwait(false);

                    return negotiate.RemoteIdentity.Name is { Length: > 0 } name ? name : null;

                default:
                    _logger.LogWarning("GSSAPI context establishment failed: {Status}.", status);
                    await GssapiMessage.WriteAbortAsync(stream, cancellationToken).ConfigureAwait(false);
                    return null;
            }
        }
    }

    /// <summary>
    /// Runs the RFC 1961 §4.3 protection-level negotiation and returns the level in force.
    /// </summary>
    private async ValueTask<GssapiProtectionLevel> NegotiateProtectionAsync(
        Stream stream,
        NegotiateAuthentication negotiate,
        CancellationToken cancellationToken)
    {
        (GssapiMessageType type, byte[] token) = await GssapiMessage
            .ReadAsync(stream, cancellationToken)
            .ConfigureAwait(false);

        if (type != GssapiMessageType.ProtectionLevel)
        {
            throw new InvalidDataException(
                $"Expected a GSSAPI protection-level message, got type 0x{(byte)type:X2}.");
        }

        GssapiProtectionLevel requested = ReadProtectionLevel(token, negotiate);

        // The server may only lower what the client asked for.
        GssapiProtectionLevel agreed = (GssapiProtectionLevel)Math.Min((byte)requested, (byte)_maximumProtection);

        await GssapiMessage
            .WriteAsync(
                stream,
                GssapiMessageType.ProtectionLevel,
                WriteProtectionLevel(agreed, negotiate),
                cancellationToken)
            .ConfigureAwait(false);

        return agreed;
    }

    /// <summary>
    /// Reads the requested protection level, tolerating implementations that send the byte
    /// unwrapped.
    /// </summary>
    /// <remarks>
    /// RFC 1961 has this message pass through <c>gss_wrap</c>, but several implementations send a
    /// bare byte instead — the interop quirk behind curl's <c>--socks5-gssapi-nec</c> flag.
    /// Accepting both costs nothing and is the difference between working and not with those
    /// clients.
    /// </remarks>
    private GssapiProtectionLevel ReadProtectionLevel(byte[] token, NegotiateAuthentication negotiate)
    {
        if (token.Length == 1)
        {
            _logger.LogDebug("Client sent an unwrapped GSSAPI protection level (NEC-style).");
            return Clamp(token[0]);
        }

        ArrayBufferWriter<byte> plaintext = new(token.Length);
        NegotiateAuthenticationStatusCode status = negotiate.Unwrap(token, plaintext, out _);

        if (status != NegotiateAuthenticationStatusCode.Completed || plaintext.WrittenCount == 0)
        {
            throw new InvalidDataException($"Could not read the GSSAPI protection level: {status}.");
        }

        return Clamp(plaintext.WrittenSpan[0]);
    }

    private static byte[] WriteProtectionLevel(GssapiProtectionLevel level, NegotiateAuthentication negotiate)
    {
        ArrayBufferWriter<byte> wrapped = new(64);
        NegotiateAuthenticationStatusCode status = negotiate.Wrap([(byte)level], wrapped, false, out _);

        return status == NegotiateAuthenticationStatusCode.Completed
            ? wrapped.WrittenSpan.ToArray()
            : throw new InvalidDataException($"Could not wrap the GSSAPI protection level: {status}.");
    }

    private static GssapiProtectionLevel Clamp(byte value) =>
        value > (byte)GssapiProtectionLevel.Confidentiality
            ? GssapiProtectionLevel.Confidentiality
            : (GssapiProtectionLevel)value;

    private async ValueTask<AuthenticationResult> AuthorizeAsync(
        string principal,
        UserStoreContext context,
        CancellationToken cancellationToken)
    {
        if (!_requireKnownAccount)
        {
            return AuthenticationResult.Success(new ProxyIdentity(principal, AuthenticationMethod.Gssapi));
        }

        AuthenticationResult result = await _users
            .ValidateNameAsync(principal, context, cancellationToken)
            .ConfigureAwait(false);

        if (result.Succeeded)
        {
            return result;
        }

        // Principals arrive as DOMAIN\user or user@realm; try the bare name too so operators do
        // not have to write the domain into every config entry.
        string bare = BareName(principal);
        return bare.Length == principal.Length
            ? result
            : await _users.ValidateNameAsync(bare, context, cancellationToken).ConfigureAwait(false);
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

}
