using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication.Socks;

/// <summary>RFC 1928 method <c>0x00</c>, "NO AUTHENTICATION REQUIRED".</summary>
public sealed class Socks5NoAuthenticator : ISocks5Authenticator
{
    /// <summary>The RFC 1928 method identifier for anonymous access.</summary>
    public const byte Code = 0x00;

    /// <inheritdoc />
    public AuthenticationMethod Method => AuthenticationMethod.Anonymous;

    /// <inheritdoc />
    public byte MethodCode => Code;

    /// <inheritdoc />
    public ValueTask<AuthenticationResult> AuthenticateAsync(
        Stream stream,
        UserStoreContext context,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(AuthenticationResult.Success(ProxyIdentity.Anonymous));
}
