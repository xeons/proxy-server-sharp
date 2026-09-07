using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication.Socks;

/// <summary>
/// Checks the SOCKS4 <c>USERID</c> field. SOCKS4 has no password exchange at all, so this is an
/// ident-style assertion: the name is matched against the account directory and against that
/// account's listener and client-address grants, nothing more.
/// </summary>
public sealed class Socks4Authenticator
{
    private readonly IUserStore _users;
    private readonly bool _requireUserId;

    /// <summary>Creates the authenticator.</summary>
    /// <param name="users">The account directory.</param>
    /// <param name="requireUserId">
    /// When <see langword="true"/>, the <c>USERID</c> must name an account; when
    /// <see langword="false"/> the listener is anonymous and any value is accepted.
    /// </param>
    public Socks4Authenticator(IUserStore users, bool requireUserId)
    {
        ArgumentNullException.ThrowIfNull(users);
        _users = users;
        _requireUserId = requireUserId;
    }

    /// <summary>Whether the listener demands a recognised <c>USERID</c>.</summary>
    public bool RequiresUserId => _requireUserId;

    /// <summary>Validates the <c>USERID</c> carried in the SOCKS4 request.</summary>
    public async ValueTask<AuthenticationResult> AuthenticateAsync(
        string userId,
        UserStoreContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(userId);

        if (!_requireUserId)
        {
            return AuthenticationResult.Success(ProxyIdentity.Anonymous);
        }

        if (userId.Length == 0)
        {
            return AuthenticationResult.Fail("SOCKS4 request carried no USERID.");
        }

        return await _users.ValidateNameAsync(userId, context, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Builds the authenticator implied by a listener's configured methods.</summary>
    public static Socks4Authenticator ForListener(IUserStore users, ListenerOptions listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        bool anonymous = listener.EffectiveAuthentication.Contains(AuthenticationMethod.Anonymous);
        return new Socks4Authenticator(users, requireUserId: !anonymous);
    }
}
