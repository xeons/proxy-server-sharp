namespace ProxyServerSharp.Authentication;

/// <summary>The outcome of a credential check.</summary>
public readonly struct AuthenticationResult
{
    private AuthenticationResult(ProxyIdentity? identity, string? failureReason)
    {
        Identity = identity;
        FailureReason = failureReason;
    }

    /// <summary>The authenticated principal, or <see langword="null"/> when the check failed.</summary>
    public ProxyIdentity? Identity { get; }

    /// <summary>Why the check failed, for the log. Never sent to the client.</summary>
    public string? FailureReason { get; }

    /// <summary>Whether the client proved its identity.</summary>
    public bool Succeeded => Identity is not null;

    /// <summary>The client proved its identity.</summary>
    public static AuthenticationResult Success(ProxyIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return new AuthenticationResult(identity, null);
    }

    /// <summary>The client failed the check.</summary>
    public static AuthenticationResult Fail(string reason) => new(null, reason);
}
