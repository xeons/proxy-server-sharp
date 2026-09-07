using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication;

/// <summary>The authenticated principal behind a connection.</summary>
/// <param name="Name">The account name, or <c>"anonymous"</c> for an open listener.</param>
/// <param name="Method">The scheme that produced this identity.</param>
public sealed record ProxyIdentity(string Name, AuthenticationMethod Method)
{
    /// <summary>The principal used when a listener offers <see cref="AuthenticationMethod.Anonymous"/>.</summary>
    public static ProxyIdentity Anonymous { get; } = new("anonymous", AuthenticationMethod.Anonymous);

    /// <summary>Whether this identity came from an open listener rather than a credential check.</summary>
    public bool IsAnonymous => Method == AuthenticationMethod.Anonymous;

    /// <inheritdoc />
    public override string ToString() => $"{Name} ({Method})";
}
