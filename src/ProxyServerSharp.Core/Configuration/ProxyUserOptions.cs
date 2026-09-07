namespace ProxyServerSharp.Configuration;

/// <summary>The configuration-file shape of a proxy account.</summary>
public sealed class ProxyUserOptions
{
    /// <summary>The login name presented by the client.</summary>
    public string Username { get; set; } = "";

    /// <summary>
    /// A PBKDF2 verifier produced by <see cref="Authentication.PasswordHasher"/>. Preferred over
    /// <see cref="Password"/> everywhere except Digest, which cannot use a one-way hash.
    /// </summary>
    public string? PasswordHash { get; set; }

    /// <summary>
    /// A plaintext password. Required only if this account must work with Digest and no
    /// <see cref="DigestHa1"/> is supplied; prefer <see cref="PasswordHash"/> otherwise.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Precomputed Digest <c>HA1</c> values keyed by <c>"&lt;realm&gt;:&lt;algorithm&gt;"</c>, letting an
    /// account support Digest without the server storing a reversible password.
    /// </summary>
    public IDictionary<string, string> DigestHa1 { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Bearer tokens accepted for this account, hashed the same way as <see cref="PasswordHash"/>.</summary>
    public IList<string> TokenHashes { get; init; } = [];

    /// <summary>Whether the account may authenticate at all.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Listener names this account may use. Empty means every listener.</summary>
    public IList<string> Listeners { get; init; } = [];

    /// <summary>Client CIDR blocks this account may authenticate from. Empty means anywhere.</summary>
    public IList<string> AllowedClients { get; init; } = [];
}
