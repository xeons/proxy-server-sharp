using System.ComponentModel;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.App;

/// <summary>
/// The grid-friendly projection of a <see cref="ListenerOptions"/>: flat, mutable properties a
/// <see cref="DataGridView"/> can bind to, with the list-shaped settings edited beside the grid.
/// </summary>
internal sealed class ListenerRow
{
    internal ListenerRow(ListenerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        Enabled = options.Enabled;
        Name = options.Name;
        Protocol = options.Protocol;
        Address = options.Address;
        Port = options.Port;
        Realm = options.Realm;
        AllowBind = options.AllowBind;
        AllowUdpAssociate = options.AllowUdpAssociate;
        AllowPlainHttpForwarding = options.AllowPlainHttpForwarding;
        Tls = options.Tls.Enabled;
        Authentication = [.. options.Authentication];
        DigestAlgorithms = [.. options.DigestAlgorithms];
        Allow = [.. options.Access.Allow];
        Deny = [.. options.Access.Deny];
        Destinations = options.Destinations;
    }

    public bool Enabled { get; set; }

    public string Name { get; set; }

    public ProxyProtocol Protocol { get; set; }

    public string Address { get; set; }

    public int Port { get; set; }

    /// <summary>The methods offered, shown as a read-only column and edited in the side panel.</summary>
    [Browsable(false)]
    public List<AuthenticationMethod> Authentication { get; }

    /// <summary>The methods offered, rendered for the grid column.</summary>
    public string AuthenticationSummary =>
        Authentication.Count == 0 ? "Anonymous" : string.Join(", ", Authentication);

    [Browsable(false)]
    public string Realm { get; set; }

    [Browsable(false)]
    public List<string> DigestAlgorithms { get; set; }

    [Browsable(false)]
    public List<string> Allow { get; set; }

    [Browsable(false)]
    public List<string> Deny { get; set; }

    [Browsable(false)]
    public bool Tls { get; set; }

    [Browsable(false)]
    public bool AllowBind { get; set; }

    [Browsable(false)]
    public bool AllowUdpAssociate { get; set; }

    [Browsable(false)]
    public bool AllowPlainHttpForwarding { get; set; }

    /// <summary>
    /// Destination rules are not exposed in the UI, so they are carried through untouched rather
    /// than being silently reset to defaults on every save.
    /// </summary>
    [Browsable(false)]
    public DestinationPolicyOptions Destinations { get; }

    internal ListenerOptions ToOptions()
    {
        ListenerOptions options = new()
        {
            Enabled = Enabled,
            Name = Name,
            Protocol = Protocol,
            Address = Address,
            Port = Port,
            Realm = Realm,
            AllowBind = AllowBind,
            AllowUdpAssociate = AllowUdpAssociate,
            AllowPlainHttpForwarding = AllowPlainHttpForwarding,
        };

        options.Tls.Enabled = Tls;
        options.Tls.AllowSelfSigned = Tls;

        foreach (AuthenticationMethod method in Authentication)
        {
            options.Authentication.Add(method);
        }

        foreach (string algorithm in DigestAlgorithms)
        {
            options.DigestAlgorithms.Add(algorithm);
        }

        foreach (string entry in Allow)
        {
            options.Access.Allow.Add(entry);
        }

        foreach (string entry in Deny)
        {
            options.Access.Deny.Add(entry);
        }

        foreach (string entry in Destinations.Allow)
        {
            options.Destinations.Allow.Add(entry);
        }

        foreach (string entry in Destinations.Deny)
        {
            options.Destinations.Deny.Add(entry);
        }

        options.Destinations.BlockLoopback = Destinations.BlockLoopback;
        options.Destinations.BlockLinkLocal = Destinations.BlockLinkLocal;
        options.Destinations.BlockPrivateNetworks = Destinations.BlockPrivateNetworks;

        return options;
    }
}

/// <summary>The grid-friendly projection of a <see cref="ProxyUserOptions"/>.</summary>
internal sealed class UserRow
{
    private readonly IDictionary<string, string> _digestHa1;
    private readonly List<string> _tokenHashes;
    private readonly List<string> _allowedClients;
    private readonly string? _existingHash;

    internal UserRow(ProxyUserOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        Username = options.Username;
        Enabled = options.Enabled;
        Password = options.Password ?? "";
        AllowDigest = options.Password is not null || options.DigestHa1.Count > 0;
        ListenerNames = string.Join(", ", options.Listeners);

        _existingHash = options.PasswordHash;
        _digestHa1 = options.DigestHa1;
        _tokenHashes = [.. options.TokenHashes];
        _allowedClients = [.. options.AllowedClients];
    }

    public bool Enabled { get; set; }

    public string Username { get; set; }

    /// <summary>
    /// The password in plain text. It is hashed on save; it is only kept alongside the hash when
    /// <see cref="AllowDigest"/> is set, because Digest cannot verify a one-way hash.
    /// </summary>
    public string Password { get; set; }

    public bool AllowDigest { get; set; }

    public string ListenerNames { get; set; }

    internal ProxyUserOptions ToOptions()
    {
        ProxyUserOptions options = new()
        {
            Username = Username,
            Enabled = Enabled,

            // An untouched password box leaves the stored verifier alone, so editing a user's
            // listener grants does not wipe their credentials.
            PasswordHash = Password.Length > 0 ? PasswordHasher.Hash(Password) : _existingHash,
            Password = AllowDigest && Password.Length > 0 ? Password : null,
        };

        foreach ((string key, string value) in _digestHa1)
        {
            options.DigestHa1[key] = value;
        }

        foreach (string token in _tokenHashes)
        {
            options.TokenHashes.Add(token);
        }

        foreach (string client in _allowedClients)
        {
            options.AllowedClients.Add(client);
        }

        foreach (string listener in ListenerNames.Split(
            ',',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            options.Listeners.Add(listener);
        }

        return options;
    }
}
