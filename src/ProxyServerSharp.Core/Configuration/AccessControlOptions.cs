using System.Net;

namespace ProxyServerSharp.Configuration;

/// <summary>
/// A CIDR allow/deny list evaluated before any protocol bytes are read.
/// Deny wins over allow; an empty <see cref="Allow"/> list permits every address.
/// </summary>
public sealed class AccessControlOptions
{
    /// <summary>CIDR blocks or bare addresses permitted to connect. Empty means "any".</summary>
    public IList<string> Allow { get; init; } = [];

    /// <summary>CIDR blocks or bare addresses always refused, even when listed in <see cref="Allow"/>.</summary>
    public IList<string> Deny { get; init; } = [];

    /// <summary>Parses the string form into a matcher, throwing on malformed entries.</summary>
    public AccessControlList Build() => AccessControlList.Parse(Allow, Deny);
}

/// <summary>An immutable, parsed <see cref="AccessControlOptions"/>.</summary>
public sealed class AccessControlList
{
    /// <summary>An ACL that permits every address.</summary>
    public static AccessControlList PermitAll { get; } = new([], []);

    private readonly IPNetwork[] _allow;
    private readonly IPNetwork[] _deny;

    private AccessControlList(IPNetwork[] allow, IPNetwork[] deny)
    {
        _allow = allow;
        _deny = deny;
    }

    /// <summary>Parses CIDR blocks and bare IP addresses into an <see cref="AccessControlList"/>.</summary>
    /// <exception cref="FormatException">An entry is neither a CIDR block nor an IP address.</exception>
    public static AccessControlList Parse(IEnumerable<string> allow, IEnumerable<string> deny) =>
        new([.. allow.Select(ParseEntry)], [.. deny.Select(ParseEntry)]);

    /// <summary>Returns <see langword="true"/> when <paramref name="address"/> may use the listener.</summary>
    public bool IsAllowed(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        // IPv4-mapped IPv6 (::ffff:127.0.0.1) must match IPv4 rules, otherwise a dual-stack
        // listener would silently ignore every rule an operator writes.
        IPAddress candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        foreach (IPNetwork network in _deny)
        {
            if (Contains(network, candidate))
            {
                return false;
            }
        }

        if (_allow.Length == 0)
        {
            return true;
        }

        foreach (IPNetwork network in _allow)
        {
            if (Contains(network, candidate))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Contains(IPNetwork network, IPAddress address) =>
        network.BaseAddress.AddressFamily == address.AddressFamily && network.Contains(address);

    private static IPNetwork ParseEntry(string entry)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(entry);
        string trimmed = entry.Trim();

        if (trimmed.Contains('/', StringComparison.Ordinal))
        {
            return IPNetwork.Parse(trimmed);
        }

        IPAddress address = IPAddress.Parse(trimmed);
        int hostBits = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        return new IPNetwork(address, hostBits);
    }
}
