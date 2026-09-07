using System.Net;
using System.Net.Sockets;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Net;

/// <summary>Why a destination was refused.</summary>
public enum DestinationRejection
{
    /// <summary>The destination is permitted.</summary>
    None,

    /// <summary>The address is not in the allow list, or is in the deny list.</summary>
    AddressBlocked,

    /// <summary>The address is loopback and loopback destinations are blocked.</summary>
    LoopbackBlocked,

    /// <summary>The address is link-local and link-local destinations are blocked.</summary>
    LinkLocalBlocked,

    /// <summary>The address is in a private range and private destinations are blocked.</summary>
    PrivateNetworkBlocked,

    /// <summary>The port is not in the allow list, or is in the deny list.</summary>
    PortBlocked,
}

/// <summary>
/// Decides which destinations an authenticated client may reach.
/// </summary>
/// <remarks>
/// The check runs against the resolved IP address, not the requested host name, so a name that
/// resolves to a blocked address cannot be used to walk around the policy.
/// </remarks>
public sealed class DestinationPolicy
{
    private static readonly IPNetwork Ipv4Loopback = IPNetwork.Parse("127.0.0.0/8");
    private static readonly IPNetwork Ipv4LinkLocal = IPNetwork.Parse("169.254.0.0/16");
    private static readonly IPNetwork[] Ipv4Private =
    [
        IPNetwork.Parse("10.0.0.0/8"),
        IPNetwork.Parse("172.16.0.0/12"),
        IPNetwork.Parse("192.168.0.0/16"),
        IPNetwork.Parse("100.64.0.0/10"),
    ];

    private static readonly IPNetwork Ipv6UniqueLocal = IPNetwork.Parse("fc00::/7");

    private readonly AccessControlList _addresses;
    private readonly HashSet<int> _allowedPorts;
    private readonly HashSet<int> _deniedPorts;
    private readonly DestinationPolicyOptions _options;

    /// <summary>Builds a policy from bound configuration.</summary>
    public DestinationPolicy(DestinationPolicyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _addresses = AccessControlList.Parse(options.Allow, options.Deny);
        _allowedPorts = [.. options.AllowedPorts];
        _deniedPorts = [.. options.DeniedPorts];
    }

    /// <summary>A policy that permits every destination, for tests and tooling.</summary>
    public static DestinationPolicy PermitAll { get; } = new(new DestinationPolicyOptions
    {
        BlockLoopback = false,
        BlockLinkLocal = false,
        BlockPrivateNetworks = false,
    });

    /// <summary>Evaluates one resolved destination.</summary>
    public DestinationRejection Evaluate(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (_deniedPorts.Contains(port) || (_allowedPorts.Count > 0 && !_allowedPorts.Contains(port)))
        {
            return DestinationRejection.PortBlocked;
        }

        IPAddress candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        if (_options.BlockLoopback && IsLoopback(candidate))
        {
            return DestinationRejection.LoopbackBlocked;
        }

        if (_options.BlockLinkLocal && IsLinkLocal(candidate))
        {
            return DestinationRejection.LinkLocalBlocked;
        }

        if (_options.BlockPrivateNetworks && IsPrivate(candidate))
        {
            return DestinationRejection.PrivateNetworkBlocked;
        }

        return _addresses.IsAllowed(candidate) ? DestinationRejection.None : DestinationRejection.AddressBlocked;
    }

    private static bool IsLoopback(IPAddress address) =>
        IPAddress.IsLoopback(address)
        || (address.AddressFamily == AddressFamily.InterNetwork && Ipv4Loopback.Contains(address));

    private static bool IsLinkLocal(IPAddress address) =>
        address.IsIPv6LinkLocal
        || (address.AddressFamily == AddressFamily.InterNetwork && Ipv4LinkLocal.Contains(address));

    private static bool IsPrivate(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6SiteLocal || Ipv6UniqueLocal.Contains(address);
        }

        foreach (IPNetwork network in Ipv4Private)
        {
            if (network.Contains(address))
            {
                return true;
            }
        }

        return false;
    }
}
