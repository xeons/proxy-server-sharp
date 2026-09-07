namespace ProxyServerSharp.Configuration;

/// <summary>
/// Where authenticated clients are allowed to go. The defaults block the loopback and
/// link-local ranges so an exposed proxy cannot be used to reach services that trust
/// "requests from localhost".
/// </summary>
public sealed class DestinationPolicyOptions
{
    /// <summary>Destination CIDR blocks clients may reach. Empty means "anywhere not denied".</summary>
    public IList<string> Allow { get; init; } = [];

    /// <summary>Destination CIDR blocks clients may never reach.</summary>
    public IList<string> Deny { get; init; } = [];

    /// <summary>Blocks loopback destinations (<c>127.0.0.0/8</c>, <c>::1</c>).</summary>
    public bool BlockLoopback { get; set; } = true;

    /// <summary>Blocks link-local destinations, including the cloud metadata address <c>169.254.169.254</c>.</summary>
    public bool BlockLinkLocal { get; set; } = true;

    /// <summary>Blocks RFC 1918 and unique-local destinations.</summary>
    public bool BlockPrivateNetworks { get; set; }

    /// <summary>Destination ports clients may reach. Empty means "any port".</summary>
    public IList<int> AllowedPorts { get; init; } = [];

    /// <summary>Destination ports clients may never reach.</summary>
    public IList<int> DeniedPorts { get; init; } = [];
}
