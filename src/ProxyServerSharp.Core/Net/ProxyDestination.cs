using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace ProxyServerSharp.Net;

/// <summary>
/// Where a client asked to go: either a literal address or a host name the proxy resolves itself.
/// </summary>
public sealed class ProxyDestination : IEquatable<ProxyDestination>
{
    private ProxyDestination(string host, IPAddress? address, int port)
    {
        Host = host;
        Address = address;
        Port = port;
    }

    /// <summary>The host as the client wrote it: a name, or an address in string form.</summary>
    public string Host { get; }

    /// <summary>The literal address, when the client supplied one rather than a name.</summary>
    public IPAddress? Address { get; }

    /// <summary>The destination port.</summary>
    public int Port { get; }

    /// <summary>Whether the destination still needs a DNS lookup.</summary>
    [MemberNotNullWhen(false, nameof(Address))]
    public bool RequiresResolution => Address is null;

    /// <summary>Creates a destination from a literal address.</summary>
    public static ProxyDestination FromAddress(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        ValidatePort(port);
        return new ProxyDestination(address.ToString(), address, port);
    }

    /// <summary>
    /// Creates a destination from a host name, collapsing to
    /// <see cref="FromAddress"/> when the name is really an address literal.
    /// </summary>
    public static ProxyDestination FromHost(string host, int port)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ValidatePort(port);

        // Strip the brackets an IPv6 literal wears inside a URI authority.
        string trimmed = host.Trim();
        if (trimmed.Length > 2 && trimmed[0] == '[' && trimmed[^1] == ']')
        {
            trimmed = trimmed[1..^1];
        }

        return IPAddress.TryParse(trimmed, out IPAddress? address)
            ? FromAddress(address, port)
            : new ProxyDestination(trimmed, null, port);
    }

    /// <summary>Parses an <c>authority</c> such as <c>example.com:443</c> or <c>[::1]:8080</c>.</summary>
    public static bool TryParseAuthority(string? authority, int defaultPort, [NotNullWhen(true)] out ProxyDestination? destination)
    {
        destination = null;

        if (string.IsNullOrWhiteSpace(authority))
        {
            return false;
        }

        string value = authority.Trim();
        string host;
        int port = defaultPort;

        if (value.StartsWith('['))
        {
            int close = value.IndexOf(']', StringComparison.Ordinal);
            if (close < 0)
            {
                return false;
            }

            host = value[..(close + 1)];
            if (close + 1 < value.Length)
            {
                if (value[close + 1] != ':' || !int.TryParse(value[(close + 2)..], out port))
                {
                    return false;
                }
            }
        }
        else
        {
            int colon = value.LastIndexOf(':');

            // An unbracketed value with several colons is a bare IPv6 literal, not host:port.
            if (colon < 0 || value.IndexOf(':', StringComparison.Ordinal) != colon)
            {
                host = value;
            }
            else if (!int.TryParse(value[(colon + 1)..], out port))
            {
                return false;
            }
            else
            {
                host = value[..colon];
            }
        }

        if (host.Length == 0 || port is < 1 or > 65535)
        {
            return false;
        }

        destination = FromHost(host, port);
        return true;
    }

    /// <inheritdoc />
    public bool Equals(ProxyDestination? other) =>
        other is not null
        && Port == other.Port
        && string.Equals(Host, other.Host, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as ProxyDestination);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Host.ToLowerInvariant(), Port);

    /// <inheritdoc />
    public override string ToString() =>
        Host.Contains(':', StringComparison.Ordinal) ? $"[{Host}]:{Port}" : $"{Host}:{Port}";

    /// <summary>
    /// Validates a port, allowing zero. SOCKS5 <c>BIND</c> and <c>UDP ASSOCIATE</c> requests carry
    /// <c>0.0.0.0:0</c> when the client cannot yet name the peer it expects, so zero has to survive
    /// parsing; the connector rejects it later if an outbound connection is actually attempted.
    /// </summary>
    private static void ValidatePort(int port)
    {
        if (port is < 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be between 0 and 65535.");
        }
    }
}
