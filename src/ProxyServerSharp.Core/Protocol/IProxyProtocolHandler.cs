using ProxyServerSharp.Configuration;
using ProxyServerSharp.Server;

namespace ProxyServerSharp.Protocol;

/// <summary>Speaks one proxy protocol to an accepted client.</summary>
/// <remarks>
/// Replaces the original <c>IProxyCore</c>, which owned its own listening socket, accept loop and
/// thread pool. Accepting, connection limits and lifetime now belong to
/// <see cref="ProxyListener"/>, leaving a handler responsible only for the conversation on one
/// already-accepted connection.
/// </remarks>
public interface IProxyProtocolHandler
{
    /// <summary>The protocol this handler implements.</summary>
    ProxyProtocol Protocol { get; }

    /// <summary>Runs the whole conversation for one client connection.</summary>
    /// <param name="context">The connection's streams, configuration and services.</param>
    /// <param name="cancellationToken">Cancelled when the server is shutting down.</param>
    Task HandleAsync(ProxyConnectionContext context, CancellationToken cancellationToken);
}
