using System.Text;
using Microsoft.Extensions.Logging;
using ProxyServerSharp.Authentication.Http;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Diagnostics;
using ProxyServerSharp.Net;
using ProxyServerSharp.Server;

namespace ProxyServerSharp.Protocol.Http;

/// <summary>
/// An HTTP proxy: <c>CONNECT</c> tunnelling plus absolute-URI forwarding, with Basic, Digest,
/// Bearer and Negotiate proxy authentication. Wrapping the listener in TLS makes it an HTTPS
/// proxy, so the client's credentials are encrypted on the way to the proxy as well.
/// </summary>
/// <remarks>
/// Forwarded (non-<c>CONNECT</c>) requests get a fresh upstream connection each time and are sent
/// with <c>Connection: close</c>. That keeps message framing honest without this proxy having to
/// reimplement chunked and <c>Content-Length</c> parsing in both directions; <c>CONNECT</c>, which
/// is what carries almost all real traffic, is unaffected.
/// </remarks>
public sealed class HttpProxyHandler : IProxyProtocolHandler
{
    /// <summary>Header fields that belong to a single hop and must not be forwarded (RFC 9110 §7.6.1).</summary>
    private static readonly string[] HopByHopHeaders =
    [
        "Connection",
        "Proxy-Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
    ];

    private readonly HttpProxyAuthentication _authentication;

    /// <summary>Creates the handler for one listener.</summary>
    public HttpProxyHandler(HttpProxyAuthentication authentication)
    {
        ArgumentNullException.ThrowIfNull(authentication);
        _authentication = authentication;
    }

    /// <inheritdoc />
    public ProxyProtocol Protocol => ProxyProtocol.Http;

    /// <inheritdoc />
    public async Task HandleAsync(ProxyConnectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        BufferedReadStream client = context.ClientStream;
        using HttpConnectionAuthenticator authenticator = _authentication.CreateConnectionAuthenticator();

        // Authentication may take several round trips (Negotiate) and the client may retry after
        // a 407, so requests are read in a loop until one is both authenticated and actionable.
        while (!cancellationToken.IsCancellationRequested)
        {
            HttpRequestHead? request;
            try
            {
                request = await HttpRequestHead.ReadAsync(client, cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidDataException exception)
            {
                context.Logger.LogInformation("Connection #{Id}: {Reason}", context.Connection.Id, exception.Message);
                await WriteStatusAsync(client, 400, "Bad Request", cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            if (request is null)
            {
                return;
            }

            HttpAuthenticationContext authContext = new(
                context.StoreContext,
                context.Listener.Realm,
                request.Method,
                request.Target);

            HttpAuthenticationOutcome outcome = await authenticator
                .AuthenticateAsync(request, authContext, cancellationToken)
                .ConfigureAwait(false);

            if (!outcome.Succeeded)
            {
                if (outcome.Status == HttpAuthenticationStatus.Failed && outcome.FailureReason is not null)
                {
                    context.Logger.LogWarning(
                        "Connection #{Id} from {Client} failed proxy authentication: {Reason}",
                        context.Connection.Id,
                        context.ClientEndPoint,
                        outcome.FailureReason);
                }

                await WriteChallengeAsync(
                        client,
                        authenticator.BuildChallenges(outcome, authContext),
                        cancellationToken)
                    .ConfigureAwait(false);

                // A 407 keeps the connection open so the client can retry, and so a multi-leg
                // Negotiate exchange keeps its security context.
                continue;
            }

            context.SetIdentity(outcome.Identity!);

            if (request.IsConnect)
            {
                await TunnelAsync(context, request, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!context.Listener.AllowPlainHttpForwarding)
            {
                context.Logger.LogWarning(
                    "Connection #{Id} tried to forward a plain {Method} request, which this listener does not allow.",
                    context.Connection.Id,
                    request.Method);

                await WriteStatusAsync(client, 405, "Method Not Allowed", cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            await ForwardAsync(context, request, cancellationToken).ConfigureAwait(false);
            return;
        }
    }

    private static async Task TunnelAsync(
        ProxyConnectionContext context,
        HttpRequestHead request,
        CancellationToken cancellationToken)
    {
        BufferedReadStream client = context.ClientStream;

        if (!ProxyDestination.TryParseAuthority(request.Target, 443, out ProxyDestination? destination))
        {
            context.Logger.LogInformation(
                "Connection #{Id} sent an unparsable CONNECT target '{Target}'.",
                context.Connection.Id,
                request.Target);

            await WriteStatusAsync(client, 400, "Bad Request", cancellationToken: cancellationToken).ConfigureAwait(false);
            return;
        }

        context.Connection.Destination = destination;

        RemoteConnection remote;
        try
        {
            remote = await context.Connector.ConnectAsync(destination, cancellationToken).ConfigureAwait(false);
        }
        catch (ProxyDestinationException exception)
        {
            context.Logger.LogInformation(
                "Connection #{Id} to {Destination} failed: {Reason}",
                context.Connection.Id,
                destination,
                exception.Message);

            (int status, string reason) = MapStatus(exception.Failure);
            await WriteStatusAsync(client, status, reason, cancellationToken: cancellationToken).ConfigureAwait(false);
            return;
        }

        await using (remote.ConfigureAwait(false))
        {
            await WriteStatusAsync(client, 200, "Connection Established", cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            context.Connection.State = ProxyConnectionState.Relaying;
            context.Logger.LogInformation(
                "Connection #{Id} {Identity} tunnelling {Client} -> {Destination}",
                context.Connection.Id,
                context.Connection.Identity,
                context.ClientEndPoint,
                remote.RemoteEndPoint);

            await TunnelRelay.RunAsync(
                    client,
                    remote.Stream,
                    context.CreateRelayOptions(),
                    context.ClientSocket,
                    remote.Socket,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static async Task ForwardAsync(
        ProxyConnectionContext context,
        HttpRequestHead request,
        CancellationToken cancellationToken)
    {
        BufferedReadStream client = context.ClientStream;

        if (!Uri.TryCreate(request.Target, UriKind.Absolute, out Uri? uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            context.Logger.LogInformation(
                "Connection #{Id} sent request-target '{Target}', which is not an absolute http(s) URI.",
                context.Connection.Id,
                request.Target);

            await WriteStatusAsync(client, 400, "Bad Request", cancellationToken: cancellationToken).ConfigureAwait(false);
            return;
        }

        ProxyDestination destination = ProxyDestination.FromHost(uri.Host, uri.Port);
        context.Connection.Destination = destination;

        RemoteConnection remote;
        try
        {
            remote = await context.Connector.ConnectAsync(destination, cancellationToken).ConfigureAwait(false);
        }
        catch (ProxyDestinationException exception)
        {
            context.Logger.LogInformation(
                "Connection #{Id} to {Destination} failed: {Reason}",
                context.Connection.Id,
                destination,
                exception.Message);

            (int status, string reason) = MapStatus(exception.Failure);
            await WriteStatusAsync(client, status, reason, cancellationToken: cancellationToken).ConfigureAwait(false);
            return;
        }

        await using (remote.ConfigureAwait(false))
        {
            PrepareForForwarding(request, context.ClientEndPoint.Address.ToString());

            // RFC 9112 §3.2.1: an origin server receives the path, not the absolute URI.
            string originForm = uri.PathAndQuery + uri.Fragment;
            await remote.Stream.WriteAsync(request.Serialize(originForm), cancellationToken).ConfigureAwait(false);
            await remote.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            context.Connection.State = ProxyConnectionState.Relaying;
            context.Logger.LogInformation(
                "Connection #{Id} {Identity} forwarding {Method} to {Destination}",
                context.Connection.Id,
                context.Connection.Identity,
                request.Method,
                remote.RemoteEndPoint);

            // Connection: close was forced upstream and down, so both ends signal completion by
            // closing, and the relay can stay framing-agnostic.
            await TunnelRelay.RunAsync(
                    client,
                    remote.Stream,
                    context.CreateRelayOptions(),
                    context.ClientSocket,
                    remote.Socket,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>Strips hop-by-hop fields, adds <c>Via</c>, and forces the connection closed.</summary>
    private static void PrepareForForwarding(HttpRequestHead request, string clientAddress)
    {
        // Fields named by Connection are hop-by-hop too, so collect them before Connection goes.
        List<string> connectionTokens = [];
        foreach (string value in request.Headers.GetAll("Connection").Concat(request.Headers.GetAll("Proxy-Connection")))
        {
            connectionTokens.AddRange(value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        foreach (string header in HopByHopHeaders)
        {
            request.Headers.Remove(header);
        }

        foreach (string token in connectionTokens)
        {
            if (!string.Equals(token, "close", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(token, "keep-alive", StringComparison.OrdinalIgnoreCase))
            {
                request.Headers.Remove(token);
            }
        }

        string via = $"{request.Version.Replace("HTTP/", "", StringComparison.Ordinal)} proxyserversharp";
        string? existingVia = request.Headers.GetFirst("Via");
        request.Headers.Set("Via", existingVia is null ? via : $"{existingVia}, {via}");

        request.Headers.Set("Connection", "close");
        request.Headers.Set("X-Forwarded-For", clientAddress);
    }

    private static (int Status, string Reason) MapStatus(DestinationFailure failure) => failure switch
    {
        DestinationFailure.NotAllowed => (403, "Forbidden"),
        DestinationFailure.HostUnreachable or DestinationFailure.NetworkUnreachable => (502, "Bad Gateway"),
        DestinationFailure.ConnectionRefused => (502, "Bad Gateway"),
        DestinationFailure.TimedOut => (504, "Gateway Timeout"),
        _ => (502, "Bad Gateway"),
    };

    private static async ValueTask WriteChallengeAsync(
        Stream stream,
        IReadOnlyList<string> challenges,
        CancellationToken cancellationToken)
    {
        StringBuilder headers = new();
        foreach (string challenge in challenges)
        {
            headers.Append("Proxy-Authenticate: ").Append(challenge).Append("\r\n");
        }

        // The connection must stay open: a client that has to retry with credentials, and a
        // Negotiate exchange mid-handshake, both depend on it.
        headers.Append("Connection: keep-alive\r\n");

        await WriteStatusAsync(stream, 407, "Proxy Authentication Required", headers.ToString(), cancellationToken)
            .ConfigureAwait(false);
    }

    private static async ValueTask WriteStatusAsync(
        Stream stream,
        int status,
        string reason,
        string? extraHeaders = null,
        CancellationToken cancellationToken = default)
    {
        StringBuilder response = new(128);
        response.Append("HTTP/1.1 ").Append(status).Append(' ').Append(reason).Append("\r\n");

        if (extraHeaders is not null)
        {
            response.Append(extraHeaders);
        }

        // 200 Connection Established introduces a tunnel and must carry no framing headers.
        if (status != 200)
        {
            response.Append("Content-Length: 0\r\n");
        }

        response.Append("\r\n");

        await stream.WriteAsync(Encoding.Latin1.GetBytes(response.ToString()), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
