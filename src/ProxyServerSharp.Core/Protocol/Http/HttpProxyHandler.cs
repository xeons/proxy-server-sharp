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
/// Forwarded requests are framed properly — <c>Content-Length</c>, chunked, or until-close — so
/// the client connection and the upstream connection are both kept alive across requests, interim
/// <c>1xx</c> responses are relayed, and a <c>101</c> upgrade switches the connection to a raw
/// tunnel.
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

        // One upstream connection is kept across requests and reopened when the destination
        // changes or the far end hangs up.
        UpstreamConnection upstream = new(context);

        try
        {
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

                HttpBodyFraming requestBody;
                try
                {
                    requestBody = HttpMessageBody.ForRequest(request);
                }
                catch (InvalidDataException exception)
                {
                    context.Logger.LogInformation("Connection #{Id}: {Reason}", context.Connection.Id, exception.Message);
                    await WriteStatusAsync(client, 400, "Bad Request", cancellationToken: cancellationToken)
                        .ConfigureAwait(false);
                    return;
                }

                // Only Digest auth-int ever pulls on this, and only when the listener enables it.
                RequestBodyBuffer body = new(client, requestBody, context.Options.MaxBufferedRequestBody);

                HttpAuthenticationContext authContext = new(
                    context.StoreContext,
                    context.Listener.Realm,
                    request.Method,
                    request.Target,
                    context.Listener.AllowDigestAuthInt ? body.EnsureAsync : null);

                HttpAuthenticationOutcome outcome = await authenticator
                    .AuthenticateAsync(request, authContext, cancellationToken)
                    .ConfigureAwait(false);

                if (!outcome.Succeeded)
                {
                    if (!await RejectAsync(
                            context, client, requestBody, body, authenticator, outcome, authContext, cancellationToken)
                        .ConfigureAwait(false))
                    {
                        return;
                    }

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

                if (!await ForwardAsync(context, upstream, request, requestBody, body, cancellationToken)
                    .ConfigureAwait(false))
                {
                    return;
                }
            }
        }
        finally
        {
            await upstream.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Answers a failed credential with a <c>407</c>.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> if the connection can be reused for the client's retry.
    /// A request body has to be drained first, or its bytes would be read as the next request.
    /// </returns>
    private static async ValueTask<bool> RejectAsync(
        ProxyConnectionContext context,
        BufferedReadStream client,
        HttpBodyFraming framing,
        RequestBodyBuffer body,
        HttpConnectionAuthenticator authenticator,
        HttpAuthenticationOutcome outcome,
        HttpAuthenticationContext authContext,
        CancellationToken cancellationToken)
    {
        if (outcome.Status == HttpAuthenticationStatus.Failed && outcome.FailureReason is not null)
        {
            context.Logger.LogWarning(
                "Connection #{Id} from {Client} failed proxy authentication: {Reason}",
                context.Connection.Id,
                context.ClientEndPoint,
                outcome.FailureReason);
        }

        // Draining an unbounded body to keep one connection alive is not worth it; tell the
        // client to reconnect instead. A body already buffered for auth-int needs no draining.
        bool reusable = body.IsBuffered || framing.Kind switch
        {
            HttpBodyKind.None => true,
            HttpBodyKind.ContentLength => framing.Length <= MaxDrainableBody,
            _ => false,
        };

        await WriteChallengeAsync(
                client,
                authenticator.BuildChallenges(outcome, authContext),
                reusable,
                cancellationToken)
            .ConfigureAwait(false);

        if (!reusable)
        {
            return false;
        }

        if (!body.IsBuffered)
        {
            await HttpMessageBody
                .CopyAsync(client, Stream.Null, framing, context.Options.BufferSize, cancellationToken)
                .ConfigureAwait(false);
        }

        return true;
    }

    /// <summary>The largest request body drained so a 407 can keep the connection open.</summary>
    private const int MaxDrainableBody = 64 * 1024;

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

    /// <summary>Forwards one request and its response.</summary>
    /// <returns><see langword="true"/> if the client connection can carry another request.</returns>
    private static async Task<bool> ForwardAsync(
        ProxyConnectionContext context,
        UpstreamConnection upstream,
        HttpRequestHead request,
        HttpBodyFraming requestBody,
        RequestBodyBuffer body,
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
            return false;
        }

        ProxyDestination destination = ProxyDestination.FromHost(uri.Host, uri.Port);
        context.Connection.Destination = destination;

        bool clientKeepAlive = WantsKeepAlive(request.Version, request.Headers);
        bool upgrading = IsUpgradeRequest(request);

        string? upgradeProtocol = upgrading ? request.Headers.GetFirst("Upgrade") : null;
        byte[] head = PrepareForForwarding(request, uri, context.ClientEndPoint.Address.ToString(), upgradeProtocol);

        BufferedReadStream remote;
        try
        {
            remote = await upstream.SendHeadAsync(destination, head, cancellationToken).ConfigureAwait(false);
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
            return clientKeepAlive;
        }

        context.Connection.State = ProxyConnectionState.Relaying;
        context.Logger.LogInformation(
            "Connection #{Id} {Identity} forwarding {Method} to {Destination}",
            context.Connection.Id,
            context.Connection.Identity,
            request.Method,
            upstream.EndPoint);

        try
        {
            if (body.Content is { } buffered)
            {
                // auth-int already pulled the body into memory, so it is replayed from there.
                await remote.WriteAsync(buffered, cancellationToken).ConfigureAwait(false);
                await remote.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await HttpMessageBody
                    .CopyAsync(client, remote, requestBody, context.Options.BufferSize, cancellationToken)
                    .ConfigureAwait(false);
            }

            HttpResponseHead response = await ReadFinalResponseAsync(
                    context, client, remote, request.Method, cancellationToken)
                .ConfigureAwait(false);

            if (response.IsUpgrade && upgrading)
            {
                await UpgradeAsync(context, response, remote, upstream, cancellationToken).ConfigureAwait(false);
                return false;
            }

            HttpBodyFraming responseBody = HttpMessageBody.ForResponse(response, request.Method);
            bool upstreamKeepAlive = WantsKeepAlive(response.Version, response.Headers) && !responseBody.RequiresClose;

            // The proxy decides its own connection policy with the client, independent of the
            // one it has upstream.
            bool keepAlive = clientKeepAlive && !responseBody.RequiresClose;
            PrepareForClient(response, keepAlive);

            await client.WriteAsync(response.Serialize(), cancellationToken).ConfigureAwait(false);
            await HttpMessageBody
                .CopyAsync(remote, client, responseBody, context.Options.BufferSize, cancellationToken)
                .ConfigureAwait(false);

            upstream.KeepAlive = upstreamKeepAlive;
            return keepAlive;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or EndOfStreamException)
        {
            context.Logger.LogInformation(
                "Connection #{Id} upstream exchange with {Destination} failed: {Reason}",
                context.Connection.Id,
                destination,
                exception.Message);

            upstream.KeepAlive = false;
            return false;
        }
    }

    /// <summary>Relays interim <c>1xx</c> responses and returns the final one.</summary>
    private static async Task<HttpResponseHead> ReadFinalResponseAsync(
        ProxyConnectionContext context,
        Stream client,
        BufferedReadStream remote,
        string method,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            HttpResponseHead response = await HttpResponseHead.ReadAsync(remote, cancellationToken)
                .ConfigureAwait(false);

            // 101 ends the sequence even though it is 1xx: it is the switch itself, not an interim
            // status on the way to another response.
            if (!response.IsInformational || response.IsUpgrade)
            {
                return response;
            }

            // Pass "100 Continue" and friends straight through so the client knows to send its body.
            context.Logger.LogDebug(
                "Connection #{Id} relaying interim {Status} for {Method}.",
                context.Connection.Id,
                response.Status,
                method);

            await client.WriteAsync(response.Serialize(), cancellationToken).ConfigureAwait(false);
            await client.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Completes a protocol upgrade, such as a WebSocket handshake, by forwarding the <c>101</c>
    /// and then relaying raw bytes in both directions.
    /// </summary>
    private static async Task UpgradeAsync(
        ProxyConnectionContext context,
        HttpResponseHead response,
        Stream remote,
        UpstreamConnection upstream,
        CancellationToken cancellationToken)
    {
        BufferedReadStream client = context.ClientStream;

        await client.WriteAsync(response.Serialize(), cancellationToken).ConfigureAwait(false);
        await client.FlushAsync(cancellationToken).ConfigureAwait(false);

        context.Logger.LogInformation(
            "Connection #{Id} {Identity} upgraded to '{Protocol}' with {Destination}",
            context.Connection.Id,
            context.Connection.Identity,
            response.Headers.GetFirst("Upgrade") ?? "unknown",
            upstream.EndPoint);

        await TunnelRelay.RunAsync(
                client,
                remote,
                context.CreateRelayOptions(),
                context.ClientSocket,
                upstream.Socket,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Strips hop-by-hop fields, adds <c>Via</c>, and rewrites the target to origin form.</summary>
    private static byte[] PrepareForForwarding(
        HttpRequestHead request,
        Uri uri,
        string clientAddress,
        string? upgradeProtocol)
    {
        // Fields named by Connection are hop-by-hop too, so collect them before Connection goes.
        List<string> connectionTokens = [];
        foreach (string value in request.Headers.GetAll("Connection").Concat(request.Headers.GetAll("Proxy-Connection")))
        {
            connectionTokens.AddRange(value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        bool chunked = HttpMessageBody.IsChunked(request.Headers);

        foreach (string header in HopByHopHeaders)
        {
            request.Headers.Remove(header);
        }

        foreach (string token in connectionTokens)
        {
            if (!string.Equals(token, "close", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(token, "keep-alive", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(token, "upgrade", StringComparison.OrdinalIgnoreCase))
            {
                request.Headers.Remove(token);
            }
        }

        // Transfer-Encoding is hop-by-hop but the body really is chunked on the wire, so it has to
        // be reinstated for the next hop to frame it the same way.
        if (chunked)
        {
            request.Headers.Set("Transfer-Encoding", "chunked");
        }

        // RFC 9110 §7.8: a proxy that supports upgrades forwards the request's Upgrade offer.
        if (upgradeProtocol is not null)
        {
            request.Headers.Set("Upgrade", upgradeProtocol);
            request.Headers.Set("Connection", "Upgrade");
        }
        else
        {
            request.Headers.Set("Connection", "keep-alive");
        }

        string via = $"{request.Version.Replace("HTTP/", "", StringComparison.Ordinal)} proxyserversharp";
        string? existingVia = request.Headers.GetFirst("Via");
        request.Headers.Set("Via", existingVia is null ? via : $"{existingVia}, {via}");
        request.Headers.Set("X-Forwarded-For", clientAddress);

        // RFC 9112 §3.2.1: an origin server receives the path, not the absolute URI.
        return request.Serialize(uri.PathAndQuery + uri.Fragment);
    }

    /// <summary>Rewrites a response for the client hop.</summary>
    private static void PrepareForClient(HttpResponseHead response, bool keepAlive)
    {
        bool chunked = HttpMessageBody.IsChunked(response.Headers);

        foreach (string header in HopByHopHeaders)
        {
            response.Headers.Remove(header);
        }

        if (chunked)
        {
            response.Headers.Set("Transfer-Encoding", "chunked");
        }

        response.Headers.Set("Connection", keepAlive ? "keep-alive" : "close");

        string via = $"{response.Version.Replace("HTTP/", "", StringComparison.Ordinal)} proxyserversharp";
        string? existingVia = response.Headers.GetFirst("Via");
        response.Headers.Set("Via", existingVia is null ? via : $"{existingVia}, {via}");
    }

    private static bool IsUpgradeRequest(HttpRequestHead request)
    {
        if (!request.Headers.Contains("Upgrade"))
        {
            return false;
        }

        foreach (string value in request.Headers.GetAll("Connection"))
        {
            foreach (string token in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (string.Equals(token, "upgrade", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>Applies the RFC 9112 §9.3 persistence defaults for a version and header block.</summary>
    private static bool WantsKeepAlive(string version, HttpHeaders headers)
    {
        bool close = false;
        bool keepAlive = false;

        foreach (string value in headers.GetAll("Connection").Concat(headers.GetAll("Proxy-Connection")))
        {
            foreach (string token in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (string.Equals(token, "close", StringComparison.OrdinalIgnoreCase))
                {
                    close = true;
                }
                else if (string.Equals(token, "keep-alive", StringComparison.OrdinalIgnoreCase))
                {
                    keepAlive = true;
                }
            }
        }

        if (close)
        {
            return false;
        }

        // HTTP/1.1 persists by default; HTTP/1.0 has to ask.
        return string.Equals(version, "HTTP/1.0", StringComparison.OrdinalIgnoreCase) ? keepAlive : true;
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
        bool keepAlive,
        CancellationToken cancellationToken)
    {
        StringBuilder headers = new();
        foreach (string challenge in challenges)
        {
            headers.Append("Proxy-Authenticate: ").Append(challenge).Append("\r\n");
        }

        // A client that has to retry with credentials, and a Negotiate exchange mid-handshake,
        // both depend on the connection staying open.
        headers.Append("Connection: ").Append(keepAlive ? "keep-alive" : "close").Append("\r\n");

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
