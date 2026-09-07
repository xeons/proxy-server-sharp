using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ProxyServerSharp.Tests;

/// <summary>
/// A small HTTP/1.1 origin server that keeps connections alive, so tests can prove the proxy
/// really reuses an upstream connection rather than opening one per request.
/// </summary>
internal sealed class HttpOriginServer : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _acceptLoop;
    private readonly Func<HttpOriginRequest, HttpOriginResponse> _responder;
    private readonly List<string> _requests = [];
    private readonly Lock _sync = new();

    private int _connections;

    private HttpOriginServer(Socket listener, Func<HttpOriginRequest, HttpOriginResponse> responder)
    {
        _listener = listener;
        _responder = responder;
        EndPoint = (IPEndPoint)listener.LocalEndPoint!;
        _acceptLoop = AcceptAsync();
    }

    /// <summary>Where the origin server is listening.</summary>
    internal IPEndPoint EndPoint { get; }

    /// <summary>How many TCP connections have been accepted.</summary>
    internal int ConnectionCount => Volatile.Read(ref _connections);

    /// <summary>The request heads received, in order.</summary>
    internal IReadOnlyList<string> Requests
    {
        get
        {
            lock (_sync)
            {
                return [.. _requests];
            }
        }
    }

    /// <summary>The most recent request head.</summary>
    internal string LastRequest
    {
        get
        {
            lock (_sync)
            {
                return _requests.Count > 0 ? _requests[^1] : "";
            }
        }
    }

    /// <summary>Starts a server answering every request with the same body.</summary>
    internal static HttpOriginServer Start(string body = "hello from origin") =>
        Start(_ => HttpOriginResponse.Text(body));

    /// <summary>Starts a server whose reply is chosen per request.</summary>
    internal static HttpOriginServer Start(Func<HttpOriginRequest, HttpOriginResponse> responder)
    {
        Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(16);
        return new HttpOriginServer(listener, responder);
    }

    public async ValueTask DisposeAsync()
    {
        await _shutdown.CancelAsync();
        _listener.Close();

        try
        {
            await _acceptLoop;
        }
        catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException)
        {
            // Shutting down.
        }

        _shutdown.Dispose();
    }

    private async Task AcceptAsync()
    {
        while (!_shutdown.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(_shutdown.Token);
            }
            catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            Interlocked.Increment(ref _connections);
            _ = ServeAsync(client);
        }
    }

    private async Task ServeAsync(Socket client)
    {
        using (client)
        {
            try
            {
                await using NetworkStream stream = new(client, ownsSocket: false);
                LineReader reader = new(stream);

                // Serve requests until the client stops sending or asks to close.
                while (!_shutdown.IsCancellationRequested)
                {
                    HttpOriginRequest? request = await reader.ReadRequestAsync(_shutdown.Token);
                    if (request is null)
                    {
                        return;
                    }

                    lock (_sync)
                    {
                        _requests.Add(request.Head);
                    }

                    HttpOriginResponse response = _responder(request);
                    await stream.WriteAsync(response.ToBytes(), _shutdown.Token);
                    await stream.FlushAsync(_shutdown.Token);

                    if (response.CloseAfter || request.WantsClose)
                    {
                        client.Shutdown(SocketShutdown.Send);
                        return;
                    }
                }
            }
            catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException or IOException or InvalidDataException)
            {
                // The client went away.
            }
        }
    }

    /// <summary>Reads request heads and bodies off a connection.</summary>
    private sealed class LineReader(Stream stream)
    {
        private readonly byte[] _buffer = new byte[16384];
        private int _start;
        private int _end;

        internal async Task<HttpOriginRequest?> ReadRequestAsync(CancellationToken cancellationToken)
        {
            StringBuilder head = new();
            string? line;

            while ((line = await ReadLineAsync(cancellationToken)) is { Length: > 0 })
            {
                head.Append(line).Append("\r\n");
            }

            if (line is null && head.Length == 0)
            {
                return null;
            }

            string headText = head.ToString();
            string body = await ReadBodyAsync(headText, cancellationToken);

            return new HttpOriginRequest(headText, body);
        }

        private async Task<string> ReadBodyAsync(string head, CancellationToken cancellationToken)
        {
            if (Header(head, "Transfer-Encoding") is { } te
                && te.Contains("chunked", StringComparison.OrdinalIgnoreCase))
            {
                StringBuilder body = new();

                while (true)
                {
                    string size = await ReadLineAsync(cancellationToken) ?? "0";
                    int semicolon = size.IndexOf(';', StringComparison.Ordinal);
                    int length = Convert.ToInt32(semicolon < 0 ? size : size[..semicolon], 16);

                    if (length == 0)
                    {
                        // Consume trailers up to the blank line.
                        while (await ReadLineAsync(cancellationToken) is { Length: > 0 })
                        {
                        }

                        return body.ToString();
                    }

                    body.Append(await ReadExactAsync(length, cancellationToken));
                    await ReadLineAsync(cancellationToken);
                }
            }

            if (Header(head, "Content-Length") is { } cl && int.TryParse(cl.Trim(), out int contentLength))
            {
                return await ReadExactAsync(contentLength, cancellationToken);
            }

            return "";
        }

        private async Task<string> ReadExactAsync(int count, CancellationToken cancellationToken)
        {
            StringBuilder value = new(count);

            while (value.Length < count)
            {
                if (_start == _end && !await FillAsync(cancellationToken))
                {
                    break;
                }

                int take = Math.Min(count - value.Length, _end - _start);
                value.Append(Encoding.Latin1.GetString(_buffer, _start, take));
                _start += take;
            }

            return value.ToString();
        }

        private async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
        {
            StringBuilder line = new();

            while (true)
            {
                if (_start == _end && !await FillAsync(cancellationToken))
                {
                    return line.Length == 0 ? null : line.ToString();
                }

                byte b = _buffer[_start++];
                if (b == (byte)'\n')
                {
                    return line.ToString().TrimEnd('\r');
                }

                line.Append((char)b);
            }
        }

        private async Task<bool> FillAsync(CancellationToken cancellationToken)
        {
            _start = 0;
            _end = await stream.ReadAsync(_buffer, cancellationToken);
            return _end > 0;
        }

        private static string? Header(string head, string name)
        {
            foreach (string line in head.Split("\r\n"))
            {
                if (line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
                {
                    return line[(name.Length + 1)..];
                }
            }

            return null;
        }
    }
}

/// <summary>One request the origin server received.</summary>
/// <param name="Head">The request line and header block.</param>
/// <param name="Body">The decoded body, with any chunked framing removed.</param>
internal sealed record HttpOriginRequest(string Head, string Body)
{
    /// <summary>The request method.</summary>
    internal string Method => Head.Split(' ')[0];

    /// <summary>Whether the client asked for the connection to close.</summary>
    internal bool WantsClose => Head.Contains("Connection: close", StringComparison.OrdinalIgnoreCase);
}

/// <summary>A reply for the origin server to send.</summary>
internal sealed class HttpOriginResponse
{
    private HttpOriginResponse(string raw, bool closeAfter)
    {
        Raw = raw;
        CloseAfter = closeAfter;
    }

    /// <summary>The bytes to send, verbatim.</summary>
    internal string Raw { get; }

    /// <summary>Whether the connection is closed after sending.</summary>
    internal bool CloseAfter { get; }

    /// <summary>A <c>Content-Length</c> framed response that keeps the connection alive.</summary>
    internal static HttpOriginResponse Text(string body, int status = 200) =>
        new(
            $"HTTP/1.1 {status} OK\r\nContent-Length: {body.Length}\r\nConnection: keep-alive\r\n\r\n{body}",
            closeAfter: false);

    /// <summary>A chunked response, split into the given pieces.</summary>
    internal static HttpOriginResponse Chunked(params string[] chunks)
    {
        StringBuilder raw = new("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n");

        foreach (string chunk in chunks)
        {
            raw.Append(chunk.Length.ToString("x", System.Globalization.CultureInfo.InvariantCulture))
                .Append("\r\n").Append(chunk).Append("\r\n");
        }

        raw.Append("0\r\n\r\n");
        return new HttpOriginResponse(raw.ToString(), closeAfter: false);
    }

    /// <summary>A response with no framing headers, delimited by the connection closing.</summary>
    internal static HttpOriginResponse UntilClose(string body) =>
        new($"HTTP/1.1 200 OK\r\n\r\n{body}", closeAfter: true);

    /// <summary>An interim <c>100 Continue</c> followed by a final response.</summary>
    internal static HttpOriginResponse ContinueThen(string body) =>
        new(
            "HTTP/1.1 100 Continue\r\n\r\n"
            + $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nConnection: keep-alive\r\n\r\n{body}",
            closeAfter: false);

    /// <summary>A <c>101</c> switch, after which the connection is a raw tunnel.</summary>
    internal static HttpOriginResponse SwitchingProtocols(string protocol) =>
        new(
            $"HTTP/1.1 101 Switching Protocols\r\nUpgrade: {protocol}\r\nConnection: Upgrade\r\n\r\n",
            closeAfter: false);

    /// <summary>Renders the response.</summary>
    internal byte[] ToBytes() => Encoding.Latin1.GetBytes(Raw);
}
