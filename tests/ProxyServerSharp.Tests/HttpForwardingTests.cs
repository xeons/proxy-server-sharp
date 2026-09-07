using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Tests;

/// <summary>
/// Tests for HTTP/1.1 message framing on the forwarding path: persistent connections, chunked
/// bodies, interim responses and protocol upgrades.
/// </summary>
public sealed class HttpForwardingTests
{
    [Fact]
    public async Task KeepAlive_ReusesOneUpstreamConnectionForSeveralRequests()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start(_ => HttpOriginResponse.Text("ok"));
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        for (int i = 0; i < 3; i++)
        {
            (int status, _, string body) = await client.GetAsync(OriginUri(origin));
            Assert.Equal(200, status);
            Assert.Equal("ok", body);
        }

        Assert.Equal(3, origin.Requests.Count);

        // The whole point: one TCP connection upstream carried all three requests.
        Assert.Equal(1, origin.ConnectionCount);
    }

    [Fact]
    public async Task KeepAlive_OpensANewUpstreamConnectionWhenTheDestinationChanges()
    {
        await using HttpOriginServer first = HttpOriginServer.Start(_ => HttpOriginResponse.Text("first"));
        await using HttpOriginServer second = HttpOriginServer.Start(_ => HttpOriginResponse.Text("second"));

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal("first", (await client.GetAsync(OriginUri(first))).Body);
        Assert.Equal("second", (await client.GetAsync(OriginUri(second))).Body);
        Assert.Equal("first", (await client.GetAsync(OriginUri(first))).Body);

        Assert.Equal(2, first.ConnectionCount);
        Assert.Equal(1, second.ConnectionCount);
    }

    [Fact]
    public async Task ClientConnectionClose_EndsTheConversationAfterOneRequest()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start(_ => HttpOriginResponse.Text("ok"));
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        (int status, IReadOnlyList<string> headers, _) = await client.GetAsync(
            OriginUri(origin),
            extraHeaders: ["Connection: close"]);

        Assert.Equal(200, status);
        Assert.Contains(headers, h => h.Equals("Connection: close", StringComparison.OrdinalIgnoreCase));
        Assert.True(await client.IsClosedByPeerAsync());
    }

    [Fact]
    public async Task ChunkedRequestBody_ReachesTheOriginIntact()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start(
            request => HttpOriginResponse.Text($"got:{request.Body}"));

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        (int status, _, string body) = await client.PostChunkedAsync(
            OriginUri(origin),
            ["hello ", "chunked ", "world"]);

        Assert.Equal(200, status);
        Assert.Equal("got:hello chunked world", body);
        Assert.Contains("Transfer-Encoding: chunked", origin.LastRequest, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ChunkedResponseBody_ReachesTheClientIntact()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start(
            _ => HttpOriginResponse.Chunked("part one ", "part two ", "part three"));

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        (int status, IReadOnlyList<string> headers, string body) = await client.GetAsync(OriginUri(origin));

        Assert.Equal(200, status);
        Assert.Equal("part one part two part three", body);
        Assert.Contains(headers, h => h.Equals("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase));

        // A chunked response is self-delimiting, so the connection stays usable.
        Assert.Equal("part one part two part three", (await client.GetAsync(OriginUri(origin))).Body);
        Assert.Equal(1, origin.ConnectionCount);
    }

    [Fact]
    public async Task ContentLengthRequestBody_ReachesTheOriginIntact()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start(
            request => HttpOriginResponse.Text($"got:{request.Body}"));

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        (_, _, string body) = await client.PostAsync(OriginUri(origin), "a body with content length");

        Assert.Equal("got:a body with content length", body);
    }

    [Fact]
    public async Task UntilCloseResponse_IsRelayedAndThenClosesTheClientConnection()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start(_ => HttpOriginResponse.UntilClose("no framing"));

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        (int status, IReadOnlyList<string> headers, string body) = await client.GetAsync(OriginUri(origin));

        Assert.Equal(200, status);
        Assert.Equal("no framing", body);

        // With no way to delimit the body, the client hop must close too.
        Assert.Contains(headers, h => h.Equals("Connection: close", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task InterimResponse_IsRelayedBeforeTheFinalOne()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start(_ => HttpOriginResponse.ContinueThen("done"));

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        (int interim, _, _) = await client.ReadResponseAsync(
            sendFirst: () => client.SendGetAsync(OriginUri(origin), ["Expect: 100-continue"]),
            expectBody: false);

        Assert.Equal(100, interim);

        (int status, _, string body) = await client.ReadResponseAsync(expectBody: true);

        Assert.Equal(200, status);
        Assert.Equal("done", body);
    }

    [Fact]
    public async Task Upgrade_SwitchesTheConnectionToARawTunnel()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start(
            _ => HttpOriginResponse.SwitchingProtocols("websocket"));

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        await client.SendGetAsync(OriginUri(origin), ["Upgrade: websocket", "Connection: Upgrade"]);
        (int status, IReadOnlyList<string> headers, _) = await client.ReadResponseAsync(expectBody: false);

        Assert.Equal(101, status);
        Assert.Contains(headers, h => h.Equals("Upgrade: websocket", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ConflictingContentLength_IsRejected()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        // Disagreeing Content-Length fields are a request-smuggling vector.
        await client.SendRawAsync(
            $"GET {OriginUri(origin)} HTTP/1.1\r\nHost: {origin.EndPoint}\r\n"
            + "Content-Length: 0\r\nContent-Length: 12\r\n\r\n");

        (int status, _, _) = await client.ReadResponseAsync(expectBody: true);

        Assert.Equal(400, status);
        Assert.Empty(origin.Requests);
    }

    [Fact]
    public async Task AuthenticatedKeepAlive_ChallengesOnceAndThenReusesTheConnection()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start(_ => HttpOriginResponse.Text("ok"));
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Basic),
            [
                new ProxyUserOptions
                {
                    Username = "alice",
                    PasswordHash = ProxyServerSharp.Authentication.PasswordHasher.Hash("hunter2", 1000),
                },
            ]);

        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy.EndPoint);

        (int challenged, _, _) = await client.GetAsync(OriginUri(origin));
        Assert.Equal(407, challenged);

        string credential = Convert.ToBase64String(Encoding.UTF8.GetBytes("alice:hunter2"));

        // The 407 kept the connection open, so the retry rides the same socket.
        for (int i = 0; i < 2; i++)
        {
            (int status, _, string body) = await client.GetAsync(
                OriginUri(origin),
                extraHeaders: [$"Proxy-Authorization: Basic {credential}"]);

            Assert.Equal(200, status);
            Assert.Equal("ok", body);
        }

        Assert.Equal(1, proxy.Connections.TotalAccepted);
    }

    private static Uri OriginUri(HttpOriginServer origin) => new($"http://127.0.0.1:{origin.EndPoint.Port}/");
}

/// <summary>
/// A raw HTTP client that keeps one socket open across requests, so tests can assert on
/// connection reuse rather than letting <see cref="HttpClient"/> manage a pool invisibly.
/// </summary>
internal sealed class RawHttpClient : IAsyncDisposable
{
    private readonly Socket _socket;
    private readonly NetworkStream _stream;
    private readonly byte[] _buffer = new byte[16384];

    private int _start;
    private int _end;

    private RawHttpClient(Socket socket)
    {
        _socket = socket;
        _stream = new NetworkStream(socket, ownsSocket: false);
    }

    internal static async Task<RawHttpClient> ConnectAsync(IPEndPoint proxy)
    {
        Socket socket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        return new RawHttpClient(socket);
    }

    internal async Task<(int Status, IReadOnlyList<string> Headers, string Body)> GetAsync(
        Uri target,
        IReadOnlyList<string>? extraHeaders = null)
    {
        await SendGetAsync(target, extraHeaders);
        return await ReadResponseAsync(expectBody: true);
    }

    internal async Task<(int Status, IReadOnlyList<string> Headers, string Body)> PostAsync(
        Uri target,
        string body,
        IReadOnlyList<string>? extraHeaders = null)
    {
        StringBuilder request = new();
        request.Append($"POST {target} HTTP/1.1\r\nHost: {target.Authority}\r\nContent-Length: {body.Length}\r\n");

        foreach (string header in extraHeaders ?? [])
        {
            request.Append(header).Append("\r\n");
        }

        request.Append("\r\n").Append(body);

        await SendRawAsync(request.ToString());
        return await ReadResponseAsync(expectBody: true);
    }

    internal async Task<(int Status, IReadOnlyList<string> Headers, string Body)> PostChunkedAsync(
        Uri target,
        IReadOnlyList<string> chunks)
    {
        StringBuilder request = new();
        request.Append($"POST {target} HTTP/1.1\r\nHost: {target.Authority}\r\nTransfer-Encoding: chunked\r\n\r\n");

        foreach (string chunk in chunks)
        {
            request.Append(chunk.Length.ToString("x", System.Globalization.CultureInfo.InvariantCulture))
                .Append("\r\n").Append(chunk).Append("\r\n");
        }

        request.Append("0\r\n\r\n");

        await SendRawAsync(request.ToString());
        return await ReadResponseAsync(expectBody: true);
    }

    internal Task SendGetAsync(Uri target, IReadOnlyList<string>? extraHeaders = null)
    {
        StringBuilder request = new();
        request.Append($"GET {target} HTTP/1.1\r\nHost: {target.Authority}\r\n");

        foreach (string header in extraHeaders ?? [])
        {
            request.Append(header).Append("\r\n");
        }

        request.Append("\r\n");
        return SendRawAsync(request.ToString());
    }

    internal async Task SendRawAsync(string request) =>
        await _stream.WriteAsync(Encoding.Latin1.GetBytes(request));

    internal async Task<(int Status, IReadOnlyList<string> Headers, string Body)> ReadResponseAsync(
        Func<Task>? sendFirst = null,
        bool expectBody = true)
    {
        if (sendFirst is not null)
        {
            await sendFirst();
        }

        List<string> headers = [];
        string? statusLine = await ReadLineAsync();

        if (statusLine is null)
        {
            throw new InvalidDataException("The proxy closed without responding.");
        }

        while (await ReadLineAsync() is { Length: > 0 } line)
        {
            headers.Add(line);
        }

        int status = int.Parse(statusLine.Split(' ')[1], System.Globalization.CultureInfo.InvariantCulture);

        if (!expectBody || status is 101 or >= 100 and < 200 or 204 or 304)
        {
            return (status, headers, "");
        }

        string body = await ReadBodyAsync(headers);
        return (status, headers, body);
    }

    /// <summary>Whether the peer has closed its side, used to assert on <c>Connection: close</c>.</summary>
    internal async Task<bool> IsClosedByPeerAsync()
    {
        if (_start < _end)
        {
            return false;
        }

        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        try
        {
            return await _stream.ReadAsync(_buffer, timeout.Token) == 0;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync();
        _socket.Dispose();
    }

    private async Task<string> ReadBodyAsync(List<string> headers)
    {
        string? transferEncoding = Find(headers, "Transfer-Encoding");

        if (transferEncoding is not null && transferEncoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            StringBuilder body = new();

            while (true)
            {
                string size = await ReadLineAsync() ?? "0";
                int semicolon = size.IndexOf(';', StringComparison.Ordinal);
                int length = Convert.ToInt32(semicolon < 0 ? size : size[..semicolon], 16);

                if (length == 0)
                {
                    while (await ReadLineAsync() is { Length: > 0 })
                    {
                    }

                    return body.ToString();
                }

                body.Append(await ReadExactAsync(length));
                await ReadLineAsync();
            }
        }

        if (Find(headers, "Content-Length") is { } contentLength
            && int.TryParse(contentLength.Trim(), out int length2))
        {
            return await ReadExactAsync(length2);
        }

        // No framing: read to end of stream.
        StringBuilder rest = new();
        while (true)
        {
            if (_start == _end && !await FillAsync())
            {
                return rest.ToString();
            }

            rest.Append(Encoding.Latin1.GetString(_buffer, _start, _end - _start));
            _start = _end;
        }
    }

    private static string? Find(List<string> headers, string name)
    {
        foreach (string header in headers)
        {
            if (header.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
            {
                return header[(name.Length + 1)..];
            }
        }

        return null;
    }

    private async Task<string> ReadExactAsync(int count)
    {
        StringBuilder value = new(count);

        while (value.Length < count)
        {
            if (_start == _end && !await FillAsync())
            {
                break;
            }

            int take = Math.Min(count - value.Length, _end - _start);
            value.Append(Encoding.Latin1.GetString(_buffer, _start, take));
            _start += take;
        }

        return value.ToString();
    }

    private async Task<string?> ReadLineAsync()
    {
        StringBuilder line = new();

        while (true)
        {
            if (_start == _end && !await FillAsync())
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

    private async Task<bool> FillAsync()
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(15));
        _start = 0;
        _end = await _stream.ReadAsync(_buffer, timeout.Token);
        return _end > 0;
    }
}
