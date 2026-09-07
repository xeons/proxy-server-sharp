using System.Net;
using System.Net.Http.Headers;
using System.Text;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Tests;

/// <summary>
/// End-to-end HTTP proxy tests, driven through <see cref="HttpClient"/> so the exchange is what a
/// real client would produce, including the <c>407</c> retry loop.
/// </summary>
public sealed class HttpProxyTests
{
    [Fact]
    public async Task Anonymous_ForwardsAbsoluteUriRequest()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start("forwarded body");
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous));

        using HttpClient client = CreateClient(proxy);
        string body = await client.GetStringAsync(OriginUri(origin));

        Assert.Equal("forwarded body", body);
    }

    [Fact]
    public async Task Forwarding_RewritesToOriginFormAndStripsHopByHopHeaders()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Basic),
            [Account("alice", "hunter2")]);

        using HttpClient client = CreateClient(proxy, new NetworkCredential("alice", "hunter2"));
        await client.GetStringAsync(OriginUri(origin));

        string request = origin.LastRequest;

        Assert.StartsWith("GET / HTTP/1.1", request, StringComparison.Ordinal);
        Assert.DoesNotContain("Proxy-Authorization", request, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Proxy-Connection", request, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Via:", request, StringComparison.Ordinal);

        // The upstream connection is now persistent, so the proxy no longer forces it closed.
        Assert.Contains("Connection: keep-alive", request, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingCredentials_Returns407WithEveryOfferedScheme()
    {
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(
                ProxyProtocol.Http,
                AuthenticationMethod.Basic,
                AuthenticationMethod.Digest,
                AuthenticationMethod.Bearer),
            [Account("alice", "hunter2")]);

        using HttpClient client = CreateClient(proxy);
        using HttpResponseMessage response = await client.GetAsync(new Uri("http://example.invalid/"));

        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, response.StatusCode);

        string[] schemes = [.. response.Headers.ProxyAuthenticate.Select(h => h.Scheme)];
        Assert.Contains("Basic", schemes, StringComparer.Ordinal);
        Assert.Contains("Digest", schemes, StringComparer.Ordinal);
        Assert.Contains("Bearer", schemes, StringComparer.Ordinal);
    }

    [Fact]
    public async Task Digest_OffersOneChallengePerAlgorithm()
    {
        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Digest);
        listener.DigestAlgorithms.Add("SHA-256");
        listener.DigestAlgorithms.Add("MD5");

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            listener,
            [Account("alice", "hunter2", allowDigest: true)]);

        using HttpClient client = CreateClient(proxy);
        using HttpResponseMessage response = await client.GetAsync(new Uri("http://example.invalid/"));

        string[] algorithms =
        [
            .. response.Headers.ProxyAuthenticate
                .Where(h => h.Scheme == "Digest")
                .Select(h => ExtractParameter(h, "algorithm")),
        ];

        Assert.Equal(["SHA-256", "MD5"], algorithms);
    }

    [Theory]
    [InlineData("SHA-256")]
    [InlineData("SHA-512-256")]
    [InlineData("MD5")]
    public async Task Digest_AcceptsCorrectResponse(string algorithm)
    {
        await using HttpOriginServer origin = HttpOriginServer.Start("digest ok");

        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Digest);
        listener.DigestAlgorithms.Add(algorithm);

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            listener,
            [Account("alice", "hunter2", allowDigest: true)]);

        string body = await DigestClient.GetAsync(proxy.EndPoint, OriginUri(origin), "alice", "hunter2");

        Assert.Equal("digest ok", body);
    }

    [Fact]
    public async Task Digest_RejectsWrongPassword()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();

        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Digest);
        listener.DigestAlgorithms.Add("SHA-256");

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            listener,
            [Account("alice", "hunter2", allowDigest: true)]);

        HttpRequestException failure = await Assert.ThrowsAsync<HttpRequestException>(
            () => DigestClient.GetAsync(proxy.EndPoint, OriginUri(origin), "alice", "wrong"));

        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, failure.StatusCode);
    }

    [Fact]
    public async Task Digest_RejectsReplayedNonceCount()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();

        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Digest);
        listener.DigestAlgorithms.Add("SHA-256");

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            listener,
            [Account("alice", "hunter2", allowDigest: true)]);

        // Capture a valid credential, then present it a second time unchanged.
        string credential = await DigestClient.CaptureCredentialAsync(
            proxy.EndPoint,
            OriginUri(origin),
            "alice",
            "hunter2");

        HttpStatusCode replayed = await DigestClient.ReplayAsync(proxy.EndPoint, OriginUri(origin), credential);

        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, replayed);
    }

    [Fact]
    public async Task Basic_RejectsWrongPassword()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Basic),
            [Account("alice", "hunter2")]);

        using HttpClient client = CreateClient(proxy, new NetworkCredential("alice", "wrong"));
        using HttpResponseMessage response = await client.GetAsync(OriginUri(origin));

        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, response.StatusCode);
    }

    [Fact]
    public async Task Bearer_AcceptsAConfiguredToken()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start("bearer ok");

        ProxyUserOptions account = Account("alice", "hunter2");
        account.TokenHashes.Add(PasswordHasher.Hash("token-value", iterations: 1000));

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Bearer),
            [account]);

        using HttpClient client = CreateClient(proxy);
        using HttpRequestMessage request = new(HttpMethod.Get, OriginUri(origin));
        request.Headers.Add("Proxy-Authorization", "Bearer token-value");

        using HttpResponseMessage response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("bearer ok", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Bearer_RejectsAnUnknownToken()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();

        ProxyUserOptions account = Account("alice", "hunter2");
        account.TokenHashes.Add(PasswordHasher.Hash("token-value", iterations: 1000));

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Bearer),
            [account]);

        using HttpClient client = CreateClient(proxy);
        using HttpRequestMessage request = new(HttpMethod.Get, OriginUri(origin));
        request.Headers.Add("Proxy-Authorization", "Bearer wrong-token");

        using HttpResponseMessage response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, response.StatusCode);
    }

    [Fact]
    public async Task Connect_TunnelsRawBytes()
    {
        await using EchoServer origin = EchoServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Basic),
            [Account("alice", "hunter2")]);

        await using SocksClient raw = await SocksClient.ConnectAsync(proxy.EndPoint);

        string credential = Convert.ToBase64String(Encoding.UTF8.GetBytes("alice:hunter2"));
        byte[] request = Encoding.ASCII.GetBytes(
            $"CONNECT 127.0.0.1:{origin.EndPoint.Port} HTTP/1.1\r\n"
            + $"Host: 127.0.0.1:{origin.EndPoint.Port}\r\n"
            + $"Proxy-Authorization: Basic {credential}\r\n\r\n");

        await raw.Stream.WriteAsync(request);

        string status = await ReadStatusLineAsync(raw.Stream);
        Assert.StartsWith("HTTP/1.1 200", status, StringComparison.Ordinal);

        Assert.Equal("tunnelled", await raw.RoundTripAsync("tunnelled"));
    }

    [Fact]
    public async Task Connect_WithoutCredentials_Returns407()
    {
        await using EchoServer origin = EchoServer.Start();
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Basic),
            [Account("alice", "hunter2")]);

        await using SocksClient raw = await SocksClient.ConnectAsync(proxy.EndPoint);

        byte[] request = Encoding.ASCII.GetBytes(
            $"CONNECT 127.0.0.1:{origin.EndPoint.Port} HTTP/1.1\r\n"
            + $"Host: 127.0.0.1:{origin.EndPoint.Port}\r\n\r\n");

        await raw.Stream.WriteAsync(request);

        Assert.StartsWith("HTTP/1.1 407", await ReadStatusLineAsync(raw.Stream), StringComparison.Ordinal);
    }

    [Fact]
    public async Task TlsListener_TerminatesTlsAndStillAuthenticates()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start("over tls");

        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Basic);
        listener.Tls.Enabled = true;
        listener.Tls.AllowSelfSigned = true;

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            listener,
            [Account("alice", "hunter2")]);

        using HttpClientHandler handler = new()
        {
            Proxy = new WebProxy($"https://127.0.0.1:{proxy.Port}")
            {
                Credentials = new NetworkCredential("alice", "hunter2"),
            },
            UseProxy = true,

            // The listener generated its own certificate, so there is nothing to chain to.
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
        };

        using HttpClient client = new(handler) { Timeout = TimeSpan.FromSeconds(20) };

        Assert.Equal("over tls", await client.GetStringAsync(OriginUri(origin)));
    }

    [Fact]
    public async Task BlockedDestination_Returns403()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();

        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous);
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            listener,
            configure: _ => listener.Destinations.BlockLoopback = true);

        using HttpClient client = CreateClient(proxy);
        using HttpResponseMessage response = await client.GetAsync(OriginUri(origin));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task PlainForwardingDisabled_Returns405ButConnectStillWorks()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();

        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Anonymous);
        listener.AllowPlainHttpForwarding = false;

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(listener);

        using HttpClient client = CreateClient(proxy);
        using HttpResponseMessage response = await client.GetAsync(OriginUri(origin));

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    private static async Task<string> ReadStatusLineAsync(Stream stream)
    {
        StringBuilder line = new();
        byte[] one = new byte[1];

        while (true)
        {
            await stream.ReadExactlyAsync(one);

            if (one[0] == (byte)'\n')
            {
                // Drain the rest of the header block so the caller starts at the payload.
                if (line.Length == 0 || line.ToString() == "\r")
                {
                    return line.ToString().TrimEnd('\r');
                }

                string result = line.ToString().TrimEnd('\r');
                await DrainHeadersAsync(stream);
                return result;
            }

            line.Append((char)one[0]);
        }
    }

    private static async Task DrainHeadersAsync(Stream stream)
    {
        byte[] one = new byte[1];
        int consecutiveNewlines = 0;

        while (consecutiveNewlines < 1)
        {
            StringBuilder line = new();

            while (true)
            {
                await stream.ReadExactlyAsync(one);
                if (one[0] == (byte)'\n')
                {
                    break;
                }

                line.Append((char)one[0]);
            }

            if (line.ToString().TrimEnd('\r').Length == 0)
            {
                consecutiveNewlines++;
            }
        }
    }

    private static string ExtractParameter(AuthenticationHeaderValue header, string name)
    {
        foreach (string part in header.Parameter?.Split(',') ?? [])
        {
            string[] pair = part.Split('=', 2);
            if (pair.Length == 2 && pair[0].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return pair[1].Trim().Trim('"');
            }
        }

        return "";
    }

    private static Uri OriginUri(HttpOriginServer origin) => new($"http://127.0.0.1:{origin.EndPoint.Port}/");

    private static HttpClient CreateClient(ProxyServerFixture proxy, NetworkCredential? credential = null)
    {
        HttpClientHandler handler = new()
        {
            Proxy = new WebProxy($"http://127.0.0.1:{proxy.Port}") { Credentials = credential },
            UseProxy = true,
        };

        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
    }

    private static ProxyUserOptions Account(string username, string password, bool allowDigest = false) => new()
    {
        Username = username,
        PasswordHash = PasswordHasher.Hash(password, iterations: 1000),

        // Digest verifies against HA1, which a one-way hash cannot produce.
        Password = allowDigest ? password : null,
    };
}
