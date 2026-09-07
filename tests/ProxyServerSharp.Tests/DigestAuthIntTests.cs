using System.Net;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Authentication.Http;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Tests;

/// <summary>
/// Tests for Digest <c>qop=auth-int</c>, whose response hash covers the request body.
/// </summary>
public sealed class DigestAuthIntTests
{
    [Fact]
    public async Task AuthInt_IsNotOfferedUnlessEnabled()
    {
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            DigestListener(allowAuthInt: false),
            [Account("alice", "hunter2")]);

        string challenge = await FetchChallengeAsync(proxy.EndPoint);

        Assert.Contains("qop=\"auth\"", challenge, StringComparison.Ordinal);
        Assert.DoesNotContain("auth-int", challenge, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthInt_IsOfferedWhenEnabled()
    {
        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            DigestListener(allowAuthInt: true),
            [Account("alice", "hunter2")]);

        string challenge = await FetchChallengeAsync(proxy.EndPoint);

        Assert.Contains("qop=\"auth,auth-int\"", challenge, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthInt_AcceptsACorrectBodyHashAndForwardsTheBody()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start(
            request => HttpOriginResponse.Text($"got:{request.Body}"));

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            DigestListener(allowAuthInt: true),
            [Account("alice", "hunter2")]);

        (HttpStatusCode status, string body) = await AuthIntClient.PostAsync(
            proxy.EndPoint,
            OriginUri(origin),
            "alice",
            "hunter2",
            "the entity body");

        Assert.Equal(HttpStatusCode.OK, status);

        // The body was buffered to verify the credential and then replayed to the origin intact.
        Assert.Equal("got:the entity body", body);
    }

    [Fact]
    public async Task AuthInt_RejectsAResponseComputedOverADifferentBody()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            DigestListener(allowAuthInt: true),
            [Account("alice", "hunter2")]);

        (HttpStatusCode status, _) = await AuthIntClient.PostAsync(
            proxy.EndPoint,
            OriginUri(origin),
            "alice",
            "hunter2",
            "the entity body",
            hashedBody: "a different body");

        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, status);
        Assert.Empty(origin.Requests);
    }

    [Fact]
    public async Task AuthInt_IsRefusedWhenTheListenerDoesNotOfferIt()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            DigestListener(allowAuthInt: false),
            [Account("alice", "hunter2")]);

        (HttpStatusCode status, _) = await AuthIntClient.PostAsync(
            proxy.EndPoint,
            OriginUri(origin),
            "alice",
            "hunter2",
            "the entity body");

        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, status);
    }

    [Fact]
    public async Task AuthInt_RefusesABodyLargerThanTheCap()
    {
        await using HttpOriginServer origin = HttpOriginServer.Start();

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(
            DigestListener(allowAuthInt: true),
            [Account("alice", "hunter2")],
            options => options.MaxBufferedRequestBody = 32);

        (HttpStatusCode status, _) = await AuthIntClient.PostAsync(
            proxy.EndPoint,
            OriginUri(origin),
            "alice",
            "hunter2",
            new string('x', 1024));

        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, status);
    }

    [Fact]
    public void AuthIntHash_MatchesTheRfcDefinition()
    {
        // RFC 7616 §3.4.3: A2 = method:uri:H(entity-body)
        byte[] body = "the entity body"u8.ToArray();
        string bodyHash = DigestHash.ComputeBytes(DigestHash.Sha256, body);

        Assert.Equal(DigestHash.Compute(DigestHash.Sha256, "the entity body"), bodyHash);
    }

    private static ListenerOptions DigestListener(bool allowAuthInt)
    {
        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Http, AuthenticationMethod.Digest);
        listener.DigestAlgorithms.Add("SHA-256");
        listener.AllowDigestAuthInt = allowAuthInt;
        listener.Realm = "testrealm";
        return listener;
    }

    private static ProxyUserOptions Account(string username, string password) => new()
    {
        Username = username,
        Password = password,
    };

    private static Uri OriginUri(HttpOriginServer origin) => new($"http://127.0.0.1:{origin.EndPoint.Port}/");

    private static async Task<string> FetchChallengeAsync(IPEndPoint proxy)
    {
        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy);
        (_, IReadOnlyList<string> headers, _) = await client.GetAsync(new Uri("http://example.invalid/"));

        foreach (string header in headers)
        {
            if (header.StartsWith("Proxy-Authenticate: Digest", StringComparison.OrdinalIgnoreCase))
            {
                return header;
            }
        }

        throw new InvalidOperationException("No Digest challenge was offered.");
    }
}

/// <summary>A Digest client that computes an <c>auth-int</c> response over a request body.</summary>
internal static class AuthIntClient
{
    internal static async Task<(HttpStatusCode Status, string Body)> PostAsync(
        IPEndPoint proxy,
        Uri target,
        string username,
        string password,
        string body,
        string? hashedBody = null)
    {
        await using RawHttpClient client = await RawHttpClient.ConnectAsync(proxy);

        (_, IReadOnlyList<string> headers, _) = await client.PostAsync(target, body);
        string challenge = Find(headers) ?? throw new InvalidOperationException("No Digest challenge.");

        DigestParameters parameters = DigestParameters.Parse(challenge["Proxy-Authenticate: Digest ".Length..]);
        string realm = parameters["realm"]!;
        string nonce = parameters["nonce"]!;
        string algorithm = parameters["algorithm"] ?? "MD5";

        string uri = target.AbsoluteUri;
        const string Nc = "00000001";
        const string CNonce = "0a4f113b";

        // Hashing a body other than the one sent is how the tamper case is simulated.
        string entityHash = DigestHash.ComputeBytes(
            algorithm,
            System.Text.Encoding.UTF8.GetBytes(hashedBody ?? body));

        string ha1 = DigestHash.ComputeHa1(algorithm, username, realm, password);
        string ha2 = DigestHash.Compute(algorithm, $"POST:{uri}:{entityHash}");
        string response = DigestHash.Compute(algorithm, $"{ha1}:{nonce}:{Nc}:{CNonce}:auth-int:{ha2}");

        string credential =
            $"Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", "
            + $"algorithm={algorithm}, qop=auth-int, nc={Nc}, cnonce=\"{CNonce}\", response=\"{response}\"";

        await using RawHttpClient authenticated = await RawHttpClient.ConnectAsync(proxy);
        (int status, _, string responseBody) = await authenticated.PostAsync(target, body, [$"Proxy-Authorization: {credential}"]);

        return ((HttpStatusCode)status, responseBody);
    }

    private static string? Find(IReadOnlyList<string> headers)
    {
        foreach (string header in headers)
        {
            if (header.StartsWith("Proxy-Authenticate: Digest", StringComparison.OrdinalIgnoreCase))
            {
                return header;
            }
        }

        return null;
    }
}
