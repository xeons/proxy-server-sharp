using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Authentication.Http;

namespace ProxyServerSharp.Tests;

/// <summary>
/// A Digest proxy client written against RFC 7616 directly. <see cref="HttpClient"/> only speaks
/// MD5 Digest on Windows, so testing the SHA-256 and SHA-512-256 paths needs a client that
/// computes the response itself.
/// </summary>
internal static class DigestClient
{
    /// <summary>Performs a full 407-then-authenticate exchange and returns the response body.</summary>
    /// <exception cref="HttpRequestException">The proxy did not accept the credential.</exception>
    internal static async Task<string> GetAsync(IPEndPoint proxy, Uri target, string username, string password)
    {
        (string credential, _) = await NegotiateAsync(proxy, target, username, password);
        (HttpStatusCode status, string body) = await SendAsync(proxy, target, credential);

        return status == HttpStatusCode.OK
            ? body
            : throw new HttpRequestException($"Proxy answered {(int)status}.", null, status);
    }

    /// <summary>Runs the exchange and hands back the credential that was accepted.</summary>
    internal static async Task<string> CaptureCredentialAsync(
        IPEndPoint proxy,
        Uri target,
        string username,
        string password)
    {
        (string credential, _) = await NegotiateAsync(proxy, target, username, password);

        (HttpStatusCode status, _) = await SendAsync(proxy, target, credential);
        Assert.Equal(HttpStatusCode.OK, status);

        return credential;
    }

    /// <summary>Presents a previously accepted credential again, unchanged.</summary>
    internal static async Task<HttpStatusCode> ReplayAsync(IPEndPoint proxy, Uri target, string credential)
    {
        (HttpStatusCode status, _) = await SendAsync(proxy, target, credential);
        return status;
    }

    private static async Task<(string Credential, string Challenge)> NegotiateAsync(
        IPEndPoint proxy,
        Uri target,
        string username,
        string password)
    {
        (HttpStatusCode status, string head, _) = await SendRawAsync(proxy, target, credential: null);
        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, status);

        string challenge = FindDigestChallenge(head);
        DigestParameters parameters = DigestParameters.Parse(challenge["Digest ".Length..]);

        string realm = parameters["realm"] ?? throw new InvalidOperationException("Challenge had no realm.");
        string nonce = parameters["nonce"] ?? throw new InvalidOperationException("Challenge had no nonce.");
        string algorithm = parameters["algorithm"] ?? "MD5";
        string opaque = parameters["opaque"] ?? "";

        string uri = target.AbsoluteUri;
        string cnonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
        const string Nc = "00000001";

        string ha1 = DigestHash.ComputeHa1(algorithm, username, realm, password);
        string ha2 = DigestHash.Compute(algorithm, $"GET:{uri}");
        string response = DigestHash.Compute(algorithm, $"{ha1}:{nonce}:{Nc}:{cnonce}:auth:{ha2}");

        string credential =
            $"Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", "
            + $"algorithm={algorithm}, qop=auth, nc={Nc}, cnonce=\"{cnonce}\", response=\"{response}\""
            + (opaque.Length > 0 ? $", opaque=\"{opaque}\"" : "");

        return (credential, challenge);
    }

    private static async Task<(HttpStatusCode Status, string Body)> SendAsync(
        IPEndPoint proxy,
        Uri target,
        string credential)
    {
        (HttpStatusCode status, _, string body) = await SendRawAsync(proxy, target, credential);
        return (status, body);
    }

    /// <summary>Sends one request and splits the reply into its status, header block and body.</summary>
    private static async Task<(HttpStatusCode Status, string Head, string Body)> SendRawAsync(
        IPEndPoint proxy,
        Uri target,
        string? credential)
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        await using NetworkStream stream = new(socket, ownsSocket: false);

        StringBuilder request = new();
        request.Append("GET ").Append(target.AbsoluteUri).Append(" HTTP/1.1\r\n");
        request.Append("Host: ").Append(target.Authority).Append("\r\n");

        if (credential is not null)
        {
            request.Append("Proxy-Authorization: ").Append(credential).Append("\r\n");
        }

        request.Append("\r\n");
        await stream.WriteAsync(Encoding.Latin1.GetBytes(request.ToString()));

        (string head, string body) = await ReadResponseAsync(stream);
        int statusStart = head.IndexOf(' ', StringComparison.Ordinal) + 1;
        int status = int.Parse(head.AsSpan(statusStart, 3), System.Globalization.CultureInfo.InvariantCulture);

        return ((HttpStatusCode)status, head, body);
    }

    /// <summary>
    /// Reads one response, framed by <c>Content-Length</c> where it is present.
    /// </summary>
    /// <remarks>
    /// A <c>407</c> deliberately keeps the connection open so the client can retry, so reading
    /// until close would hang. The proxy always sends <c>Content-Length</c> on its own responses,
    /// and the test origin server sends it too.
    /// </remarks>
    private static async Task<(string Head, string Body)> ReadResponseAsync(Stream stream)
    {
        StringBuilder received = new();
        byte[] buffer = new byte[4096];
        int headerEnd;

        while ((headerEnd = received.ToString().IndexOf("\r\n\r\n", StringComparison.Ordinal)) < 0)
        {
            int read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(15));
            if (read == 0)
            {
                throw new InvalidDataException($"Connection closed inside the header block:\r\n{received}");
            }

            received.Append(Encoding.Latin1.GetString(buffer, 0, read));
        }

        string all = received.ToString();
        string head = all[..headerEnd];
        StringBuilder body = new(all[(headerEnd + 4)..]);

        if (FindContentLength(head) is not { } contentLength)
        {
            // No Content-Length: the response is framed by connection close.
            while (true)
            {
                int read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(15));
                if (read == 0)
                {
                    break;
                }

                body.Append(Encoding.Latin1.GetString(buffer, 0, read));
            }

            return (head, body.ToString());
        }

        while (body.Length < contentLength)
        {
            int read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(15));
            if (read == 0)
            {
                break;
            }

            body.Append(Encoding.Latin1.GetString(buffer, 0, read));
        }

        return (head, body.ToString());
    }

    private static int? FindContentLength(string head)
    {
        foreach (string line in head.Split("\r\n"))
        {
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(line["Content-Length:".Length..].Trim(), out int length))
            {
                return length;
            }
        }

        return null;
    }

    private static string FindDigestChallenge(string head)
    {
        foreach (string line in head.Split("\r\n"))
        {
            if (line.StartsWith("Proxy-Authenticate: Digest ", StringComparison.OrdinalIgnoreCase))
            {
                return line["Proxy-Authenticate: ".Length..];
            }
        }

        throw new InvalidOperationException($"No Digest challenge in:\r\n{head}");
    }
}
