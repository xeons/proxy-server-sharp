using System.Text;
using ProxyServerSharp.Net;

namespace ProxyServerSharp.Protocol.Http;

/// <summary>A parsed HTTP request line plus its header block.</summary>
public sealed class HttpRequestHead
{
    private const int MaxHeaderFields = 128;

    private HttpRequestHead(string method, string target, string version, HttpHeaders headers)
    {
        Method = method;
        Target = target;
        Version = version;
        Headers = headers;
    }

    /// <summary>The request method, e.g. <c>GET</c> or <c>CONNECT</c>.</summary>
    public string Method { get; }

    /// <summary>The raw request-target: an authority for <c>CONNECT</c>, an absolute URI otherwise.</summary>
    public string Target { get; }

    /// <summary>The protocol version token, e.g. <c>HTTP/1.1</c>.</summary>
    public string Version { get; }

    /// <summary>The header fields, in arrival order.</summary>
    public HttpHeaders Headers { get; }

    /// <summary>Whether this is a tunnel request rather than a forwardable one.</summary>
    public bool IsConnect => string.Equals(Method, "CONNECT", StringComparison.Ordinal);

    /// <summary>
    /// Reads a request head, or returns <see langword="null"/> if the client closed the
    /// connection cleanly before sending one.
    /// </summary>
    /// <exception cref="InvalidDataException">The request line or a header field is malformed.</exception>
    public static async ValueTask<HttpRequestHead?> ReadAsync(
        BufferedReadStream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        string? requestLine = await stream.ReadLineAsync(cancellationToken).ConfigureAwait(false);

        // RFC 9112 §2.2: a server should skip at least one blank line before the request line.
        while (requestLine is { Length: 0 })
        {
            requestLine = await stream.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        }

        if (requestLine is null)
        {
            return null;
        }

        string[] parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3)
        {
            throw new InvalidDataException($"Malformed HTTP request line: '{Truncate(requestLine)}'.");
        }

        HttpHeaders headers = new();
        string? previousName = null;

        while (true)
        {
            string? line = await stream.ReadLineAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("Stream ended inside the HTTP header block.");

            if (line.Length == 0)
            {
                break;
            }

            if (headers.Count >= MaxHeaderFields)
            {
                throw new InvalidDataException($"HTTP request carried more than {MaxHeaderFields} header fields.");
            }

            // Obsolete line folding (RFC 9112 §5.2) still shows up from old clients.
            if (line[0] is ' ' or '\t')
            {
                if (previousName is null)
                {
                    throw new InvalidDataException("HTTP header block began with a folded line.");
                }

                string folded = headers.GetAll(previousName).Last() + " " + line.Trim();
                headers.Remove(previousName);
                headers.Add(previousName, folded);
                continue;
            }

            int colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                throw new InvalidDataException($"Malformed HTTP header field: '{Truncate(line)}'.");
            }

            previousName = line[..colon];
            headers.Add(previousName, line[(colon + 1)..].Trim());
        }

        return new HttpRequestHead(parts[0], parts[1], parts[2], headers);
    }

    /// <summary>Serialises the head with <paramref name="target"/> in place of <see cref="Target"/>.</summary>
    public byte[] Serialize(string target)
    {
        ArgumentNullException.ThrowIfNull(target);

        StringBuilder builder = new(256);
        builder.Append(Method).Append(' ').Append(target).Append(' ').Append(Version).Append("\r\n");
        Headers.WriteTo(builder);
        return Encoding.Latin1.GetBytes(builder.ToString());
    }

    private static string Truncate(string value) => value.Length <= 120 ? value : value[..120] + "...";
}
