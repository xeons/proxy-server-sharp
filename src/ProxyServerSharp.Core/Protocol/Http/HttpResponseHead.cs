using System.Globalization;
using System.Text;
using ProxyServerSharp.Net;

namespace ProxyServerSharp.Protocol.Http;

/// <summary>A parsed HTTP status line plus its header block.</summary>
public sealed class HttpResponseHead
{
    private const int MaxHeaderFields = 128;

    private HttpResponseHead(string version, int status, string reason, HttpHeaders headers)
    {
        Version = version;
        Status = status;
        Reason = reason;
        Headers = headers;
    }

    /// <summary>The protocol version token, e.g. <c>HTTP/1.1</c>.</summary>
    public string Version { get; }

    /// <summary>The status code.</summary>
    public int Status { get; }

    /// <summary>The reason phrase, which may be empty.</summary>
    public string Reason { get; }

    /// <summary>The header fields, in arrival order.</summary>
    public HttpHeaders Headers { get; }

    /// <summary>Whether this is an interim response that will be followed by another.</summary>
    public bool IsInformational => Status is >= 100 and < 200;

    /// <summary>Whether this response switches the connection to another protocol.</summary>
    public bool IsUpgrade => Status == 101;

    /// <summary>Reads a status line and header block.</summary>
    /// <exception cref="InvalidDataException">The response is malformed.</exception>
    /// <exception cref="EndOfStreamException">The upstream closed before sending a response.</exception>
    public static async ValueTask<HttpResponseHead> ReadAsync(
        BufferedReadStream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        string statusLine = await stream.ReadLineAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new EndOfStreamException("The upstream connection closed before sending a response.");

        // "HTTP/1.1 200 OK" — the reason phrase is optional and may itself contain spaces.
        string[] parts = statusLine.Split(' ', 3);
        if (parts.Length < 2
            || !parts[0].StartsWith("HTTP/", StringComparison.Ordinal)
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int status))
        {
            throw new InvalidDataException($"Malformed HTTP status line: '{Truncate(statusLine)}'.");
        }

        HttpHeaders headers = new();
        string? previousName = null;

        while (true)
        {
            string? line = await stream.ReadLineAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("Stream ended inside the HTTP response header block.");

            if (line.Length == 0)
            {
                break;
            }

            if (headers.Count >= MaxHeaderFields)
            {
                throw new InvalidDataException($"HTTP response carried more than {MaxHeaderFields} header fields.");
            }

            if (line[0] is ' ' or '\t')
            {
                if (previousName is null)
                {
                    throw new InvalidDataException("HTTP response header block began with a folded line.");
                }

                string folded = headers.GetAll(previousName).Last() + " " + line.Trim();
                headers.Remove(previousName);
                headers.Add(previousName, folded);
                continue;
            }

            int colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                throw new InvalidDataException($"Malformed HTTP response header field: '{Truncate(line)}'.");
            }

            previousName = line[..colon];
            headers.Add(previousName, line[(colon + 1)..].Trim());
        }

        return new HttpResponseHead(parts[0], status, parts.Length > 2 ? parts[2] : "", headers);
    }

    /// <summary>Serialises the status line and headers.</summary>
    public byte[] Serialize()
    {
        StringBuilder builder = new(256);
        builder.Append(Version).Append(' ').Append(Status);

        if (Reason.Length > 0)
        {
            builder.Append(' ').Append(Reason);
        }

        builder.Append("\r\n");
        Headers.WriteTo(builder);
        return Encoding.Latin1.GetBytes(builder.ToString());
    }

    private static string Truncate(string value) => value.Length <= 120 ? value : value[..120] + "...";
}
