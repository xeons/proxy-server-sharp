using System.Buffers;
using System.Text;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication.Socks;

/// <summary>
/// RFC 1929 username/password sub-negotiation, advertised as RFC 1928 method <c>0x02</c>.
/// </summary>
/// <remarks>
/// The credential travels in the clear, exactly as the RFC specifies. Put the listener on
/// loopback, on a trusted network, or behind a tunnel if that matters.
/// </remarks>
public sealed class Socks5UsernamePasswordAuthenticator : ISocks5Authenticator
{
    /// <summary>The RFC 1928 method identifier for username/password.</summary>
    public const byte Code = 0x02;

    private const byte SubNegotiationVersion = 0x01;
    private const byte StatusSuccess = 0x00;
    private const byte StatusFailure = 0x01;

    private readonly IUserStore _users;

    /// <summary>Creates the authenticator over an account directory.</summary>
    public Socks5UsernamePasswordAuthenticator(IUserStore users)
    {
        ArgumentNullException.ThrowIfNull(users);
        _users = users;
    }

    /// <inheritdoc />
    public AuthenticationMethod Method => AuthenticationMethod.UsernamePassword;

    /// <inheritdoc />
    public byte MethodCode => Code;

    /// <inheritdoc />
    public async ValueTask<Socks5AuthenticationOutcome> AuthenticateAsync(
        Stream stream,
        UserStoreContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        // +----+------+----------+------+----------+
        // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        // +----+------+----------+------+----------+
        byte[] header = new byte[2];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

        if (header[0] != SubNegotiationVersion)
        {
            await ReplyAsync(stream, StatusFailure, cancellationToken).ConfigureAwait(false);
            return Socks5AuthenticationOutcome.Fail($"Unsupported RFC 1929 version 0x{header[0]:X2}.");
        }

        string username = await ReadStringAsync(stream, header[1], cancellationToken).ConfigureAwait(false);

        byte[] passwordLength = new byte[1];
        await stream.ReadExactlyAsync(passwordLength, cancellationToken).ConfigureAwait(false);
        string password = await ReadStringAsync(stream, passwordLength[0], cancellationToken).ConfigureAwait(false);

        AuthenticationResult result = await _users
            .ValidatePasswordAsync(username, password, context, cancellationToken)
            .ConfigureAwait(false);

        await ReplyAsync(stream, result.Succeeded ? StatusSuccess : StatusFailure, cancellationToken)
            .ConfigureAwait(false);

        return Socks5AuthenticationOutcome.From(result);
    }

    private static async ValueTask<string> ReadStringAsync(Stream stream, byte length, CancellationToken cancellationToken)
    {
        if (length == 0)
        {
            return "";
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            await stream.ReadExactlyAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            return Encoding.UTF8.GetString(buffer, 0, length);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static ValueTask ReplyAsync(Stream stream, byte status, CancellationToken cancellationToken) =>
        stream.WriteAsync(new byte[] { SubNegotiationVersion, status }, cancellationToken);
}
