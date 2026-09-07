using System.Buffers;
using System.Net;
using System.Net.Security;
using System.Text;
using ProxyServerSharp.Authentication.Socks;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Tests;

/// <summary>
/// Tests for SOCKS5 GSS-API (RFC 1961).
/// </summary>
/// <remarks>
/// The end-to-end cases need the platform to act as both GSSAPI peers against the running user's
/// own credentials. That works through SSPI on Windows; elsewhere it needs a configured Kerberos
/// or NTLM environment, so those tests skip rather than fail on a machine that cannot do it.
/// </remarks>
public sealed class GssapiTests
{
    private const byte GssapiMethod = 0x01;
    private const byte Connect = 0x01;

    [Fact]
    public async Task MessageFraming_RoundTrips()
    {
        MemoryStream stream = new();
        byte[] token = [1, 2, 3, 4, 5];

        await GssapiMessage.WriteAsync(
            stream,
            GssapiMessageType.Authentication,
            token,
            TestContext.Current.CancellationToken);

        stream.Position = 0;
        (GssapiMessageType type, byte[] read) = await GssapiMessage.ReadAsync(
            stream,
            TestContext.Current.CancellationToken);

        Assert.Equal(GssapiMessageType.Authentication, type);
        Assert.Equal(token, read);
    }

    [Fact]
    public async Task MessageFraming_RejectsTheWrongVersionByte()
    {
        // The sub-negotiation version is 0x01, not the SOCKS version 0x05 — a classic mix-up.
        MemoryStream stream = new([0x05, 0x01, 0x00, 0x00]);

        await Assert.ThrowsAsync<InvalidDataException>(
            async () => await GssapiMessage.ReadAsync(stream, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task MessageFraming_ReadsAnEmptyToken()
    {
        MemoryStream stream = new([0x01, 0xFF, 0x00, 0x00]);

        (GssapiMessageType type, byte[] token) = await GssapiMessage.ReadAsync(
            stream,
            TestContext.Current.CancellationToken);

        Assert.Equal(GssapiMessageType.Abort, type);
        Assert.Empty(token);
    }

    [Fact]
    public async Task MessageFraming_RefusesAnOversizedToken()
    {
        MemoryStream stream = new();
        byte[] tooBig = new byte[GssapiMessage.MaxTokenLength + 1];

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await GssapiMessage.WriteAsync(
                stream,
                GssapiMessageType.EncapsulatedData,
                tooBig,
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public void ListenerValidation_AcceptsGssapiOnSocks5Only()
    {
        ListenerOptions socks5 = new() { Name = "s5", Protocol = ProxyProtocol.Socks5, Port = 1080 };
        socks5.Authentication.Add(AuthenticationMethod.Gssapi);
        ProxyServerSharp.Server.ProxyHandlerFactory.Validate(socks5);

        ListenerOptions http = new() { Name = "http", Protocol = ProxyProtocol.Http, Port = 8080 };
        http.Authentication.Add(AuthenticationMethod.Gssapi);

        Assert.Throws<InvalidOperationException>(() => ProxyServerSharp.Server.ProxyHandlerFactory.Validate(http));
    }

    [Fact]
    public async Task Gssapi_AuthenticatesAndRelays_AtProtectionLevelNone()
    {
        await RunEndToEndAsync(GssapiProtectionLevel.None);
    }

    [Fact]
    public async Task Gssapi_AuthenticatesAndRelays_AtIntegrityProtection()
    {
        await RunEndToEndAsync(GssapiProtectionLevel.Integrity);
    }

    [Fact]
    public async Task Gssapi_AuthenticatesAndRelays_AtConfidentialityProtection()
    {
        await RunEndToEndAsync(GssapiProtectionLevel.Confidentiality);
    }

    [Fact]
    public async Task Gssapi_ServerLowersAProtectionLevelAboveItsCap()
    {
        // The client asks for confidentiality; the listener caps at none, so the relay stays raw.
        await RunEndToEndAsync(
            listenerCap: GssapiProtectionLevel.None,
            clientRequest: GssapiProtectionLevel.Confidentiality,
            expected: GssapiProtectionLevel.None);
    }

    [Fact]
    public async Task Gssapi_AcceptsAnUnwrappedProtectionLevel()
    {
        // The NEC-style variant that curl's --socks5-gssapi-nec exists for.
        await RunEndToEndAsync(GssapiProtectionLevel.None, wrapProtectionLevel: false);
    }

    private static Task RunEndToEndAsync(
        GssapiProtectionLevel level,
        bool wrapProtectionLevel = true) =>
        RunEndToEndAsync(level, level, level, wrapProtectionLevel);

    private static Task RunEndToEndAsync(
        GssapiProtectionLevel listenerCap,
        GssapiProtectionLevel clientRequest,
        GssapiProtectionLevel expected,
        bool wrapProtectionLevel = true) =>
        RunAsync(listenerCap, clientRequest, expected, wrapProtectionLevel);

    private static async Task RunAsync(
        GssapiProtectionLevel listenerCap,
        GssapiProtectionLevel clientRequest,
        GssapiProtectionLevel expected,
        bool wrapProtectionLevel)
    {
        Assert.SkipUnless(GssapiTestClient.IsSupported, "The host cannot act as a GSSAPI peer against itself.");

        await using EchoServer origin = EchoServer.Start();

        ListenerOptions listener = ProxyServerFixture.Listener(ProxyProtocol.Socks5, AuthenticationMethod.Gssapi);
        listener.GssapiProtection = listenerCap;

        await using ProxyServerFixture proxy = await ProxyServerFixture.StartAsync(listener);
        await using SocksClient client = await SocksClient.ConnectAsync(proxy.EndPoint);

        Assert.Equal(GssapiMethod, await client.GreetAsync(GssapiMethod));

        GssapiProtectionLevel agreed = await GssapiTestClient.HandshakeAsync(
            client.Stream,
            clientRequest,
            wrapProtectionLevel);

        Assert.Equal(expected, agreed);

        // At a level above none, every SOCKS message from here on is encapsulated.
        Stream conversation = GssapiTestClient.Wrap(client.Stream, agreed);

        (byte reply, _) = await SocksClient.RequestOverAsync(conversation, Connect, origin.EndPoint);
        Assert.Equal(0x00, reply);

        byte[] payload = "gssapi payload"u8.ToArray();
        await conversation.WriteAsync(payload, TestContext.Current.CancellationToken);
        await conversation.FlushAsync(TestContext.Current.CancellationToken);

        byte[] echoed = new byte[payload.Length];
        await conversation.ReadExactlyAsync(echoed, TestContext.Current.CancellationToken);

        Assert.Equal("gssapi payload", Encoding.UTF8.GetString(echoed));
    }
}

/// <summary>The client half of an RFC 1961 exchange, for driving the server under test.</summary>
internal static class GssapiTestClient
{
    /// <summary>Whether this host can complete a loopback GSSAPI handshake.</summary>
    internal static bool IsSupported { get; } = Probe();

    private static NegotiateAuthentication? _lastContext;

    /// <summary>Runs context establishment and protection-level negotiation.</summary>
    internal static async Task<GssapiProtectionLevel> HandshakeAsync(
        Stream stream,
        GssapiProtectionLevel requested,
        bool wrapProtectionLevel)
    {
        NegotiateAuthentication client = new(new NegotiateAuthenticationClientOptions
        {
            Package = "Negotiate",
            TargetName = TargetName,
            RequiredProtectionLevel = ProtectionLevel.EncryptAndSign,
        });

        byte[]? outgoing = client.GetOutgoingBlob([], out NegotiateAuthenticationStatusCode status);

        while (outgoing is not null)
        {
            await GssapiMessage.WriteAsync(stream, GssapiMessageType.Authentication, outgoing, CancellationToken.None);

            (GssapiMessageType type, byte[] token) = await GssapiMessage.ReadAsync(stream, CancellationToken.None);

            if (type == GssapiMessageType.Abort)
            {
                throw new InvalidOperationException("The server aborted the GSSAPI exchange.");
            }

            if (status == NegotiateAuthenticationStatusCode.Completed)
            {
                break;
            }

            outgoing = client.GetOutgoingBlob(token, out status);

            if (status == NegotiateAuthenticationStatusCode.Completed && outgoing is null)
            {
                break;
            }
        }

        _lastContext = client;

        // The protection-level byte is normally wrapped; some implementations send it bare.
        byte[] request;
        if (wrapProtectionLevel)
        {
            ArrayBufferWriter<byte> wrapped = new(64);
            client.Wrap([(byte)requested], wrapped, false, out _);
            request = wrapped.WrittenSpan.ToArray();
        }
        else
        {
            request = [(byte)requested];
        }

        await GssapiMessage.WriteAsync(stream, GssapiMessageType.ProtectionLevel, request, CancellationToken.None);

        (_, byte[] answer) = await GssapiMessage.ReadAsync(stream, CancellationToken.None);

        ArrayBufferWriter<byte> plaintext = new(16);
        client.Unwrap(answer, plaintext, out _);
        return (GssapiProtectionLevel)plaintext.WrittenSpan[0];
    }

    /// <summary>Wraps the connection when the negotiated level calls for encapsulation.</summary>
    internal static Stream Wrap(Stream stream, GssapiProtectionLevel level) =>
        level == GssapiProtectionLevel.None
            ? stream
            : new TestProtectedStream(stream, _lastContext!, level == GssapiProtectionLevel.Confidentiality);

    private static string TargetName =>
        $"HOST/{Dns.GetHostName()}";

    private static bool Probe()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using NegotiateAuthentication client = new(new NegotiateAuthenticationClientOptions
            {
                Package = "Negotiate",
                TargetName = $"HOST/{Dns.GetHostName()}",
            });

            using NegotiateAuthentication server = new(new NegotiateAuthenticationServerOptions
            {
                Package = "Negotiate",
            });

            byte[]? blob = client.GetOutgoingBlob([], out NegotiateAuthenticationStatusCode status);

            for (int leg = 0; leg < 8 && blob is not null; leg++)
            {
                byte[]? response = server.GetOutgoingBlob(blob, out NegotiateAuthenticationStatusCode serverStatus);

                if (serverStatus == NegotiateAuthenticationStatusCode.Completed)
                {
                    return server.IsAuthenticated;
                }

                if (serverStatus != NegotiateAuthenticationStatusCode.ContinueNeeded || response is null)
                {
                    return false;
                }

                blob = client.GetOutgoingBlob(response, out status);

                if (status is not (NegotiateAuthenticationStatusCode.ContinueNeeded
                    or NegotiateAuthenticationStatusCode.Completed))
                {
                    return false;
                }
            }

            return false;
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>The client-side mirror of the server's encapsulating stream.</summary>
    private sealed class TestProtectedStream(Stream inner, NegotiateAuthentication context, bool encrypt) : Stream
    {
        private byte[] _pending = [];
        private int _offset;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (_offset == _pending.Length)
            {
                (GssapiMessageType type, byte[] token) = await GssapiMessage.ReadAsync(inner, cancellationToken);
                if (type != GssapiMessageType.EncapsulatedData)
                {
                    return 0;
                }

                ArrayBufferWriter<byte> plaintext = new(token.Length);
                context.Unwrap(token, plaintext, out _);
                _pending = plaintext.WrittenSpan.ToArray();
                _offset = 0;
            }

            int count = Math.Min(buffer.Length, _pending.Length - _offset);
            _pending.AsMemory(_offset, count).CopyTo(buffer);
            _offset += count;
            return count;
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ArrayBufferWriter<byte> wrapped = new(buffer.Length + 128);
            context.Wrap(buffer.Span, wrapped, encrypt, out _);
            await GssapiMessage.WriteAsync(inner, GssapiMessageType.EncapsulatedData, wrapped.WrittenMemory, cancellationToken);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count) =>
            WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override void Flush() => inner.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
