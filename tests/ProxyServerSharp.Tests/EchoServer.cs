using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ProxyServerSharp.Tests;

/// <summary>
/// A trivial TCP origin server that echoes what it receives, so a test can prove bytes really
/// travelled through the proxy in both directions.
/// </summary>
internal sealed class EchoServer : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _acceptLoop;

    private EchoServer(Socket listener)
    {
        _listener = listener;
        EndPoint = (IPEndPoint)listener.LocalEndPoint!;
        _acceptLoop = AcceptAsync();
    }

    /// <summary>Where the echo server is listening.</summary>
    internal IPEndPoint EndPoint { get; }

    /// <summary>Starts an echo server on an ephemeral loopback port.</summary>
    internal static EchoServer Start()
    {
        Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(16);
        return new EchoServer(listener);
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

            _ = EchoAsync(client);
        }
    }

    private async Task EchoAsync(Socket client)
    {
        using (client)
        {
            byte[] buffer = new byte[4096];

            try
            {
                while (true)
                {
                    int read = await client.ReceiveAsync(buffer, SocketFlags.None, _shutdown.Token);
                    if (read == 0)
                    {
                        break;
                    }

                    await client.SendAsync(buffer.AsMemory(0, read), SocketFlags.None, _shutdown.Token);
                }
            }
            catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                // The client went away.
            }
        }
    }
}

/// <summary>
/// A minimal HTTP origin server that answers every request with a fixed body, for exercising the
/// HTTP proxy's forwarding path.
/// </summary>
internal sealed class HttpOriginServer : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _acceptLoop;
    private readonly string _body;

    private HttpOriginServer(Socket listener, string body)
    {
        _listener = listener;
        _body = body;
        EndPoint = (IPEndPoint)listener.LocalEndPoint!;
        _acceptLoop = AcceptAsync();
    }

    /// <summary>Where the origin server is listening.</summary>
    internal IPEndPoint EndPoint { get; }

    /// <summary>The most recent request head the server received, for asserting on rewriting.</summary>
    internal string LastRequest { get; private set; } = "";

    /// <summary>Starts an origin server on an ephemeral loopback port.</summary>
    internal static HttpOriginServer Start(string body = "hello from origin")
    {
        Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(16);
        return new HttpOriginServer(listener, body);
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

            _ = RespondAsync(client);
        }
    }

    private async Task RespondAsync(Socket client)
    {
        using (client)
        {
            try
            {
                await using NetworkStream stream = new(client, ownsSocket: false);
                byte[] buffer = new byte[8192];
                StringBuilder request = new();

                // Read until the header block ends; these tests never send a request body.
                while (!request.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    int read = await stream.ReadAsync(buffer, _shutdown.Token);
                    if (read == 0)
                    {
                        return;
                    }

                    request.Append(Encoding.Latin1.GetString(buffer, 0, read));
                }

                LastRequest = request.ToString();

                byte[] response = Encoding.Latin1.GetBytes(
                    $"HTTP/1.1 200 OK\r\nContent-Length: {_body.Length}\r\nConnection: close\r\n\r\n{_body}");

                await stream.WriteAsync(response, _shutdown.Token);
                await stream.FlushAsync(_shutdown.Token);
                client.Shutdown(SocketShutdown.Send);
            }
            catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException or IOException)
            {
                // The client went away.
            }
        }
    }
}
