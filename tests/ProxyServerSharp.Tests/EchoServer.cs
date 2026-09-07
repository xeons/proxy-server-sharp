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
