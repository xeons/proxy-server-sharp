using System.Buffers;
using System.Net.Sockets;

namespace ProxyServerSharp.Net;

/// <summary>Which way bytes were flowing.</summary>
public enum RelayDirection
{
    /// <summary>From the proxy client towards the destination.</summary>
    ClientToRemote,

    /// <summary>From the destination back to the proxy client.</summary>
    RemoteToClient,
}

/// <summary>Live byte counters for one tunnel, safe to read from another thread.</summary>
public sealed class RelayCounters
{
    private long _clientToRemote;
    private long _remoteToClient;

    /// <summary>Bytes sent from the client towards the destination.</summary>
    public long ClientToRemote => Interlocked.Read(ref _clientToRemote);

    /// <summary>Bytes sent from the destination back to the client.</summary>
    public long RemoteToClient => Interlocked.Read(ref _remoteToClient);

    /// <summary>Total bytes relayed in both directions.</summary>
    public long Total => ClientToRemote + RemoteToClient;

    internal void Add(RelayDirection direction, int count)
    {
        if (direction == RelayDirection.ClientToRemote)
        {
            Interlocked.Add(ref _clientToRemote, count);
        }
        else
        {
            Interlocked.Add(ref _remoteToClient, count);
        }
    }
}

/// <summary>How a tunnel should be pumped.</summary>
/// <param name="BufferSize">Relay buffer size per direction, in bytes.</param>
/// <param name="IdleTimeout">
/// How long the tunnel may sit with no traffic in either direction before it is torn down.
/// <see cref="Timeout.InfiniteTimeSpan"/> disables the check.
/// </param>
/// <param name="Counters">Optional live counters, shared with whatever is displaying progress.</param>
public readonly record struct RelayOptions(
    int BufferSize = 32 * 1024,
    TimeSpan IdleTimeout = default,
    RelayCounters? Counters = null);

/// <summary>
/// Pumps bytes between a proxy client and its destination until both directions finish.
/// </summary>
/// <remarks>
/// The original implementation gave each direction a dedicated thread and tore both sockets down
/// as soon as either end closed, which truncated responses whenever a client half-closed after
/// sending its request. This version is fully asynchronous and honours half-close: the end of one
/// direction only shuts down the far side's send channel, and the other direction keeps running.
/// </remarks>
public static class TunnelRelay
{
    /// <summary>Relays until both directions close, the idle timeout fires, or the token is cancelled.</summary>
    /// <param name="client">The stream facing the proxy client.</param>
    /// <param name="remote">The stream facing the destination.</param>
    /// <param name="options">Buffer size, idle timeout and counters.</param>
    /// <param name="clientSocket">The client socket, when half-close is possible.</param>
    /// <param name="remoteSocket">The destination socket, when half-close is possible.</param>
    /// <param name="cancellationToken">Tears the tunnel down on shutdown.</param>
    public static async Task<RelayCounters> RunAsync(
        Stream client,
        Stream remote,
        RelayOptions options,
        Socket? clientSocket = null,
        Socket? remoteSocket = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(remote);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.BufferSize, 1024);

        RelayCounters counters = options.Counters ?? new RelayCounters();
        IdleWatchdog watchdog = new(options.IdleTimeout);

        using CancellationTokenSource tunnel = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        Task upstream = PumpAsync(
            client, remote, remoteSocket, RelayDirection.ClientToRemote, options, counters, watchdog, tunnel);
        Task downstream = PumpAsync(
            remote, client, clientSocket, RelayDirection.RemoteToClient, options, counters, watchdog, tunnel);
        Task idle = watchdog.RunAsync(tunnel);

        try
        {
            await Task.WhenAll(upstream, downstream).ConfigureAwait(false);
        }
        finally
        {
            await tunnel.CancelAsync().ConfigureAwait(false);
            await idle.ConfigureAwait(false);
        }

        return counters;
    }

    private static async Task PumpAsync(
        Stream source,
        Stream destination,
        Socket? destinationSocket,
        RelayDirection direction,
        RelayOptions options,
        RelayCounters counters,
        IdleWatchdog watchdog,
        CancellationTokenSource tunnel)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(options.BufferSize);
        try
        {
            while (true)
            {
                int read;
                try
                {
                    read = await source.ReadAsync(buffer, tunnel.Token).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsExpectedTermination(exception))
                {
                    // A reset or a cancelled shutdown is a normal way for a tunnel to end.
                    break;
                }

                if (read == 0)
                {
                    break;
                }

                watchdog.Touch();

                try
                {
                    await destination.WriteAsync(buffer.AsMemory(0, read), tunnel.Token).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsExpectedTermination(exception))
                {
                    break;
                }

                counters.Add(direction, read);
                watchdog.Touch();
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            HalfClose(destinationSocket);
        }
    }

    /// <summary>
    /// Signals end-of-stream to the far side without killing the other direction, so a client
    /// that half-closes still receives the rest of the response.
    /// </summary>
    private static void HalfClose(Socket? socket)
    {
        if (socket is null)
        {
            return;
        }

        try
        {
            socket.Shutdown(SocketShutdown.Send);
        }
        catch (SocketException)
        {
            // The peer is already gone; nothing to signal.
        }
        catch (ObjectDisposedException)
        {
            // The connection was torn down underneath us.
        }
    }

    private static bool IsExpectedTermination(Exception exception) => exception switch
    {
        OperationCanceledException => true,
        ObjectDisposedException => true,
        IOException { InnerException: SocketException } => true,
        SocketException => true,
        _ => false,
    };

    /// <summary>Cancels the tunnel once neither direction has moved a byte for the idle window.</summary>
    private sealed class IdleWatchdog(TimeSpan idleTimeout)
    {
        private readonly TimeSpan _idleTimeout = idleTimeout <= TimeSpan.Zero ? Timeout.InfiniteTimeSpan : idleTimeout;
        private long _lastActivityTicks = Environment.TickCount64;

        public void Touch() => Interlocked.Exchange(ref _lastActivityTicks, Environment.TickCount64);

        public async Task RunAsync(CancellationTokenSource tunnel)
        {
            if (_idleTimeout == Timeout.InfiniteTimeSpan)
            {
                return;
            }

            // Poll at a quarter of the window: precise enough for a timeout measured in minutes,
            // and far cheaper than rescheduling a timer on every chunk of traffic.
            TimeSpan interval = TimeSpan.FromMilliseconds(Math.Max(500, _idleTimeout.TotalMilliseconds / 4));
            using PeriodicTimer timer = new(interval);

            try
            {
                while (await timer.WaitForNextTickAsync(tunnel.Token).ConfigureAwait(false))
                {
                    long idleMs = Environment.TickCount64 - Interlocked.Read(ref _lastActivityTicks);
                    if (idleMs >= _idleTimeout.TotalMilliseconds)
                    {
                        await tunnel.CancelAsync().ConfigureAwait(false);
                        return;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // The tunnel finished on its own.
            }
        }
    }
}
