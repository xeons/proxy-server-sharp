using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;

namespace ProxyServerSharp.Authentication.Http;

/// <summary>Whether a nonce presented by a client is usable.</summary>
public enum NonceValidation
{
    /// <summary>The nonce is genuine, unexpired, and the nonce count has not been seen before.</summary>
    Valid,

    /// <summary>The nonce is genuine but expired or replayed; answer with <c>stale=true</c>.</summary>
    Stale,

    /// <summary>The nonce was not issued by this server.</summary>
    Invalid,
}

/// <summary>
/// Issues and validates Digest nonces. Each nonce is an HMAC-signed timestamp, so validity is
/// self-describing and no state is needed to reject forgeries; the in-memory table exists only
/// to enforce strictly increasing nonce counts and stop replay.
/// </summary>
public sealed class DigestNonceManager
{
    private const int RandomBytes = 12;
    private const int SignatureBytes = 16;

    private readonly ConcurrentDictionary<string, NonceState> _issued = new(StringComparer.Ordinal);
    private readonly byte[] _secret = RandomNumberGenerator.GetBytes(32);
    private readonly TimeSpan _lifetime;
    private readonly TimeProvider _timeProvider;
    private long _lastSweepTicks;

    /// <summary>Creates a nonce manager.</summary>
    /// <param name="lifetime">How long a nonce stays fresh.</param>
    /// <param name="timeProvider">The clock, overridable in tests.</param>
    public DigestNonceManager(TimeSpan lifetime, TimeProvider? timeProvider = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);
        _lifetime = lifetime;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _lastSweepTicks = _timeProvider.GetUtcNow().UtcTicks;
    }

    /// <summary>The server-side opaque value echoed by clients across a protection space.</summary>
    public string Opaque { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    /// <summary>Issues a fresh nonce.</summary>
    public string Create()
    {
        long timestamp = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();

        Span<byte> payload = stackalloc byte[sizeof(long) + RandomBytes];
        BitConverter.TryWriteBytes(payload, timestamp);
        RandomNumberGenerator.Fill(payload[sizeof(long)..]);

        Span<byte> nonce = stackalloc byte[payload.Length + SignatureBytes];
        payload.CopyTo(nonce);
        Sign(payload, nonce[payload.Length..]);

        string encoded = Convert.ToBase64String(nonce);
        _issued[encoded] = new NonceState(timestamp);
        Sweep();
        return encoded;
    }

    /// <summary>
    /// Validates a nonce and its nonce count.
    /// </summary>
    /// <param name="nonce">The <c>nonce</c> parameter echoed by the client.</param>
    /// <param name="nonceCount">
    /// The <c>nc</c> parameter, which must strictly increase per nonce. Pass <c>0</c> when the
    /// client did not send one, which skips the replay check.
    /// </param>
    public NonceValidation Validate(string? nonce, long nonceCount)
    {
        if (string.IsNullOrEmpty(nonce))
        {
            return NonceValidation.Invalid;
        }

        Span<byte> decoded = stackalloc byte[sizeof(long) + RandomBytes + SignatureBytes];
        if (!Convert.TryFromBase64String(nonce, decoded, out int written) || written != decoded.Length)
        {
            return NonceValidation.Invalid;
        }

        ReadOnlySpan<byte> payload = decoded[..(sizeof(long) + RandomBytes)];
        Span<byte> expected = stackalloc byte[SignatureBytes];
        Sign(payload, expected);

        if (!CryptographicOperations.FixedTimeEquals(expected, decoded[payload.Length..]))
        {
            return NonceValidation.Invalid;
        }

        long issuedAt = BitConverter.ToInt64(payload);
        long age = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds() - issuedAt;
        if (age < 0 || age > _lifetime.TotalMilliseconds)
        {
            _issued.TryRemove(nonce, out _);
            return NonceValidation.Stale;
        }

        // A nonce this server signed but has no record of survived a restart, or was swept.
        // Treat it as stale so the client simply retries with a fresh one.
        if (!_issued.TryGetValue(nonce, out NonceState? state))
        {
            return NonceValidation.Stale;
        }

        if (nonceCount > 0 && !state.TryAdvance(nonceCount))
        {
            return NonceValidation.Stale;
        }

        return NonceValidation.Valid;
    }

    private void Sign(ReadOnlySpan<byte> payload, Span<byte> destination)
    {
        Span<byte> full = stackalloc byte[HMACSHA256.HashSizeInBytes];
        HMACSHA256.HashData(_secret, payload, full);
        full[..SignatureBytes].CopyTo(destination);
    }

    private void Sweep()
    {
        long now = _timeProvider.GetUtcNow().UtcTicks;
        long last = Interlocked.Read(ref _lastSweepTicks);

        // Amortise cleanup: at most one sweep per lifetime window, whoever gets there first.
        if (now - last < _lifetime.Ticks)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _lastSweepTicks, now, last) != last)
        {
            return;
        }

        long cutoff = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds() - (long)_lifetime.TotalMilliseconds;
        foreach ((string nonce, NonceState state) in _issued)
        {
            if (state.IssuedAtUnixMs < cutoff)
            {
                _issued.TryRemove(nonce, out _);
            }
        }
    }

    private sealed class NonceState(long issuedAtUnixMs)
    {
        private long _highestNonceCount;

        public long IssuedAtUnixMs { get; } = issuedAtUnixMs;

        /// <summary>Accepts <paramref name="nonceCount"/> only if it exceeds every count seen so far.</summary>
        public bool TryAdvance(long nonceCount)
        {
            long observed = Interlocked.Read(ref _highestNonceCount);
            while (nonceCount > observed)
            {
                long previous = Interlocked.CompareExchange(ref _highestNonceCount, nonceCount, observed);
                if (previous == observed)
                {
                    return true;
                }

                observed = previous;
            }

            return false;
        }
    }

    /// <summary>Parses the hex <c>nc</c> parameter, returning <c>0</c> when it is absent or malformed.</summary>
    internal static long ParseNonceCount(string? nc) =>
        !string.IsNullOrEmpty(nc) && long.TryParse(nc, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long value)
            ? value
            : 0;
}
