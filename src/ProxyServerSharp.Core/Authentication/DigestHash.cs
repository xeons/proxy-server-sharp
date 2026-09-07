using System.Security.Cryptography;
using System.Text;

namespace ProxyServerSharp.Authentication;

/// <summary>The hash primitives RFC 7616 Digest is defined in terms of.</summary>
public static class DigestHash
{
    /// <summary>RFC 7616 <c>SHA-256</c>.</summary>
    public const string Sha256 = "SHA-256";

    /// <summary>RFC 7616 <c>SHA-512-256</c>.</summary>
    public const string Sha512Trunc256 = "SHA-512-256";

    /// <summary>RFC 2617 <c>MD5</c>, kept for clients that never implemented anything newer.</summary>
    public const string Md5 = "MD5";

    /// <summary>The algorithms this server will negotiate, strongest first.</summary>
    public static IReadOnlyList<string> SupportedAlgorithms { get; } = [Sha256, Sha512Trunc256, Md5];

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="algorithm"/> is supported, stripping any
    /// <c>-sess</c> suffix into <paramref name="isSession"/>.
    /// </summary>
    public static bool TryNormalize(string? algorithm, out string normalized, out bool isSession)
    {
        normalized = Sha256;
        isSession = false;

        // RFC 7616 §3.4.2: a missing algorithm parameter means MD5.
        string candidate = string.IsNullOrEmpty(algorithm) ? Md5 : algorithm.Trim();

        if (candidate.EndsWith("-sess", StringComparison.OrdinalIgnoreCase))
        {
            isSession = true;
            candidate = candidate[..^"-sess".Length];
        }

        foreach (string supported in SupportedAlgorithms)
        {
            if (string.Equals(candidate, supported, StringComparison.OrdinalIgnoreCase))
            {
                normalized = supported;
                return true;
            }
        }

        return false;
    }

    /// <summary>Hashes <paramref name="value"/> with <paramref name="algorithm"/>, returning lowercase hex.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The algorithm is not one of <see cref="SupportedAlgorithms"/>.</exception>
    public static string Compute(string algorithm, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        byte[] bytes = Encoding.UTF8.GetBytes(value);

        byte[] digest = algorithm switch
        {
            Sha256 => SHA256.HashData(bytes),
            // SHA-512-256 is SHA-512 truncated to its first 256 bits, per RFC 7616 §6.1.
            Sha512Trunc256 => SHA512.HashData(bytes)[..32],
            Md5 => MD5.HashData(bytes),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported digest algorithm."),
        };

        return Convert.ToHexStringLower(digest);
    }

    /// <summary>Computes <c>HA1 = H(username:realm:password)</c>.</summary>
    public static string ComputeHa1(string algorithm, string username, string realm, string password) =>
        Compute(algorithm, $"{username}:{realm}:{password}");
}
