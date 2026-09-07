using System.Security.Cryptography;
using System.Text;

namespace ProxyServerSharp.Authentication;

/// <summary>
/// PBKDF2-HMAC-SHA256 password verifiers, stored as
/// <c>pbkdf2-sha256$&lt;iterations&gt;$&lt;base64 salt&gt;$&lt;base64 hash&gt;</c>.
/// </summary>
/// <remarks>
/// The original project stored nothing at all; this replaces that with a verifier that is safe
/// to keep in a config file checked into source control.
/// </remarks>
public static class PasswordHasher
{
    private const string Prefix = "pbkdf2-sha256";
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    /// <summary>OWASP's 2023 floor for PBKDF2-HMAC-SHA256.</summary>
    public const int DefaultIterations = 600_000;

    /// <summary>Derives a storable verifier for <paramref name="password"/>.</summary>
    public static string Hash(string password, int iterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);

        byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
        byte[] hash = Derive(password, salt, iterations);
        return $"{Prefix}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    /// <summary>
    /// Verifies <paramref name="password"/> against <paramref name="encoded"/> in constant time.
    /// Returns <see langword="false"/> for malformed verifiers rather than throwing, so a typo in
    /// the config file cannot crash the handshake path.
    /// </summary>
    public static bool Verify(string? password, string? encoded)
    {
        if (password is null || string.IsNullOrEmpty(encoded))
        {
            return false;
        }

        string[] parts = encoded.Split('$');
        if (parts.Length != 4 || !string.Equals(parts[0], Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        if (!int.TryParse(parts[1], out int iterations) || iterations < 1)
        {
            return false;
        }

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length == 0 || expected.Length == 0)
        {
            return false;
        }

        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            expected.Length);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> looks like a PBKDF2 verifier.</summary>
    public static bool IsHash(string? value) =>
        value is not null && value.StartsWith(Prefix + "$", StringComparison.Ordinal);

    private static byte[] Derive(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            HashBytes);
}
