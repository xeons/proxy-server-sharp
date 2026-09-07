using System.Net;
using System.Security.Cryptography;
using System.Text;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Authentication;

/// <summary>
/// The default <see cref="IUserStore"/>: accounts loaded from configuration and held in memory.
/// </summary>
public sealed class InMemoryUserStore : IUserStore
{
    private readonly Dictionary<string, Account> _accounts;

    /// <summary>Builds a store from bound configuration.</summary>
    /// <exception cref="ArgumentException">An account has no username, or two share one.</exception>
    public InMemoryUserStore(IEnumerable<ProxyUserOptions> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        _accounts = new Dictionary<string, Account>(StringComparer.OrdinalIgnoreCase);
        foreach (ProxyUserOptions user in users)
        {
            if (string.IsNullOrWhiteSpace(user.Username))
            {
                throw new ArgumentException("A proxy user was configured without a username.", nameof(users));
            }

            if (!_accounts.TryAdd(user.Username, Account.From(user)))
            {
                throw new ArgumentException($"Duplicate proxy user '{user.Username}'.", nameof(users));
            }
        }
    }

    /// <inheritdoc />
    public bool IsEmpty => _accounts.Count == 0;

    /// <summary>The configured account names, for diagnostics and the desktop UI.</summary>
    public IReadOnlyCollection<string> Usernames => _accounts.Keys;

    /// <inheritdoc />
    public ValueTask<AuthenticationResult> ValidatePasswordAsync(
        string username,
        string password,
        UserStoreContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(password);
        cancellationToken.ThrowIfCancellationRequested();

        if (!TryResolve(username, context, out Account? account, out string? failure))
        {
            // Verify against a throwaway hash anyway, so an unknown username and a wrong
            // password cost roughly the same and cannot be told apart by timing.
            _ = PasswordHasher.Verify(password, DummyHash.Value);
            return ValueTask.FromResult(AuthenticationResult.Fail(failure));
        }

        bool valid = account.PasswordHash is not null
            ? PasswordHasher.Verify(password, account.PasswordHash)
            : account.Password is not null && FixedTimeEquals(password, account.Password);

        return ValueTask.FromResult(valid
            ? AuthenticationResult.Success(new ProxyIdentity(account.Username, AuthenticationMethod.UsernamePassword))
            : AuthenticationResult.Fail($"Incorrect password for '{username}'."));
    }

    /// <inheritdoc />
    public ValueTask<AuthenticationResult> ValidateTokenAsync(
        string token,
        UserStoreContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        cancellationToken.ThrowIfCancellationRequested();

        // A bearer token names its own account, so every account's tokens are candidates.
        foreach (Account account in _accounts.Values)
        {
            foreach (string tokenHash in account.TokenHashes)
            {
                if (!PasswordHasher.Verify(token, tokenHash))
                {
                    continue;
                }

                return ValueTask.FromResult(IsPermitted(account, context, out string? failure)
                    ? AuthenticationResult.Success(new ProxyIdentity(account.Username, AuthenticationMethod.Bearer))
                    : AuthenticationResult.Fail(failure!));
            }
        }

        return ValueTask.FromResult(AuthenticationResult.Fail("No account matches the presented bearer token."));
    }

    /// <inheritdoc />
    public ValueTask<AuthenticationResult> ValidateNameAsync(
        string username,
        UserStoreContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(username);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(TryResolve(username, context, out Account? account, out string? failure)
            ? AuthenticationResult.Success(new ProxyIdentity(account.Username, AuthenticationMethod.UserId))
            : AuthenticationResult.Fail(failure));
    }

    /// <inheritdoc />
    public ValueTask<string?> GetDigestHa1Async(
        string username,
        string realm,
        string algorithm,
        UserStoreContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(realm);
        ArgumentNullException.ThrowIfNull(algorithm);
        cancellationToken.ThrowIfCancellationRequested();

        if (!TryResolve(username, context, out Account? account, out _))
        {
            return ValueTask.FromResult<string?>(null);
        }

        if (account.DigestHa1.TryGetValue($"{realm}:{algorithm}", out string? precomputed))
        {
            return ValueTask.FromResult<string?>(precomputed);
        }

        // Digest is a challenge-response over the password itself, so a one-way PasswordHash
        // cannot satisfy it; only a stored plaintext password or a precomputed HA1 can.
        return ValueTask.FromResult(account.Password is null
            ? null
            : DigestHash.ComputeHa1(algorithm, account.Username, realm, account.Password));
    }

    /// <summary>Whether <paramref name="username"/> could ever satisfy a Digest challenge.</summary>
    public bool SupportsDigest(string username) =>
        _accounts.TryGetValue(username, out Account? account)
        && (account.Password is not null || account.DigestHa1.Count > 0);

    private bool TryResolve(
        string username,
        UserStoreContext context,
        out Account account,
        out string failure)
    {
        if (!_accounts.TryGetValue(username, out Account? found))
        {
            account = null!;
            failure = $"No such proxy user '{username}'.";
            return false;
        }

        account = found;
        bool permitted = IsPermitted(found, context, out string? reason);
        failure = reason ?? "";
        return permitted;
    }

    private static bool IsPermitted(Account account, UserStoreContext context, out string? failure)
    {
        if (!account.Enabled)
        {
            failure = $"Account '{account.Username}' is disabled.";
            return false;
        }

        if (account.Listeners.Count > 0
            && !string.IsNullOrEmpty(context.ListenerName)
            && !account.Listeners.Contains(context.ListenerName))
        {
            failure = $"Account '{account.Username}' is not granted listener '{context.ListenerName}'.";
            return false;
        }

        if (context.ClientAddress is not null && !account.AllowedClients.IsAllowed(context.ClientAddress))
        {
            failure = $"Account '{account.Username}' is not permitted from {context.ClientAddress}.";
            return false;
        }

        failure = null;
        return true;
    }

    private static bool FixedTimeEquals(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(left),
            Encoding.UTF8.GetBytes(right));

    private sealed class Account
    {
        private Account(ProxyUserOptions options)
        {
            Username = options.Username;
            PasswordHash = string.IsNullOrEmpty(options.PasswordHash) ? null : options.PasswordHash;
            Password = string.IsNullOrEmpty(options.Password) ? null : options.Password;
            Enabled = options.Enabled;
            DigestHa1 = new Dictionary<string, string>(options.DigestHa1, StringComparer.OrdinalIgnoreCase);
            TokenHashes = [.. options.TokenHashes.Where(t => !string.IsNullOrWhiteSpace(t))];
            Listeners = new HashSet<string>(options.Listeners, StringComparer.OrdinalIgnoreCase);
            AllowedClients = AccessControlList.Parse(options.AllowedClients, []);
        }

        public string Username { get; }

        public string? PasswordHash { get; }

        public string? Password { get; }

        public bool Enabled { get; }

        public Dictionary<string, string> DigestHa1 { get; }

        public string[] TokenHashes { get; }

        public HashSet<string> Listeners { get; }

        public AccessControlList AllowedClients { get; }

        public static Account From(ProxyUserOptions options) => new(options);
    }

    private static class DummyHash
    {
        // Built once with a random secret nobody can present, purely as timing ballast.
        internal static readonly string Value = PasswordHasher.Hash(
            Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));
    }
}
