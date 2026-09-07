using System.Net;
using ProxyServerSharp.Authentication;
using ProxyServerSharp.Authentication.Http;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Tests;

/// <summary>Unit tests for the credential primitives.</summary>
public sealed class PasswordHasherTests
{
    [Fact]
    public void Verify_AcceptsTheOriginalPassword()
    {
        string hash = PasswordHasher.Hash("correct horse", iterations: 1000);

        Assert.True(PasswordHasher.Verify("correct horse", hash));
    }

    [Fact]
    public void Verify_RejectsADifferentPassword()
    {
        string hash = PasswordHasher.Hash("correct horse", iterations: 1000);

        Assert.False(PasswordHasher.Verify("correct horsf", hash));
    }

    [Fact]
    public void Hash_UsesAFreshSaltEachTime()
    {
        Assert.NotEqual(
            PasswordHasher.Hash("same", iterations: 1000),
            PasswordHasher.Hash("same", iterations: 1000));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("pbkdf2-sha256$notanumber$c2FsdA==$aGFzaA==")]
    [InlineData("pbkdf2-sha256$1000$!!!not base64!!!$aGFzaA==")]
    [InlineData("pbkdf2-sha256$1000$c2FsdA==")]
    public void Verify_ReturnsFalseForMalformedVerifiers(string encoded)
    {
        // A typo in a configuration file must not take the handshake path down with it.
        Assert.False(PasswordHasher.Verify("anything", encoded));
    }

    [Fact]
    public void IsHash_RecognisesItsOwnFormat()
    {
        Assert.True(PasswordHasher.IsHash(PasswordHasher.Hash("x", iterations: 1000)));
        Assert.False(PasswordHasher.IsHash("plaintext"));
    }
}

/// <summary>Unit tests for the in-memory account directory.</summary>
public sealed class InMemoryUserStoreTests
{
    [Fact]
    public async Task ValidatePassword_AcceptsAHashedAccount()
    {
        InMemoryUserStore store = new([Account("alice", "hunter2")]);

        AuthenticationResult result = await store.ValidatePasswordAsync(
            "alice",
            "hunter2",
            UserStoreContext.None);

        Assert.True(result.Succeeded);
        Assert.Equal("alice", result.Identity!.Name);
    }

    [Fact]
    public async Task ValidatePassword_IsCaseInsensitiveOnTheUsername()
    {
        InMemoryUserStore store = new([Account("Alice", "hunter2")]);

        AuthenticationResult result = await store.ValidatePasswordAsync("ALICE", "hunter2", UserStoreContext.None);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidatePassword_RejectsADisabledAccount()
    {
        ProxyUserOptions account = Account("alice", "hunter2");
        account.Enabled = false;

        InMemoryUserStore store = new([account]);
        AuthenticationResult result = await store.ValidatePasswordAsync("alice", "hunter2", UserStoreContext.None);

        Assert.False(result.Succeeded);
        Assert.Contains("disabled", result.FailureReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidatePassword_EnforcesTheClientAddressGrant()
    {
        ProxyUserOptions account = Account("alice", "hunter2");
        account.AllowedClients.Add("10.0.0.0/8");

        InMemoryUserStore store = new([account]);

        AuthenticationResult allowed = await store.ValidatePasswordAsync(
            "alice",
            "hunter2",
            new UserStoreContext("listener", IPAddress.Parse("10.1.2.3")));

        AuthenticationResult refused = await store.ValidatePasswordAsync(
            "alice",
            "hunter2",
            new UserStoreContext("listener", IPAddress.Parse("192.168.1.1")));

        Assert.True(allowed.Succeeded);
        Assert.False(refused.Succeeded);
    }

    [Fact]
    public async Task GetDigestHa1_DerivesFromAStoredPassword()
    {
        InMemoryUserStore store = new([new ProxyUserOptions { Username = "alice", Password = "hunter2" }]);

        string? ha1 = await store.GetDigestHa1Async("alice", "realm", DigestHash.Sha256, UserStoreContext.None);

        Assert.Equal(DigestHash.ComputeHa1(DigestHash.Sha256, "alice", "realm", "hunter2"), ha1);
    }

    [Fact]
    public async Task GetDigestHa1_PrefersAPrecomputedValue()
    {
        ProxyUserOptions account = new() { Username = "alice", Password = "ignored" };
        account.DigestHa1["realm:SHA-256"] = "precomputed";

        InMemoryUserStore store = new([account]);
        string? ha1 = await store.GetDigestHa1Async("alice", "realm", DigestHash.Sha256, UserStoreContext.None);

        Assert.Equal("precomputed", ha1);
    }

    [Fact]
    public async Task GetDigestHa1_ReturnsNullForAHashOnlyAccount()
    {
        // A one-way PBKDF2 verifier cannot produce HA1, so Digest is impossible for this account.
        InMemoryUserStore store = new([Account("alice", "hunter2")]);

        Assert.Null(await store.GetDigestHa1Async("alice", "realm", DigestHash.Sha256, UserStoreContext.None));
        Assert.False(store.SupportsDigest("alice"));
    }

    [Fact]
    public async Task ValidateToken_MatchesAcrossAccounts()
    {
        ProxyUserOptions bob = Account("bob", "x");
        bob.TokenHashes.Add(PasswordHasher.Hash("bob-token", iterations: 1000));

        InMemoryUserStore store = new([Account("alice", "hunter2"), bob]);

        AuthenticationResult result = await store.ValidateTokenAsync("bob-token", UserStoreContext.None);

        Assert.True(result.Succeeded);
        Assert.Equal("bob", result.Identity!.Name);
    }

    [Fact]
    public void Constructor_RejectsDuplicateUsernames()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            new InMemoryUserStore([Account("alice", "a"), Account("alice", "b")]));

        Assert.Contains("Duplicate", exception.Message, StringComparison.Ordinal);
    }

    private static ProxyUserOptions Account(string username, string password) => new()
    {
        Username = username,
        PasswordHash = PasswordHasher.Hash(password, iterations: 1000),
    };
}

/// <summary>Unit tests for Digest primitives.</summary>
public sealed class DigestTests
{
    [Fact]
    public void Parse_ReadsQuotedAndUnquotedParameters()
    {
        DigestParameters parameters = DigestParameters.Parse(
            "username=\"alice\", realm=\"a realm\", nc=00000001, qop=auth, response=\"abc\"");

        Assert.Equal("alice", parameters["username"]);
        Assert.Equal("a realm", parameters["realm"]);
        Assert.Equal("00000001", parameters["nc"]);
        Assert.Equal("auth", parameters["qop"]);
        Assert.Equal("abc", parameters["response"]);
    }

    [Fact]
    public void Parse_HandlesEscapedQuotesAndCommasInsideValues()
    {
        DigestParameters parameters = DigestParameters.Parse("realm=\"a \\\"quoted\\\", realm\", nc=1");

        Assert.Equal("a \"quoted\", realm", parameters["realm"]);
        Assert.Equal("1", parameters["nc"]);
    }

    [Fact]
    public void Parse_IsCaseInsensitiveOnParameterNames()
    {
        DigestParameters parameters = DigestParameters.Parse("USERNAME=\"alice\"");

        Assert.Equal("alice", parameters["username"]);
    }

    [Theory]
    [InlineData("SHA-256", "SHA-256", false)]
    [InlineData("sha-256", "SHA-256", false)]
    [InlineData("MD5-sess", "MD5", true)]
    [InlineData("SHA-512-256", "SHA-512-256", false)]
    [InlineData(null, "MD5", false)]
    public void TryNormalize_AcceptsSupportedAlgorithms(string? input, string expected, bool expectedSession)
    {
        Assert.True(DigestHash.TryNormalize(input, out string normalized, out bool isSession));
        Assert.Equal(expected, normalized);
        Assert.Equal(expectedSession, isSession);
    }

    [Fact]
    public void TryNormalize_RejectsAnUnknownAlgorithm()
    {
        Assert.False(DigestHash.TryNormalize("SHA-1", out _, out _));
    }

    [Fact]
    public void ComputeHa1_MatchesTheRfcDefinition()
    {
        // HA1 = H(username:realm:password)
        Assert.Equal(
            DigestHash.Compute(DigestHash.Md5, "alice:realm:hunter2"),
            DigestHash.ComputeHa1(DigestHash.Md5, "alice", "realm", "hunter2"));
    }

    [Fact]
    public void NonceManager_AcceptsAFreshNonceOnce()
    {
        DigestNonceManager nonces = new(TimeSpan.FromMinutes(5));
        string nonce = nonces.Create();

        Assert.Equal(NonceValidation.Valid, nonces.Validate(nonce, 1));
    }

    [Fact]
    public void NonceManager_RejectsAReplayedNonceCount()
    {
        DigestNonceManager nonces = new(TimeSpan.FromMinutes(5));
        string nonce = nonces.Create();

        Assert.Equal(NonceValidation.Valid, nonces.Validate(nonce, 1));
        Assert.Equal(NonceValidation.Stale, nonces.Validate(nonce, 1));
        Assert.Equal(NonceValidation.Valid, nonces.Validate(nonce, 2));
    }

    [Fact]
    public void NonceManager_RejectsAForgedNonce()
    {
        DigestNonceManager nonces = new(TimeSpan.FromMinutes(5));

        Assert.Equal(NonceValidation.Invalid, nonces.Validate("not-a-nonce", 1));
        Assert.Equal(NonceValidation.Invalid, nonces.Validate(Convert.ToBase64String(new byte[36]), 1));
    }

    [Fact]
    public void NonceManager_MarksAnExpiredNonceStale()
    {
        FakeTimeProvider clock = new(DateTimeOffset.UtcNow);
        DigestNonceManager nonces = new(TimeSpan.FromMinutes(5), clock);

        string nonce = nonces.Create();
        clock.Advance(TimeSpan.FromMinutes(6));

        Assert.Equal(NonceValidation.Stale, nonces.Validate(nonce, 1));
    }

    /// <summary>A clock the nonce tests can move forward without waiting.</summary>
    private sealed class FakeTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }
}

/// <summary>Unit tests for credential header parsing.</summary>
public sealed class HttpCredentialTests
{
    [Theory]
    [InlineData("Basic YWxpY2U6aHVudGVyMg==", "Basic", "YWxpY2U6aHVudGVyMg==")]
    [InlineData("  Digest   username=\"a\"  ", "Digest", "username=\"a\"")]
    [InlineData("Negotiate", "Negotiate", "")]
    public void TryParse_SplitsSchemeFromParameter(string header, string scheme, string parameter)
    {
        Assert.True(HttpCredential.TryParse(header, out HttpCredential credential));
        Assert.Equal(scheme, credential.Scheme);
        Assert.Equal(parameter, credential.Parameter);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryParse_RejectsEmptyValues(string? header)
    {
        Assert.False(HttpCredential.TryParse(header, out _));
    }

    [Fact]
    public void Is_ComparesTheSchemeCaseInsensitively()
    {
        Assert.True(HttpCredential.TryParse("basic abc", out HttpCredential credential));
        Assert.True(credential.Is("Basic"));
        Assert.False(credential.Is("Digest"));
    }
}
