using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Tests.Fakes;
using Xunit;

namespace Vellum.Tests;

public sealed class PayloadEncryptorTests
{
    private const string Scope = "tenant:42";

    private static (PayloadEncryptor Encryptor, FakeKeyEncryptionProvider Provider, DekManager DekManager)
        BuildSut(TimeSpan? dekCacheTtl = null)
    {
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();
        CountingRandomBytesProvider random = new();
        MemoryCache cache = new(new MemoryCacheOptions());
        VellumOptions options = new();
        if (dekCacheTtl is not null)
        {
            options.DekCacheTtl = dekCacheTtl.Value;
        }

        DekManager dekManager = new(
            provider,
            store,
            cache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);

        PayloadEncryptor encryptor = new(
            dekManager,
            random,
            NullLogger<PayloadEncryptor>.Instance);

        return (encryptor, provider, dekManager);
    }

    [Fact]
    public void IsEnabled_Default_IsTrue()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();
        encryptor.IsEnabled.Should().BeTrue();
    }

    [Fact]
    public async Task EncryptDecrypt_Roundtrip_BinaryPayload()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("hello vellum — \u0041\u00e9");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        byte[] decrypted = await encryptor.DecryptAsync(envelope);

        decrypted.Should().Equal(plaintext);
        envelope.Nonce.Should().HaveCount(12);
        envelope.Ciphertext.Length.Should().Be(plaintext.Length + 16);
    }

    [Fact]
    public async Task EncryptDecrypt_Roundtrip_EmptyPayload()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Array.Empty<byte>();
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        byte[] decrypted = await encryptor.DecryptAsync(envelope);

        decrypted.Should().BeEmpty();
        envelope.Ciphertext.Length.Should().Be(16, "empty plaintext still carries a 16-byte auth tag");
    }

    [Fact]
    public async Task EncryptTwice_SamePlaintext_ProducesDifferentCiphertexts()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("repeated plaintext");
        EncryptedPayload first = await encryptor.EncryptAsync(plaintext, Scope);
        EncryptedPayload second = await encryptor.EncryptAsync(plaintext, Scope);

        first.Nonce.Should().NotEqual(second.Nonce, "nonces must never repeat");
        first.Ciphertext.Should().NotEqual(second.Ciphertext);
    }

    [Fact]
    public async Task Decrypt_TamperedCiphertext_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("tamper me");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        envelope.Ciphertext[0] ^= 0xFF;

        Func<Task> act = async () => await encryptor.DecryptAsync(envelope);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_TamperedNonce_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("swap the nonce");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        envelope.Nonce[0] ^= 0xFF;

        Func<Task> act = async () => await encryptor.DecryptAsync(envelope);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_NonceOfWrongLength_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("short nonce");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        EncryptedPayload malformed = new(envelope.Ciphertext, new byte[8], envelope.WrappedDek, envelope.KeyId);

        Func<Task> act = async () => await encryptor.DecryptAsync(malformed);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_CiphertextShorterThanTag_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("tag check");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        EncryptedPayload malformed = new(new byte[8], envelope.Nonce, envelope.WrappedDek, envelope.KeyId);

        Func<Task> act = async () => await encryptor.DecryptAsync(malformed);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_SelfContained_UsesOwnEnvelopeNotStoreLookup()
    {
        // Envelopes carry their own WrappedKey, so decryption goes through the
        // IKeyEncryptionProvider via IDekManager.GetDekByWrappedKeyAsync — never back to
        // IEncryptionKeyStore. This pins the self-contained envelope contract (C3).
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("self contained");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        byte[] decrypted = await encryptor.DecryptAsync(envelope);
        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public async Task DecryptAsync_CachesUnwrappedDek_OnSecondCall()
    {
        // Issue #6: two DecryptAsync calls on the same envelope must trigger exactly ONE
        // IKeyEncryptionProvider.UnwrapAsync. The second call hits the wrapped-key cache.
        (PayloadEncryptor encryptor, FakeKeyEncryptionProvider provider, _) = BuildSut(
            dekCacheTtl: TimeSpan.FromMinutes(30));

        byte[] plaintext = Encoding.UTF8.GetBytes("cached decrypt payload");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        int unwrapsBefore = provider.UnwrapCalls;
        _ = await encryptor.DecryptAsync(envelope);
        _ = await encryptor.DecryptAsync(envelope);

        provider.UnwrapCalls.Should().Be(unwrapsBefore + 1,
            "the second decrypt must hit the wrapped-key cache and avoid a second KEK round-trip");
    }

    [Fact]
    public async Task DecryptAsync_DifferentWrappedKeys_UnwrapBoth()
    {
        // Issue #6: the cache is keyed by the hash of the wrapped ciphertext, not by
        // envelope identity. Two envelopes with DIFFERENT wrapped keys must each trigger
        // their own Unwrap, even when produced by the same PayloadEncryptor.
        (PayloadEncryptor encryptor, FakeKeyEncryptionProvider provider, DekManager dekManager) =
            BuildSut(dekCacheTtl: TimeSpan.FromMinutes(30));

        // First envelope under scope A — primes the cache for WrappedKey A.
        EncryptedPayload envelopeA = await encryptor.EncryptAsync(
            Encoding.UTF8.GetBytes("payload-a"),
            scope: "tenant:a");
        _ = await encryptor.DecryptAsync(envelopeA);

        // Rotate the DEK for scope A so the next EncryptAsync produces a DIFFERENT
        // WrappedKey (different ciphertext handle in the fake provider). This guarantees
        // envelopeA.WrappedDek != envelopeB.WrappedDek even within the same scope.
        await dekManager.RotateDekAsync(scope: "tenant:a");

        EncryptedPayload envelopeB = await encryptor.EncryptAsync(
            Encoding.UTF8.GetBytes("payload-b"),
            scope: "tenant:a");

        envelopeB.WrappedDek.Should().NotBe(envelopeA.WrappedDek,
            "rotation must produce a fresh DEK and therefore a fresh wrapped ciphertext");

        int unwrapsBefore = provider.UnwrapCalls;
        _ = await encryptor.DecryptAsync(envelopeB);
        provider.UnwrapCalls.Should().Be(unwrapsBefore + 1,
            "a different wrapped key must miss the cache and trigger its own Unwrap");

        // And decrypting envelopeA a second time should still be a cache hit.
        int unwrapsAfter = provider.UnwrapCalls;
        _ = await encryptor.DecryptAsync(envelopeA);
        provider.UnwrapCalls.Should().Be(unwrapsAfter,
            "envelopeA's wrapped key must still be cache-hot after envelopeB's decrypt");
    }

    [Fact]
    public async Task StringConvenience_Roundtrip()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        EncryptedPayload envelope = await encryptor.EncryptStringAsync("Hé, Vellum!", Scope);
        string decrypted = await encryptor.DecryptStringAsync(envelope);

        decrypted.Should().Be("Hé, Vellum!");
    }

    [Fact]
    public async Task Decrypt_ProviderReturnsShortDek_ThrowsAndPreservesAes256Contract()
    {
        // H-1: pin the fail-closed behavior on the unwrap path. A buggy or compromised KEK
        // provider returning a 16-byte DEK must NOT silently downgrade the envelope to
        // AES-128. The rejection fires inside IDekManager.GetDekByWrappedKeyAsync (which
        // wraps the unwrap call and runs EnsureDekLength), so PayloadEncryptor sees the
        // CryptographicException bubbling out of the decrypt cache's slow path.
        FakeKeyEncryptionProvider realProvider = new();
        FakeEncryptionKeyStore store = new();
        CountingRandomBytesProvider random = new();
        MemoryCache cache = new(new MemoryCacheOptions());
        VellumOptions options = new();

        DekManager dekManager = new(
            realProvider,
            store,
            cache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);

        PayloadEncryptor encryptor = new(
            dekManager,
            random,
            NullLogger<PayloadEncryptor>.Instance);

        byte[] plaintext = Encoding.UTF8.GetBytes("downgrade check");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        // Rebuild a decrypt-only stack whose KEK provider returns 16 bytes instead of 32.
        // The DekManager under test is fresh (no cache primed for envelope.WrappedDek), so
        // the first DecryptAsync goes through the slow path and hits EnsureDekLength.
        ShortDekKeyEncryptionProvider shortProvider = new(dekBytesLength: 16);
        MemoryCache freshCache = new(new MemoryCacheOptions());
        DekManager decryptDekManager = new(
            shortProvider,
            store,
            freshCache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);
        PayloadEncryptor decryptOnly = new(
            decryptDekManager,
            random,
            NullLogger<PayloadEncryptor>.Instance);

        Func<Task> act = async () => await decryptOnly.DecryptAsync(envelope);
        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage("*expected 32 bytes*");
    }

    [Fact]
    public async Task EncryptAsync_StampsCurrentFormatVersion()
    {
        // C-1/C-2: every freshly produced envelope must carry the current wire-format
        // version so that persisted envelopes are self-describing and future format
        // changes (AAD, key commitment, algorithm) can be detected at decrypt time.
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        EncryptedPayload envelope = await encryptor.EncryptAsync(
            Encoding.UTF8.GetBytes("version stamp"),
            Scope);

        envelope.FormatVersion.Should().Be(EncryptedPayload.CurrentFormatVersion);
        envelope.FormatVersion.Should().Be(1, "version 1 is the only format ever produced so far");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(99)]
    public async Task Decrypt_UnsupportedFormatVersion_FailsClosedBeforeAnyCryptoWork(int unsupportedVersion)
    {
        // C-2: an unknown format version must be rejected BEFORE any crypto work — no DEK
        // unwrap, no KEK round-trip, no AES-GCM call. Interpreting a future format's bytes
        // under the version-1 layout would be undefined behavior.
        (PayloadEncryptor encryptor, FakeKeyEncryptionProvider provider, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("unknown version");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        EncryptedPayload futuristic = envelope with { FormatVersion = unsupportedVersion };

        int unwrapsBefore = provider.UnwrapCalls;
        Func<Task> act = async () => await encryptor.DecryptAsync(futuristic);

        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage($"*format version {unsupportedVersion}*");
        provider.UnwrapCalls.Should().Be(unwrapsBefore,
            "version validation must fire before any DEK unwrap / KEK round-trip");

        // The rejection must not have touched the envelope: the original (version-1) copy
        // sharing the same ciphertext/nonce arrays still decrypts.
        byte[] decrypted = await encryptor.DecryptAsync(envelope);
        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public async Task Decrypt_LegacyEnvelopeWithoutExplicitVersion_StillDecrypts()
    {
        // Backward compatibility: consumers that persisted envelopes field-by-field before
        // FormatVersion existed reconstruct them with the original four positional
        // arguments. The constructor defaults FormatVersion to CurrentFormatVersion (1),
        // which is exactly the format those envelopes were produced under.
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("legacy envelope");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        EncryptedPayload legacy = new(envelope.Ciphertext, envelope.Nonce, envelope.WrappedDek, envelope.KeyId);

        legacy.FormatVersion.Should().Be(EncryptedPayload.CurrentFormatVersion);
        byte[] decrypted = await encryptor.DecryptAsync(legacy);
        decrypted.Should().Equal(plaintext);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    public async Task Encrypt_DekManagerReturnsShortDek_ThrowsAndPreservesAes256Contract(int dekBytesLength)
    {
        // H-1 symmetry (encrypt side): AesGcm accepts 16/24/32-byte keys, so a buggy
        // IDekManager returning a short DEK would silently downgrade NEW envelopes to
        // AES-128/192. PayloadEncryptor must reject anything that is not 32 bytes.
        FixedDekManager dekManager = new(dekBytesLength);
        PayloadEncryptor encryptor = new(
            dekManager,
            new CountingRandomBytesProvider(),
            NullLogger<PayloadEncryptor>.Instance);

        Func<Task> act = async () => await encryptor.EncryptAsync(
            Encoding.UTF8.GetBytes("downgrade check"),
            Scope);

        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage("*expected 32 bytes*");
    }

    [Fact]
    public async Task Encrypt_DekManagerReturns32ByteDek_Succeeds()
    {
        // Companion to the anti-downgrade theory above: the same fake manager with a
        // 32-byte DEK passes the length gate and produces a valid envelope.
        FixedDekManager dekManager = new(dekBytesLength: 32);
        PayloadEncryptor encryptor = new(
            dekManager,
            new CountingRandomBytesProvider(),
            NullLogger<PayloadEncryptor>.Instance);

        byte[] plaintext = Encoding.UTF8.GetBytes("aes-256 ok");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        envelope.Ciphertext.Length.Should().Be(plaintext.Length + 16);
        envelope.FormatVersion.Should().Be(EncryptedPayload.CurrentFormatVersion);
    }

    [Fact]
    public async Task EncryptAsync_ConcurrentCalls_AllNoncesAreDistinct()
    {
        // L-5: nonce reuse in AES-GCM is the #1 catastrophic failure mode of the algorithm —
        // two messages with the same (key, nonce) pair leak the XOR of their plaintexts AND
        // allow forging arbitrary ciphertexts. The sequential test EncryptTwice_*_ProducesDifferentCiphertexts
        // proves the nonce generator works for back-to-back calls, but we also want a
        // high-concurrency stress test to catch any future refactor that introduces an
        // internal buffer reuse, a shared counter, or a race in the RNG path.

        (PayloadEncryptor encryptor, _, _) = BuildSut();

        // Warm the DEK cache so every task exercises the hot path and shares the same key
        // — this is the scenario we care about (maximum chance of nonce collision, since the
        // key is constant).
        byte[] plaintext = Encoding.UTF8.GetBytes("concurrent nonce stress test payload");
        _ = await encryptor.EncryptAsync(plaintext, Scope);

        const int iterations = 1000;
        Task<EncryptedPayload>[] tasks = new Task<EncryptedPayload>[iterations];
        for (int i = 0; i < iterations; i++)
        {
            tasks[i] = Task.Run(() => encryptor.EncryptAsync(plaintext, Scope));
        }

        EncryptedPayload[] envelopes = await Task.WhenAll(tasks);

        HashSet<string> uniqueNonces = envelopes
            .Select(e => Convert.ToBase64String(e.Nonce))
            .ToHashSet(StringComparer.Ordinal);

        uniqueNonces.Count.Should().Be(iterations,
            "nonce reuse in AES-GCM is catastrophic — every concurrent call must produce a fresh nonce");

        HashSet<string> uniqueCiphertexts = envelopes
            .Select(e => Convert.ToBase64String(e.Ciphertext))
            .ToHashSet(StringComparer.Ordinal);

        uniqueCiphertexts.Count.Should().Be(iterations,
            "distinct nonces over the same plaintext must yield distinct ciphertexts");
    }

    /// <summary>
    /// Minimal KEK provider whose <see cref="UnwrapAsync"/> returns a buffer of the
    /// configured length, regardless of what was wrapped. Used to prove that Vellum
    /// rejects short/long DEKs on the decrypt path.
    /// </summary>
    private sealed class ShortDekKeyEncryptionProvider(int dekBytesLength) : IKeyEncryptionProvider
    {
        public string ProviderName => "short-fake";

        public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default)
            => Task.FromResult(new WrappedKey("short:v1", "v1"));

        public Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
            => Task.FromResult(new byte[dekBytesLength]);
    }

    /// <summary>
    /// Minimal <see cref="IDekManager"/> whose <see cref="GetActiveDekAsync"/> returns a DEK
    /// of the configured length, bypassing the real DekManager's own length enforcement.
    /// Used to prove that <see cref="PayloadEncryptor"/> rejects short DEKs on the ENCRYPT
    /// path itself (anti-downgrade), independent of upstream guarantees. A fresh array is
    /// handed out per call because PayloadEncryptor zeroes the key in its finally block.
    /// </summary>
    private sealed class FixedDekManager(int dekBytesLength) : IDekManager
    {
        private static readonly WrappedKey _wrappedKey = new("fixed:v1", "v1");
        private static readonly Guid _keyId = Guid.NewGuid();

        public ValueTask<Dek> GetActiveDekAsync(string scope, CancellationToken cancellationToken = default)
        {
            byte[] key = new byte[dekBytesLength];
            RandomNumberGenerator.Fill(key);
            return ValueTask.FromResult(new Dek(key, _keyId, _wrappedKey));
        }

        public Task<Dek> CreateDekAsync(string scope, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Not used by these tests.");

        public Task RotateDekAsync(string scope, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Not used by these tests.");

        public ValueTask<Dek> GetDekByKeyIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Not used by these tests.");

        public ValueTask<Dek> GetDekByWrappedKeyAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Not used by these tests.");
    }
}
