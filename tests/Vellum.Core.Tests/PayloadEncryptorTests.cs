using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Tests.Fakes;
using Xunit;

namespace Vellum.Tests;

public sealed class PayloadEncryptorTests
{
    private const string Scope = "tenant:42";

    private static (PayloadEncryptor Encryptor, FakeKeyEncryptionProvider Provider, DekManager DekManager)
        BuildSut(TimeSpan? dekCacheTtl = null, bool bindScopeToCiphertext = true)
    {
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();
        CountingRandomBytesProvider random = new();
        VellumDekCache cache = new();
        VellumOptions options = new()
        {
            BindScopeToCiphertext = bindScopeToCiphertext,
        };
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
            Options.Create(options),
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
        byte[] decrypted = await encryptor.DecryptAsync(envelope, Scope);

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
        byte[] decrypted = await encryptor.DecryptAsync(envelope, Scope);

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

        Func<Task> act = async () => await encryptor.DecryptAsync(envelope, Scope);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_TamperedNonce_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("swap the nonce");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        envelope.Nonce[0] ^= 0xFF;

        Func<Task> act = async () => await encryptor.DecryptAsync(envelope, Scope);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_NonceOfWrongLength_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("short nonce");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        EncryptedPayload malformed = envelope with { Nonce = new byte[8] };

        Func<Task> act = async () => await encryptor.DecryptAsync(malformed, Scope);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_CiphertextShorterThanTag_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("tag check");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        EncryptedPayload malformed = envelope with { Ciphertext = new byte[8] };

        Func<Task> act = async () => await encryptor.DecryptAsync(malformed, Scope);
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

        byte[] decrypted = await encryptor.DecryptAsync(envelope, Scope);
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
        _ = await encryptor.DecryptAsync(envelope, Scope);
        _ = await encryptor.DecryptAsync(envelope, Scope);

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
        _ = await encryptor.DecryptAsync(envelopeA, scope: "tenant:a");

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
        _ = await encryptor.DecryptAsync(envelopeB, scope: "tenant:a");
        provider.UnwrapCalls.Should().Be(unwrapsBefore + 1,
            "a different wrapped key must miss the cache and trigger its own Unwrap");

        // And decrypting envelopeA a second time should still be a cache hit.
        int unwrapsAfter = provider.UnwrapCalls;
        _ = await encryptor.DecryptAsync(envelopeA, scope: "tenant:a");
        provider.UnwrapCalls.Should().Be(unwrapsAfter,
            "envelopeA's wrapped key must still be cache-hot after envelopeB's decrypt");
    }

    [Fact]
    public async Task StringConvenience_Roundtrip()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        EncryptedPayload envelope = await encryptor.EncryptStringAsync("Hé, Vellum!", Scope);
        string decrypted = await encryptor.DecryptStringAsync(envelope, Scope);

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
        VellumDekCache cache = new();
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
            Options.Create(options),
            NullLogger<PayloadEncryptor>.Instance);

        byte[] plaintext = Encoding.UTF8.GetBytes("downgrade check");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        // Rebuild a decrypt-only stack whose KEK provider returns 16 bytes instead of 32.
        // The DekManager under test is fresh (no cache primed for envelope.WrappedDek), so
        // the first DecryptAsync goes through the slow path and hits EnsureDekLength.
        ShortDekKeyEncryptionProvider shortProvider = new(dekBytesLength: 16);
        VellumDekCache freshCache = new();
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
            Options.Create(options),
            NullLogger<PayloadEncryptor>.Instance);

        Func<Task> act = async () => await decryptOnly.DecryptAsync(envelope, Scope);
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
        envelope.FormatVersion.Should().Be(EncryptedPayload.ScopeBoundFormatVersion,
            "scope binding is on by default, so fresh envelopes are format version 2");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(99)]
    public async Task Decrypt_UnsupportedFormatVersion_FailsClosedBeforeAnyCryptoWork(int unsupportedVersion)
    {
        // C-2: an unknown format version must be rejected BEFORE any crypto work — no DEK
        // unwrap, no KEK round-trip, no AES-GCM call. Interpreting a future format's bytes
        // under a known-version layout would be undefined behavior.
        (PayloadEncryptor encryptor, FakeKeyEncryptionProvider provider, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("unknown version");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        EncryptedPayload futuristic = envelope with { FormatVersion = unsupportedVersion };

        int unwrapsBefore = provider.UnwrapCalls;
        Func<Task> act = async () => await encryptor.DecryptAsync(futuristic, Scope);

        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage($"*format version {unsupportedVersion}*");
        provider.UnwrapCalls.Should().Be(unwrapsBefore,
            "version validation must fire before any DEK unwrap / KEK round-trip");

        // The rejection must not have touched the envelope: the original copy sharing the
        // same ciphertext/nonce arrays still decrypts.
        byte[] decrypted = await encryptor.DecryptAsync(envelope, Scope);
        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public async Task Decrypt_LegacyEnvelopeWithoutExplicitVersion_StillDecrypts()
    {
        // Backward compatibility: consumers that persisted envelopes field-by-field before
        // FormatVersion existed reconstruct them with the original four positional
        // arguments. The constructor defaults FormatVersion to UnboundFormatVersion (1),
        // which is exactly the format those envelopes were produced under (0.1.x had no
        // AAD). Encrypt with binding disabled to simulate a 0.1.x-era envelope.
        (PayloadEncryptor legacyProducer, _, _) = BuildSut(bindScopeToCiphertext: false);

        byte[] plaintext = Encoding.UTF8.GetBytes("legacy envelope");
        EncryptedPayload envelope = await legacyProducer.EncryptAsync(plaintext, Scope);
        envelope.FormatVersion.Should().Be(EncryptedPayload.UnboundFormatVersion);

        EncryptedPayload legacy = new(envelope.Ciphertext, envelope.Nonce, envelope.WrappedDek, envelope.KeyId);

        legacy.FormatVersion.Should().Be(EncryptedPayload.UnboundFormatVersion);
        byte[] decrypted = await legacyProducer.DecryptAsync(legacy, Scope);
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
            Options.Create(new VellumOptions()),
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
            Options.Create(new VellumOptions()),
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

    // -----------------------------------------------------------------------------------
    // M-B: scope binding via AES-GCM associated data (format version 2).
    // -----------------------------------------------------------------------------------

    [Fact]
    public async Task EncryptDecrypt_V2RoundTrip_SameScope_Succeeds()
    {
        // F3-1: the happy path of scope binding. Encrypt under scope S, decrypt under the
        // same scope S — and the envelope self-describes as format version 2.
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("scope-bound payload");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        envelope.FormatVersion.Should().Be(EncryptedPayload.ScopeBoundFormatVersion);

        byte[] decrypted = await encryptor.DecryptAsync(envelope, Scope);
        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public async Task Decrypt_V2EnvelopeMovedToAnotherScope_ThrowsGcmAuthFailure()
    {
        // F3-2 (the M-B attack): an envelope encrypted for tenant A, copied verbatim into
        // tenant B's records, must NOT decrypt when presented under tenant B's scope. The
        // AAD mismatch fails the AES-GCM authentication tag check — that is the
        // cryptographic guarantee, with no extra equality check in Vellum code.
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("tenant A's secret");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, scope: "tenant:a");

        Func<Task> act = async () => await encryptor.DecryptAsync(envelope, scope: "tenant:b");
        await act.Should().ThrowAsync<CryptographicException>();

        // Sanity: the same envelope still decrypts under its own scope.
        byte[] decrypted = await encryptor.DecryptAsync(envelope, scope: "tenant:a");
        decrypted.Should().Equal(plaintext);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Decrypt_V2EnvelopeWithMissingScope_FailsClosedBeforeAnyUnwrap(string? missingScope)
    {
        // F3-3: a version 2 envelope without a scope can never pass the tag check, so the
        // rejection must fire BEFORE any DEK unwrap / KEK round-trip (fail closed, no
        // wasted KEK call). Use a cold cache (TTL <= 0 disables caching) so a successful
        // unwrap would be observable on the fake provider.
        (PayloadEncryptor encryptor, FakeKeyEncryptionProvider provider, _) = BuildSut(
            dekCacheTtl: TimeSpan.Zero);

        EncryptedPayload envelope = await encryptor.EncryptAsync(
            Encoding.UTF8.GetBytes("needs a scope"),
            Scope);

        int unwrapsBefore = provider.UnwrapCalls;
        Func<Task> act = async () => await encryptor.DecryptAsync(envelope, missingScope!);

        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage("*Scope is required for format version 2*");
        provider.UnwrapCalls.Should().Be(unwrapsBefore,
            "the scope-required check must fire before any DEK unwrap / KEK round-trip");
    }

    [Fact]
    public async Task Decrypt_V1Envelope_DecryptsRegardlessOfScopeArgument()
    {
        // F3-4: legacy version 1 envelopes carry NO scope binding — they decrypt under any
        // scope argument, including empty. This is the documented legacy-compat trade-off.
        (PayloadEncryptor encryptor, _, _) = BuildSut(bindScopeToCiphertext: false);

        byte[] plaintext = Encoding.UTF8.GetBytes("unbound legacy payload");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, scope: "tenant:a");

        envelope.FormatVersion.Should().Be(EncryptedPayload.UnboundFormatVersion);

        (await encryptor.DecryptAsync(envelope, scope: "tenant:a")).Should().Equal(plaintext);
        (await encryptor.DecryptAsync(envelope, scope: "tenant:b")).Should().Equal(plaintext);
        (await encryptor.DecryptAsync(envelope, scope: string.Empty)).Should().Equal(plaintext);
    }

    [Fact]
    public async Task Encrypt_BindScopeToCiphertextDisabled_ProducesV1EnvelopeWithoutAad()
    {
        // F3-5: the opt-out. BindScopeToCiphertext=false produces version 1 envelopes (no
        // AAD) for consumers who cannot supply the scope at decrypt time — and a default
        // (binding-enabled) decryptor still honors the envelope's own version and decrypts
        // it without requiring the original scope.
        (PayloadEncryptor unboundProducer, _, _) = BuildSut(bindScopeToCiphertext: false);

        byte[] plaintext = Encoding.UTF8.GetBytes("opt-out payload");
        EncryptedPayload envelope = await unboundProducer.EncryptAsync(plaintext, Scope);

        envelope.FormatVersion.Should().Be(EncryptedPayload.UnboundFormatVersion,
            "the opt-out must be visible in the envelope's self-described format version");

        byte[] decrypted = await unboundProducer.DecryptAsync(envelope, scope: "some:other:scope");
        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public async Task Decrypt_V2EnvelopeWithTamperedScope_Throws()
    {
        // F3-6: tampered-scope simulation — even a single trailing character appended to
        // the correct scope produces different AAD bytes and must fail the tag check.
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        EncryptedPayload envelope = await encryptor.EncryptAsync(
            Encoding.UTF8.GetBytes("exact scope required"),
            Scope);

        Func<Task> act = async () => await encryptor.DecryptAsync(envelope, Scope + "x");
        await act.Should().ThrowAsync<CryptographicException>();
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
