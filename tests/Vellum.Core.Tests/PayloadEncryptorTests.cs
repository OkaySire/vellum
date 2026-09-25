using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using FluentAssertions.Specialized;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Tests.Fakes;
using Xunit;

namespace Vellum.Tests;

[Collection("PayloadDecryptMetrics")]
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
            provider,
            random,
            Options.Create(options),
            NullLogger<PayloadEncryptor>.Instance);

        return (encryptor, provider, dekManager);
    }

    /// <summary>
    /// Builds an encryptor over caller-supplied collaborators, so a test can simulate a fresh
    /// process reading an existing row: same store and same KEK provider, but a COLD
    /// <see cref="VellumDekCache"/>. Needed since 0.4.0, because decrypt resolves the DEK by
    /// <see cref="EncryptedPayload.KeyId"/> and the encrypt leaves that very entry cache-hot —
    /// reusing one cache would make every decrypt free and hide the round-trip under test.
    /// </summary>
    private static PayloadEncryptor BuildEncryptorOver(
        FakeKeyEncryptionProvider provider,
        FakeEncryptionKeyStore store,
        VellumDekCache cache,
        TimeSpan? dekCacheTtl = null)
    {
        CountingRandomBytesProvider random = new();
        VellumOptions options = new();
        if (dekCacheTtl is not null)
        {
            options.DekCacheTtl = dekCacheTtl.Value;
        }

        DekManager manager = new(
            provider,
            store,
            cache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);

        return new PayloadEncryptor(
            manager,
            provider,
            random,
            Options.Create(options),
            NullLogger<PayloadEncryptor>.Instance);
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
    public async Task Decrypt_SelfContained_SucceedsWithAStoreThatCannotServeTheKey()
    {
        // The self-contained envelope contract (C3), restated for 0.4.0. C3 guarantees that an
        // envelope carries everything needed to decrypt it; it does NOT say the store is left alone
        // — since 0.4.0 decrypt asks IEncryptionKeyStore by KeyId FIRST and only then reads the
        // envelope's own WrappedKey. So the guarantee is tested the only way it still can be: the
        // reader is handed a store that has never heard of this KeyId, and the decrypt must still
        // succeed off the envelope copy.
        //
        // (Until this rename the test was Decrypt_SelfContained_UsesOwnEnvelopeNotStoreLookup and
        // claimed "never back to IEncryptionKeyStore" — the opposite of the 0.4.0 order. It passed
        // only because the single store present happened to serve the key, i.e. through the path it
        // asserted was not taken.)
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore writeStore = new();
        byte[] plaintext = Encoding.UTF8.GetBytes("self contained");

        EncryptedPayload envelope;
        using (VellumDekCache writeCache = new())
        {
            PayloadEncryptor writer = BuildEncryptorOver(provider, writeStore, writeCache);
            envelope = await writer.EncryptAsync(plaintext, Scope);
        }

        // A different store, empty: the lookup by KeyId can only come back with nothing.
        FakeEncryptionKeyStore storelessReader = new();
        using VellumDekCache readCache = new();
        PayloadEncryptor reader = BuildEncryptorOver(provider, storelessReader, readCache);

        long attemptsBefore = VellumDecryptMetrics.FallbackAttemptsTotal;
        long recoveredBefore = VellumDecryptMetrics.FallbackRecoveredTotal;

        byte[] decrypted = await reader.DecryptAsync(envelope, Scope);

        decrypted.Should().Equal(plaintext);
        VellumDecryptMetrics.FallbackAttemptsTotal.Should().Be(
            attemptsBefore + 1,
            "the store WAS consulted first and could not serve the key");
        VellumDecryptMetrics.FallbackRecoveredTotal.Should().Be(
            recoveredBefore + 1,
            "the envelope's own copy is what decrypted the payload");
    }

    [Fact]
    public async Task DecryptAsync_CachesUnwrappedDek_OnSecondCall()
    {
        // Issue #6, restated for the 0.4.0 resolution order: two DecryptAsync calls on the same
        // envelope must trigger exactly ONE IKeyEncryptionProvider.UnwrapAsync. Decrypt now
        // resolves the DEK by KeyId through the store, so the cache entry that has to absorb the
        // second call is the by-id one — and the read must start from a COLD cache, otherwise the
        // entry the encrypt left behind makes both decrypts free and the test proves nothing.
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();
        byte[] plaintext = Encoding.UTF8.GetBytes("cached decrypt payload");

        EncryptedPayload envelope;
        using (VellumDekCache writeCache = new())
        {
            PayloadEncryptor writer = BuildEncryptorOver(provider, store, writeCache, TimeSpan.FromMinutes(30));
            envelope = await writer.EncryptAsync(plaintext, Scope);
        }

        using VellumDekCache readCache = new();
        PayloadEncryptor reader = BuildEncryptorOver(provider, store, readCache, TimeSpan.FromMinutes(30));

        int unwrapsBefore = provider.UnwrapCalls;
        (await reader.DecryptAsync(envelope, Scope)).Should().Equal(plaintext);
        (await reader.DecryptAsync(envelope, Scope)).Should().Equal(plaintext);

        provider.UnwrapCalls.Should().Be(unwrapsBefore + 1,
            "the second decrypt must hit the by-id cache and avoid a second KEK round-trip");
    }

    [Fact]
    public async Task DecryptAsync_ByIdCacheHotFromEncrypt_CostsNoKekRoundTrip()
    {
        // 0.4.0 side effect worth pinning: EncryptAsync caches the active DEK under BOTH the
        // active-scope key and the by-id key, and decrypt now looks up by id — so a decrypt that
        // follows its own encrypt in the same process pays no KEK round-trip at all. In 0.3.x it
        // paid one, because the wrapped-ciphertext cache key had never been populated.
        (PayloadEncryptor encryptor, FakeKeyEncryptionProvider provider, _) = BuildSut(
            dekCacheTtl: TimeSpan.FromMinutes(30));

        byte[] plaintext = Encoding.UTF8.GetBytes("no round-trip at all");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        int unwrapsBefore = provider.UnwrapCalls;
        (await encryptor.DecryptAsync(envelope, Scope)).Should().Equal(plaintext);

        provider.UnwrapCalls.Should().Be(unwrapsBefore,
            "the encrypt already cached this DEK under its by-id key, which is the key decrypt now looks up");
    }

    [Fact]
    public async Task DecryptAsync_TwoDistinctKeys_UnwrapBoth()
    {
        // 0.4.0 restatement of the Issue #6 partitioning guarantee at the encryptor level: the
        // decrypt cache is partitioned per resolved key, so two envelopes written under two
        // DIFFERENT DEKs each cost their own Unwrap, and neither serves the other. The cache-key
        // derivation itself (SHA-256 of the wrapped ciphertext for the fallback path, scope+id for
        // the store path) is pinned in DekManagerTests; what is asserted here is that decrypting
        // through PayloadEncryptor never mixes two keys up.
        const string ScopeA = "tenant:a";
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();

        EncryptedPayload envelopeA;
        EncryptedPayload envelopeB;
        using (VellumDekCache writeCache = new())
        {
            CountingRandomBytesProvider random = new();
            VellumOptions writeOptions = new() { DekCacheTtl = TimeSpan.FromMinutes(30) };
            DekManager writeManager = new(
                provider,
                store,
                writeCache,
                random,
                TimeProvider.System,
                Options.Create(writeOptions),
                NullLogger<DekManager>.Instance);
            PayloadEncryptor writer = new(
                writeManager,
                provider,
                random,
                Options.Create(writeOptions),
                NullLogger<PayloadEncryptor>.Instance);

            envelopeA = await writer.EncryptAsync(Encoding.UTF8.GetBytes("payload-a"), ScopeA);

            // Rotation gives scope A a second DEK, so envelopeB carries a different KeyId AND a
            // different wrapped ciphertext.
            await writeManager.RotateDekAsync(ScopeA);
            envelopeB = await writer.EncryptAsync(Encoding.UTF8.GetBytes("payload-b"), ScopeA);
        }

        envelopeB.KeyId.Should().NotBe(envelopeA.KeyId, "rotation must produce a fresh DEK record");
        envelopeB.WrappedDek.Should().NotBe(envelopeA.WrappedDek,
            "rotation must produce a fresh DEK and therefore a fresh wrapped ciphertext");

        // Cold cache: a fresh process reading both rows.
        using VellumDekCache readCache = new();
        PayloadEncryptor reader = BuildEncryptorOver(provider, store, readCache, TimeSpan.FromMinutes(30));

        int unwrapsBefore = provider.UnwrapCalls;
        (await reader.DecryptAsync(envelopeA, ScopeA)).Should().Equal(Encoding.UTF8.GetBytes("payload-a"));
        provider.UnwrapCalls.Should().Be(unwrapsBefore + 1, "the first key is a cache miss");

        (await reader.DecryptAsync(envelopeB, ScopeA)).Should().Equal(Encoding.UTF8.GetBytes("payload-b"));
        provider.UnwrapCalls.Should().Be(unwrapsBefore + 2,
            "a different key must miss the cache and trigger its own Unwrap, not reuse the first one");

        // And both stay cache-hot afterwards, independently of one another.
        int unwrapsAfter = provider.UnwrapCalls;
        (await reader.DecryptAsync(envelopeA, ScopeA)).Should().Equal(Encoding.UTF8.GetBytes("payload-a"));
        (await reader.DecryptAsync(envelopeB, ScopeA)).Should().Equal(Encoding.UTF8.GetBytes("payload-b"));
        provider.UnwrapCalls.Should().Be(unwrapsAfter,
            "each key keeps its own live cache entry after the other one has been decrypted");
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
            realProvider,
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
            shortProvider,
            random,
            Options.Create(options),
            NullLogger<PayloadEncryptor>.Instance);

        // Both resolution paths hit the same short-DEK provider, so both fail and the raised
        // message names only the two failure TYPES (M1: it may be echoed to an untrusted caller).
        // The AES-256 contract wording is therefore asserted on the causes, where it now lives.
        Func<Task> act = async () => await decryptOnly.DecryptAsync(envelope, Scope);
        ExceptionAssertions<CryptographicException> thrown = await act.Should().ThrowAsync<CryptographicException>();

        AggregateException? causes = thrown.Which.InnerException as AggregateException;
        causes.Should().NotBeNull();
        causes!.InnerExceptions.Should().AllSatisfy(cause =>
            cause.Message.Should().Contain("expected 32 bytes", "the AES-256 length contract is what failed closed"));
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
            new FakeKeyEncryptionProvider(),
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
            new FakeKeyEncryptionProvider(),
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

    // ---------------------------------------------------------------------
    // RewrapPayloadAsync (H3 — envelope-level KEK rewrap)
    // ---------------------------------------------------------------------

    [Fact]
    public async Task RewrapPayloadAsync_OnlyWrappedDekChanges_AndEnvelopeDecryptsIdentically()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("rewrap me");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        EncryptedPayload rewrapped = await encryptor.RewrapPayloadAsync(envelope);

        // The DEK plaintext is untouched by the rewrap, so the AES-GCM payload fields are
        // carried over verbatim — only the wrapped DEK differs.
        rewrapped.WrappedDek.Should().NotBe(envelope.WrappedDek);
        rewrapped.Ciphertext.Should().BeSameAs(envelope.Ciphertext);
        rewrapped.Nonce.Should().BeSameAs(envelope.Nonce);
        rewrapped.KeyId.Should().Be(envelope.KeyId);
        rewrapped.FormatVersion.Should().Be(envelope.FormatVersion);

        byte[] decrypted = await encryptor.DecryptAsync(rewrapped, Scope);
        decrypted.Should().Equal(plaintext, "the rewrapped envelope must decrypt to the same plaintext");
    }

    [Fact]
    public async Task RewrapPayloadAsync_UpdatesProviderVersion()
    {
        (PayloadEncryptor encryptor, FakeKeyEncryptionProvider provider, _) = BuildSut();

        EncryptedPayload envelope = await encryptor.EncryptAsync(
            Encoding.UTF8.GetBytes("version bump"),
            Scope);
        envelope.WrappedDek.ProviderVersion.Should().Be("v1");

        EncryptedPayload rewrapped = await encryptor.RewrapPayloadAsync(envelope);

        rewrapped.WrappedDek.ProviderVersion.Should().Be("v2",
            "the fake provider rewraps under the current KEK version");
        provider.RewrapCalls.Should().Be(1);
    }

    [Fact]
    public async Task RewrapPayloadAsync_NullPayload_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        Func<Task> act = async () => await encryptor.RewrapPayloadAsync(null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task RewrapPayloadAsync_ProviderFails_FailsClosed()
    {
        (PayloadEncryptor encryptor, FakeKeyEncryptionProvider provider, _) = BuildSut();

        EncryptedPayload envelope = await encryptor.EncryptAsync(
            Encoding.UTF8.GetBytes("fail closed"),
            Scope);
        provider.FailRewrapHandles.Add(envelope.WrappedDek.Ciphertext);

        Func<Task> act = async () => await encryptor.RewrapPayloadAsync(envelope);

        await act.Should().ThrowAsync<InvalidOperationException>(
            "a failed rewrap must throw — the original envelope is never returned as if it had been rewrapped");
    }

    [Fact]
    public async Task RewrapPayloadAsync_CacheInteraction_BothOldAndNewEnvelopesDecrypt()
    {
        // L24 restated for 0.4.0: rewrapping an envelope changes only EncryptedPayload.WrappedDek,
        // and decrypt resolves by KeyId — which the rewrap carries over verbatim. So the rewrapped
        // envelope no longer forces a cache miss the way it did in 0.3.x (where the cache key was
        // the SHA-256 of the wrapped ciphertext, and a new ciphertext meant a new key). Both
        // envelopes decrypt, and they share a single resolution and a single cache entry.
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();
        byte[] plaintext = Encoding.UTF8.GetBytes("cache interaction");

        EncryptedPayload oldEnvelope;
        using (VellumDekCache writeCache = new())
        {
            PayloadEncryptor writer = BuildEncryptorOver(provider, store, writeCache);
            oldEnvelope = await writer.EncryptAsync(plaintext, Scope);
        }

        // Cold cache: a fresh process reading the row.
        using VellumDekCache readCache = new();
        PayloadEncryptor encryptor = BuildEncryptorOver(provider, store, readCache);

        int unwrapsBefore = provider.UnwrapCalls;
        (await encryptor.DecryptAsync(oldEnvelope, Scope)).Should().Equal(plaintext);
        provider.UnwrapCalls.Should().Be(unwrapsBefore + 1, "cold cache: the store record is unwrapped once");
        int unwrapsAfterPrime = provider.UnwrapCalls;

        EncryptedPayload newEnvelope = await encryptor.RewrapPayloadAsync(oldEnvelope);
        newEnvelope.WrappedDek.Should().NotBe(oldEnvelope.WrappedDek, "the rewrap must produce a fresh ciphertext");
        newEnvelope.KeyId.Should().Be(oldEnvelope.KeyId, "the rewrap carries the KeyId over verbatim");

        // 1) The NEW envelope decrypts with NO extra unwrap: same KeyId, same live cache entry.
        (await encryptor.DecryptAsync(newEnvelope, Scope)).Should().Equal(plaintext);
        provider.UnwrapCalls.Should().Be(unwrapsAfterPrime,
            "the rewrapped envelope resolves through the same KeyId, so it no longer costs a cache miss");

        // 2) The OLD envelope still decrypts too — the rewrap invalidates nothing.
        (await encryptor.DecryptAsync(oldEnvelope, Scope)).Should().Equal(plaintext);
        provider.UnwrapCalls.Should().Be(unwrapsAfterPrime,
            "the rewrap touched neither the store record nor the cache entry the old envelope resolves to");
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

        public Task<WrappedKey> RewrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Not used by these tests.");
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
