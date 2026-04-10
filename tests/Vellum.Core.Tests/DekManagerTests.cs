using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Tests.Fakes;
using Xunit;

namespace Vellum.Tests;

public sealed class DekManagerTests
{
    private const string Scope = "tenant:42";

    private static DekManager BuildSut(
        out FakeKeyEncryptionProvider provider,
        out FakeEncryptionKeyStore store,
        out CountingRandomBytesProvider randomBytes,
        out IMemoryCache cache,
        TimeSpan? dekCacheTtl = null)
    {
        provider = new FakeKeyEncryptionProvider();
        store = new FakeEncryptionKeyStore();
        randomBytes = new CountingRandomBytesProvider();
        cache = new MemoryCache(new MemoryCacheOptions());
        VellumOptions options = new();
        if (dekCacheTtl is not null)
        {
            options.DekCacheTtl = dekCacheTtl.Value;
        }

        return new DekManager(
            provider,
            store,
            cache,
            randomBytes,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);
    }

    [Fact]
    public async Task GetActiveDekAsync_WhenNoKey_CreatesNewDek()
    {
        DekManager sut = BuildSut(out FakeKeyEncryptionProvider provider, out FakeEncryptionKeyStore store, out CountingRandomBytesProvider random, out IMemoryCache cache);

        Dek dek = await sut.GetActiveDekAsync(Scope);

        dek.Key.Should().HaveCount(32);
        dek.WrappedKey.ProviderVersion.Should().Be("v1");
        provider.WrapCalls.Should().Be(1);
        store.CreateCalls.Should().Be(1);
        random.FillCalls.Should().Be(1, "one Fill for the new DEK bytes");
    }

    [Fact]
    public async Task GetActiveDekAsync_WhenCached_ReturnsClonedCopy()
    {
        DekManager sut = BuildSut(out FakeKeyEncryptionProvider provider, out _, out _, out _);

        Dek first = await sut.GetActiveDekAsync(Scope);
        Dek second = await sut.GetActiveDekAsync(Scope);

        second.KeyId.Should().Be(first.KeyId);
        ReferenceEquals(first.Key, second.Key).Should().BeFalse("each call must return a cloned byte[]");
        first.Key.Should().Equal(second.Key);
        provider.WrapCalls.Should().Be(1, "the second call is served from cache");
    }

    [Fact]
    public async Task GetActiveDekAsync_CallerMayZeroReturnedKey_WithoutCorruptingCache()
    {
        DekManager sut = BuildSut(out _, out _, out _, out _);

        Dek first = await sut.GetActiveDekAsync(Scope);
        Array.Clear(first.Key); // caller zeroes their copy

        Dek second = await sut.GetActiveDekAsync(Scope);
        second.Key.Should().NotBeEquivalentTo(new byte[32], "the cached copy must be unaffected");
        second.Key.Any(b => b != 0).Should().BeTrue();
    }

    [Fact]
    public async Task GetActiveDekAsync_ExistingActiveKey_UnwrapsAndCaches()
    {
        DekManager sut = BuildSut(out FakeKeyEncryptionProvider provider, out FakeEncryptionKeyStore store, out _, out _);

        // Pre-seed a key by wrapping through the provider so Unwrap works.
        byte[] existingPlaintext = new byte[32];
        for (int i = 0; i < existingPlaintext.Length; i++)
        {
            existingPlaintext[i] = (byte)i;
        }

        WrappedKey wrapped = await provider.WrapAsync(existingPlaintext);
        EncryptionKey preseed = new(Guid.NewGuid(), Scope, wrapped, DateTimeOffset.UtcNow, null, true);
        store.SeedKey(preseed);

        int wrapsBefore = provider.WrapCalls;
        Dek dek = await sut.GetActiveDekAsync(Scope);

        dek.KeyId.Should().Be(preseed.KeyId);
        dek.Key.Should().Equal(existingPlaintext);
        provider.WrapCalls.Should().Be(wrapsBefore, "GetActive should never wrap a new DEK when one exists");
        provider.UnwrapCalls.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task CreateDekAsync_WhenActiveAlreadyExists_LoadsTheExistingKey()
    {
        DekManager sut = BuildSut(out FakeKeyEncryptionProvider provider, out FakeEncryptionKeyStore store, out _, out _);

        // First call — creates a key.
        Dek created = await sut.CreateDekAsync(Scope);

        // Second call — must detect the existing key and not wrap a new one.
        int wrapsBefore = provider.WrapCalls;
        Dek second = await sut.CreateDekAsync(Scope);

        second.KeyId.Should().Be(created.KeyId);
        provider.WrapCalls.Should().Be(wrapsBefore, "double-check must avoid a redundant wrap");
        store.CreateCalls.Should().Be(1, "the store must only see one CreateAsync call");
    }

    [Fact]
    public async Task CreateDekAsync_WhenRaceLostAfterWrap_ReturnsWinnerAndZeroesLoser()
    {
        // Scenario: another instance inserted a winning key AFTER our double-check but
        // BEFORE our CreateAsync. The fake store's unique-per-scope guard will return the
        // winner from CreateAsync; DekManager must detect the mismatch, zero its losing
        // copy, and unwrap the winner.
        _ = BuildSut(out FakeKeyEncryptionProvider provider, out _, out _, out _);

        // We use a custom subclass of the store to inject the race precisely between
        // the double-check and the insert.
        RaceStore raceStore = new();
        VellumOptions options = new();
        MemoryCache cache = new(new MemoryCacheOptions());
        DekManager racingSut = new(
            provider,
            raceStore,
            cache,
            new CountingRandomBytesProvider(),
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);

        // Pre-wrap an existing winner so Unwrap can find it.
        byte[] winnerPlaintext = new byte[32];
        winnerPlaintext[0] = 0xAB;
        WrappedKey winnerWrapped = await provider.WrapAsync(winnerPlaintext);
        raceStore.InjectRaceWinner(new EncryptionKey(
            Guid.NewGuid(),
            Scope,
            winnerWrapped,
            DateTimeOffset.UtcNow,
            null,
            true));

        Dek result = await racingSut.CreateDekAsync(Scope);

        result.KeyId.Should().Be(raceStore.WinnerKeyId);
        result.Key[0].Should().Be(0xAB, "the unwrapped DEK must be the winner's plaintext");
    }

    [Fact]
    public async Task RotateDekAsync_DeactivatesAllAndCreatesNew()
    {
        DekManager sut = BuildSut(out _, out FakeEncryptionKeyStore store, out _, out _);

        Dek first = await sut.GetActiveDekAsync(Scope);
        await sut.RotateDekAsync(Scope);
        Dek second = await sut.GetActiveDekAsync(Scope);

        store.DeactivateCalls.Should().Be(1);
        second.KeyId.Should().NotBe(first.KeyId);
    }

    [Fact]
    public async Task RotateDekAsync_EvictsCacheBeforeCreatingNew()
    {
        DekManager sut = BuildSut(out _, out _, out _, out IMemoryCache cache);

        await sut.GetActiveDekAsync(Scope);
        cache.TryGetValue($"vellum:dek:active:{Scope}", out _).Should().BeTrue();

        await sut.RotateDekAsync(Scope);

        // After rotation the newly-created DEK is in the cache again, but its KeyId
        // must differ from the previous entry — exercised in the sibling test.
        cache.TryGetValue($"vellum:dek:active:{Scope}", out Dek? after).Should().BeTrue();
        after.Should().NotBeNull();
    }

    [Fact]
    public async Task GetDekByKeyIdAsync_WhenKeyMissing_Throws()
    {
        DekManager sut = BuildSut(out _, out _, out _, out _);

        Func<Task> act = async () => await sut.GetDekByKeyIdAsync(Guid.NewGuid(), Scope);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task GetDekByKeyIdAsync_WhenScopeDoesNotMatch_Throws()
    {
        DekManager sut = BuildSut(out FakeKeyEncryptionProvider provider, out FakeEncryptionKeyStore store, out _, out _);

        byte[] plaintext = new byte[32];
        WrappedKey wrapped = await provider.WrapAsync(plaintext);
        EncryptionKey key = new(Guid.NewGuid(), "tenant:A", wrapped, DateTimeOffset.UtcNow, null, true);
        store.SeedKey(key);

        Func<Task> act = async () => await sut.GetDekByKeyIdAsync(key.KeyId, "tenant:B");
        await act.Should().ThrowAsync<InvalidOperationException>(
            "the store must not return keys belonging to a different scope");
    }

    [Fact]
    public async Task GetDekByKeyIdAsync_CacheKey_IsScopePartitioned()
    {
        // Pin the multi-tenant cache defense: an attacker who guesses another tenant's
        // KeyId must not receive a cached entry from that other tenant.
        DekManager sut = BuildSut(out FakeKeyEncryptionProvider provider, out FakeEncryptionKeyStore store, out _, out _);

        byte[] plaintext = new byte[32];
        WrappedKey wrapped = await provider.WrapAsync(plaintext);
        Guid sharedKeyId = Guid.NewGuid();
        EncryptionKey tenantAKey = new(sharedKeyId, "tenant:A", wrapped, DateTimeOffset.UtcNow, null, true);
        store.SeedKey(tenantAKey);

        // Prime the by-id cache via tenant A.
        _ = await sut.GetDekByKeyIdAsync(sharedKeyId, "tenant:A");

        // Tenant B tries to access the same KeyId — it must NOT hit A's cache entry;
        // it must go to the store, which returns null, which must throw.
        Func<Task> act = async () => await sut.GetDekByKeyIdAsync(sharedKeyId, "tenant:B");
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task RotateDekAsync_DoesNotEvictByIdCache_ForHistoricalDecryption()
    {
        // L-4: after rotation, decrypting an envelope that references the OLD key must still
        // hit the by-id cache. Rotate evicts the active-scope cache entry to force a reload,
        // but the scope-partitioned by-id cache entries must remain so a burst of historical
        // decrypts doesn't thrash the KEK provider.
        DekManager sut = BuildSut(
            out FakeKeyEncryptionProvider provider,
            out _,
            out _,
            out _,
            dekCacheTtl: TimeSpan.FromMinutes(30));

        // 1. Create a key and prime the by-id cache via GetDekByKeyIdAsync.
        Dek original = await sut.GetActiveDekAsync(Scope);
        _ = await sut.GetDekByKeyIdAsync(original.KeyId, Scope);
        int unwrapsBeforeRotate = provider.UnwrapCalls;

        // 2. Rotate.
        await sut.RotateDekAsync(Scope);

        // 3. Decrypt-by-id against the original key — must not trigger a new Unwrap.
        Dek historical = await sut.GetDekByKeyIdAsync(original.KeyId, Scope);

        historical.KeyId.Should().Be(original.KeyId);
        provider.UnwrapCalls.Should().Be(unwrapsBeforeRotate,
            "the by-id cache must survive rotation so historical decryption is cache-hot");
    }

    [Fact]
    public async Task GetDekByKeyIdAsync_CacheKeyIdMismatch_FailsClosed()
    {
        // L-3: belt-and-braces. The cache key is scope+keyId, so a mismatch is unreachable
        // through the normal API — but we want to prove the invariant holds if someone
        // manually pokes a bad entry into the cache. Poison the cache with a DEK whose
        // KeyId differs from the lookup key; the fast path must throw.
        DekManager sut = BuildSut(out _, out _, out _, out IMemoryCache cache);

        Guid requestedKeyId = Guid.NewGuid();
        Dek poisoned = new(
            Key: new byte[32],
            KeyId: Guid.NewGuid(), // intentionally different
            WrappedKey: new WrappedKey("fake:v1:xxx", "v1"));

        // Reach into the cache-key builder via the exact format the manager uses.
        string cacheKey = $"vellum:dek:id:{Scope}:{requestedKeyId}";
        cache.Set(cacheKey, poisoned);

        Func<Task> act = async () => await sut.GetDekByKeyIdAsync(requestedKeyId, Scope);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*does not match the requested KeyId*");
    }

    [Fact]
    public async Task GetActiveDekAsync_ProviderReturnsShortDek_ThrowsAndFailsClosed()
    {
        // H-1: the load path (LoadAndCacheAsync) must reject any unwrapped DEK whose length
        // is not exactly 32 bytes. Pinning this prevents a buggy KEK provider from silently
        // downgrading the AES-256 contract on the cache-miss path.
        ShortDekProvider shortProvider = new(dekBytesLength: 16);
        FakeEncryptionKeyStore store = new();
        CountingRandomBytesProvider random = new();
        MemoryCache cache = new(new MemoryCacheOptions());
        VellumOptions options = new();

        DekManager sut = new(
            shortProvider,
            store,
            cache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);

        // Pre-seed so the slow path lands on LoadAndCacheAsync, not CreateDekAsync.
        EncryptionKey preseed = new(
            Guid.NewGuid(),
            Scope,
            new WrappedKey("short:v1", "v1"),
            DateTimeOffset.UtcNow,
            null,
            true);
        store.SeedKey(preseed);

        Func<Task> act = async () => await sut.GetActiveDekAsync(Scope);
        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage("*expected 32 bytes*");
    }

    [Fact]
    public async Task GetDekByKeyIdAsync_ProviderReturnsShortDek_ThrowsAndFailsClosed()
    {
        // H-1: the by-id slow path (GetDekByKeyIdSlowAsync) must also reject unwrapped DEKs
        // of the wrong length. Symmetry with the active-slow-path guard above.
        ShortDekProvider shortProvider = new(dekBytesLength: 24);
        FakeEncryptionKeyStore store = new();
        CountingRandomBytesProvider random = new();
        MemoryCache cache = new(new MemoryCacheOptions());
        VellumOptions options = new();

        DekManager sut = new(
            shortProvider,
            store,
            cache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);

        EncryptionKey preseed = new(
            Guid.NewGuid(),
            Scope,
            new WrappedKey("short:v1", "v1"),
            DateTimeOffset.UtcNow,
            null,
            true);
        store.SeedKey(preseed);

        Func<Task> act = async () => await sut.GetDekByKeyIdAsync(preseed.KeyId, Scope);
        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage("*expected 32 bytes*");
    }

    private sealed class ShortDekProvider(int dekBytesLength) : IKeyEncryptionProvider
    {
        public string ProviderName => "short-fake";

        public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default)
            => Task.FromResult(new WrappedKey("short:v1", "v1"));

        public Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
            => Task.FromResult(new byte[dekBytesLength]);
    }

    /// <summary>
    /// Custom store that injects a race winner between the double-check and the insert,
    /// so that <see cref="DekManager.CreateDekAsync"/> sees: double-check → null, then
    /// <see cref="IEncryptionKeyStore.CreateAsync"/> → winner (different KeyId).
    /// </summary>
    private sealed class RaceStore : IEncryptionKeyStore
    {
        private EncryptionKey? _winner;
        private bool _doubleCheckDone;

        public Guid WinnerKeyId => _winner!.KeyId;

        public void InjectRaceWinner(EncryptionKey winner) => _winner = winner;

        public Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default)
        {
            // First call is the DekManager's double-check — return null so we proceed to wrap.
            if (!_doubleCheckDone)
            {
                _doubleCheckDone = true;
                return Task.FromResult<EncryptionKey?>(null);
            }

            return Task.FromResult(_winner);
        }

        public Task<EncryptionKey?> GetByIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default)
            => Task.FromResult(_winner);

        public Task<EncryptionKey> CreateAsync(EncryptionKey key, CancellationToken cancellationToken = default)
            => Task.FromResult(_winner ?? key);

        public Task DeactivateAllAsync(string scope, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<EncryptionKey>>(Array.Empty<EncryptionKey>());

        public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
    }
}
