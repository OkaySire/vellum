using System.Security.Cryptography;
using FluentAssertions;
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
        out VellumDekCache cache,
        TimeSpan? dekCacheTtl = null)
    {
        provider = new FakeKeyEncryptionProvider();
        store = new FakeEncryptionKeyStore();
        randomBytes = new CountingRandomBytesProvider();
        cache = new VellumDekCache();
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
        DekManager sut = BuildSut(out FakeKeyEncryptionProvider provider, out FakeEncryptionKeyStore store, out CountingRandomBytesProvider random, out VellumDekCache cache);

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
        VellumDekCache cache = new();
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
    public async Task RotateDekAsync_AtomicallySwapsViaStoreRotate()
    {
        // A1/A2: rotation pins the NEW fail-safe order — a single atomic store.RotateAsync
        // (deactivate-old + insert-new in one transaction), never the old two-step
        // DeactivateAllAsync-then-CreateAsync sequence that could leave the scope with zero
        // active keys when the KEK provider failed in between.
        DekManager sut = BuildSut(out _, out FakeEncryptionKeyStore store, out _, out _);

        Dek first = await sut.GetActiveDekAsync(Scope);
        await sut.RotateDekAsync(Scope);
        Dek second = await sut.GetActiveDekAsync(Scope);

        store.RotateCalls.Should().Be(1, "rotation must go through the atomic store swap");
        store.DeactivateCalls.Should().Be(0, "the unsafe two-step deactivate-then-create order is gone");
        second.KeyId.Should().NotBe(first.KeyId);

        IReadOnlyList<EncryptionKey> history = await store.GetHistoricalAsync(Scope);
        history.Where(k => k.IsActive).Should().ContainSingle()
            .Which.KeyId.Should().Be(second.KeyId);
    }

    [Fact]
    public async Task RotateDekAsync_ReplacesActiveCacheEntry_WithoutEvictionWindow()
    {
        // A2: rotation must atomically REPLACE the active cache entry (_cache.Set) rather than
        // Remove-then-repopulate — readers either see the old DEK or the new one, never a miss.
        DekManager sut = BuildSut(out _, out _, out _, out VellumDekCache cache);

        await sut.GetActiveDekAsync(Scope);
        cache.TryGetValue($"vellum:dek:active:{Scope}", out Dek? before).Should().BeTrue();

        await sut.RotateDekAsync(Scope);

        cache.TryGetValue($"vellum:dek:active:{Scope}", out Dek? after).Should().BeTrue();
        after.Should().NotBeNull();
        after!.KeyId.Should().NotBe(before!.KeyId, "the entry must be swapped to the new DEK in place");
    }

    [Fact]
    public async Task RotateDekAsync_WrapFails_OldKeyStillActiveAndCacheStillServes()
    {
        // A2: the production root cause. If the KEK provider (Vault) fails during rotation,
        // NOTHING must change: the store is untouched (old key still active) and the cache
        // still serves the old DEK — encrypts keep working. The old order (deactivate →
        // evict cache → wrap) left the scope with zero active DEKs on a Vault hiccup.
        FakeKeyEncryptionProvider inner = new();
        FailingWrapProvider provider = new(inner);
        FakeEncryptionKeyStore store = new();
        VellumDekCache cache = new();
        DekManager sut = new(
            provider,
            store,
            cache,
            new CountingRandomBytesProvider(),
            TimeProvider.System,
            Options.Create(new VellumOptions()),
            NullLogger<DekManager>.Instance);

        Dek original = await sut.GetActiveDekAsync(Scope);

        provider.FailWraps = true;
        Func<Task> act = async () => await sut.RotateDekAsync(Scope);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*KEK provider unavailable*");

        // Store untouched: the rotation never reached the store.
        store.RotateCalls.Should().Be(0, "wrap failed before any store mutation");
        store.DeactivateCalls.Should().Be(0);
        EncryptionKey? activeInStore = await store.GetActiveAsync(Scope);
        activeInStore.Should().NotBeNull();
        activeInStore!.KeyId.Should().Be(original.KeyId, "the old key must still be active");

        // Cache untouched: encrypts keep being served from the cached old DEK.
        Dek fromCache = await sut.GetActiveDekAsync(Scope);
        fromCache.KeyId.Should().Be(original.KeyId);
        fromCache.Key.Should().Equal(original.Key);

        // And even after a cache wipe, the store still resolves the old key.
        cache.Remove($"vellum:dek:active:{Scope}");
        Dek fromStore = await sut.GetActiveDekAsync(Scope);
        fromStore.KeyId.Should().Be(original.KeyId);
        fromStore.Key.Should().Equal(original.Key);
    }

    [Fact]
    public async Task RotateDekAsync_Concurrent_GetActiveDek_NeverServesDeactivatedKeyAfterRotation()
    {
        // A3: the re-poisoning race. Old behaviour: a slow GetActiveDekAsync read that loaded
        // the soon-to-be-deactivated key from the store could complete AFTER RotateDekAsync
        // evicted the cache, re-caching the deactivated DEK — every encrypt then used a dead
        // key until TTL expiry. The per-scope lock serialises the slow read and the rotation,
        // and the rotation's _cache.Set overwrites whatever the slow read cached.
        DekManager sut = BuildSut(
            out FakeKeyEncryptionProvider provider,
            out FakeEncryptionKeyStore store,
            out _,
            out _);

        // Seed an active key that is NOT cached yet, so the first read takes the slow path.
        byte[] oldPlaintext = new byte[32];
        oldPlaintext[0] = 0x11;
        WrappedKey oldWrapped = await provider.WrapAsync(oldPlaintext);
        EncryptionKey oldKey = new(Guid.NewGuid(), Scope, oldWrapped, DateTimeOffset.UtcNow, null, true);
        store.SeedKey(oldKey);

        TaskCompletionSource readEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource readRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int pauses = 0;
        store.GetActiveDelay = async _ =>
        {
            // One-shot gate: pause only the first slow read.
            if (Interlocked.Increment(ref pauses) == 1)
            {
                readEntered.SetResult();
                await readRelease.Task;
            }
        };

        // 1. Slow read: takes the scope lock, then pauses inside the store read.
        Task<Dek> slowRead = sut.GetActiveDekAsync(Scope).AsTask();
        await readEntered.Task;

        // 2. Rotation: queues on the scope lock — it cannot interleave with the slow read.
        Task rotation = sut.RotateDekAsync(Scope);
        rotation.IsCompleted.Should().BeFalse("the rotation must wait for the in-flight slow read");

        // 3. Release the slow read; it caches the OLD key and releases the lock, then the
        //    rotation runs and swaps in the NEW key.
        readRelease.SetResult();
        Dek stale = await slowRead;
        stale.KeyId.Should().Be(oldKey.KeyId, "the slow read legitimately observed the pre-rotation key");
        await rotation;

        // 4. Post-rotation reads must serve the NEW key — never the deactivated one.
        Dek current = await sut.GetActiveDekAsync(Scope);
        current.KeyId.Should().NotBe(oldKey.KeyId, "the deactivated DEK must never be re-cached after rotation");
        EncryptionKey? activeInStore = await store.GetActiveAsync(Scope);
        current.KeyId.Should().Be(activeInStore!.KeyId);
    }

    [Fact]
    public async Task GetActiveDekAsync_ConcurrentCacheMisses_SingleUnwrapCall()
    {
        // A3 anti-stampede: N concurrent cache misses on the same scope must collapse into a
        // single store + KEK-provider round-trip. The first lock holder unwraps and caches;
        // the other N-1 are answered by the double-check under the lock.
        DekManager sut = BuildSut(
            out FakeKeyEncryptionProvider provider,
            out FakeEncryptionKeyStore store,
            out _,
            out _);

        byte[] plaintext = new byte[32];
        plaintext[0] = 0x42;
        WrappedKey wrapped = await provider.WrapAsync(plaintext);
        EncryptionKey seeded = new(Guid.NewGuid(), Scope, wrapped, DateTimeOffset.UtcNow, null, true);
        store.SeedKey(seeded);
        int wrapsAfterSeed = provider.WrapCalls;

        const int parallelism = 20;
        Task<Dek>[] tasks = Enumerable.Range(0, parallelism)
            .Select(_ => Task.Run(async () => await sut.GetActiveDekAsync(Scope)))
            .ToArray();
        Dek[] results = await Task.WhenAll(tasks);

        results.Select(dek => dek.KeyId).Distinct().Should().ContainSingle()
            .Which.Should().Be(seeded.KeyId);
        provider.UnwrapCalls.Should().Be(1, "20 concurrent misses must produce exactly one unwrap");
        provider.WrapCalls.Should().Be(wrapsAfterSeed, "no new DEK may be wrapped");
        store.CreateCalls.Should().Be(0, "no caller may attempt a redundant create");
    }

    [Fact]
    public async Task GetActiveDekAsync_ConcurrentCacheMisses_EmptyScope_SingleCreateAndWrap()
    {
        // A3 anti-stampede, bootstrap variant: N concurrent misses on a scope with no key yet
        // must produce at most one create and one wrap.
        DekManager sut = BuildSut(
            out FakeKeyEncryptionProvider provider,
            out FakeEncryptionKeyStore store,
            out _,
            out _);

        const int parallelism = 20;
        Task<Dek>[] tasks = Enumerable.Range(0, parallelism)
            .Select(_ => Task.Run(async () => await sut.GetActiveDekAsync(Scope)))
            .ToArray();
        Dek[] results = await Task.WhenAll(tasks);

        results.Select(dek => dek.KeyId).Distinct().Should().ContainSingle();
        store.CreateCalls.Should().Be(1, "exactly one caller may bootstrap the scope");
        provider.WrapCalls.Should().Be(1, "exactly one DEK may be wrapped");
        provider.UnwrapCalls.Should().Be(0, "the creator caches its own plaintext, no unwrap needed");
    }

    [Fact]
    public async Task RotateDekAsync_ConcurrentRotations_SingleActiveKeyAtEnd()
    {
        DekManager sut = BuildSut(out _, out FakeEncryptionKeyStore store, out _, out _);

        Dek initial = await sut.GetActiveDekAsync(Scope);

        const int rotations = 8;
        Task[] tasks = Enumerable.Range(0, rotations)
            .Select(_ => Task.Run(async () => await sut.RotateDekAsync(Scope)))
            .ToArray();
        await Task.WhenAll(tasks);

        IReadOnlyList<EncryptionKey> history = await store.GetHistoricalAsync(Scope);
        history.Should().HaveCount(rotations + 1, "the initial key plus one per rotation");
        EncryptionKey lastActive = history.Where(k => k.IsActive).Should().ContainSingle().Subject;
        lastActive.KeyId.Should().NotBe(initial.KeyId);

        // The cache must agree with the store: the served DEK is the single active key.
        Dek current = await sut.GetActiveDekAsync(Scope);
        current.KeyId.Should().Be(lastActive.KeyId);
    }

    [Fact]
    public async Task RotateDekAsync_RaceLoss_UnwrapsAndCachesWinner()
    {
        // A2: when a concurrent rotation wins at the store, this rotation must zero its losing
        // plaintext, unwrap the winner, and cache THAT.
        _ = BuildSut(out FakeKeyEncryptionProvider provider, out _, out _, out _);

        RaceStore raceStore = new();
        VellumDekCache cache = new();
        DekManager racingSut = new(
            provider,
            raceStore,
            cache,
            new CountingRandomBytesProvider(),
            TimeProvider.System,
            Options.Create(new VellumOptions()),
            NullLogger<DekManager>.Instance);

        byte[] winnerPlaintext = new byte[32];
        winnerPlaintext[0] = 0xAB;
        WrappedKey winnerWrapped = await provider.WrapAsync(winnerPlaintext);
        raceStore.InjectRaceWinner(new EncryptionKey(
            Guid.NewGuid(), Scope, winnerWrapped, DateTimeOffset.UtcNow, null, true));

        await racingSut.RotateDekAsync(Scope);

        Dek current = await racingSut.GetActiveDekAsync(Scope);
        current.KeyId.Should().Be(raceStore.WinnerKeyId);
        current.Key[0].Should().Be(0xAB, "the cached DEK must be the winner's plaintext");
    }

    [Fact]
    public async Task CreateDekAsync_RaceLossWinnerWrongLength_FailsClosed()
    {
        // A4: the create race-loss path previously cached the winner's unwrapped bytes WITHOUT
        // EnsureDekLength — the only unwrap path missing the AES-256 length guard. A buggy or
        // compromised KEK provider returning short winner bytes must fail closed.
        _ = BuildSut(out FakeKeyEncryptionProvider provider, out _, out _, out _);

        RaceStore raceStore = new();
        DekManager racingSut = new(
            provider,
            raceStore,
            new VellumDekCache(),
            new CountingRandomBytesProvider(),
            TimeProvider.System,
            Options.Create(new VellumOptions()),
            NullLogger<DekManager>.Instance);

        WrappedKey shortWrapped = await provider.WrapAsync(new byte[16]);
        raceStore.InjectRaceWinner(new EncryptionKey(
            Guid.NewGuid(), Scope, shortWrapped, DateTimeOffset.UtcNow, null, true));

        Func<Task> act = async () => await racingSut.CreateDekAsync(Scope);
        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage("*expected 32 bytes*");
    }

    [Fact]
    public async Task RotateDekAsync_RaceLossWinnerWrongLength_FailsClosed()
    {
        // A4 symmetry on the rotation race-loss path.
        _ = BuildSut(out FakeKeyEncryptionProvider provider, out _, out _, out _);

        RaceStore raceStore = new();
        DekManager racingSut = new(
            provider,
            raceStore,
            new VellumDekCache(),
            new CountingRandomBytesProvider(),
            TimeProvider.System,
            Options.Create(new VellumOptions()),
            NullLogger<DekManager>.Instance);

        WrappedKey shortWrapped = await provider.WrapAsync(new byte[24]);
        raceStore.InjectRaceWinner(new EncryptionKey(
            Guid.NewGuid(), Scope, shortWrapped, DateTimeOffset.UtcNow, null, true));

        Func<Task> act = async () => await racingSut.RotateDekAsync(Scope);
        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage("*expected 32 bytes*");
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
        DekManager sut = BuildSut(out _, out _, out _, out VellumDekCache cache);

        Guid requestedKeyId = Guid.NewGuid();
        Dek poisoned = new(
            Key: new byte[32],
            KeyId: Guid.NewGuid(), // intentionally different
            WrappedKey: new WrappedKey("fake:v1:xxx", "v1"));

        // Reach into the cache-key builder via the exact format the manager uses.
        string cacheKey = $"vellum:dek:id:{Scope}:{requestedKeyId}";
        cache.Set(cacheKey, poisoned, TimeSpan.FromMinutes(5));

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
        VellumDekCache cache = new();
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
        VellumDekCache cache = new();
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

    [Fact]
    public async Task GetDekByWrappedKeyAsync_CacheMiss_CallsUnwrapAndCaches()
    {
        // Issue #6: first call on a fresh wrapped key goes through the provider; second
        // call on the same wrapped key hits the cache and does NOT call Unwrap again.
        DekManager sut = BuildSut(
            out FakeKeyEncryptionProvider provider,
            out _,
            out _,
            out _,
            dekCacheTtl: TimeSpan.FromMinutes(30));

        byte[] plaintext = new byte[32];
        for (int i = 0; i < plaintext.Length; i++)
        {
            plaintext[i] = (byte)(i ^ 0x5A);
        }
        WrappedKey wrapped = await provider.WrapAsync(plaintext);

        int unwrapsBefore = provider.UnwrapCalls;
        Dek first = await sut.GetDekByWrappedKeyAsync(wrapped);
        Dek second = await sut.GetDekByWrappedKeyAsync(wrapped);

        first.Key.Should().Equal(plaintext);
        second.Key.Should().Equal(plaintext);
        provider.UnwrapCalls.Should().Be(unwrapsBefore + 1,
            "the second call must be served from the wrapped-key cache");
    }

    [Fact]
    public async Task GetDekByWrappedKeyAsync_CacheHit_ReturnsClonedCopy()
    {
        // L-3 preservation: the cache entry is cloned before being handed back so the
        // caller can zero its copy without corrupting the cache.
        DekManager sut = BuildSut(
            out FakeKeyEncryptionProvider provider,
            out _,
            out _,
            out _,
            dekCacheTtl: TimeSpan.FromMinutes(30));

        byte[] plaintext = new byte[32];
        plaintext[0] = 0xAB;
        WrappedKey wrapped = await provider.WrapAsync(plaintext);

        Dek first = await sut.GetDekByWrappedKeyAsync(wrapped);
        Array.Clear(first.Key); // caller zeroes their copy

        Dek second = await sut.GetDekByWrappedKeyAsync(wrapped);
        second.Key[0].Should().Be(0xAB, "the cached copy must be unaffected by the caller's zeroing");
        ReferenceEquals(first.Key, second.Key).Should().BeFalse("each call must return a cloned byte[]");
    }

    [Fact]
    public async Task GetDekByWrappedKeyAsync_DifferentWrappedKeys_ProducesDifferentCacheKeys()
    {
        // Issue #6 / L24: two different wrapped ciphertexts must produce two different
        // cache keys — the hash of the wrapped ciphertext is globally unique, no scope
        // partitioning needed. Prime the cache with one wrapped key, then prove the
        // second wrapped key MISSES the cache (its Unwrap actually runs).
        DekManager sut = BuildSut(
            out FakeKeyEncryptionProvider provider,
            out _,
            out _,
            out _,
            dekCacheTtl: TimeSpan.FromMinutes(30));

        byte[] plaintextA = new byte[32];
        plaintextA[0] = 0x01;
        WrappedKey wrappedA = await provider.WrapAsync(plaintextA);

        byte[] plaintextB = new byte[32];
        plaintextB[0] = 0x02;
        WrappedKey wrappedB = await provider.WrapAsync(plaintextB);

        wrappedA.Should().NotBe(wrappedB, "each Wrap call should produce a fresh ciphertext handle");

        // Prime wrappedA.
        _ = await sut.GetDekByWrappedKeyAsync(wrappedA);
        int unwrapsAfterA = provider.UnwrapCalls;

        // Ask for wrappedB — must NOT hit A's cache entry.
        Dek dekB = await sut.GetDekByWrappedKeyAsync(wrappedB);

        dekB.Key.Should().Equal(plaintextB);
        provider.UnwrapCalls.Should().Be(unwrapsAfterA + 1,
            "wrappedB must miss the cache and run its own Unwrap");

        // And verify wrappedA is still cached.
        int unwrapsAfterB = provider.UnwrapCalls;
        _ = await sut.GetDekByWrappedKeyAsync(wrappedA);
        provider.UnwrapCalls.Should().Be(unwrapsAfterB, "wrappedA's entry must still be cache-hot");
    }

    [Fact]
    public async Task GetActiveDekAsync_CachingDisabled_ZeroesInternalUnwrappedArray()
    {
        // L-A: when DekCacheTtl <= 0 the Cache* helpers refuse the entry; the manager must
        // then zero its internal source array (the exact byte[] the KEK provider returned
        // from UnwrapAsync) instead of abandoning the plaintext on the managed heap. The
        // returned Dek is an independent clone and must stay intact.
        CapturingUnwrapProvider provider = new();
        FakeEncryptionKeyStore store = new();
        DekManager sut = new(
            provider,
            store,
            new VellumDekCache(),
            new CountingRandomBytesProvider(),
            TimeProvider.System,
            Options.Create(new VellumOptions { DekCacheTtl = TimeSpan.Zero }),
            NullLogger<DekManager>.Instance);

        byte[] plaintext = new byte[32];
        plaintext[0] = 0x7E;
        WrappedKey wrapped = await provider.WrapAsync(plaintext);
        store.SeedKey(new EncryptionKey(Guid.NewGuid(), Scope, wrapped, DateTimeOffset.UtcNow, null, true));

        Dek dek = await sut.GetActiveDekAsync(Scope);

        dek.Key[0].Should().Be(0x7E, "the returned Dek must be a valid independent clone");
        provider.UnwrappedArrays.Should().ContainSingle()
            .Which.Should().OnlyContain(b => b == 0, "the manager-internal source array must be scrubbed");
    }

    [Fact]
    public async Task GetDekByKeyIdAsync_CachingDisabled_ZeroesInternalUnwrappedArray()
    {
        // L-A symmetry on the by-id slow path.
        CapturingUnwrapProvider provider = new();
        FakeEncryptionKeyStore store = new();
        DekManager sut = new(
            provider,
            store,
            new VellumDekCache(),
            new CountingRandomBytesProvider(),
            TimeProvider.System,
            Options.Create(new VellumOptions { DekCacheTtl = TimeSpan.Zero }),
            NullLogger<DekManager>.Instance);

        byte[] plaintext = new byte[32];
        plaintext[0] = 0x5C;
        WrappedKey wrapped = await provider.WrapAsync(plaintext);
        EncryptionKey seeded = new(Guid.NewGuid(), Scope, wrapped, DateTimeOffset.UtcNow, null, true);
        store.SeedKey(seeded);

        Dek dek = await sut.GetDekByKeyIdAsync(seeded.KeyId, Scope);

        dek.Key[0].Should().Be(0x5C, "the returned Dek must be a valid independent clone");
        provider.UnwrappedArrays.Should().ContainSingle()
            .Which.Should().OnlyContain(b => b == 0, "the manager-internal source array must be scrubbed");
    }

    [Fact]
    public async Task GetDekByWrappedKeyAsync_CachingDisabled_ZeroesInternalUnwrappedArray()
    {
        // L-A symmetry on the wrapped-key slow path.
        CapturingUnwrapProvider provider = new();
        DekManager sut = new(
            provider,
            new FakeEncryptionKeyStore(),
            new VellumDekCache(),
            new CountingRandomBytesProvider(),
            TimeProvider.System,
            Options.Create(new VellumOptions { DekCacheTtl = TimeSpan.Zero }),
            NullLogger<DekManager>.Instance);

        byte[] plaintext = new byte[32];
        plaintext[0] = 0x99;
        WrappedKey wrapped = await provider.WrapAsync(plaintext);

        Dek dek = await sut.GetDekByWrappedKeyAsync(wrapped);

        dek.Key[0].Should().Be(0x99, "the returned Dek must be a valid independent clone");
        provider.UnwrappedArrays.Should().ContainSingle()
            .Which.Should().OnlyContain(b => b == 0, "the manager-internal source array must be scrubbed");
    }

    [Fact]
    public async Task GetDekByWrappedKeyAsync_NullWrappedKey_Throws()
    {
        DekManager sut = BuildSut(out _, out _, out _, out _);

        Func<Task> act = async () => await sut.GetDekByWrappedKeyAsync(null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task GetDekByWrappedKeyAsync_ProviderReturnsShortDek_FailsClosed()
    {
        // H-1 symmetry: the wrapped-key slow path must also reject unwrapped DEKs of the
        // wrong length. Buggy KEK providers must not downgrade the AES-256 contract.
        ShortDekProvider shortProvider = new(dekBytesLength: 16);
        FakeEncryptionKeyStore store = new();
        CountingRandomBytesProvider random = new();
        VellumDekCache cache = new();
        VellumOptions options = new();

        DekManager sut = new(
            shortProvider,
            store,
            cache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);

        WrappedKey wrapped = new("short:v1", "v1");

        Func<Task> act = async () => await sut.GetDekByWrappedKeyAsync(wrapped);
        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage("*expected 32 bytes*");
    }

    /// <summary>
    /// Delegating provider whose <see cref="WrapAsync"/> can be toggled to fail, simulating a
    /// KEK provider (Vault/KMS) outage during rotation while unwrap keeps working.
    /// </summary>
    private sealed class FailingWrapProvider(FakeKeyEncryptionProvider inner) : IKeyEncryptionProvider
    {
        public bool FailWraps { get; set; }

        public string ProviderName => "failing-fake";

        public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default)
            => FailWraps
                ? Task.FromException<WrappedKey>(new InvalidOperationException("KEK provider unavailable (simulated outage)."))
                : inner.WrapAsync(dek, cancellationToken);

        public Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
            => inner.UnwrapAsync(wrappedKey, cancellationToken);

        public Task<WrappedKey> RewrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
            => inner.RewrapAsync(wrappedKey, cancellationToken);
    }

    /// <summary>
    /// Delegating provider that records the exact <see cref="byte"/>[] instances it returned
    /// from <see cref="UnwrapAsync"/>, so tests can assert the manager scrubbed them (L-A).
    /// </summary>
    private sealed class CapturingUnwrapProvider : IKeyEncryptionProvider
    {
        private readonly FakeKeyEncryptionProvider _inner = new();

        public List<byte[]> UnwrappedArrays { get; } = new();

        public string ProviderName => "capturing-fake";

        public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default)
            => _inner.WrapAsync(dek, cancellationToken);

        public async Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
        {
            byte[] bytes = await _inner.UnwrapAsync(wrappedKey, cancellationToken);
            UnwrappedArrays.Add(bytes);
            return bytes;
        }

        public Task<WrappedKey> RewrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
            => _inner.RewrapAsync(wrappedKey, cancellationToken);
    }

    private sealed class ShortDekProvider(int dekBytesLength) : IKeyEncryptionProvider
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

        public Task<EncryptionKey> RotateAsync(EncryptionKey newKey, CancellationToken cancellationToken = default)
            => Task.FromResult(_winner ?? newKey);

        public Task<EncryptionKey> UpdateWrappedKeyAsync(Guid keyId, string scope, WrappedKey newWrappedKey, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Not used by these tests.");

        public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<EncryptionKey>>(Array.Empty<EncryptionKey>());

        public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
    }
}
