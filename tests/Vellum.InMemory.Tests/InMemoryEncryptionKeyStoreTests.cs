using FluentAssertions;
using Microsoft.Extensions.Logging;
using Vellum.InMemory;
using Vellum.InMemory.Tests.Fakes;
using Xunit;

namespace Vellum.InMemory.Tests;

public sealed class InMemoryEncryptionKeyStoreTests
{
    private const string ScopeA = "tenant:a";
    private const string ScopeB = "tenant:b";

    // ---------- GetActiveAsync ----------

    [Fact]
    public async Task GetActiveAsync_EmptyStore_ReturnsNull()
    {
        InMemoryEncryptionKeyStore store = new();

        EncryptionKey? result = await store.GetActiveAsync(ScopeA);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetActiveAsync_AfterCreate_ReturnsCreated()
    {
        InMemoryEncryptionKeyStore store = new();
        EncryptionKey key = MakeKey(ScopeA);

        await store.CreateAsync(key);

        EncryptionKey? result = await store.GetActiveAsync(ScopeA);
        result.Should().NotBeNull();
        result!.KeyId.Should().Be(key.KeyId);
    }

    [Fact]
    public async Task GetActiveAsync_AfterDeactivate_ReturnsNull()
    {
        InMemoryEncryptionKeyStore store = new();
        await store.CreateAsync(MakeKey(ScopeA));

        await store.DeactivateAllAsync(ScopeA);

        (await store.GetActiveAsync(ScopeA)).Should().BeNull();
    }

    [Fact]
    public async Task GetActiveAsync_NullScope_Throws()
    {
        InMemoryEncryptionKeyStore store = new();

        Func<Task> act = () => store.GetActiveAsync(null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    // ---------- GetByIdAsync ----------

    [Fact]
    public async Task GetByIdAsync_UnknownId_ReturnsNull()
    {
        InMemoryEncryptionKeyStore store = new();

        EncryptionKey? result = await store.GetByIdAsync(Guid.NewGuid(), ScopeA);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetByIdAsync_WrongScope_ReturnsNull()
    {
        // Multi-tenant defense (see IEncryptionKeyStore.GetByIdAsync): a caller that knows a
        // KeyId but not the owning scope must not be able to exfiltrate another tenant's key.
        InMemoryEncryptionKeyStore store = new();
        EncryptionKey key = MakeKey(ScopeA);
        await store.CreateAsync(key);

        EncryptionKey? result = await store.GetByIdAsync(key.KeyId, ScopeB);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetByIdAsync_CorrectScope_ReturnsKey()
    {
        InMemoryEncryptionKeyStore store = new();
        EncryptionKey key = MakeKey(ScopeA);
        await store.CreateAsync(key);

        EncryptionKey? result = await store.GetByIdAsync(key.KeyId, ScopeA);

        result.Should().NotBeNull();
        result!.KeyId.Should().Be(key.KeyId);
    }

    [Fact]
    public async Task GetByIdAsync_InactiveKey_ReturnedIfScopeMatches()
    {
        // Historical (deactivated) keys must remain resolvable so legacy payloads can be
        // decrypted. This matches the contract documented on IEncryptionKeyStore.
        InMemoryEncryptionKeyStore store = new();
        EncryptionKey key = MakeKey(ScopeA);
        await store.CreateAsync(key);
        await store.DeactivateAllAsync(ScopeA);

        EncryptionKey? result = await store.GetByIdAsync(key.KeyId, ScopeA);

        result.Should().NotBeNull();
        result!.IsActive.Should().BeFalse();
    }

    // ---------- CreateAsync ----------

    [Fact]
    public async Task CreateAsync_NewScope_StoresAndReturnsKey()
    {
        InMemoryEncryptionKeyStore store = new();
        EncryptionKey key = MakeKey(ScopeA);

        EncryptionKey returned = await store.CreateAsync(key);

        returned.Should().BeSameAs(key);
        (await store.GetActiveAsync(ScopeA)).Should().BeEquivalentTo(key);
    }

    [Fact]
    public async Task CreateAsync_DuplicateActive_ReturnsExistingWinner()
    {
        // IEncryptionKeyStore contract: when an active key already exists for the scope,
        // implementations must return the winner rather than throw. The caller (DekManager)
        // detects the race by comparing KeyId.
        InMemoryEncryptionKeyStore store = new();
        EncryptionKey first = MakeKey(ScopeA);
        EncryptionKey second = MakeKey(ScopeA);
        await store.CreateAsync(first);

        EncryptionKey returned = await store.CreateAsync(second);

        returned.KeyId.Should().Be(first.KeyId);
        returned.KeyId.Should().NotBe(second.KeyId);
    }

    [Fact]
    public async Task CreateAsync_DifferentScopes_Succeed()
    {
        InMemoryEncryptionKeyStore store = new();
        EncryptionKey keyA = MakeKey(ScopeA);
        EncryptionKey keyB = MakeKey(ScopeB);

        EncryptionKey returnedA = await store.CreateAsync(keyA);
        EncryptionKey returnedB = await store.CreateAsync(keyB);

        returnedA.KeyId.Should().Be(keyA.KeyId);
        returnedB.KeyId.Should().Be(keyB.KeyId);
    }

    [Fact]
    public async Task CreateAsync_NullKey_Throws()
    {
        InMemoryEncryptionKeyStore store = new();

        Func<Task> act = () => store.CreateAsync(null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    // ---------- DeactivateAllAsync ----------

    [Fact]
    public async Task DeactivateAllAsync_OnlyAffectsGivenScope()
    {
        InMemoryEncryptionKeyStore store = new();
        EncryptionKey keyA = MakeKey(ScopeA);
        EncryptionKey keyB = MakeKey(ScopeB);
        await store.CreateAsync(keyA);
        await store.CreateAsync(keyB);

        await store.DeactivateAllAsync(ScopeA);

        (await store.GetActiveAsync(ScopeA)).Should().BeNull();
        EncryptionKey? stillActiveB = await store.GetActiveAsync(ScopeB);
        stillActiveB.Should().NotBeNull();
        stillActiveB!.KeyId.Should().Be(keyB.KeyId);
    }

    [Fact]
    public async Task DeactivateAllAsync_Idempotent()
    {
        InMemoryEncryptionKeyStore store = new();
        await store.CreateAsync(MakeKey(ScopeA));

        await store.DeactivateAllAsync(ScopeA);
        Func<Task> act = () => store.DeactivateAllAsync(ScopeA);

        await act.Should().NotThrowAsync();
        (await store.GetActiveAsync(ScopeA)).Should().BeNull();
    }

    // ---------- GetHistoricalAsync ----------

    [Fact]
    public async Task GetHistoricalAsync_ReturnsAllKeysForScope_ActiveAndInactive()
    {
        InMemoryEncryptionKeyStore store = new();
        DateTimeOffset t0 = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        EncryptionKey older = MakeKey(ScopeA, createdAt: t0);
        await store.CreateAsync(older);
        await store.DeactivateAllAsync(ScopeA);

        EncryptionKey newer = MakeKey(ScopeA, createdAt: t0.AddHours(1));
        await store.CreateAsync(newer);

        IReadOnlyList<EncryptionKey> history = await store.GetHistoricalAsync(ScopeA);

        history.Should().HaveCount(2);
        history.Select(k => k.KeyId).Should().Contain(new[] { older.KeyId, newer.KeyId });
    }

    [Fact]
    public async Task GetHistoricalAsync_OrdersByCreatedAtDescending()
    {
        InMemoryEncryptionKeyStore store = new();
        DateTimeOffset t0 = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        EncryptionKey oldest = MakeKey(ScopeA, createdAt: t0);
        EncryptionKey middle = MakeKey(ScopeA, isActive: false, createdAt: t0.AddHours(1));
        EncryptionKey newest = MakeKey(ScopeA, isActive: false, createdAt: t0.AddHours(2));

        // Insert out of order; the store must sort on read.
        await store.CreateAsync(middle);
        await store.DeactivateAllAsync(ScopeA);
        await store.CreateAsync(newest);
        await store.DeactivateAllAsync(ScopeA);
        await store.CreateAsync(oldest);

        IReadOnlyList<EncryptionKey> history = await store.GetHistoricalAsync(ScopeA);

        history.Should().HaveCount(3);
        history[0].CreatedAt.Should().Be(t0.AddHours(2));
        history[1].CreatedAt.Should().Be(t0.AddHours(1));
        history[2].CreatedAt.Should().Be(t0);
    }

    [Fact]
    public async Task GetHistoricalAsync_OnlyReturnsKeysInScope()
    {
        InMemoryEncryptionKeyStore store = new();
        EncryptionKey keyA = MakeKey(ScopeA);
        EncryptionKey keyB = MakeKey(ScopeB);
        await store.CreateAsync(keyA);
        await store.CreateAsync(keyB);

        IReadOnlyList<EncryptionKey> history = await store.GetHistoricalAsync(ScopeA);

        history.Should().ContainSingle();
        history[0].KeyId.Should().Be(keyA.KeyId);
    }

    // ---------- GetActiveScopesAsync ----------

    [Fact]
    public async Task GetActiveScopesAsync_EmptyStore_ReturnsEmpty()
    {
        InMemoryEncryptionKeyStore store = new();

        IReadOnlyList<string> scopes = await store.GetActiveScopesAsync();

        scopes.Should().BeEmpty();
    }

    [Fact]
    public async Task GetActiveScopesAsync_ReturnsDistinctActiveScopes()
    {
        // Multiple historical keys per scope (rotated active + deactivated): the scope
        // should still appear only once in the result.
        InMemoryEncryptionKeyStore store = new();
        await store.CreateAsync(MakeKey(ScopeA));
        await store.DeactivateAllAsync(ScopeA);
        await store.CreateAsync(MakeKey(ScopeA));
        await store.CreateAsync(MakeKey(ScopeB));

        IReadOnlyList<string> scopes = await store.GetActiveScopesAsync();

        scopes.Should().BeEquivalentTo(new[] { ScopeA, ScopeB });
    }

    [Fact]
    public async Task GetActiveScopesAsync_IgnoresInactiveOnlyScopes()
    {
        InMemoryEncryptionKeyStore store = new();
        await store.CreateAsync(MakeKey(ScopeA));
        await store.CreateAsync(MakeKey(ScopeB));
        await store.DeactivateAllAsync(ScopeA);

        IReadOnlyList<string> scopes = await store.GetActiveScopesAsync();

        scopes.Should().ContainSingle().Which.Should().Be(ScopeB);
    }

    // ---------- Cancellation ----------

    [Fact]
    public async Task GetActiveAsync_Cancelled_Throws()
    {
        InMemoryEncryptionKeyStore store = new();
        using CancellationTokenSource cts = new();
        await cts.CancelAsync();

        Func<Task> act = () => store.GetActiveAsync(ScopeA, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // ---------- Concurrency ----------

    [Fact]
    public async Task Concurrent_CreateAsync_SameScope_ExactlyOneWinner()
    {
        // Ten tasks race to create an active key for the same scope. Thanks to the write
        // lock, exactly one CreateAsync persists its candidate and the other nine return the
        // winner. After the dust settles, the store must hold exactly one active key for the
        // scope and every CreateAsync caller must have observed the same winner KeyId.
        InMemoryEncryptionKeyStore store = new();
        const int parallelism = 10;

        using CountdownEvent gate = new(parallelism);
        using ManualResetEventSlim release = new(initialState: false);

        Task<EncryptionKey>[] tasks = Enumerable.Range(0, parallelism)
            .Select(_ => Task.Run(() =>
            {
                EncryptionKey candidate = MakeKey(ScopeA);
                gate.Signal();
                release.Wait();
                return store.CreateAsync(candidate);
            }))
            .ToArray();

        gate.Wait();
        release.Set();

        EncryptionKey[] results = await Task.WhenAll(tasks);

        // Exactly one unique winner KeyId across all tasks.
        Guid[] distinctWinners = results.Select(r => r.KeyId).Distinct().ToArray();
        distinctWinners.Should().HaveCount(1);

        // The store must hold exactly one active key for the scope.
        IReadOnlyList<EncryptionKey> history = await store.GetHistoricalAsync(ScopeA);
        history.Where(k => k.IsActive).Should().ContainSingle()
            .Which.KeyId.Should().Be(distinctWinners[0]);

        // Nothing leaked into ScopeB.
        (await store.GetActiveAsync(ScopeB)).Should().BeNull();
    }

    [Fact]
    public async Task Concurrent_ReadWrite_NoExceptions()
    {
        InMemoryEncryptionKeyStore store = new();
        await store.CreateAsync(MakeKey(ScopeA));

        using CancellationTokenSource cts = new(TimeSpan.FromMilliseconds(500));

        Task reader = Task.Run(async () =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                _ = await store.GetActiveAsync(ScopeA, CancellationToken.None);
                _ = await store.GetHistoricalAsync(ScopeA, CancellationToken.None);
                _ = await store.GetActiveScopesAsync(CancellationToken.None);
            }
        });

        Task writer = Task.Run(async () =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                await store.DeactivateAllAsync(ScopeA, CancellationToken.None);
                await store.CreateAsync(MakeKey(ScopeA), CancellationToken.None);
            }
        });

        Func<Task> act = () => Task.WhenAll(reader, writer);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Concurrent_CreateAsync_IsolatedAcrossScopes()
    {
        // Parallel creates on disjoint scopes must all succeed — the per-scope invariant must
        // not degenerate into a global "one active key anywhere" rule.
        InMemoryEncryptionKeyStore store = new();
        const int scopeCount = 20;

        Task<EncryptionKey>[] tasks = Enumerable.Range(0, scopeCount)
            .Select(i => Task.Run(() => store.CreateAsync(MakeKey($"tenant:{i}"))))
            .ToArray();

        EncryptionKey[] created = await Task.WhenAll(tasks);

        created.Should().HaveCount(scopeCount);
        created.Select(k => k.Scope).Distinct().Should().HaveCount(scopeCount);

        IReadOnlyList<string> activeScopes = await store.GetActiveScopesAsync();
        activeScopes.Should().HaveCount(scopeCount);
    }

    // ---------- Helpers ----------

    private static EncryptionKey MakeKey(
        string scope,
        bool isActive = true,
        DateTimeOffset? createdAt = null)
    {
        return new EncryptionKey(
            KeyId: Guid.NewGuid(),
            Scope: scope,
            WrappedKey: new WrappedKey("opaque-ciphertext", "v1"),
            CreatedAt: createdAt ?? DateTimeOffset.UtcNow,
            ExpiresAt: null,
            IsActive: isActive);
    }
}
