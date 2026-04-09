using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Vellum.EntityFrameworkCore;
using Vellum.EntityFrameworkCore.Internal;
using Vellum.EntityFrameworkCore.Tests.Fixtures;
using Xunit;

namespace Vellum.EntityFrameworkCore.Tests;

public sealed class EntityFrameworkCoreEncryptionKeyStoreTests
{
    private const string ScopeA = "tenant:a";
    private const string ScopeB = "tenant:b";

    // ---------- GetActiveAsync ----------

    [Fact]
    public async Task GetActiveAsync_EmptyStore_ReturnsNull()
    {
        await using TestHarness harness = new();

        EncryptionKey? result = await harness.Store.GetActiveAsync(ScopeA);

        result.Should().BeNull();
    }

    [Fact]
    public async Task CreateAsync_Then_GetActive_ReturnsCreated()
    {
        await using TestHarness harness = new();
        EncryptionKey key = MakeKey(ScopeA);

        EncryptionKey created = await harness.Store.CreateAsync(key);

        created.KeyId.Should().Be(key.KeyId);

        EncryptionKey? fetched = await harness.Store.GetActiveAsync(ScopeA);
        fetched.Should().NotBeNull();
        fetched!.KeyId.Should().Be(key.KeyId);
        fetched.Scope.Should().Be(ScopeA);
        fetched.WrappedKey.Should().Be(key.WrappedKey);
        fetched.IsActive.Should().BeTrue();
    }

    // ---------- GetByIdAsync (M1 defence) ----------

    [Fact]
    public async Task GetByIdAsync_WrongScope_ReturnsNull()
    {
        await using TestHarness harness = new();
        EncryptionKey key = MakeKey(ScopeA);
        await harness.Store.CreateAsync(key);

        EncryptionKey? result = await harness.Store.GetByIdAsync(key.KeyId, ScopeB);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetByIdAsync_CorrectScope_Returns()
    {
        await using TestHarness harness = new();
        EncryptionKey key = MakeKey(ScopeA);
        await harness.Store.CreateAsync(key);

        EncryptionKey? result = await harness.Store.GetByIdAsync(key.KeyId, ScopeA);

        result.Should().NotBeNull();
        result!.KeyId.Should().Be(key.KeyId);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsInactiveKey()
    {
        // Historical payloads reference keys that may have been deactivated. The store must
        // still return them so the consumer can decrypt.
        await using TestHarness harness = new();
        EncryptionKey key = MakeKey(ScopeA);
        await harness.Store.CreateAsync(key);
        await harness.Store.DeactivateAllAsync(ScopeA);

        EncryptionKey? result = await harness.Store.GetByIdAsync(key.KeyId, ScopeA);

        result.Should().NotBeNull();
        result!.IsActive.Should().BeFalse();
    }

    // ---------- CreateAsync (race handling) ----------

    [Fact]
    public async Task CreateAsync_TwiceSameScope_SequentialReturnsExistingWinner()
    {
        // Sequential case exercises layer 1 of the 4-layer defence: the double-check via
        // GetActiveAsync finds the existing active key and returns it without attempting
        // a new insert.
        await using TestHarness harness = new();

        EncryptionKey first = MakeKey(ScopeA);
        EncryptionKey persisted = await harness.Store.CreateAsync(first);

        EncryptionKey second = MakeKey(ScopeA);
        EncryptionKey result = await harness.Store.CreateAsync(second);

        result.KeyId.Should().Be(persisted.KeyId);
        result.KeyId.Should().NotBe(second.KeyId);
    }

    [Fact]
    public async Task ConcurrentCreateAsync_SameScope_OnlyOneWinner_ViaUniqueIndex()
    {
        // Concurrent case: multiple stores sharing the same SQLite database race to install
        // the first active key for the scope. The filtered unique index guarantees at most
        // one wins at the DB layer; the store must either (a) short-circuit via layer 1 or
        // (b) catch the DbUpdateException, detach the failed candidate, re-read the winner.
        // Either path MUST return the same winner to all callers.
        await using TestHarness harness = new();

        const int parallelism = 8;
        EncryptionKey[] candidates = new EncryptionKey[parallelism];
        Task<EncryptionKey>[] tasks = new Task<EncryptionKey>[parallelism];

        for (int i = 0; i < parallelism; i++)
        {
            candidates[i] = MakeKey(ScopeA);
        }

        // Each task uses its own store/context so the write lock on a single DbContext does
        // not serialise their operations.
        for (int i = 0; i < parallelism; i++)
        {
            EncryptionKey candidate = candidates[i];
            EntityFrameworkCoreEncryptionKeyStore<TestDbContext> store = harness.CreateStore();
            tasks[i] = Task.Run(async () => await store.CreateAsync(candidate));
        }

        EncryptionKey[] results = await Task.WhenAll(tasks);

        // All returned winners must be the same KeyId.
        Guid winnerKeyId = results[0].KeyId;
        results.Should().AllSatisfy(result => result.KeyId.Should().Be(winnerKeyId));

        // The DB must carry exactly one active row for the scope.
        int activeCount = await harness.Context.Set<EncryptionKeyRecord>()
            .IgnoreQueryFilters()
            .CountAsync(k => k.Scope == ScopeA && k.IsActive);
        activeCount.Should().Be(1);
    }

    // ---------- DeactivateAllAsync ----------

    [Fact]
    public async Task DeactivateAllAsync_ThenCreate_NewActive_Succeeds()
    {
        await using TestHarness harness = new();

        EncryptionKey original = MakeKey(ScopeA);
        await harness.Store.CreateAsync(original);
        await harness.Store.DeactivateAllAsync(ScopeA);

        EncryptionKey replacement = MakeKey(ScopeA);
        EncryptionKey result = await harness.Store.CreateAsync(replacement);

        result.KeyId.Should().Be(replacement.KeyId);

        EncryptionKey? active = await harness.Store.GetActiveAsync(ScopeA);
        active.Should().NotBeNull();
        active!.KeyId.Should().Be(replacement.KeyId);
    }

    [Fact]
    public async Task DeactivateAllAsync_OnlyTouchesMatchingScope()
    {
        await using TestHarness harness = new();
        EncryptionKey keyA = MakeKey(ScopeA);
        EncryptionKey keyB = MakeKey(ScopeB);
        await harness.Store.CreateAsync(keyA);
        await harness.Store.CreateAsync(keyB);

        await harness.Store.DeactivateAllAsync(ScopeA);

        EncryptionKey? activeA = await harness.Store.GetActiveAsync(ScopeA);
        EncryptionKey? activeB = await harness.Store.GetActiveAsync(ScopeB);

        activeA.Should().BeNull();
        activeB.Should().NotBeNull();
        activeB!.KeyId.Should().Be(keyB.KeyId);
    }

    // ---------- GetHistoricalAsync ----------

    [Fact]
    public async Task GetHistoricalAsync_ReturnsAllIncludingInactive_SortedDescending()
    {
        await using TestHarness harness = new();

        EncryptionKey older = MakeKey(ScopeA, createdAt: DateTimeOffset.UtcNow.AddHours(-2));
        await harness.Store.CreateAsync(older);
        await harness.Store.DeactivateAllAsync(ScopeA);

        EncryptionKey newer = MakeKey(ScopeA, createdAt: DateTimeOffset.UtcNow);
        await harness.Store.CreateAsync(newer);

        IReadOnlyList<EncryptionKey> keys = await harness.Store.GetHistoricalAsync(ScopeA);

        keys.Should().HaveCount(2);
        keys[0].KeyId.Should().Be(newer.KeyId);
        keys[1].KeyId.Should().Be(older.KeyId);
    }

    [Fact]
    public async Task GetHistoricalAsync_OnlyReturnsMatchingScope()
    {
        await using TestHarness harness = new();
        await harness.Store.CreateAsync(MakeKey(ScopeA));
        await harness.Store.CreateAsync(MakeKey(ScopeB));

        IReadOnlyList<EncryptionKey> keys = await harness.Store.GetHistoricalAsync(ScopeA);

        keys.Should().HaveCount(1);
        keys[0].Scope.Should().Be(ScopeA);
    }

    // ---------- GetActiveScopesAsync ----------

    [Fact]
    public async Task GetActiveScopesAsync_ReturnsDistinctActiveScopes()
    {
        await using TestHarness harness = new();
        await harness.Store.CreateAsync(MakeKey(ScopeA));
        await harness.Store.CreateAsync(MakeKey(ScopeB));

        IReadOnlyList<string> scopes = await harness.Store.GetActiveScopesAsync();

        scopes.Should().BeEquivalentTo(new[] { ScopeA, ScopeB });
    }

    [Fact]
    public async Task GetActiveScopesAsync_DoesNotIncludeScopesWithOnlyInactiveKeys()
    {
        await using TestHarness harness = new();
        await harness.Store.CreateAsync(MakeKey(ScopeA));
        await harness.Store.DeactivateAllAsync(ScopeA);

        IReadOnlyList<string> scopes = await harness.Store.GetActiveScopesAsync();

        scopes.Should().BeEmpty();
    }

    // ---------- L1 pinned: IgnoreQueryFilters bypasses tenant query filter ----------

    [Fact]
    public async Task IgnoreQueryFilters_TenantFilterSet_StillReadsKeys()
    {
        // TestDbContext applies a global query filter on EncryptionKeyRecord that matches
        // nothing. If the store forgot IgnoreQueryFilters() on a read path, GetActiveAsync
        // would return null and CreateAsync's double-check would then pass through to the
        // insert path — this test would still pass against a buggy store if we only checked
        // "CreateAsync_then_GetActive". That's why we go further and verify:
        //   1. A direct .Set<EncryptionKeyRecord>() query returns zero rows (query filter works).
        //   2. A direct .Set<EncryptionKeyRecord>().IgnoreQueryFilters() query returns the key.
        //   3. The store's GetActiveAsync returns the key in spite of the filter.
        await using TestHarness harness = new();
        EncryptionKey key = MakeKey(ScopeA);
        await harness.Store.CreateAsync(key);

        int filteredCount = await harness.Context.Set<EncryptionKeyRecord>()
            .CountAsync();
        filteredCount.Should().Be(0, "the test DbContext attaches a match-nothing query filter on EncryptionKeyRecord");

        int unfilteredCount = await harness.Context.Set<EncryptionKeyRecord>()
            .IgnoreQueryFilters()
            .CountAsync();
        unfilteredCount.Should().Be(1, "the row is physically there; only the filter hides it");

        EncryptionKey? active = await harness.Store.GetActiveAsync(ScopeA);
        active.Should().NotBeNull("the store MUST use IgnoreQueryFilters() on every read (lesson L1)");
        active!.KeyId.Should().Be(key.KeyId);

        EncryptionKey? byId = await harness.Store.GetByIdAsync(key.KeyId, ScopeA);
        byId.Should().NotBeNull();

        IReadOnlyList<EncryptionKey> historical = await harness.Store.GetHistoricalAsync(ScopeA);
        historical.Should().HaveCount(1);

        IReadOnlyList<string> scopes = await harness.Store.GetActiveScopesAsync();
        scopes.Should().Contain(ScopeA);
    }

    // ---------- Argument validation ----------

    [Fact]
    public async Task GetActiveAsync_NullScope_Throws()
    {
        await using TestHarness harness = new();

        Func<Task> act = async () => await harness.Store.GetActiveAsync(null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task CreateAsync_NullKey_Throws()
    {
        await using TestHarness harness = new();

        Func<Task> act = async () => await harness.Store.CreateAsync(null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    // ---------- Helpers ----------

    private static EncryptionKey MakeKey(string scope, DateTimeOffset? createdAt = null)
    {
        return new EncryptionKey(
            KeyId: Guid.NewGuid(),
            Scope: scope,
            WrappedKey: new WrappedKey("ciphertext-" + Guid.NewGuid().ToString("N"), "v1"),
            CreatedAt: createdAt ?? DateTimeOffset.UtcNow,
            ExpiresAt: null,
            IsActive: true);
    }
}
