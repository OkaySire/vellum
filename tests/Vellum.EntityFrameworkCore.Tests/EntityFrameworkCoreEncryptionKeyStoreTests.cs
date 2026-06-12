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

    // ---------- RotateAsync (A1 — atomic swap) ----------

    [Fact]
    public async Task RotateAsync_AtomicallySwapsActiveKey()
    {
        await using TestHarness harness = new();
        EncryptionKey first = MakeKey(ScopeA);
        await harness.Store.CreateAsync(first);

        EncryptionKey replacement = MakeKey(ScopeA);
        EncryptionKey returned = await harness.Store.RotateAsync(replacement);

        returned.KeyId.Should().Be(replacement.KeyId);

        EncryptionKey? active = await harness.Store.GetActiveAsync(ScopeA);
        active.Should().NotBeNull();
        active!.KeyId.Should().Be(replacement.KeyId);

        IReadOnlyList<EncryptionKey> history = await harness.Store.GetHistoricalAsync(ScopeA);
        history.Should().HaveCount(2);
        history.Single(k => k.KeyId == first.KeyId).IsActive.Should().BeFalse();

        // The filtered unique index never saw two active rows: exactly one active in the DB.
        int activeCount = await harness.Context.Set<EncryptionKeyRecord>()
            .IgnoreQueryFilters()
            .CountAsync(k => k.Scope == ScopeA && k.IsActive);
        activeCount.Should().Be(1);
    }

    [Fact]
    public async Task RotateAsync_EmptyScope_InstallsActiveKey()
    {
        await using TestHarness harness = new();
        EncryptionKey key = MakeKey(ScopeA);

        EncryptionKey returned = await harness.Store.RotateAsync(key);

        returned.KeyId.Should().Be(key.KeyId);
        (await harness.Store.GetActiveAsync(ScopeA))!.KeyId.Should().Be(key.KeyId);
    }

    [Fact]
    public async Task RotateAsync_OnlyTouchesMatchingScope()
    {
        await using TestHarness harness = new();
        EncryptionKey keyB = MakeKey(ScopeB);
        await harness.Store.CreateAsync(MakeKey(ScopeA));
        await harness.Store.CreateAsync(keyB);

        await harness.Store.RotateAsync(MakeKey(ScopeA));

        EncryptionKey? activeB = await harness.Store.GetActiveAsync(ScopeB);
        activeB.Should().NotBeNull();
        activeB!.KeyId.Should().Be(keyB.KeyId);
    }

    [Fact]
    public async Task RotateAsync_InactiveKey_ThrowsFailClosed()
    {
        await using TestHarness harness = new();
        EncryptionKey old = MakeKey(ScopeA);
        await harness.Store.CreateAsync(old);

        EncryptionKey inactive = MakeKey(ScopeA) with { IsActive = false };
        Func<Task> act = async () => await harness.Store.RotateAsync(inactive);

        await act.Should().ThrowAsync<ArgumentException>(
            "installing an inactive key would leave the scope with zero active keys");
        (await harness.Store.GetActiveAsync(ScopeA))!.KeyId.Should().Be(old.KeyId);
    }

    [Fact]
    public async Task RotateAsync_NullKey_Throws()
    {
        await using TestHarness harness = new();

        Func<Task> act = async () => await harness.Store.RotateAsync(null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task RotateAsync_OnFailure_OldKeyStillActive_AndThrows()
    {
        // A1 failure injection: provoke a DbUpdateException that is NOT a rotation race by
        // colliding the new key's primary key with a pre-existing row on another scope. The
        // single-SaveChanges transaction must roll back COMPLETELY: the old key stays active,
        // no new row appears, and the store throws fail-closed (it must not mask the failure
        // by returning the still-active old key as if a concurrent rotation had won).
        await using TestHarness harness = new();

        Guid sharedKeyId = Guid.NewGuid();
        EncryptionKey preexisting = new(
            KeyId: sharedKeyId,
            Scope: "tenant:other",
            WrappedKey: new WrappedKey("ciphertext-preexisting", "v1"),
            CreatedAt: DateTimeOffset.UtcNow,
            ExpiresAt: null,
            IsActive: false);
        await harness.Store.CreateAsync(preexisting);

        EncryptionKey old = MakeKey(ScopeA);
        await harness.Store.CreateAsync(old);

        // Fresh store/context so the PK collision surfaces at the database, not the tracker.
        EntityFrameworkCoreEncryptionKeyStore<TestDbContext> freshStore = harness.CreateStore();
        EncryptionKey colliding = MakeKey(ScopeA) with { KeyId = sharedKeyId };

        Func<Task> act = async () => await freshStore.RotateAsync(colliding);

        (await act.Should().ThrowAsync<InvalidOperationException>(
                "a non-race DbUpdateException must surface fail-closed"))
            .Which.InnerException.Should().BeAssignableTo<DbUpdateException>();

        // Atomicity: the rollback restored the old key — the scope never lost its active DEK.
        EncryptionKey? active = await harness.Store.GetActiveAsync(ScopeA);
        active.Should().NotBeNull("the failed rotation must leave the old key active");
        active!.KeyId.Should().Be(old.KeyId);

        int scopeRows = await harness.Context.Set<EncryptionKeyRecord>()
            .IgnoreQueryFilters()
            .CountAsync(k => k.Scope == ScopeA);
        scopeRows.Should().Be(1, "the colliding candidate must not have been inserted");
    }

    [Fact]
    public async Task ConcurrentRotateAsync_SameScope_ExactlyOneActiveAtEnd()
    {
        // Concurrent rotations from independent stores/contexts on the shared SQLite file.
        // Each rotation either commits its own candidate or detects the race and returns the
        // concurrent winner. Whatever the interleaving, the filtered unique index plus the
        // single-transaction swap guarantee exactly one active row at the end.
        await using TestHarness harness = new();
        await harness.Store.CreateAsync(MakeKey(ScopeA));

        const int parallelism = 8;
        EncryptionKey[] candidates = new EncryptionKey[parallelism];
        Task<EncryptionKey>[] tasks = new Task<EncryptionKey>[parallelism];

        for (int i = 0; i < parallelism; i++)
        {
            candidates[i] = MakeKey(ScopeA);
        }

        for (int i = 0; i < parallelism; i++)
        {
            EncryptionKey candidate = candidates[i];
            EntityFrameworkCoreEncryptionKeyStore<TestDbContext> store = harness.CreateStore();
            tasks[i] = Task.Run(async () => await store.RotateAsync(candidate));
        }

        EncryptionKey[] results = await Task.WhenAll(tasks);

        int activeCount = await harness.Context.Set<EncryptionKeyRecord>()
            .IgnoreQueryFilters()
            .CountAsync(k => k.Scope == ScopeA && k.IsActive);
        activeCount.Should().Be(1, "rotation must never leave zero or multiple active keys");

        EncryptionKey? active = await harness.Store.GetActiveAsync(ScopeA);
        candidates.Select(c => c.KeyId).Should().Contain(active!.KeyId,
            "the final active key must be one of the rotation candidates");
        results.Should().AllSatisfy(result => result.Should().NotBeNull());
    }

    [Fact]
    public async Task ConcurrentRotateAsync_VersusCreate_InvariantHolds()
    {
        // Rotate-vs-create storm on an initially-empty scope: whichever operations win, the
        // scope must end with exactly one active key.
        await using TestHarness harness = new();

        const int pairs = 4;
        Task[] tasks = new Task[pairs * 2];
        for (int i = 0; i < pairs; i++)
        {
            EntityFrameworkCoreEncryptionKeyStore<TestDbContext> createStore = harness.CreateStore();
            EntityFrameworkCoreEncryptionKeyStore<TestDbContext> rotateStore = harness.CreateStore();
            EncryptionKey createCandidate = MakeKey(ScopeA);
            EncryptionKey rotateCandidate = MakeKey(ScopeA);
            tasks[i * 2] = Task.Run(async () => await createStore.CreateAsync(createCandidate));
            tasks[(i * 2) + 1] = Task.Run(async () => await rotateStore.RotateAsync(rotateCandidate));
        }

        await Task.WhenAll(tasks);

        int activeCount = await harness.Context.Set<EncryptionKeyRecord>()
            .IgnoreQueryFilters()
            .CountAsync(k => k.Scope == ScopeA && k.IsActive);
        activeCount.Should().Be(1);
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

    // ---------- M-4 — DbUpdateException without a race winner ----------

    [Fact]
    public async Task CreateAsync_DbUpdateExceptionWithoutRaceWinner_ThrowsInvalidOperationException()
    {
        // M-4: fail-closed behaviour when a DbUpdateException is caused by something OTHER
        // than the filtered-unique-index race. Pre-seed a row with the same KeyId on a
        // DIFFERENT scope so the primary-key constraint trips on SaveChanges in a fresh
        // store/context, then the store must NOT silently swallow the error. It must
        // re-throw as InvalidOperationException with the original DbUpdateException
        // preserved as InnerException.
        //
        // The second store is deliberately constructed from a fresh DbContext so the change
        // tracker does not see the pre-existing row locally — the PK collision happens at
        // the database level (DbUpdateException) rather than at the tracker level (which
        // would throw a raw InvalidOperationException with no InnerException).
        await using TestHarness harness = new();

        Guid sharedKeyId = Guid.NewGuid();

        EncryptionKey preexisting = new(
            KeyId: sharedKeyId,
            Scope: "tenant:other",
            WrappedKey: new WrappedKey("ciphertext-preexisting", "v1"),
            CreatedAt: DateTimeOffset.UtcNow,
            ExpiresAt: null,
            IsActive: false);
        await harness.Store.CreateAsync(preexisting);

        EntityFrameworkCoreEncryptionKeyStore<TestDbContext> freshStore = harness.CreateStore();

        // New scope with no active key, but reuse the same KeyId — this collides on the PK.
        EncryptionKey colliding = new(
            KeyId: sharedKeyId,
            Scope: "tenant:fresh",
            WrappedKey: new WrappedKey("ciphertext-colliding", "v1"),
            CreatedAt: DateTimeOffset.UtcNow,
            ExpiresAt: null,
            IsActive: true);

        Func<Task> act = async () => await freshStore.CreateAsync(colliding);

        (await act.Should().ThrowAsync<InvalidOperationException>(
                "the DbUpdateException is NOT a filtered-unique-index race so the store must fail closed"))
            .Which.InnerException.Should().BeAssignableTo<DbUpdateException>(
                "the original DbUpdateException must be preserved as the inner exception");
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
