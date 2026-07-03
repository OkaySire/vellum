using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Vellum.Tests.Fakes;
using Xunit;

namespace Vellum.Tests;

public sealed class VellumRewrapServiceTests
{
    private const string Scope = "tenant:42";

    private static VellumRewrapService BuildSut(
        FakeKeyEncryptionProvider provider,
        FakeEncryptionKeyStore store) =>
        new(provider, store, NullLogger<VellumRewrapService>.Instance);

    /// <summary>
    /// Seeds a key whose wrapped material is a real handle of the fake provider, so that
    /// <see cref="FakeKeyEncryptionProvider.RewrapAsync"/> can resolve it.
    /// </summary>
    private static async Task<EncryptionKey> SeedKeyAsync(
        FakeKeyEncryptionProvider provider,
        FakeEncryptionKeyStore store,
        string scope,
        bool isActive,
        byte[] dek)
    {
        WrappedKey wrapped = await provider.WrapAsync(dek);
        EncryptionKey key = new(
            KeyId: Guid.NewGuid(),
            Scope: scope,
            WrappedKey: wrapped,
            CreatedAt: DateTimeOffset.UtcNow.AddDays(isActive ? 0 : -1),
            ExpiresAt: null,
            IsActive: isActive);
        store.SeedKey(key);
        return key;
    }

    [Fact]
    public async Task RewrapStoredKeysAsync_RewrapsActiveAndHistoricalKeys()
    {
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();
        byte[] dek = RandomNumberGenerator.GetBytes(32);

        EncryptionKey historical1 = await SeedKeyAsync(provider, store, Scope, isActive: false, dek);
        EncryptionKey historical2 = await SeedKeyAsync(provider, store, Scope, isActive: false, dek);
        EncryptionKey active = await SeedKeyAsync(provider, store, Scope, isActive: true, dek);

        VellumRewrapService sut = BuildSut(provider, store);
        RewrapScopeResult result = await sut.RewrapStoredKeysAsync(Scope);

        result.Total.Should().Be(3);
        result.Rewrapped.Should().Be(3);
        result.Failed.Should().Be(0);
        result.FailedKeyIds.Should().BeEmpty();

        // Every key (active AND historical) must carry NEW wrapped material under the
        // current provider version — and that material must still unwrap to the same DEK.
        foreach (EncryptionKey original in new[] { historical1, historical2, active })
        {
            EncryptionKey? refreshed = await store.GetByIdAsync(original.KeyId, Scope);
            refreshed.Should().NotBeNull();
            refreshed!.WrappedKey.Ciphertext.Should().NotBe(original.WrappedKey.Ciphertext);
            refreshed.WrappedKey.ProviderVersion.Should().Be("v2");
            refreshed.IsActive.Should().Be(original.IsActive, "rewrap never changes lifecycle state");

            byte[] unwrapped = await provider.UnwrapAsync(refreshed.WrappedKey);
            unwrapped.Should().Equal(dek, "the rewrap must preserve the DEK plaintext");
        }
    }

    [Fact]
    public async Task RewrapStoredKeysAsync_DeduplicatesActiveKeyReturnedByHistorical()
    {
        // GetHistoricalAsync contractually includes the active key; the service also reads
        // GetActiveAsync defensively. The same key must be rewrapped exactly ONCE.
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();
        byte[] dek = RandomNumberGenerator.GetBytes(32);

        _ = await SeedKeyAsync(provider, store, Scope, isActive: true, dek);

        VellumRewrapService sut = BuildSut(provider, store);
        RewrapScopeResult result = await sut.RewrapStoredKeysAsync(Scope);

        result.Total.Should().Be(1, "the active key appears in both reads but must be counted once");
        result.Rewrapped.Should().Be(1);
        provider.RewrapCalls.Should().Be(1, "deduplication must prevent a second rewrap of the same key");
    }

    [Fact]
    public async Task RewrapStoredKeysAsync_PartialFailure_ContinuesSweepAndRecordsFailedKey()
    {
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();
        byte[] dek = RandomNumberGenerator.GetBytes(32);

        EncryptionKey healthy1 = await SeedKeyAsync(provider, store, Scope, isActive: false, dek);
        EncryptionKey poisoned = await SeedKeyAsync(provider, store, Scope, isActive: false, dek);
        EncryptionKey healthy2 = await SeedKeyAsync(provider, store, Scope, isActive: true, dek);

        provider.FailRewrapHandles.Add(poisoned.WrappedKey.Ciphertext);

        VellumRewrapService sut = BuildSut(provider, store);
        RewrapScopeResult result = await sut.RewrapStoredKeysAsync(Scope);

        result.Total.Should().Be(3);
        result.Rewrapped.Should().Be(2, "one key failing must not abort the sweep of the others");
        result.Failed.Should().Be(1);
        result.FailedKeyIds.Should().ContainSingle().Which.Should().Be(poisoned.KeyId);

        // The healthy keys were refreshed; the poisoned one keeps its original material so a
        // re-run of the sweep can pick it up (idempotent resume).
        (await store.GetByIdAsync(healthy1.KeyId, Scope))!.WrappedKey.Ciphertext
            .Should().NotBe(healthy1.WrappedKey.Ciphertext);
        (await store.GetByIdAsync(healthy2.KeyId, Scope))!.WrappedKey.Ciphertext
            .Should().NotBe(healthy2.WrappedKey.Ciphertext);
        (await store.GetByIdAsync(poisoned.KeyId, Scope))!.WrappedKey
            .Should().Be(poisoned.WrappedKey);
    }

    [Fact]
    public async Task RewrapStoredKeysAsync_EmptyScope_ReturnsZeroTotal()
    {
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();

        VellumRewrapService sut = BuildSut(provider, store);
        RewrapScopeResult result = await sut.RewrapStoredKeysAsync("tenant:empty");

        result.Total.Should().Be(0);
        result.Rewrapped.Should().Be(0);
        result.Failed.Should().Be(0);
        result.FailedKeyIds.Should().BeEmpty();
        provider.RewrapCalls.Should().Be(0);
    }

    [Fact]
    public async Task RewrapStoredKeysAsync_DoesNotTouchOtherScopes()
    {
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();
        byte[] dek = RandomNumberGenerator.GetBytes(32);

        EncryptionKey other = await SeedKeyAsync(provider, store, "tenant:other", isActive: true, dek);
        _ = await SeedKeyAsync(provider, store, Scope, isActive: true, dek);

        VellumRewrapService sut = BuildSut(provider, store);
        RewrapScopeResult result = await sut.RewrapStoredKeysAsync(Scope);

        result.Total.Should().Be(1);
        (await store.GetByIdAsync(other.KeyId, "tenant:other"))!.WrappedKey
            .Should().Be(other.WrappedKey, "a sweep is strictly per-scope");
    }

    [Fact]
    public async Task RewrapStoredKeysAsync_NullScope_Throws()
    {
        VellumRewrapService sut = BuildSut(new FakeKeyEncryptionProvider(), new FakeEncryptionKeyStore());

        Func<Task> act = async () => await sut.RewrapStoredKeysAsync(null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }
}
