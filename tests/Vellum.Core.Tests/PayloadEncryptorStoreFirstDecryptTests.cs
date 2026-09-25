using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using FluentAssertions.Specialized;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Tests.Fakes;
using Xunit;

namespace Vellum.Tests;

/// <summary>
/// 0.4.0 — <see cref="PayloadEncryptor.DecryptAsync"/> resolves the DEK from the key store by
/// <see cref="EncryptedPayload.KeyId"/> first and only falls back to the wrapped DEK copy carried
/// by the envelope. Each test here has a documented negative control: the source-level change that
/// makes it go red, recorded in the test's own remarks so a later reader can re-run the control
/// rather than trust it.
/// </summary>
/// <remarks>
/// The collection attribute serialises these tests against every other class in this assembly that
/// decrypts, because <see cref="VellumDecryptMetrics"/> is process-global: a concurrent
/// tampered-ciphertext test elsewhere also increments the fallback gauges, and the delta assertions
/// below would pick it up.
/// </remarks>
[Collection("PayloadDecryptMetrics")]
public sealed class PayloadEncryptorStoreFirstDecryptTests
{
    private const string Scope = "tenant:42";

    private static (PayloadEncryptor Encryptor, DekManager Manager) Build(
        FakeKeyEncryptionProvider provider,
        FakeEncryptionKeyStore store,
        VellumDekCache cache)
    {
        CountingRandomBytesProvider random = new();
        VellumOptions options = new();

        DekManager manager = new(
            provider,
            store,
            cache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);

        PayloadEncryptor encryptor = new(
            manager,
            provider,
            random,
            Options.Create(options),
            NullLogger<PayloadEncryptor>.Instance);

        return (encryptor, manager);
    }

    /// <summary>
    /// Case 1 of the plan: a DEK rewrapped onto a second KEK mount, and a persisted envelope whose
    /// own wrapped-DEK copy no longer unwraps there. The decrypt must succeed off the store record.
    /// </summary>
    /// <remarks>
    /// <b>Negative control.</b> Swap the two resolution steps in
    /// <c>PayloadEncryptor.DecryptAsync</c> back to 0.3.x order (envelope copy first) and this test
    /// fails: the envelope handle is unknown to the second provider, so the only path tried throws.
    /// </remarks>
    [Fact]
    public async Task Decrypt_StoreRecordRewrappedOnNewMount_EnvelopeCopyUnusable_SucceedsViaStore()
    {
        FakeEncryptionKeyStore store = new();
        FakeKeyEncryptionProvider oldMount = new();
        byte[] plaintext = Encoding.UTF8.GetBytes("a row written before the mount split");

        // Written on the old mount: the envelope carries a handle only `oldMount` can unwrap.
        EncryptedPayload envelope;
        byte[] dekBytes;
        using (VellumDekCache oldCache = new())
        {
            (PayloadEncryptor oldEncryptor, DekManager oldManager) = Build(oldMount, store, oldCache);
            envelope = await oldEncryptor.EncryptAsync(plaintext, Scope);

            // The migration reads the DEK once while both mounts are reachable.
            Dek dek = await oldManager.GetDekByKeyIdAsync(envelope.KeyId, Scope);
            dekBytes = dek.Key;
        }

        // The migration rewraps ONLY the store record onto the new mount: 1 record, not 1 row per
        // payload. The persisted envelope is deliberately left alone — that is the whole point.
        FakeKeyEncryptionProvider newMount = new();
        WrappedKey rewrapped = await newMount.WrapAsync(dekBytes);
        _ = await store.UpdateWrappedKeyAsync(envelope.KeyId, Scope, rewrapped);
        CryptographicOperations.ZeroMemory(dekBytes);

        // The process now only talks to the new mount, and its DEK cache is cold.
        using VellumDekCache newCache = new();
        (PayloadEncryptor newEncryptor, _) = Build(newMount, store, newCache);

        // Witness: the envelope's own copy really is unusable on the new mount, so the success
        // below cannot come from that path.
        Func<Task> envelopeCopyDirectly = async () => await newMount.UnwrapAsync(envelope.WrappedDek);
        _ = await envelopeCopyDirectly.Should().ThrowAsync<InvalidOperationException>(
            "the new mount does not know the handle the old mount issued");

        byte[] decrypted = await newEncryptor.DecryptAsync(envelope, Scope);

        decrypted.Should().Equal(plaintext);
    }

    /// <summary>
    /// Case 2 of the plan, the correction infra made to the first design: the store returns a
    /// record, but a <b>wrong</b> one. It does not return "nothing" — it returns key material that
    /// fails the AES-GCM tag check. The envelope's own copy must still rescue the decrypt, or the
    /// reordering would turn a 0.3.x success into a 0.4.0 failure.
    /// </summary>
    /// <remarks>
    /// <b>Negative control.</b> Delete the <c>catch</c> around the store-first step in
    /// <c>PayloadEncryptor.DecryptAsync</c> (or narrow it so the AES-GCM
    /// <see cref="CryptographicException"/> escapes) and this test fails with that exception:
    /// the fallback never runs.
    /// </remarks>
    [Fact]
    public async Task Decrypt_StoreRecordWrongForThatKeyId_FallsBackToEnvelopeCopy()
    {
        FakeEncryptionKeyStore store = new();
        FakeKeyEncryptionProvider provider = new();
        byte[] plaintext = Encoding.UTF8.GetBytes("the store record for this key is a lie");

        EncryptedPayload envelope;
        using (VellumDekCache writeCache = new())
        {
            (PayloadEncryptor writer, _) = Build(provider, store, writeCache);
            envelope = await writer.EncryptAsync(plaintext, Scope);
        }

        // A record that unwraps cleanly to 32 valid bytes that are simply NOT this payload's DEK:
        // the failure surfaces at the AES-GCM tag check, not at the unwrap.
        byte[] unrelatedDek = new byte[32];
        RandomNumberGenerator.Fill(unrelatedDek);
        WrappedKey wrongRecord = await provider.WrapAsync(unrelatedDek);
        _ = await store.UpdateWrappedKeyAsync(envelope.KeyId, Scope, wrongRecord);

        using VellumDekCache readCache = new();
        (PayloadEncryptor reader, _) = Build(provider, store, readCache);

        long attemptsBefore = VellumDecryptMetrics.FallbackAttemptsTotal;
        long recoveredBefore = VellumDecryptMetrics.FallbackRecoveredTotal;
        long failedBefore = VellumDecryptMetrics.FallbackFailedTotal;

        byte[] decrypted = await reader.DecryptAsync(envelope, Scope);

        decrypted.Should().Equal(plaintext);
        VellumDecryptMetrics.FallbackAttemptsTotal.Should().Be(
            attemptsBefore + 1,
            "the store path was tried and failed, so the KEK provider was called twice for this decrypt");
        VellumDecryptMetrics.FallbackRecoveredTotal.Should().Be(
            recoveredBefore + 1,
            "a recovered fallback is the remaining-to-migrate signal");
        VellumDecryptMetrics.FallbackFailedTotal.Should().Be(
            failedBefore,
            "nothing genuinely failed");
    }

    /// <summary>
    /// Case 3 of the plan: when both paths fail, the raised error must name both attempts.
    /// </summary>
    /// <remarks>
    /// <b>Negative control.</b> Replace the aggregating <c>throw</c> in the second
    /// <c>catch</c> of <c>PayloadEncryptor.DecryptAsync</c> with a bare <c>throw;</c> and this test
    /// fails: the message names one path, the reader goes hunting down the wrong one.
    /// </remarks>
    [Fact]
    public async Task Decrypt_BothPathsFail_ErrorNamesBothAttempts()
    {
        FakeEncryptionKeyStore store = new();
        FakeKeyEncryptionProvider provider = new();

        EncryptedPayload envelope;
        using (VellumDekCache writeCache = new())
        {
            (PayloadEncryptor writer, _) = Build(provider, store, writeCache);
            envelope = await writer.EncryptAsync(Encoding.UTF8.GetBytes("unreachable either way"), Scope);
        }

        _ = await store.UpdateWrappedKeyAsync(
            envelope.KeyId,
            Scope,
            new WrappedKey(Ciphertext: "handle-the-provider-never-issued-store", ProviderVersion: "v1"));
        EncryptedPayload broken = envelope with
        {
            WrappedDek = new WrappedKey(Ciphertext: "handle-the-provider-never-issued-envelope", ProviderVersion: "v1"),
        };

        using VellumDekCache readCache = new();
        (PayloadEncryptor reader, _) = Build(provider, store, readCache);

        long failedBefore = VellumDecryptMetrics.FallbackFailedTotal;

        Func<Task> act = async () => await reader.DecryptAsync(broken, Scope);
        ExceptionAssertions<CryptographicException> thrown = await act.Should().ThrowAsync<CryptographicException>();

        CryptographicException error = thrown.Which;
        error.Message.Should().Contain("BOTH", "an operator must not read this as a single failed path");
        error.Message.Should().Contain("(1) Key store lookup by KeyId threw");
        error.Message.Should().Contain("(2) Fallback to the wrapped DEK carried by the envelope also threw");
        error.Message.Should().Contain("handle-the-provider-never-issued-store");
        error.Message.Should().Contain("handle-the-provider-never-issued-envelope");

        AggregateException? causes = error.InnerException as AggregateException;
        causes.Should().NotBeNull("both originals must survive for the stack traces");
        causes!.InnerExceptions.Should().HaveCount(2);

        VellumDecryptMetrics.FallbackFailedTotal.Should().Be(failedBefore + 1);
    }

    /// <summary>
    /// The store cannot be consulted without a (KeyId, scope) pair. A format version 1 envelope is
    /// explicitly allowed to be decrypted without a scope, and a hand-built envelope may carry an
    /// empty <see cref="EncryptedPayload.KeyId"/> — both go straight to the envelope copy, exactly
    /// as in 0.3.x, and are counted so they are not silently missing from the backlog gauge.
    /// </summary>
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task Decrypt_NoUsableLookupPair_SkipsStoreAndUsesEnvelopeCopy(bool emptyScope, bool emptyKeyId)
    {
        FakeEncryptionKeyStore store = new();
        FakeKeyEncryptionProvider provider = new();
        byte[] plaintext = Encoding.UTF8.GetBytes("legacy unbound envelope");

        // Format version 1: no scope binding, so decrypting with an empty scope is legal.
        CountingRandomBytesProvider random = new();
        VellumOptions options = new() { BindScopeToCiphertext = false };
        using VellumDekCache cache = new();
        DekManager manager = new(
            provider,
            store,
            cache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);
        PayloadEncryptor encryptor = new(
            manager,
            provider,
            random,
            Options.Create(options),
            NullLogger<PayloadEncryptor>.Instance);

        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        envelope.FormatVersion.Should().Be(EncryptedPayload.UnboundFormatVersion);

        EncryptedPayload presented = emptyKeyId ? envelope with { KeyId = Guid.Empty } : envelope;
        string presentedScope = emptyScope ? string.Empty : Scope;

        long skippedBefore = VellumDecryptMetrics.StoreLookupSkippedTotal;
        long attemptsBefore = VellumDecryptMetrics.FallbackAttemptsTotal;

        byte[] decrypted = await encryptor.DecryptAsync(presented, presentedScope);

        decrypted.Should().Equal(plaintext);
        VellumDecryptMetrics.StoreLookupSkippedTotal.Should().Be(skippedBefore + 1);
        VellumDecryptMetrics.FallbackAttemptsTotal.Should().Be(
            attemptsBefore,
            "a skipped lookup is not a fallback: no second KEK round-trip was paid");
    }

    /// <summary>
    /// The happy path after the reordering: nothing was migrated, the store record and the envelope
    /// copy agree, and the decrypt is served by the store without any fallback at all.
    /// </summary>
    [Fact]
    public async Task Decrypt_StoreAndEnvelopeAgree_ServedByStoreWithNoFallback()
    {
        FakeEncryptionKeyStore store = new();
        FakeKeyEncryptionProvider provider = new();
        byte[] plaintext = Encoding.UTF8.GetBytes("nothing to migrate here");

        using VellumDekCache cache = new();
        (PayloadEncryptor encryptor, _) = Build(provider, store, cache);
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        long attemptsBefore = VellumDecryptMetrics.FallbackAttemptsTotal;
        long skippedBefore = VellumDecryptMetrics.StoreLookupSkippedTotal;

        byte[] decrypted = await encryptor.DecryptAsync(envelope, Scope);

        decrypted.Should().Equal(plaintext);
        VellumDecryptMetrics.FallbackAttemptsTotal.Should().Be(attemptsBefore);
        VellumDecryptMetrics.StoreLookupSkippedTotal.Should().Be(skippedBefore);
    }

    /// <summary>
    /// Cancellation must not be mistaken for a store failure and swallowed into a fallback: the
    /// <see cref="OperationCanceledException"/> has to surface.
    /// </summary>
    [Fact]
    public async Task Decrypt_CancelledDuringStoreLookup_DoesNotFallBack()
    {
        FakeEncryptionKeyStore store = new();
        FakeKeyEncryptionProvider provider = new();

        // Cold read cache, so the decrypt really reaches the store — which is where the fake
        // observes the token.
        EncryptedPayload envelope;
        using (VellumDekCache writeCache = new())
        {
            (PayloadEncryptor writer, _) = Build(provider, store, writeCache);
            envelope = await writer.EncryptAsync(Encoding.UTF8.GetBytes("cancel me"), Scope);
        }

        using VellumDekCache readCache = new();
        (PayloadEncryptor encryptor, _) = Build(provider, store, readCache);

        using CancellationTokenSource cts = new();
        await cts.CancelAsync();

        long attemptsBefore = VellumDecryptMetrics.FallbackAttemptsTotal;

        Func<Task> act = async () => await encryptor.DecryptAsync(envelope, Scope, cts.Token);
        _ = await act.Should().ThrowAsync<OperationCanceledException>();

        VellumDecryptMetrics.FallbackAttemptsTotal.Should().Be(
            attemptsBefore,
            "a cancellation is not a store failure and must not buy a second KEK round-trip");
    }
}
