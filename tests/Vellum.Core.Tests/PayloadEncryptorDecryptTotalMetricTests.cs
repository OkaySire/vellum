using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Tests.Fakes;
using Xunit;

namespace Vellum.Tests;

/// <summary>
/// 0.4.1 — <see cref="VellumDecryptMetrics.DecryptsTotal"/> is the <b>denominator</b> the four
/// fallback gauges were missing: it counts every call to
/// <see cref="PayloadEncryptor.DecryptAsync"/>, whichever path that call takes and whether it
/// succeeds or throws. Without it, "the DEK cache warmed up" and "nobody is reading any more"
/// produce the same decreasing curve on the recovered-fallback gauge.
/// </summary>
/// <remarks>
/// The collection attribute serialises these tests against every other class in this assembly that
/// decrypts, because <see cref="VellumDecryptMetrics"/> is process-global: any concurrent decrypt
/// elsewhere would also move these totals and the delta assertions below would pick it up.
/// </remarks>
[Collection("PayloadDecryptMetrics")]
public sealed class PayloadEncryptorDecryptTotalMetricTests
{
    private const string Scope = "tenant:42";

    private static (PayloadEncryptor Encryptor, DekManager Manager) Build(
        FakeKeyEncryptionProvider provider,
        IEncryptionKeyStore store,
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
    /// Path 1 — served by the key store, no fallback. This is also <b>the control that matters</b>:
    /// the total must move while <see cref="VellumDecryptMetrics.FallbackAttemptsTotal"/> stays
    /// put. An implementation that incremented the total next to the fallback counters would
    /// satisfy every other test in this class and fail this one.
    /// </summary>
    /// <remarks>
    /// <b>Negative control.</b> Move the <c>RecordDecrypt()</c> call in
    /// <c>PayloadEncryptor.DecryptAsync</c> from the head of the method into the store-failure
    /// <c>catch</c> block (next to <c>RecordFallbackAttempt()</c>) and this test fails: the total
    /// stays at its previous value on a decrypt that never fell back.
    /// </remarks>
    [Fact]
    public async Task Decrypt_ServedByStore_IncrementsTotalWithoutTouchingFallbackGauges()
    {
        FakeEncryptionKeyStore store = new();
        FakeKeyEncryptionProvider provider = new();
        byte[] plaintext = Encoding.UTF8.GetBytes("no migration in flight");

        using VellumDekCache cache = new();
        (PayloadEncryptor encryptor, _) = Build(provider, store, cache);
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        long totalBefore = VellumDecryptMetrics.DecryptsTotal;
        long attemptsBefore = VellumDecryptMetrics.FallbackAttemptsTotal;
        long recoveredBefore = VellumDecryptMetrics.FallbackRecoveredTotal;
        long skippedBefore = VellumDecryptMetrics.StoreLookupSkippedTotal;

        byte[] decrypted = await encryptor.DecryptAsync(envelope, Scope);

        decrypted.Should().Equal(plaintext);
        VellumDecryptMetrics.DecryptsTotal.Should().Be(
            totalBefore + 1,
            "the denominator counts every decrypt, including the ones no fallback gauge ever sees");
        VellumDecryptMetrics.FallbackAttemptsTotal.Should().Be(
            attemptsBefore,
            "the total must DIVERGE from the fallback gauges, otherwise it is not a denominator");
        VellumDecryptMetrics.FallbackRecoveredTotal.Should().Be(recoveredBefore);
        VellumDecryptMetrics.StoreLookupSkippedTotal.Should().Be(skippedBefore);
    }

    /// <summary>
    /// Path 2 — the store record is stale and the envelope's own wrapped-DEK copy rescues the
    /// decrypt. One decrypt, one increment: the total must not double-count a call that walked
    /// both resolution paths.
    /// </summary>
    [Fact]
    public async Task Decrypt_RecoveredByEnvelopeCopy_IncrementsTotalExactlyOnce()
    {
        FakeEncryptionKeyStore store = new();
        FakeKeyEncryptionProvider provider = new();
        byte[] plaintext = Encoding.UTF8.GetBytes("the store record for this key is stale");

        EncryptedPayload envelope;
        using (VellumDekCache writeCache = new())
        {
            (PayloadEncryptor writer, _) = Build(provider, store, writeCache);
            envelope = await writer.EncryptAsync(plaintext, Scope);
        }

        // A record that unwraps to 32 valid bytes that are simply not this payload's DEK: the
        // failure surfaces at the AES-GCM tag check, so the store path is really attempted.
        byte[] unrelatedDek = new byte[32];
        RandomNumberGenerator.Fill(unrelatedDek);
        WrappedKey wrongRecord = await provider.WrapAsync(unrelatedDek);
        _ = await store.UpdateWrappedKeyAsync(envelope.KeyId, Scope, wrongRecord);

        using VellumDekCache readCache = new();
        (PayloadEncryptor reader, _) = Build(provider, store, readCache);

        long totalBefore = VellumDecryptMetrics.DecryptsTotal;
        long attemptsBefore = VellumDecryptMetrics.FallbackAttemptsTotal;
        long recoveredBefore = VellumDecryptMetrics.FallbackRecoveredTotal;

        byte[] decrypted = await reader.DecryptAsync(envelope, Scope);

        decrypted.Should().Equal(plaintext);
        VellumDecryptMetrics.DecryptsTotal.Should().Be(
            totalBefore + 1,
            "one call is one decrypt, even when it walked both resolution paths");
        VellumDecryptMetrics.FallbackAttemptsTotal.Should().Be(attemptsBefore + 1);
        VellumDecryptMetrics.FallbackRecoveredTotal.Should().Be(recoveredBefore + 1);
    }

    /// <summary>
    /// Path 3 — the one that gets forgotten: <b>both</b> paths failed and the call threw. If failed
    /// decrypts were left out of the denominator it would not cover the cases an operator cares
    /// about most.
    /// </summary>
    [Fact]
    public async Task Decrypt_BothPathsFail_StillIncrementsTotal()
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

        long totalBefore = VellumDecryptMetrics.DecryptsTotal;
        long failedBefore = VellumDecryptMetrics.FallbackFailedTotal;

        Func<Task> act = async () => await reader.DecryptAsync(broken, Scope);
        _ = await act.Should().ThrowAsync<CryptographicException>();

        VellumDecryptMetrics.DecryptsTotal.Should().Be(
            totalBefore + 1,
            "a decrypt that threw is still a decrypt, and it is the failure rate the denominator serves");
        VellumDecryptMetrics.FallbackFailedTotal.Should().Be(failedBefore + 1);
    }

    /// <summary>
    /// The early validation exits at the head of <c>DecryptAsync</c> — an unsupported format
    /// version, a missing scope on a version 2 envelope, a malformed nonce or ciphertext — return
    /// before any DEK resolution happens. They are still calls to <c>DecryptAsync</c>, and a
    /// denominator that missed them would understate the traffic exactly when a bad producer is
    /// flooding a consumer with envelopes it cannot read.
    /// </summary>
    /// <remarks>
    /// <b>Negative control.</b> Move the <c>RecordDecrypt()</c> call below the four validation
    /// guards in <c>PayloadEncryptor.DecryptAsync</c> and every case here fails.
    /// </remarks>
    [Theory]
    [InlineData("format")]
    [InlineData("scope")]
    [InlineData("nonce")]
    [InlineData("ciphertext")]
    public async Task Decrypt_RejectedByHeadValidation_StillIncrementsTotal(string invalidity)
    {
        FakeEncryptionKeyStore store = new();
        FakeKeyEncryptionProvider provider = new();

        using VellumDekCache cache = new();
        (PayloadEncryptor encryptor, _) = Build(provider, store, cache);
        EncryptedPayload envelope = await encryptor.EncryptAsync(Encoding.UTF8.GetBytes("rejected early"), Scope);

        EncryptedPayload presented = invalidity switch
        {
            "format" => envelope with { FormatVersion = 99 },
            "scope" => envelope,
            "nonce" => envelope with { Nonce = new byte[8] },
            "ciphertext" => envelope with { Ciphertext = new byte[4] },
            _ => throw new ArgumentOutOfRangeException(nameof(invalidity)),
        };
        string presentedScope = invalidity == "scope" ? string.Empty : Scope;

        long totalBefore = VellumDecryptMetrics.DecryptsTotal;
        long attemptsBefore = VellumDecryptMetrics.FallbackAttemptsTotal;
        long skippedBefore = VellumDecryptMetrics.StoreLookupSkippedTotal;

        Func<Task> act = async () => await encryptor.DecryptAsync(presented, presentedScope);
        _ = await act.Should().ThrowAsync<CryptographicException>();

        VellumDecryptMetrics.DecryptsTotal.Should().Be(
            totalBefore + 1,
            "an envelope rejected before any crypto work is still a decrypt call the denominator must cover");
        VellumDecryptMetrics.FallbackAttemptsTotal.Should().Be(attemptsBefore);
        VellumDecryptMetrics.StoreLookupSkippedTotal.Should().Be(skippedBefore);
    }
}
