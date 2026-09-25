using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;

namespace Vellum;

/// <summary>
/// Process-wide observability for the two DEK resolution paths
/// <see cref="PayloadEncryptor.DecryptAsync"/> can take: the key store lookup by
/// <see cref="EncryptedPayload.KeyId"/> (tried first) and the fallback onto the wrapped DEK copy
/// carried by the envelope itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>Gauges, not counters — on purpose.</b> A <see cref="Counter{T}"/> that is never incremented
/// emits no time series at all, so "no fallback happened" and "the metric pipeline is broken" read
/// identically on a dashboard. Every instrument here is an <see cref="ObservableGauge{T}"/> over a
/// monotonically increasing process-local total, so a series exists — reporting <c>0</c> — from the
/// first collection onwards.
/// </para>
/// <para>
/// <b>What to alert on.</b>
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>vellum.decrypt.fallback.recovered</c> is the <i>remaining migration backlog</i> signal:
///     it rises for every row whose stored key record could not decrypt but whose envelope copy
///     could. It stops rising once every key record has been rewrapped against the KEK the process
///     can actually reach. It is expected to be non-zero <i>during</i> a KEK/mount migration and
///     flat afterwards.
///   </description></item>
///   <item><description>
///     <c>vellum.decrypt.fallback.failed</c> is a genuine outage signal: both paths were tried and
///     both failed. Any increase deserves a page.
///   </description></item>
///   <item><description>
///     <c>vellum.decrypt.fallback.attempts</c> is the <i>cost</i> signal. Each attempt means the
///     KEK provider (Vault, KMS, ...) was called <b>twice</b> for that decrypt: once for the store
///     record, once for the envelope copy. The DEK cache amortises this from the second read of the
///     same key onwards, but the doubling must be visible rather than guessed at.
///   </description></item>
///   <item><description>
///     <c>vellum.decrypt.store_lookup.skipped</c> counts decrypts where the store was not consulted
///     at all because the envelope carried no usable lookup pair — an empty
///     <see cref="EncryptedPayload.KeyId"/>, or an empty scope (legal for format version 1
///     envelopes). Those decrypts can never be served by the store, so they do not appear in the
///     backlog signal above; this gauge keeps them from being invisible.
///   </description></item>
/// </list>
/// <para>
/// <b>Static, not injected.</b> The instruments hang off a static <see cref="Meter"/> rather than an
/// <c>IMeterFactory</c> resolved from DI, so that turning the fallback path into an observable one
/// required no change to Vellum's registration surface. Subscribe with
/// <c>MeterListener</c>, or via OpenTelemetry's <c>AddMeter(VellumDecryptMetrics.MeterName)</c>.
/// </para>
/// <para>
/// The <c>Total</c> properties expose the same values synchronously, for tests and for consumers
/// that prefer to publish through their own metrics stack.
/// </para>
/// </remarks>
[SuppressMessage(
    "Performance",
    "CA1810:Initialize reference type static fields inline",
    Justification = "CreateObservableGauge is called for its registration side effect on the Meter; the returned ObservableGauge<long> instances are deliberately not stored in fields, which a field initializer would force. A static constructor is the only way to discard them.")]
public static class VellumDecryptMetrics
{
    /// <summary>
    /// The <see cref="Meter"/> name to subscribe to, for example via OpenTelemetry's
    /// <c>AddMeter</c>. Stable across versions.
    /// </summary>
    public const string MeterName = "Vellum.Core.Decrypt";

    /// <summary>
    /// Instrument name of the gauge reporting how many decrypts fell back from the key store to
    /// the envelope's own wrapped DEK copy. Each one cost an extra KEK provider round-trip.
    /// </summary>
    public const string FallbackAttemptsInstrumentName = "vellum.decrypt.fallback.attempts";

    /// <summary>
    /// Instrument name of the gauge reporting how many of those fallbacks then <b>succeeded</b> —
    /// the remaining-to-migrate signal, which goes flat when the migration is complete.
    /// </summary>
    public const string FallbackRecoveredInstrumentName = "vellum.decrypt.fallback.recovered";

    /// <summary>
    /// Instrument name of the gauge reporting how many decrypts failed after <b>both</b> paths
    /// were tried. A genuine outage signal.
    /// </summary>
    public const string FallbackFailedInstrumentName = "vellum.decrypt.fallback.failed";

    /// <summary>
    /// Instrument name of the gauge reporting how many decrypts never consulted the store because
    /// the envelope carried no usable (<see cref="EncryptedPayload.KeyId"/>, scope) lookup pair.
    /// </summary>
    public const string StoreLookupSkippedInstrumentName = "vellum.decrypt.store_lookup.skipped";

    private const string _decryptUnit = "{decrypt}";

    private static readonly Meter _meter = new(MeterName);

    private static long _fallbackAttempts;
    private static long _fallbackRecovered;
    private static long _fallbackFailed;
    private static long _storeLookupSkipped;

    static VellumDecryptMetrics()
    {
        _ = _meter.CreateObservableGauge(
            FallbackAttemptsInstrumentName,
            static () => Volatile.Read(ref _fallbackAttempts),
            unit: _decryptUnit,
            description: "Decrypts that fell back from the key store lookup to the wrapped DEK copy carried by the envelope. Each one cost a second KEK provider round-trip.");

        _ = _meter.CreateObservableGauge(
            FallbackRecoveredInstrumentName,
            static () => Volatile.Read(ref _fallbackRecovered),
            unit: _decryptUnit,
            description: "Fallbacks that succeeded: the key store record could not decrypt the payload but the envelope's own copy could. Rises while a KEK migration is outstanding, flat once it is done.");

        _ = _meter.CreateObservableGauge(
            FallbackFailedInstrumentName,
            static () => Volatile.Read(ref _fallbackFailed),
            unit: _decryptUnit,
            description: "Decrypts that failed after both the key store lookup and the envelope's wrapped DEK copy were tried. A genuine failure.");

        _ = _meter.CreateObservableGauge(
            StoreLookupSkippedInstrumentName,
            static () => Volatile.Read(ref _storeLookupSkipped),
            unit: _decryptUnit,
            description: "Decrypts where the key store was not consulted because the envelope carried no usable KeyId/scope pair.");
    }

    /// <summary>
    /// Running process-local total behind <see cref="FallbackAttemptsInstrumentName"/>.
    /// </summary>
    public static long FallbackAttemptsTotal => Volatile.Read(ref _fallbackAttempts);

    /// <summary>
    /// Running process-local total behind <see cref="FallbackRecoveredInstrumentName"/>.
    /// </summary>
    public static long FallbackRecoveredTotal => Volatile.Read(ref _fallbackRecovered);

    /// <summary>
    /// Running process-local total behind <see cref="FallbackFailedInstrumentName"/>.
    /// </summary>
    public static long FallbackFailedTotal => Volatile.Read(ref _fallbackFailed);

    /// <summary>
    /// Running process-local total behind <see cref="StoreLookupSkippedInstrumentName"/>.
    /// </summary>
    public static long StoreLookupSkippedTotal => Volatile.Read(ref _storeLookupSkipped);

    internal static void RecordFallbackAttempt() => _ = Interlocked.Increment(ref _fallbackAttempts);

    internal static void RecordFallbackRecovered() => _ = Interlocked.Increment(ref _fallbackRecovered);

    internal static void RecordFallbackFailed() => _ = Interlocked.Increment(ref _fallbackFailed);

    internal static void RecordStoreLookupSkipped() => _ = Interlocked.Increment(ref _storeLookupSkipped);
}
