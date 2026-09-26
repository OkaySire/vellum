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
/// <b>Gauges for the four fallback signals, a counter for the total.</b> The four fallback
/// instruments are <see cref="ObservableGauge{T}"/>s over a monotonically increasing process-local
/// total: a <see cref="Counter{T}"/> that is never incremented emits no time series at all, so
/// "no fallback happened" and "the metric pipeline is broken" would read identically on a
/// dashboard. Those four therefore report <c>0</c> from the first collection onwards, and their
/// mere presence is the proof that the meter is subscribed.
/// </para>
/// <para>
/// <c>vellum.decrypt.total</c> is the exception and is a real <see cref="Counter{T}"/>: it is a
/// cumulative count, the <c>.total</c> suffix is the one Prometheus reserves for counters, and any
/// reader — human or alerting rule — will put a <c>rate()</c> on it. A monotonic <i>gauge</i> under
/// a <c>rate()</c> does not raise an error, it returns a wrong number, and it cannot express a
/// counter reset: after a pod restart the series drops back to 0 and nothing distinguishes that
/// from traffic collapsing. Being a counter it stays silent until the first decrypt, which is
/// harmless precisely because the four gauges above are already reporting <c>0</c> and therefore
/// already prove the pipeline is alive.
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
///   <item><description>
///     <c>vellum.decrypt.total</c> is the <i>denominator</i>, and none of the four above should be
///     alerted on without it: a fallback gauge that stops rising reads the same whether the
///     migration is done or nobody is decrypting any more. See <see cref="DecryptsTotal"/>.
///   </description></item>
/// </list>
/// <para>
/// <b>Static, not injected.</b> The instruments hang off a static <see cref="Meter"/> rather than an
/// <c>IMeterFactory</c> resolved from DI, so that turning the fallback path into an observable one
/// required no change to Vellum's registration surface. Subscribe with
/// <c>MeterListener</c>, or via OpenTelemetry's <c>AddMeter(VellumDecryptMetrics.MeterName)</c>.
/// </para>
/// <para>
/// <b>Subscribing is not by itself enough to make the instruments exist</b> — see
/// <see cref="EnsureInstrumentsPublished"/>, which <c>AddVellum</c> calls for you. A host that does
/// not call <c>AddVellum</c> must call it itself, or it will see no Vellum series until the first
/// decrypt.
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

    /// <summary>
    /// Instrument name of the <see cref="Counter{T}"/> counting how many decrypts were attempted in
    /// total — the <b>denominator</b> for the four gauges above. A counter, not a gauge, because it
    /// is cumulative and is meant to be read through <c>rate()</c>.
    /// </summary>
    public const string DecryptsInstrumentName = "vellum.decrypt.total";

    private const string _decryptUnit = "{decrypt}";

    private static readonly Meter _meter = new(MeterName);

    /// <summary>
    /// The cumulative decrypt counter. Unlike the four observable gauges, a
    /// <see cref="Counter{T}"/> has to be kept in a field because it is pushed to rather than
    /// polled from — see <see cref="RecordDecrypt"/>.
    /// </summary>
    private static readonly Counter<long> _decryptCounter;

    private static long _fallbackAttempts;
    private static long _fallbackRecovered;
    private static long _fallbackFailed;
    private static long _storeLookupSkipped;
    private static long _decrypts;

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

        // A Counter, not an ObservableGauge: this one is cumulative and gets a rate() put on it.
        // See the class remarks for why the four instruments above stay gauges and this one cannot.
        _decryptCounter = _meter.CreateCounter<long>(
            DecryptsInstrumentName,
            unit: _decryptUnit,
            description: "Decrypt calls attempted, on every resolution path and including the ones that threw. The denominator the four fallback gauges are read against.");
    }

    /// <summary>
    /// Creates the <see cref="Meter"/> and publishes all five instruments, so that a collector
    /// subscribed to <see cref="MeterName"/> sees them <b>from process startup</b> rather than from
    /// the first decrypt. Idempotent, cheap, and safe to call from anywhere.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>DO NOT DELETE THIS METHOD OR ITS CALL SITE IN <c>AddVellum</c>. IT LOOKS LIKE DEAD CODE
    /// AND IT IS NOT.</b> It takes no argument, returns nothing and has no visible effect, so it
    /// reads exactly like something a tidy-up would remove. Removing it silently breaks
    /// observability, with no compiler error and no test failure anywhere except
    /// <c>Vellum.Core.MeterRegistration.Tests</c>, which exists for this single purpose.
    /// </para>
    /// <para>
    /// <b>Why it is needed at all.</b> The instruments are published by this type's class
    /// constructor, which the runtime only runs when something first <i>touches the type</i>. Until
    /// 0.4.2 nothing on the registration path ever did: <see cref="MeterName"/> is a
    /// <see langword="const"/>, so the recommended
    /// <c>AddMeter(VellumDecryptMetrics.MeterName)</c> is inlined by the compiler to the bare
    /// string <c>"Vellum.Core.Decrypt"</c> and never mentions the type in the emitted IL. The
    /// meter was therefore built on the <i>first decrypt</i>, and a freshly started process
    /// exported no Vellum series at all — leaving an operator unable to tell "wired up, nothing
    /// decrypted yet" from "not wired up".
    /// </para>
    /// <para>
    /// <b>Why not just make <see cref="MeterName"/> a <c>static readonly</c> field.</b> That would
    /// fix <c>AddMeter(VellumDecryptMetrics.MeterName)</c> and nothing else. Passing the name as a
    /// literal — <c>AddMeter("Vellum.Core.Decrypt")</c> — is an equally legitimate form, and the
    /// only one available to a host that does not reference this package; it would still not touch
    /// the type, and the defect would come back identically. An explicit call is the only form that
    /// does not depend on how the consumer spells the meter name.
    /// </para>
    /// </remarks>
    public static void EnsureInstrumentsPublished() =>
        // Reading a static field of this type is what forces the class constructor above to run,
        // and it has to be a *volatile* read so that neither Roslyn nor the JIT can elide it —
        // eliding the read would elide the initialisation, which is the entire point of the call.
        _ = Volatile.Read(ref _decrypts);

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

    /// <summary>
    /// Running process-local total behind <see cref="DecryptsInstrumentName"/>: every call to
    /// <see cref="PayloadEncryptor.DecryptAsync"/>, whichever resolution path it took — store,
    /// fallback, or skipped lookup — and <b>including the calls that threw</b>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What it is for: it is the denominator, and the other four gauges do not mean anything
    /// without it.</b> During a KEK migration,
    /// <see cref="FallbackRecoveredTotal"/> is expected to stop rising as the store records get
    /// rewrapped and the DEK cache warms up. But a gauge that stops rising has two causes that look
    /// identical on a dashboard: <i>the migration worked</i>, and <i>nothing is decrypting any
    /// more</i> (the consumer was scaled to zero, the queue drained, a deployment broke the read
    /// path). Read against this total, the two separate immediately: a flat recovered gauge over a
    /// <b>rising</b> total is a finished migration; a flat recovered gauge over a <b>flat</b> total
    /// is silence, and proves nothing at all. An operator who reads the fallback gauges alone reads
    /// a silence as a success.
    /// </para>
    /// <para>
    /// It also turns the other three into rates rather than raw magnitudes:
    /// <c>fallback.attempts / total</c> is the fraction of decrypts paying double KEK traffic,
    /// <c>fallback.failed / total</c> is the decrypt failure rate, and
    /// <c>store_lookup.skipped / total</c> is the share of envelopes the store can never serve.
    /// A count of 50 failures means nothing until it is known whether the process served 60 decrypts
    /// or 6 million.
    /// </para>
    /// <para>
    /// Failed calls are counted on purpose: leaving them out would make the denominator exclude
    /// precisely the population the failure signal is about, and <c>failed / total</c> could then
    /// never exceed the success rate.
    /// </para>
    /// </remarks>
    public static long DecryptsTotal => Volatile.Read(ref _decrypts);

    internal static void RecordFallbackAttempt() => _ = Interlocked.Increment(ref _fallbackAttempts);

    internal static void RecordFallbackRecovered() => _ = Interlocked.Increment(ref _fallbackRecovered);

    internal static void RecordFallbackFailed() => _ = Interlocked.Increment(ref _fallbackFailed);

    internal static void RecordStoreLookupSkipped() => _ = Interlocked.Increment(ref _storeLookupSkipped);

    /// <summary>
    /// Counts one decrypt attempt, on both instruments that report it: the exported
    /// <see cref="Counter{T}"/> and the process-local total behind <see cref="DecryptsTotal"/>.
    /// </summary>
    /// <remarks>
    /// Two instruments over one internal counter is the pattern already used by the four gauges: a
    /// <see cref="Counter{T}"/> cannot be read back, and <see cref="DecryptsTotal"/> has to stay
    /// readable for tests and for consumers publishing through their own metrics stack.
    /// </remarks>
    internal static void RecordDecrypt()
    {
        _ = Interlocked.Increment(ref _decrypts);
        _decryptCounter.Add(1);
    }
}
