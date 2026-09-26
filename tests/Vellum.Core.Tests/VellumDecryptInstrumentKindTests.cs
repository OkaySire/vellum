using System.Diagnostics.Metrics;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Tests.Fakes;
using Xunit;

namespace Vellum.Tests;

/// <summary>
/// 0.4.2 — <c>vellum.decrypt.total</c> must be a <see cref="Counter{T}"/>, and the four fallback
/// signals must stay <see cref="ObservableGauge{T}"/>s.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the instrument kind is worth a test of its own.</b> Until 0.4.2 the total was an
/// <see cref="ObservableGauge{T}"/> fed by <c>Interlocked.Increment</c> — a monotone gauge. Nothing
/// about that fails loudly: <c>rate()</c> over a gauge returns a number, just the wrong one, and a
/// gauge cannot express a counter reset, so a pod restart dropping the series back to 0 reads
/// exactly like traffic collapsing. The <c>.total</c> suffix is the one Prometheus reserves for
/// counters, so every reader will apply <c>rate()</c> to it. The kind of the instrument is the
/// contract here, not just an implementation detail, hence an assertion on the kind.
/// </para>
/// <para>
/// These tests do <b>not</b> need the pristine-process isolation that
/// <c>Vellum.Core.MeterRegistration.Tests</c> needs: they call
/// <see cref="VellumDecryptMetrics.EnsureInstrumentsPublished"/> themselves before starting the
/// listener, and <c>MeterListener.Start()</c> enumerates instruments that already exist, so the
/// result does not depend on whether some earlier test in this assembly already decrypted.
/// </para>
/// </remarks>
[Collection("PayloadDecryptMetrics")]
public sealed class VellumDecryptInstrumentKindTests
{
    private const string Scope = "tenant:42";

    private static List<Instrument> CollectVellumInstruments()
    {
        VellumDecryptMetrics.EnsureInstrumentsPublished();

        List<Instrument> collected = [];
        using MeterListener listener = new()
        {
            InstrumentPublished = (Instrument instrument, MeterListener _) =>
            {
                if (instrument.Meter.Name == VellumDecryptMetrics.MeterName)
                {
                    lock (collected)
                    {
                        collected.Add(instrument);
                    }
                }
            },
        };
        listener.Start();
        return collected;
    }

    /// <summary>
    /// The total is a counter. <b>Negative control:</b> revert it to
    /// <c>CreateObservableGauge(DecryptsInstrumentName, ...)</c> and this fails — the reported type
    /// becomes <c>ObservableGauge&lt;Int64&gt;</c>.
    /// </summary>
    [Fact]
    public void DecryptsTotal_IsACounter_NotAGauge()
    {
        Instrument total = CollectVellumInstruments()
            .Single((Instrument instrument) => instrument.Name == VellumDecryptMetrics.DecryptsInstrumentName);

        _ = total.Should().BeOfType<Counter<long>>(
            "vellum.decrypt.total is cumulative and carries the .total suffix Prometheus reserves "
                + "for counters, so readers will put rate() on it; a monotone gauge under rate() "
                + "returns a wrong number instead of an error, and cannot express a restart");
        total.IsObservable.Should().BeFalse("a Counter is pushed to, not polled");
    }

    /// <summary>
    /// The other four are unchanged: still observable gauges, so they report <c>0</c> from the first
    /// collection and their presence proves the meter is subscribed even before any fallback has
    /// happened. Changing them was explicitly out of scope for 0.4.2.
    /// </summary>
    [Theory]
    [InlineData(VellumDecryptMetrics.FallbackAttemptsInstrumentName)]
    [InlineData(VellumDecryptMetrics.FallbackRecoveredInstrumentName)]
    [InlineData(VellumDecryptMetrics.FallbackFailedInstrumentName)]
    [InlineData(VellumDecryptMetrics.StoreLookupSkippedInstrumentName)]
    public void FallbackSignals_RemainObservableGauges(string instrumentName)
    {
        Instrument instrument = CollectVellumInstruments()
            .Single((Instrument candidate) => candidate.Name == instrumentName);

        _ = instrument.Should().BeOfType<ObservableGauge<long>>(
            "a Counter at zero emits no series at all, so 'no fallback happened' would read the "
                + "same as 'the metric pipeline is broken'");
        instrument.IsObservable.Should().BeTrue();
    }

    /// <summary>
    /// The counter is actually fed: a decrypt pushes exactly one measurement of <c>1</c>. This is
    /// the half the kind assertion cannot cover — an instrument of the right type that nobody calls
    /// <c>Add</c> on would satisfy the test above and export a permanently absent series.
    /// </summary>
    [Fact]
    public async Task Decrypt_PushesExactlyOneMeasurementOnTheCounter()
    {
        VellumDecryptMetrics.EnsureInstrumentsPublished();

        List<long> measurements = [];
        using MeterListener listener = new()
        {
            InstrumentPublished = (Instrument instrument, MeterListener subscribed) =>
            {
                if (instrument.Meter.Name == VellumDecryptMetrics.MeterName
                    && instrument.Name == VellumDecryptMetrics.DecryptsInstrumentName)
                {
                    subscribed.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>(
            (Instrument _, long measurement, ReadOnlySpan<KeyValuePair<string, object?>> _, object? _) =>
            {
                lock (measurements)
                {
                    measurements.Add(measurement);
                }
            });
        listener.Start();

        FakeEncryptionKeyStore store = new();
        FakeKeyEncryptionProvider provider = new();
        CountingRandomBytesProvider random = new();
        VellumOptions options = new();
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

        byte[] plaintext = Encoding.UTF8.GetBytes("one decrypt, one increment");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        lock (measurements)
        {
            measurements.Clear();
        }

        byte[] decrypted = await encryptor.DecryptAsync(envelope, Scope);

        decrypted.Should().Equal(plaintext);
        measurements.Should().Equal(
            [1L],
            "one decrypt is one Add(1) on the counter — not zero (the counter is not wired) and not "
                + "two (the call walked both resolution paths and got double-counted)");
    }
}
