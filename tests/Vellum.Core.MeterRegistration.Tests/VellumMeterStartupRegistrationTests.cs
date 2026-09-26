using System.Diagnostics.Metrics;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Vellum.Tests.MeterRegistration;

/// <summary>
/// 0.4.2 — the Vellum decrypt <see cref="Meter"/> and its instruments must exist as soon as
/// <see cref="VellumServiceCollectionExtensions.AddVellum"/> has run, <b>before the first
/// decrypt</b>.
/// </summary>
/// <remarks>
/// <para>
/// <b>The defect this guards against.</b> <c>VellumDecryptMetrics.MeterName</c> is a
/// <see langword="const"/>, so <c>AddMeter(VellumDecryptMetrics.MeterName)</c> is inlined to the
/// bare string <c>"Vellum.Core.Decrypt"</c> at compile time and never touches the type. Nothing
/// else on the registration path touched it either, so the class constructor — which creates the
/// <see cref="Meter"/> and publishes the instruments — did not run until the <i>first decrypt</i>.
/// A freshly started process exported no Vellum series at all, and an operator could not tell
/// "wired up, nothing decrypted yet" from "the metrics are not wired up".
/// </para>
/// <para>
/// <b>Why this test lives alone in its own assembly.</b> See the comment in the
/// <c>.csproj</c>: a static class initialises at most once per process, so sharing a process with
/// anything that touches <c>VellumDecryptMetrics</c> would make this test pass without the fix.
/// Its isolation is not decoration — it is the only thing that makes a green result mean anything.
/// </para>
/// </remarks>
public sealed class VellumMeterStartupRegistrationTests
{
    /// <summary>
    /// <b>Negative control (this is what proves the test).</b> Remove the
    /// <c>VellumDecryptMetrics.EnsureInstrumentsPublished()</c> call from <c>AddVellum</c> and this
    /// test fails with an empty published-instrument list — because nothing else on the
    /// registration path touches the metrics type. If it stays green after that removal, the
    /// isolation described above has been broken and the test is worthless.
    /// </summary>
    [Fact]
    public void AddVellum_PublishesEveryDecryptInstrument_BeforeAnyDecryptHasHappened()
    {
        List<Instrument> published = [];

        // Subscribe FIRST, on a process where nothing has touched VellumDecryptMetrics yet: the
        // instruments therefore cannot already exist, and every name collected below can only have
        // arrived through the AddVellum() call that follows.
        using MeterListener listener = new()
        {
            InstrumentPublished = (Instrument instrument, MeterListener _) =>
            {
                if (instrument.Meter.Name == VellumDecryptMetrics.MeterName)
                {
                    lock (published)
                    {
                        published.Add(instrument);
                    }
                }
            },
        };
        listener.Start();

        ServiceCollection services = new();
        _ = services.AddVellum();

        // No decrypt anywhere in this test, and no ServiceProvider built: registration alone must
        // be enough.
        List<string> names = [.. published.Select(static (Instrument instrument) => instrument.Name).Order()];

        names.Should().BeEquivalentTo(
            [
                VellumDecryptMetrics.DecryptsInstrumentName,
                VellumDecryptMetrics.FallbackAttemptsInstrumentName,
                VellumDecryptMetrics.FallbackFailedInstrumentName,
                VellumDecryptMetrics.FallbackRecoveredInstrumentName,
                VellumDecryptMetrics.StoreLookupSkippedInstrumentName,
            ],
            "AddVellum() must build the Meter and publish all five instruments at startup, so a "
                + "collector that subscribed to the meter sees the series from its first scrape "
                + "instead of from the first decrypt");
    }
}
