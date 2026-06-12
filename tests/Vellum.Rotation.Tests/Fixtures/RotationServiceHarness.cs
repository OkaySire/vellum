using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Rotation.Tests.Fakes;

namespace Vellum.Rotation.Tests.Fixtures;

/// <summary>
/// Builds a <see cref="DekRotationBackgroundService"/> wired to fake store/manager through a real
/// DI <see cref="IServiceScopeFactory"/>, mirroring the scoped resolution the worker performs in
/// production (one DI scope per tick).
/// </summary>
public sealed class RotationServiceHarness : IDisposable
{
    private ServiceProvider? _provider;

    public FakeEncryptionKeyStore Store { get; } = new();

    public FakeDekManager DekManager { get; } = new();

    public DekRotationBackgroundService CreateService(RotationOptions options, TimeProvider? timeProvider = null)
    {
        ServiceCollection services = new();
        services.AddScoped<IEncryptionKeyStore>(_ => Store);
        services.AddScoped<IDekManager>(_ => DekManager);
        _provider = services.BuildServiceProvider();

        return new DekRotationBackgroundService(
            _provider.GetRequiredService<IServiceScopeFactory>(),
            timeProvider ?? TimeProvider.System,
            Options.Create(options),
            NullLogger<DekRotationBackgroundService>.Instance);
    }

    /// <summary>
    /// Options tuned for deterministic single-tick tests: 1 ms retry base delay so retry
    /// backoff does not slow the suite down, everything else explicit per test.
    /// </summary>
    public static RotationOptions FastOptions(TimeSpan maxDekAge, int maxRetriesPerScope = 3) => new()
    {
        RotationInterval = TimeSpan.FromHours(24),
        MaxDekAge = maxDekAge,
        MaxRetriesPerScope = maxRetriesPerScope,
        RetryBaseDelay = TimeSpan.FromMilliseconds(1),
        StartupDelay = TimeSpan.Zero,
    };

    public void Dispose() => _provider?.Dispose();
}
