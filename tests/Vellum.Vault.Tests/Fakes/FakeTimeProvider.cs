namespace Vellum.Vault.Tests.Fakes;

/// <summary>
/// A deterministic <see cref="TimeProvider"/> whose clock only moves when the test calls
/// <see cref="Advance"/>. Hand-rolled (only <see cref="GetUtcNow"/> is needed by the code
/// under test) to avoid pulling the Microsoft.Extensions.TimeProvider.Testing package into
/// the test project.
/// </summary>
public sealed class FakeTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _utcNow = start;

    public FakeTimeProvider()
        : this(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero))
    {
    }

    public override DateTimeOffset GetUtcNow() => _utcNow;

    /// <summary>Moves the clock forward by <paramref name="delta"/>.</summary>
    public void Advance(TimeSpan delta) => _utcNow += delta;
}
