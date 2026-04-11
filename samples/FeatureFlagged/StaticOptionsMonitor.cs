using Microsoft.Extensions.Options;

namespace Vellum.Samples.FeatureFlagged;

/// <summary>
/// Minimal <see cref="IOptionsMonitor{T}"/> that returns a single snapshot and never fires
/// change notifications. Used in the feature-flag sample so we don't have to spin up the
/// full options infrastructure just to demonstrate the decorator pattern.
/// </summary>
/// <remarks>
/// A production app would use the real <see cref="IOptionsMonitor{T}"/> wired via
/// <c>services.Configure&lt;FeatureFlags&gt;(...)</c>, which hot-reloads when
/// <c>appsettings.json</c> changes on disk or a remote flag store pushes an update.
/// </remarks>
internal sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
{
    public T CurrentValue { get; } = value;

    public T Get(string? name) => CurrentValue;

    public IDisposable? OnChange(Action<T, string?> listener) => null;
}
