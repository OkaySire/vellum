namespace Vellum.Vault.Tests.Fakes;

/// <summary>
/// A scriptable <see cref="IVaultTokenProvider"/>: serves the current token until
/// <see cref="InvalidateToken"/> is called, then dequeues the next scripted token. Passing the
/// same token twice simulates a static-token provider (invalidation yields the same credential).
/// </summary>
public sealed class FakeVaultTokenProvider(params string[] tokens) : IVaultTokenProvider
{
    private readonly Queue<string> _tokens = new(tokens);
    private string? _current;

    public int GetTokenCallCount { get; private set; }

    public int InvalidateCount { get; private set; }

    public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        GetTokenCallCount++;
        _current ??= _tokens.Dequeue();
        return new ValueTask<string>(_current);
    }

    public void InvalidateToken()
    {
        InvalidateCount++;
        _current = null;
    }
}
