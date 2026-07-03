namespace Vellum.Rotation.Tests.Fakes;

/// <summary>
/// Recording <see cref="IDekManager"/> for rotation-worker tests. Only
/// <see cref="RotateDekAsync"/> is functional: it records every attempt per scope and can be
/// programmed to fail a number of times before succeeding (or to always fail). All other members
/// throw <see cref="NotSupportedException"/> so any unexpected usage fails the test loudly.
/// </summary>
public sealed class FakeDekManager : IDekManager
{
    private readonly object _gate = new();
    private readonly List<string> _rotateAttempts = [];
    private readonly Dictionary<string, int> _remainingFailures = new(StringComparer.Ordinal);
    private readonly HashSet<string> _alwaysFailScopes = new(StringComparer.Ordinal);
    private readonly TaskCompletionSource _firstSuccessfulRotation = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Every <see cref="RotateDekAsync"/> attempt, in call order (one entry per attempt, retries included).</summary>
    public IReadOnlyList<string> RotateAttempts
    {
        get
        {
            lock (_gate)
            {
                return [.. _rotateAttempts];
            }
        }
    }

    /// <summary>Completes when the first <see cref="RotateDekAsync"/> call succeeds.</summary>
    public Task FirstSuccessfulRotation => _firstSuccessfulRotation.Task;

    /// <summary>Programs the next <paramref name="failures"/> attempts for <paramref name="scope"/> to throw before succeeding.</summary>
    public void FailTimes(string scope, int failures)
    {
        lock (_gate)
        {
            _remainingFailures[scope] = failures;
        }
    }

    /// <summary>Programs every attempt for <paramref name="scope"/> to throw.</summary>
    public void AlwaysFail(string scope)
    {
        lock (_gate)
        {
            _ = _alwaysFailScopes.Add(scope);
        }
    }

    public Task RotateDekAsync(string scope, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _rotateAttempts.Add(scope);

            if (_alwaysFailScopes.Contains(scope))
            {
                throw new InvalidOperationException($"Injected permanent rotation failure for scope '{scope}'.");
            }

            if (_remainingFailures.TryGetValue(scope, out int remaining) && remaining > 0)
            {
                _remainingFailures[scope] = remaining - 1;
                throw new InvalidOperationException($"Injected transient rotation failure for scope '{scope}' ({remaining} remaining).");
            }

            _ = _firstSuccessfulRotation.TrySetResult();
            return Task.CompletedTask;
        }
    }

    public ValueTask<Dek> GetActiveDekAsync(string scope, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The rotation worker must not call GetActiveDekAsync.");

    public Task<Dek> CreateDekAsync(string scope, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The rotation worker must not call CreateDekAsync.");

    public ValueTask<Dek> GetDekByKeyIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The rotation worker must not call GetDekByKeyIdAsync.");

    public ValueTask<Dek> GetDekByWrappedKeyAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The rotation worker must not call GetDekByWrappedKeyAsync.");
}
