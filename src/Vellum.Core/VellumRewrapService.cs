using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;

namespace Vellum;

/// <summary>
/// Orchestrates the rewrap of a scope's stored wrapped DEKs after a KEK rotation: every key
/// (active and historical) is re-encrypted under the KEK provider's current key version via
/// <see cref="IKeyEncryptionProvider.RewrapAsync(WrappedKey, CancellationToken)"/> and persisted
/// via <see cref="IEncryptionKeyStore.UpdateWrappedKeyAsync(Guid, string, WrappedKey, CancellationToken)"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>When to use.</b> Rewrapping stored keys is step 2 of the safe
/// <c>min_decryption_version</c> procedure (see <c>docs/kek-rotation.md</c>): after rotating the
/// KEK, sweep every scope with this service, then rewrap persisted envelopes via
/// <see cref="IPayloadEncryptor.RewrapPayloadAsync(EncryptedPayload, CancellationToken)"/>, and
/// only then retire old KEK versions.
/// </para>
/// <para>
/// <b>Plaintext confinement.</b> The plaintext DEKs are never unwrapped here — the rewrap happens
/// inside the KEK provider (entirely inside the backend for providers with a native rewrap
/// operation, such as Vault Transit).
/// </para>
/// <para>
/// <b>Partial failure.</b> One key failing never aborts the sweep: the failure is logged as an
/// error, recorded in <see cref="RewrapScopeResult.FailedKeyIds"/>, and the sweep continues with
/// the next key. The method does <b>not</b> throw on partial failure because the sweep must be
/// resumable — rewrap is idempotent (rewrapping an already-current wrapped key is a version-level
/// no-op), so the caller simply re-runs the sweep until <see cref="RewrapScopeResult.Failed"/> is
/// zero. Callers <b>must</b> inspect the result before treating an old KEK version as retired.
/// </para>
/// <para>
/// <b>Lifetime.</b> Registered as scoped by <c>AddVellum</c> for the same reason as
/// <see cref="DekManager"/>: it depends on <see cref="IEncryptionKeyStore"/>, whose EF Core-backed
/// implementations depend on a scoped <c>DbContext</c> that must not be captured by a singleton.
/// </para>
/// </remarks>
public sealed partial class VellumRewrapService(
    IKeyEncryptionProvider keyProvider,
    IEncryptionKeyStore store,
    ILogger<VellumRewrapService> logger)
{
    private readonly IKeyEncryptionProvider _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
    private readonly IEncryptionKeyStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly ILogger<VellumRewrapService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    /// <summary>
    /// Rewraps every stored key (active and historical) for <paramref name="scope"/> under the
    /// KEK provider's current key version and persists the refreshed material.
    /// </summary>
    /// <param name="scope">Opaque scope identifier whose keys should be rewrapped.</param>
    /// <param name="cancellationToken">Cancellation token. Cancellation aborts the sweep with <see cref="OperationCanceledException"/>.</param>
    /// <returns>A <see cref="RewrapScopeResult"/> with per-scope counts and the ids of any keys that failed.</returns>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Deliberate per-key failure isolation: one key failing its rewrap must never abort the sweep of the remaining keys. The exception is logged as an error with full detail and the key id is surfaced in RewrapScopeResult.FailedKeyIds; cancellation is re-thrown by the preceding filter.")]
    public async Task<RewrapScopeResult> RewrapStoredKeysAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        // GetHistoricalAsync is contractually "all keys (active and historical)", so it should
        // already include the active key. The explicit GetActiveAsync union is defense-in-depth
        // against third-party store implementations that read "historical" as "inactive only" —
        // missing the ACTIVE key in a rewrap sweep would be the worst possible omission, since it
        // is the key every new encryption depends on.
        IReadOnlyList<EncryptionKey> historical = await _store.GetHistoricalAsync(scope, cancellationToken).ConfigureAwait(false);
        EncryptionKey? active = await _store.GetActiveAsync(scope, cancellationToken).ConfigureAwait(false);

        List<EncryptionKey> targets = new(historical.Count + 1);
        HashSet<Guid> seenKeyIds = new();
        foreach (EncryptionKey key in historical)
        {
            if (seenKeyIds.Add(key.KeyId))
            {
                targets.Add(key);
            }
        }

        if (active is not null && seenKeyIds.Add(active.KeyId))
        {
            targets.Add(active);
        }

        LogSweepStarted(_logger, scope, targets.Count);

        int rewrapped = 0;
        List<Guid> failedKeyIds = [];

        foreach (EncryptionKey key in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                WrappedKey refreshed = await _keyProvider.RewrapAsync(key.WrappedKey, cancellationToken).ConfigureAwait(false);
                _ = await _store.UpdateWrappedKeyAsync(key.KeyId, scope, refreshed, cancellationToken).ConfigureAwait(false);
                rewrapped++;
                LogKeyRewrapped(_logger, key.KeyId, scope, key.WrappedKey.ProviderVersion, refreshed.ProviderVersion);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                failedKeyIds.Add(key.KeyId);
                LogKeyRewrapFailed(_logger, key.KeyId, scope, ex);
            }
        }

        RewrapScopeResult result = new(
            Total: targets.Count,
            Rewrapped: rewrapped,
            Failed: failedKeyIds.Count,
            FailedKeyIds: failedKeyIds);

        LogSweepCompleted(_logger, scope, result.Total, result.Rewrapped, result.Failed);
        return result;
    }

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Information,
        Message = "Rewrap sweep started for scope {Scope}: {KeyCount} stored key(s) to rewrap.")]
    private static partial void LogSweepStarted(ILogger logger, string scope, int keyCount);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Debug,
        Message = "Rewrapped stored key {KeyId} for scope {Scope} (provider version {OldProviderVersion} -> {NewProviderVersion}).")]
    private static partial void LogKeyRewrapped(ILogger logger, Guid keyId, string scope, string oldProviderVersion, string newProviderVersion);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Error,
        Message = "Failed to rewrap stored key {KeyId} for scope {Scope}; the sweep continues with the remaining keys. Re-run the sweep until Failed is 0 before retiring old KEK versions.")]
    private static partial void LogKeyRewrapFailed(ILogger logger, Guid keyId, string scope, Exception exception);

    [LoggerMessage(
        EventId = 4,
        Level = LogLevel.Information,
        Message = "Rewrap sweep completed for scope {Scope}: {Total} key(s), {Rewrapped} rewrapped, {Failed} failed.")]
    private static partial void LogSweepCompleted(ILogger logger, string scope, int total, int rewrapped, int failed);
}
