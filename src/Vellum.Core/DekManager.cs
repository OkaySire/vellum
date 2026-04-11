using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Vellum;

/// <summary>
/// Default <see cref="IDekManager"/> implementation: caches unwrapped Data Encryption Keys in
/// <see cref="IMemoryCache"/>, coordinates <see cref="IKeyEncryptionProvider"/> and
/// <see cref="IEncryptionKeyStore"/>, and handles race conditions on DEK creation.
/// </summary>
/// <remarks>
/// <para>
/// <b>Cache hot path.</b> <see cref="GetActiveDekAsync"/> and <see cref="GetDekByKeyIdAsync"/>
/// return a completed <see cref="ValueTask{TResult}"/> on cache hit, avoiding state-machine
/// allocation. On cache miss they fall through to a private async slow path.
/// </para>
/// <para>
/// <b>Clone before return.</b> The cache stores a <see cref="Dek"/> with the unwrapped key bytes,
/// but every public return path returns a clone (fresh <see cref="Dek.Key"/> byte array). Callers
/// are free to <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> their copy without
/// corrupting the cache. See <c>tasks/lessons.md</c> L3.
/// </para>
/// <para>
/// <b>Race-safe creation (L2).</b> <see cref="CreateDekAsync"/> applies a four-layer defense:
/// (1) double-check via <see cref="IEncryptionKeyStore.GetActiveAsync"/> before attempting
/// insertion, (2) delegate insertion to the store which handles unique-index conflicts and
/// returns the winner, (3) detect whether we won the race by comparing key ids, and
/// (4) on a post-wrap race loss, unwrap the winner's <see cref="WrappedKey"/> and cache that
/// instead. The plaintext of the losing DEK is zeroed out.
/// </para>
/// <para>
/// <b>Multi-tenant defense.</b> Keys cached by <see cref="Guid"/> are partitioned by scope in the
/// cache key so that a cross-scope lookup of the same <see cref="Guid"/> cannot return a cached
/// entry from a different tenant. The persisted scope is also re-verified on the slow path.
/// </para>
/// </remarks>
public sealed partial class DekManager(
    IKeyEncryptionProvider keyProvider,
    IEncryptionKeyStore store,
    IMemoryCache cache,
    IRandomBytesProvider randomBytes,
    TimeProvider timeProvider,
    IOptions<VellumOptions> options,
    ILogger<DekManager> logger) : IDekManager
{
    private const int DekSizeBytes = 32;

    private readonly IKeyEncryptionProvider _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
    private readonly IEncryptionKeyStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly IMemoryCache _cache = cache ?? throw new ArgumentNullException(nameof(cache));
    private readonly IRandomBytesProvider _randomBytes = randomBytes ?? throw new ArgumentNullException(nameof(randomBytes));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly VellumOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    private readonly ILogger<DekManager> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    /// <inheritdoc />
    public ValueTask<Dek> GetActiveDekAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (_cache.TryGetValue(BuildActiveCacheKey(scope), out Dek? cached) && cached is not null)
        {
            LogDekCacheHit(_logger, scope);
            return new ValueTask<Dek>(CloneDek(cached));
        }

        return new ValueTask<Dek>(GetActiveDekSlowAsync(scope, cancellationToken));
    }

    /// <inheritdoc />
    public async Task<Dek> CreateDekAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        // Layer 1 of L2 four-layer race defense: double-check before generating.
        EncryptionKey? winner = await _store.GetActiveAsync(scope, cancellationToken).ConfigureAwait(false);
        if (winner is not null)
        {
            LogDekRaceConditionHandled(_logger, scope);
            return await LoadAndCacheAsync(winner, cancellationToken).ConfigureAwait(false);
        }

        byte[] newDekBytes = new byte[DekSizeBytes];
        _randomBytes.Fill(newDekBytes);

        WrappedKey wrappedDek;
        try
        {
            wrappedDek = await _keyProvider.WrapAsync(newDekBytes, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(newDekBytes);
            throw;
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        EncryptionKey candidate = new(
            KeyId: Guid.NewGuid(),
            Scope: scope,
            WrappedKey: wrappedDek,
            CreatedAt: now,
            ExpiresAt: null,
            IsActive: true);

        EncryptionKey persisted;
        try
        {
            // Layers 2-4 of L2: the store is responsible for handling unique-index
            // violations, detaching the failed entity, and returning the winner.
            persisted = await _store.CreateAsync(candidate, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(newDekBytes);
            throw;
        }

        Dek active;
        if (persisted.KeyId == candidate.KeyId)
        {
            // We won the race.
            active = new Dek(newDekBytes, persisted.KeyId, persisted.WrappedKey);
            LogDekCreated(_logger, scope, persisted.KeyId, persisted.WrappedKey.ProviderVersion);
        }
        else
        {
            // The store returned a different key — another process won the race after we wrapped.
            // Zero our losing copy and unwrap the winner instead.
            CryptographicOperations.ZeroMemory(newDekBytes);
            LogDekRaceConditionHandled(_logger, scope);
            byte[] winnerBytes = await _keyProvider.UnwrapAsync(persisted.WrappedKey, cancellationToken).ConfigureAwait(false);
            active = new Dek(winnerBytes, persisted.KeyId, persisted.WrappedKey);
        }

        CacheActiveDek(scope, active);
        return CloneDek(active);
    }

    /// <inheritdoc />
    public async Task RotateDekAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        await _store.DeactivateAllAsync(scope, cancellationToken).ConfigureAwait(false);
        _cache.Remove(BuildActiveCacheKey(scope));

        _ = await CreateDekAsync(scope, cancellationToken).ConfigureAwait(false);
        LogDekRotated(_logger, scope);
    }

    /// <inheritdoc />
    public ValueTask<Dek> GetDekByWrappedKeyAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);

        string cacheKey = BuildWrappedCacheKey(wrappedKey);
        if (_cache.TryGetValue(cacheKey, out Dek? cached) && cached is not null)
        {
            LogDekWrappedCacheHit(_logger);
            return new ValueTask<Dek>(CloneDek(cached));
        }

        return new ValueTask<Dek>(GetDekByWrappedKeySlowAsync(wrappedKey, cacheKey, cancellationToken));
    }

    /// <inheritdoc />
    public ValueTask<Dek> GetDekByKeyIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        string cacheKey = BuildKeyIdCacheKey(keyId, scope);
        if (_cache.TryGetValue(cacheKey, out Dek? cached) && cached is not null)
        {
            // L-3: belt-and-braces re-verification on the fast path. The cache key is already
            // scope-partitioned (see L15) AND includes the keyId, so a mismatch here should
            // be impossible — but if some future refactor ever broke the key-building invariant,
            // we prefer to fail-closed instead of returning a cached DEK for a different KeyId.
            if (cached.KeyId != keyId)
            {
                LogDekCacheKeyIdMismatch(_logger, keyId, scope, cached.KeyId);
                throw new InvalidOperationException(
                    $"Cached DEK KeyId ({cached.KeyId}) does not match the requested KeyId ({keyId}) for scope '{scope}'. This is a Vellum bug — please file an issue with the log output.");
            }

            return new ValueTask<Dek>(CloneDek(cached));
        }

        return new ValueTask<Dek>(GetDekByKeyIdSlowAsync(keyId, scope, cancellationToken));
    }

    private async Task<Dek> GetActiveDekSlowAsync(string scope, CancellationToken cancellationToken)
    {
        EncryptionKey? active = await _store.GetActiveAsync(scope, cancellationToken).ConfigureAwait(false);

        if (active is null)
        {
            LogNoDekFound(_logger, scope);
            return await CreateDekAsync(scope, cancellationToken).ConfigureAwait(false);
        }

        return await LoadAndCacheAsync(active, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Dek> GetDekByWrappedKeySlowAsync(
        WrappedKey wrappedKey,
        string cacheKey,
        CancellationToken cancellationToken)
    {
        // Issue #6: unwrap once, cache by a SHA-256 hash of the wrapped ciphertext so the
        // next decrypt that carries the same envelope WrappedKey hits the cache instead of
        // round-tripping to the KEK provider (Vault / KMS / ...). The wrapped ciphertext
        // itself is the tenant-specific secret material, so no additional scope partitioning
        // is needed — see tasks/lessons.md L24.
        byte[] dekBytes = await _keyProvider.UnwrapAsync(wrappedKey, cancellationToken).ConfigureAwait(false);
        EnsureDekLength(dekBytes);

        // KeyId on an envelope-unwrap is informational for diagnostics only — we synthesise
        // an empty Guid here because the wrapped-key cache path does not go through the
        // store and does not know the persisted KeyId. Callers that need the KeyId read it
        // off EncryptedPayload directly.
        Dek dek = new(dekBytes, Guid.Empty, wrappedKey);

        CacheByWrappedKey(cacheKey, dek);
        LogDekWrappedLoadedAndCached(_logger);
        return CloneDek(dek);
    }

    private async Task<Dek> GetDekByKeyIdSlowAsync(Guid keyId, string scope, CancellationToken cancellationToken)
    {
        EncryptionKey? persisted = await _store.GetByIdAsync(keyId, scope, cancellationToken).ConfigureAwait(false);
        if (persisted is null)
        {
            // M-5: distinct EventId for "not found" so SIEM rules can distinguish a genuine
            // misconfiguration from a cross-tenant lookup attempt.
            LogDekNotFound(_logger, keyId, scope);
            throw new InvalidOperationException($"Encryption key {keyId} not found for scope '{scope}'.");
        }

        // Defense-in-depth: the store MUST already enforce scope match, but double-check here
        // so that a buggy store implementation cannot leak cross-tenant keys through Vellum.
        if (!string.Equals(persisted.Scope, scope, StringComparison.Ordinal))
        {
            // M-5: distinct EventId for "cross-scope attempt" — this is a security event
            // that should be alertable independently of the "not found" case.
            LogDekScopeMismatch(_logger, keyId, scope, persisted.Scope);
            throw new InvalidOperationException($"Encryption key {keyId} does not belong to scope '{scope}'.");
        }

        byte[] dekBytes = await _keyProvider.UnwrapAsync(persisted.WrappedKey, cancellationToken).ConfigureAwait(false);
        EnsureDekLength(dekBytes);
        Dek dek = new(dekBytes, persisted.KeyId, persisted.WrappedKey);

        CacheByKeyId(scope, dek);
        LogDekLoadedFromStore(_logger, scope);
        return CloneDek(dek);
    }

    private async Task<Dek> LoadAndCacheAsync(EncryptionKey persisted, CancellationToken cancellationToken)
    {
        byte[] dekBytes = await _keyProvider.UnwrapAsync(persisted.WrappedKey, cancellationToken).ConfigureAwait(false);
        EnsureDekLength(dekBytes);
        Dek dek = new(dekBytes, persisted.KeyId, persisted.WrappedKey);

        CacheActiveDek(persisted.Scope, dek);
        LogDekLoadedFromStore(_logger, persisted.Scope);
        return CloneDek(dek);
    }

    /// <summary>
    /// H-1: enforces the AES-256 DEK length contract on every unwrap path. <see cref="AesGcm"/>
    /// accepts 16/24/32-byte keys; silently accepting a shorter key would downgrade the cipher
    /// strength. Buggy or compromised KEK providers must be rejected here to preserve the
    /// symmetry with <see cref="DekSizeBytes"/> enforcement on the generate path.
    /// </summary>
    private static void EnsureDekLength(byte[] dekBytes)
    {
        if (dekBytes.Length != DekSizeBytes)
        {
            int actualLength = dekBytes.Length;
            CryptographicOperations.ZeroMemory(dekBytes);
            throw new CryptographicException(
                $"Unwrapped DEK has invalid length: expected {DekSizeBytes} bytes (AES-256), got {actualLength}.");
        }
    }

    private void CacheActiveDek(string scope, Dek dek)
    {
        if (_options.DekCacheTtl <= TimeSpan.Zero)
        {
            return;
        }

        MemoryCacheEntryOptions entryOptions = new()
        {
            AbsoluteExpirationRelativeToNow = _options.DekCacheTtl,
        };
        _cache.Set(BuildActiveCacheKey(scope), dek, entryOptions);
        _cache.Set(BuildKeyIdCacheKey(dek.KeyId, scope), dek, entryOptions);
    }

    private void CacheByWrappedKey(string cacheKey, Dek dek)
    {
        if (_options.DekCacheTtl <= TimeSpan.Zero)
        {
            return;
        }

        MemoryCacheEntryOptions entryOptions = new()
        {
            AbsoluteExpirationRelativeToNow = _options.DekCacheTtl,
        };
        _cache.Set(cacheKey, dek, entryOptions);
    }

    private void CacheByKeyId(string scope, Dek dek)
    {
        if (_options.DekCacheTtl <= TimeSpan.Zero)
        {
            return;
        }

        MemoryCacheEntryOptions entryOptions = new()
        {
            AbsoluteExpirationRelativeToNow = _options.DekCacheTtl,
        };
        _cache.Set(BuildKeyIdCacheKey(dek.KeyId, scope), dek, entryOptions);
    }

    private static Dek CloneDek(Dek source) =>
        new((byte[])source.Key.Clone(), source.KeyId, source.WrappedKey);

    private static string BuildActiveCacheKey(string scope) => $"vellum:dek:active:{scope}";

    // Scope is included in the cache key so that a compromised or buggy caller cannot use
    // another tenant's cached DEK by guessing its Guid.
    private static string BuildKeyIdCacheKey(Guid keyId, string scope) => $"vellum:dek:id:{scope}:{keyId}";

    // Issue #6 / L24: the wrapped ciphertext IS the tenant-specific secret material, so its
    // SHA-256 is a stable globally unique identifier safe to use as a cross-tenant cache key
    // without an explicit scope partition. A consumer who does not already possess the
    // wrapped ciphertext cannot guess another tenant's cache key.
    private static string BuildWrappedCacheKey(WrappedKey wrappedKey)
    {
        byte[] ciphertextBytes = System.Text.Encoding.UTF8.GetBytes(wrappedKey.Ciphertext);
        byte[] hash = SHA256.HashData(ciphertextBytes);
        return $"vellum:dek:wrapped:{Convert.ToHexString(hash)}";
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "DEK cache hit for scope {Scope}")]
    private static partial void LogDekCacheHit(ILogger logger, string scope);

    [LoggerMessage(Level = LogLevel.Debug, Message = "No active DEK for scope {Scope}, creating a new one")]
    private static partial void LogNoDekFound(ILogger logger, string scope);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DEK loaded from store for scope {Scope}")]
    private static partial void LogDekLoadedFromStore(ILogger logger, string scope);

    // L-6: KeyId is included so that audit trails can correlate the creation log entry with
    // the envelope metadata, which also carries the KeyId. The KEK provider version stays in
    // so rotation events remain visible.
    [LoggerMessage(Level = LogLevel.Information, Message = "DEK created for scope {Scope} with KeyId {KeyId} (KEK provider version {ProviderVersion})")]
    private static partial void LogDekCreated(ILogger logger, string scope, Guid keyId, string providerVersion);

    [LoggerMessage(Level = LogLevel.Information, Message = "DEK rotated for scope {Scope}")]
    private static partial void LogDekRotated(ILogger logger, string scope);

    [LoggerMessage(Level = LogLevel.Warning, Message = "DEK creation race detected for scope {Scope}, reconciling with the winner")]
    private static partial void LogDekRaceConditionHandled(ILogger logger, string scope);

    // M-5: the next two messages use explicit, stable EventIds (distinct from one another)
    // so that SIEM rules can alert on a cross-scope lookup attempt without firing on a
    // benign "key not found" misconfiguration. EventId 1001 = not found, 1002 = scope mismatch.

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Warning,
        Message = "DEK lookup missed: key {KeyId} is not present for scope {Scope}")]
    private static partial void LogDekNotFound(ILogger logger, Guid keyId, string scope);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Warning,
        Message = "DEK scope mismatch: key {KeyId} was requested for scope {RequestedScope} but belongs to scope {ActualScope}")]
    private static partial void LogDekScopeMismatch(ILogger logger, Guid keyId, string requestedScope, string actualScope);

    // L-3: EventId 1003 is distinct from not-found (1001) and scope-mismatch (1002) so that
    // a SIEM rule can alert specifically on a Vellum cache invariant violation — something
    // that should never happen in production.
    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Critical,
        Message = "DEK cache invariant violation: request for key {RequestedKeyId} on scope {Scope} resolved to cached entry with key {CachedKeyId}")]
    private static partial void LogDekCacheKeyIdMismatch(ILogger logger, Guid requestedKeyId, string scope, Guid cachedKeyId);

    // Issue #6: wrapped-key decrypt cache. No scope field because the wrapped ciphertext
    // hash is globally unique — see tasks/lessons.md L24.
    [LoggerMessage(Level = LogLevel.Debug, Message = "DEK cache hit for wrapped-key decrypt path")]
    private static partial void LogDekWrappedCacheHit(ILogger logger);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DEK unwrapped via KEK provider and cached for wrapped-key decrypt path")]
    private static partial void LogDekWrappedLoadedAndCached(ILogger logger);
}
