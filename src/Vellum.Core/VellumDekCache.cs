using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;

namespace Vellum;

/// <summary>
/// Vellum-owned in-memory cache for unwrapped Data Encryption Keys, wrapping a dedicated
/// <see cref="MemoryCache"/> instance that is never the application's shared
/// <see cref="IMemoryCache"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a dedicated cache (M-C).</b> Storing plaintext DEKs in the application-wide
/// <see cref="IMemoryCache"/> under deterministic keys would let ANY in-process code that
/// resolves <see cref="IMemoryCache"/> read plaintext key material, and would let consumer
/// <c>SizeLimit</c> budgeting or consumer-triggered compaction evict DEK entries. This type
/// owns its own <see cref="MemoryCache"/>, so the entries are reachable only through Vellum.
/// </para>
/// <para>
/// <b>No <c>SizeLimit</c> by design.</b> The entry population is bounded by the consumer's
/// scope/key count and every entry carries a TTL (<see cref="VellumOptions.DekCacheTtl"/>),
/// so memory is naturally bounded — and the consumer cannot compact or evict this cache.
/// Entries still set <c>Size = 1</c> defensively (lesson L25): it costs nothing and protects
/// against a future refactor ever introducing a limit.
/// </para>
/// <para>
/// <b>Eviction zeroing.</b> Every <see cref="Set"/> installs a post-eviction callback that
/// scrubs the cached <see cref="Dek.Key"/> bytes via
/// <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/>, so evicted, expired, or
/// replaced plaintext DEKs do not linger on the managed heap until garbage collection.
/// Centralizing the callback here makes it impossible for a future cache site to forget it.
/// </para>
/// <para>
/// <b>Concurrency safety of the zeroing.</b> Eviction callbacks run asynchronously after the
/// entry has already been removed; a concurrent reader that got a cache hit just before the
/// eviction received a CLONE of the key bytes (lesson L3), never the cached array itself, so
/// zeroing the evicted original is safe. In the worst theoretical interleaving (a clone racing
/// the eviction callback) a decrypt fails closed with an AES-GCM authentication error —
/// plaintext is never silently corrupted.
/// </para>
/// <para>
/// <b>Ownership contract.</b> <see cref="Set"/> takes ownership of the
/// <see cref="Dek.Key"/> array: the cache zeroes it on eviction. Callers must never pass a
/// <see cref="Dek"/> whose key array is still referenced by an instance handed to user code —
/// clone first, and never store the same array under two cache keys.
/// </para>
/// </remarks>
public sealed class VellumDekCache : IDisposable
{
    // Static singleton delegate: one allocation for the lifetime of the process, installed on
    // every entry so that no future cache site can forget the eviction scrub. KeyId/scope are
    // not secret — only the plaintext key bytes are zeroed.
    private static readonly PostEvictionDelegate _zeroKeyOnEviction = static (_, value, _, _) =>
    {
        if (value is Dek evicted)
        {
            CryptographicOperations.ZeroMemory(evicted.Key);
        }
    };

    private readonly MemoryCache _cache = new(new MemoryCacheOptions());

    /// <summary>
    /// Attempts to read a cached <see cref="Dek"/>.
    /// </summary>
    /// <param name="key">The cache key.</param>
    /// <param name="dek">The cached entry when found. Callers must clone <see cref="Dek.Key"/> before handing it to user code (lesson L3).</param>
    /// <returns><see langword="true"/> when an entry exists; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <see langword="null"/>.</exception>
    public bool TryGetValue(string key, [NotNullWhen(true)] out Dek? dek)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (_cache.TryGetValue(key, out Dek? cached) && cached is not null)
        {
            dek = cached;
            return true;
        }

        dek = null;
        return false;
    }

    /// <summary>
    /// Caches <paramref name="dek"/> under <paramref name="key"/> with an absolute TTL,
    /// taking ownership of <see cref="Dek.Key"/>: the bytes are zeroed when the entry is
    /// evicted, expired, replaced, or the cache is disposed.
    /// </summary>
    /// <param name="key">The cache key.</param>
    /// <param name="dek">The entry to cache. Its key array must not be shared with any other cache entry or any <see cref="Dek"/> returned to callers.</param>
    /// <param name="ttl">Absolute expiration relative to now. Must be positive.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> or <paramref name="dek"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="ttl"/> is not positive.</exception>
    public void Set(string key, Dek dek, TimeSpan ttl)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(dek);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ttl, TimeSpan.Zero);

        MemoryCacheEntryOptions entryOptions = new()
        {
            AbsoluteExpirationRelativeToNow = ttl,
            // L25: this cache never configures SizeLimit, but Size = 1 is kept defensively —
            // it costs nothing and survives a future refactor that introduces a limit.
            Size = 1,
        };
        entryOptions.RegisterPostEvictionCallback(_zeroKeyOnEviction);

        _cache.Set(key, dek, entryOptions);
    }

    /// <summary>
    /// Removes the entry under <paramref name="key"/>, if present. The eviction callback
    /// zeroes the removed entry's key bytes.
    /// </summary>
    /// <param name="key">The cache key.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <see langword="null"/>.</exception>
    public void Remove(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _cache.Remove(key);
    }

    /// <summary>
    /// Disposes the underlying cache, scrubbing all remaining plaintext DEKs.
    /// </summary>
    public void Dispose()
    {
        // MemoryCache.Dispose() does NOT run eviction callbacks for entries still present,
        // so compact everything out first: Compact(1.0) evicts every entry and fires the
        // zeroing callbacks, scrubbing all remaining plaintext DEKs on shutdown.
        _cache.Compact(1.0);
        _cache.Dispose();
    }
}
