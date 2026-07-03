using FluentAssertions;
using Xunit;

namespace Vellum.Tests;

public sealed class VellumDekCacheTests
{
    [Fact]
    public void TryGetValue_Miss_ReturnsFalse()
    {
        using VellumDekCache cache = new();

        bool found = cache.TryGetValue("vellum:dek:active:tenant:none", out Dek? dek);

        found.Should().BeFalse();
        dek.Should().BeNull();
    }

    [Fact]
    public void Set_NonPositiveTtl_Throws()
    {
        // The TTL gate (DekCacheTtl <= 0 disables caching) lives in DekManager's Cache*
        // helpers; the wrapper fails closed if a future call site forgets it.
        using VellumDekCache cache = new();
        Dek dek = MakeDek(0x11);

        Action zero = () => cache.Set("key", dek, TimeSpan.Zero);
        Action negative = () => cache.Set("key", dek, TimeSpan.FromSeconds(-1));

        zero.Should().Throw<ArgumentOutOfRangeException>();
        negative.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public async Task Remove_ZeroesEvictedKey_WhilePreviouslyReturnedCloneIsIntact()
    {
        // M-C eviction zeroing: the cache owns the Dek.Key array and scrubs it when the
        // entry is evicted. A clone taken by a reader before the eviction (L3 contract:
        // DekManager always returns clones) must be unaffected.
        using VellumDekCache cache = new();
        Dek cached = MakeDek(0xAB);
        byte[] originalArray = cached.Key;
        cache.Set("vellum:dek:active:tenant:42", cached, TimeSpan.FromMinutes(5));

        // Simulate a cache-hit reader: it receives a CLONE, never the cached array itself.
        cache.TryGetValue("vellum:dek:active:tenant:42", out Dek? hit).Should().BeTrue();
        byte[] readerClone = (byte[])hit!.Key.Clone();

        cache.Remove("vellum:dek:active:tenant:42");

        // Eviction callbacks run asynchronously after eviction — poll with a deadline.
        await WaitUntilZeroedAsync(originalArray);
        originalArray.Should().OnlyContain(b => b == 0, "the evicted original must be scrubbed");
        readerClone.Should().OnlyContain(b => b == 0xAB, "the reader's clone must stay intact");
    }

    [Fact]
    public async Task Set_ReplacingEntry_ZeroesReplacedKey()
    {
        // Rotation replaces the active entry in place (never Remove-then-Set); the replaced
        // entry's key bytes must be scrubbed while the new entry keeps serving.
        using VellumDekCache cache = new();
        Dek old = MakeDek(0x01);
        Dek fresh = MakeDek(0x02);
        byte[] oldArray = old.Key;

        cache.Set("vellum:dek:active:tenant:42", old, TimeSpan.FromMinutes(5));
        cache.Set("vellum:dek:active:tenant:42", fresh, TimeSpan.FromMinutes(5));

        await WaitUntilZeroedAsync(oldArray);
        oldArray.Should().OnlyContain(b => b == 0, "the replaced entry's key must be scrubbed");

        cache.TryGetValue("vellum:dek:active:tenant:42", out Dek? current).Should().BeTrue();
        current!.Key.Should().OnlyContain(b => b == 0x02, "the new entry must be unaffected");
    }

    [Fact]
    public async Task Expiry_ZeroesEvictedKey()
    {
        // TTL-based expiry is the most common eviction path in production (DekCacheTtl).
        using VellumDekCache cache = new();
        Dek cached = MakeDek(0xEE);
        byte[] originalArray = cached.Key;
        cache.Set("vellum:dek:active:tenant:42", cached, TimeSpan.FromMilliseconds(50));

        // Poll until the entry expires (TryGetValue triggers the expiry check), then until
        // the asynchronous eviction callback has scrubbed the array.
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        while (cache.TryGetValue("vellum:dek:active:tenant:42", out Dek? _)
               && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        await WaitUntilZeroedAsync(originalArray);
        originalArray.Should().OnlyContain(b => b == 0, "the expired entry's key must be scrubbed");
    }

    [Fact]
    public async Task Dispose_ZeroesAllRemainingEntries()
    {
        // Shutdown scrub: MemoryCache.Dispose does not fire eviction callbacks by itself,
        // so VellumDekCache.Dispose compacts everything out first.
        VellumDekCache cache = new();
        Dek first = MakeDek(0x31);
        Dek second = MakeDek(0x32);
        byte[] firstArray = first.Key;
        byte[] secondArray = second.Key;
        cache.Set("vellum:dek:active:tenant:a", first, TimeSpan.FromMinutes(5));
        cache.Set("vellum:dek:active:tenant:b", second, TimeSpan.FromMinutes(5));

        cache.Dispose();

        await WaitUntilZeroedAsync(firstArray);
        await WaitUntilZeroedAsync(secondArray);
        firstArray.Should().OnlyContain(b => b == 0, "all entries must be scrubbed on dispose");
        secondArray.Should().OnlyContain(b => b == 0, "all entries must be scrubbed on dispose");
    }

    private static Dek MakeDek(byte fill)
    {
        byte[] key = new byte[32];
        Array.Fill(key, fill);
        return new Dek(key, Guid.NewGuid(), new WrappedKey($"test:{Guid.NewGuid():N}", "v1"));
    }

    /// <summary>
    /// Post-eviction callbacks run asynchronously on the thread pool after the entry has been
    /// evicted; poll with a deadline instead of asserting immediately.
    /// </summary>
    private static async Task WaitUntilZeroedAsync(byte[] array)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        while (Array.Exists(array, static b => b != 0) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(10);
        }
    }
}
