using System.Collections.Concurrent;

namespace Vellum.Tests.Fakes;

/// <summary>
/// A deterministic in-memory KEK provider for tests. "Wrapping" a DEK stores it in a dictionary
/// keyed by a fresh <see cref="Guid"/> handle; "unwrapping" looks the handle up and returns a
/// clone of the bytes. Not cryptographic — just enough state to exercise Vellum.Core.
/// </summary>
public sealed class FakeKeyEncryptionProvider : IKeyEncryptionProvider
{
    private readonly ConcurrentDictionary<string, byte[]> _wrapped = new(StringComparer.Ordinal);

    public string ProviderName => "fake";

    public int WrapCalls { get; private set; }

    public int UnwrapCalls { get; private set; }

    public int RewrapCalls { get; private set; }

    /// <summary>
    /// Test hook: handles (ciphertexts) for which <see cref="RewrapAsync"/> throws, simulating
    /// a KEK provider that fails to rewrap specific keys mid-sweep.
    /// </summary>
    public HashSet<string> FailRewrapHandles { get; } = new(StringComparer.Ordinal);

    public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default)
    {
        WrapCalls++;
        string handle = Guid.NewGuid().ToString("N");
        _wrapped[handle] = dek.ToArray();
        return Task.FromResult(new WrappedKey(Ciphertext: handle, ProviderVersion: "v1"));
    }

    public Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
    {
        UnwrapCalls++;
        ArgumentNullException.ThrowIfNull(wrappedKey);
        if (!_wrapped.TryGetValue(wrappedKey.Ciphertext, out byte[]? bytes))
        {
            throw new InvalidOperationException($"Fake provider: unknown handle '{wrappedKey.Ciphertext}'.");
        }

        return Task.FromResult((byte[])bytes.Clone());
    }

    public Task<WrappedKey> RewrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
    {
        RewrapCalls++;
        ArgumentNullException.ThrowIfNull(wrappedKey);

        if (FailRewrapHandles.Contains(wrappedKey.Ciphertext))
        {
            throw new InvalidOperationException($"Fake provider: rewrap deliberately failed for handle '{wrappedKey.Ciphertext}'.");
        }

        if (!_wrapped.TryGetValue(wrappedKey.Ciphertext, out byte[]? bytes))
        {
            throw new InvalidOperationException($"Fake provider: unknown handle '{wrappedKey.Ciphertext}'.");
        }

        // Mirror a real rewrap: the same DEK bytes become reachable under a NEW handle wrapped
        // under the "current" provider version. The old handle stays valid (Vault keeps old
        // versions unwrappable until min_decryption_version is raised).
        string newHandle = Guid.NewGuid().ToString("N");
        _wrapped[newHandle] = (byte[])bytes.Clone();
        return Task.FromResult(new WrappedKey(Ciphertext: newHandle, ProviderVersion: "v2"));
    }
}
