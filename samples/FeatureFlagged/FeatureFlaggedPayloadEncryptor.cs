using Microsoft.Extensions.Options;
using Vellum;

namespace Vellum.Samples.FeatureFlagged;

/// <summary>
/// Decorator over <see cref="IPayloadEncryptor"/> that gates encryption on a consumer-owned
/// feature flag. When the flag is off, <see cref="EncryptAsync"/> returns a sentinel
/// envelope that <see cref="DecryptAsync"/> recognises as plaintext-passthrough — so a
/// staged rollout can flip encryption on and off without touching the DI container or
/// rewriting consumer call sites.
/// </summary>
/// <remarks>
/// <para>
/// <b>Sentinel envelope format.</b> When the flag is off, the decorator stores the raw
/// plaintext in <see cref="EncryptedPayload.Ciphertext"/>, a zero-length
/// <see cref="EncryptedPayload.Nonce"/>, and a <see cref="WrappedKey"/> whose
/// <see cref="WrappedKey.ProviderVersion"/> equals <see cref="PassthroughProviderVersion"/>.
/// On <see cref="DecryptAsync"/>, the decorator checks for the sentinel marker and returns
/// the ciphertext verbatim; otherwise it delegates to the inner encryptor.
/// </para>
/// <para>
/// <b>Semantics discussion.</b> Returning a plaintext-bearing envelope when the flag is
/// off is a deliberate design choice — it keeps the call-site API stable across the rollout
/// boundary, at the cost of slightly weird-looking on-disk data. The alternative is to throw
/// when <see cref="FeatureFlags.EncryptionEnabled"/> is false, forcing callers to check a
/// flag before calling Encrypt. Pick whichever matches your rollout strategy.
/// </para>
/// <para>
/// <b>Hot-reload.</b> This decorator takes <see cref="IOptionsMonitor{FeatureFlags}"/> so a
/// live config update flips the flag mid-process without a restart. For consumers who
/// prefer static startup-time config, replace it with <see cref="IOptions{FeatureFlags}"/>.
/// </para>
/// </remarks>
public sealed class FeatureFlaggedPayloadEncryptor(
    IPayloadEncryptor inner,
    IOptionsMonitor<FeatureFlags> flags) : IPayloadEncryptor
{
    /// <summary>
    /// Sentinel provider version stamped on a passthrough envelope so
    /// <see cref="DecryptAsync"/> can recognise and short-circuit it.
    /// </summary>
    public const string PassthroughProviderVersion = "vellum-sample:passthrough";

    private readonly IPayloadEncryptor _inner = inner;
    private readonly IOptionsMonitor<FeatureFlags> _flags = flags;

    public bool IsEnabled => _flags.CurrentValue.EncryptionEnabled && _inner.IsEnabled;

    public Task<EncryptedPayload> EncryptAsync(
        ReadOnlyMemory<byte> plaintext,
        string scope,
        CancellationToken cancellationToken = default)
    {
        if (!_flags.CurrentValue.EncryptionEnabled)
        {
            // Sentinel envelope: ciphertext IS the plaintext, nonce is empty, wrapped key
            // carries the passthrough marker. DecryptAsync recognises and short-circuits it.
            EncryptedPayload passthrough = new(
                Ciphertext: plaintext.ToArray(),
                Nonce: Array.Empty<byte>(),
                WrappedDek: new WrappedKey(string.Empty, PassthroughProviderVersion),
                KeyId: Guid.Empty);
            return Task.FromResult(passthrough);
        }

        return _inner.EncryptAsync(plaintext, scope, cancellationToken);
    }

    public Task<byte[]> DecryptAsync(
        EncryptedPayload payload,
        string scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if (string.Equals(
                payload.WrappedDek.ProviderVersion,
                PassthroughProviderVersion,
                StringComparison.Ordinal))
        {
            // Passthrough sentinel — return the raw plaintext embedded in the envelope.
            return Task.FromResult((byte[])payload.Ciphertext.Clone());
        }

        return _inner.DecryptAsync(payload, scope, cancellationToken);
    }
}
