namespace Vellum;

/// <summary>
/// Configuration for Vellum core services.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="VellumOptions"/> covers the options consumed by <see cref="DekManager"/> and
/// <see cref="PayloadEncryptor"/>. Provider-specific options (for example, Vault address,
/// AWS KMS key ARN) live in the corresponding provider package's own options type.
/// </para>
/// <para>
/// Rotation is opt-in and lives in <c>Vellum.Rotation</c>; that package exposes its own
/// <c>RotationOptions</c> type and never reads from <see cref="VellumOptions"/>.
/// </para>
/// </remarks>
public sealed class VellumOptions
{
    /// <summary>
    /// How long an unwrapped Data Encryption Key may live in the in-memory cache before being
    /// evicted. Defaults to 30 minutes.
    /// </summary>
    /// <remarks>
    /// Shorter TTLs reduce the window during which a plaintext DEK is held in process memory,
    /// at the cost of more frequent KEK provider round-trips. Set to <see cref="TimeSpan.Zero"/>
    /// or a negative value to disable caching entirely.
    /// </remarks>
    public TimeSpan DekCacheTtl { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Whether <see cref="PayloadEncryptor.EncryptAsync"/> binds the ciphertext to its scope
    /// via AES-GCM associated data (envelope format version 2). Defaults to <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>When <see langword="true"/> (default, recommended):</b> envelopes are produced as
    /// format version 2 with AAD <c>UTF8("vellum:aad:v2:scope:" + scope)</c>. Decryption then
    /// requires the original scope — an envelope encrypted for tenant A that is copied into
    /// tenant B's records fails the authentication tag check instead of decrypting
    /// (confused-deputy / envelope-swap defense in multi-tenant applications).
    /// </para>
    /// <para>
    /// <b>When <see langword="false"/>:</b> envelopes are produced as legacy format version 1
    /// with no associated data. Such envelopes decrypt under <i>any</i> scope argument. Only
    /// disable binding when the consumer genuinely cannot supply the scope at decrypt time
    /// (for example, envelopes are decrypted by a component that has no access to the tenancy
    /// context). The trade-off is explicit: you give up the cryptographic guarantee that a
    /// ciphertext belongs to the scope it is presented under.
    /// </para>
    /// <para>
    /// This option affects <b>encryption only</b>. Decryption always honors the envelope's own
    /// <see cref="EncryptedPayload.FormatVersion"/>: version 1 envelopes remain decryptable
    /// with binding enabled, and version 2 envelopes still require their scope with binding
    /// disabled.
    /// </para>
    /// </remarks>
    public bool BindScopeToCiphertext { get; set; } = true;
}
