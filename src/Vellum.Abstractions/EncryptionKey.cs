namespace Vellum;

/// <summary>
/// Persisted record of a Data Encryption Key (DEK) in wrapped form.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="EncryptionKey"/> stores only the wrapped (encrypted) DEK — the plaintext
/// DEK never touches storage. Unwrapping requires access to the configured
/// <see cref="IKeyEncryptionProvider"/>.
/// </para>
/// <para>
/// The <see cref="Scope"/> is an opaque, caller-defined string used to partition keys
/// across tenants, buses, users, or any other logical boundary. Vellum does not interpret
/// scope values; they are treated as opaque identifiers.
/// </para>
/// </remarks>
/// <param name="KeyId">Stable, globally-unique identifier for this key. Used to look up the key when decrypting historical payloads.</param>
/// <param name="Scope">Opaque scope identifier (for example, <c>"tenant:42"</c>, <c>"bus:abc"</c>, <c>"user:xyz"</c>). Scope values are never interpreted by Vellum.</param>
/// <param name="WrappedDek">KEK-provider-specific ciphertext of the DEK. The exact format depends on the provider (for example, <c>"vault:v1:..."</c> for HashiCorp Vault Transit).</param>
/// <param name="ProviderVersion">Version of the KEK used to wrap the DEK. Used by providers that support key rotation at the KEK level.</param>
/// <param name="CreatedAt">UTC timestamp when this key was created.</param>
/// <param name="ExpiresAt">Optional UTC timestamp after which this key should no longer be used for new encryptions. Decryption of historical payloads remains possible.</param>
/// <param name="IsActive">Whether this key is the currently-active key for its scope. Only one key per scope should be active at any time.</param>
public sealed record EncryptionKey(
    Guid KeyId,
    string Scope,
    string WrappedDek,
    int ProviderVersion,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    bool IsActive);
