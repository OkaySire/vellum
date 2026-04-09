namespace Vellum.EntityFrameworkCore.Internal;

/// <summary>
/// Internal Entity Framework entity mapped to the wrapped-DEK table. Not exposed to
/// consumers — they exchange <see cref="EncryptionKey"/> value objects with the store,
/// and the store translates between the domain type and this persistence type via
/// <see cref="FromDomain"/> / <see cref="ToDomain"/>.
/// </summary>
/// <remarks>
/// <para>
/// Kept as a plain mutable class (not a record) because EF Core's change-tracker expects
/// mutable entity types, and filtered-unique-index migrations read the CLR properties
/// through reflection.
/// </para>
/// <para>
/// The wrapped-DEK ciphertext and the provider version are stored as two separate columns
/// rather than as a serialised <see cref="WrappedKey"/> blob. This keeps the schema
/// transparent to SQL tooling (<c>SELECT</c> queries, schema diffs, audit exports)
/// without coupling it to a specific JSON layout that might change between Vellum versions.
/// </para>
/// </remarks>
internal sealed class EncryptionKeyRecord
{
    public Guid KeyId { get; set; }

    public string Scope { get; set; } = string.Empty;

    public string WrappedCiphertext { get; set; } = string.Empty;

    public string WrappedProviderVersion { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? ExpiresAt { get; set; }

    public bool IsActive { get; set; }

    /// <summary>
    /// Projects an <see cref="EncryptionKey"/> domain value into its persistence record.
    /// </summary>
    public static EncryptionKeyRecord FromDomain(EncryptionKey domain)
    {
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(domain.WrappedKey);

        return new EncryptionKeyRecord
        {
            KeyId = domain.KeyId,
            Scope = domain.Scope,
            WrappedCiphertext = domain.WrappedKey.Ciphertext,
            WrappedProviderVersion = domain.WrappedKey.ProviderVersion,
            CreatedAt = domain.CreatedAt,
            ExpiresAt = domain.ExpiresAt,
            IsActive = domain.IsActive,
        };
    }

    /// <summary>
    /// Projects a persisted record back into the <see cref="EncryptionKey"/> domain value.
    /// </summary>
    public EncryptionKey ToDomain()
    {
        return new EncryptionKey(
            KeyId,
            Scope,
            new WrappedKey(WrappedCiphertext, WrappedProviderVersion),
            CreatedAt,
            ExpiresAt,
            IsActive);
    }
}
