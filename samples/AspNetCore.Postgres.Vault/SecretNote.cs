namespace Vellum.Samples.AspNetCorePostgresVault;

/// <summary>
/// Sample entity that stores an encrypted note. The envelope fields mirror
/// <see cref="EncryptedPayload"/> so the sample can round-trip through a SQL table
/// without a custom JSON column.
/// </summary>
public sealed class SecretNote
{
    public Guid Id { get; set; }

    public string Scope { get; set; } = string.Empty;

    /// <summary>Ciphertext + 16-byte AES-GCM auth tag.</summary>
    public byte[] Ciphertext { get; set; } = Array.Empty<byte>();

    /// <summary>12-byte AES-GCM nonce.</summary>
    public byte[] Nonce { get; set; } = Array.Empty<byte>();

    /// <summary>Wrapped DEK ciphertext (KEK provider handle).</summary>
    public string WrappedCiphertext { get; set; } = string.Empty;

    /// <summary>Wrapped DEK provider version.</summary>
    public string WrappedProviderVersion { get; set; } = string.Empty;

    /// <summary>Audit-only identifier for the DEK — decryption does not require it.</summary>
    public Guid KeyId { get; set; }
}
