namespace Vellum;

/// <summary>
/// Source of cryptographically-secure random bytes, abstracted for testability.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IRandomBytesProvider"/> is the seam that Vellum uses to generate AES-GCM nonces,
/// fresh DEKs, and any other random material. In production, the default Core implementation
/// delegates to <see cref="System.Security.Cryptography.RandomNumberGenerator.Fill(System.Span{byte})"/>.
/// </para>
/// <para>
/// <b>Testability.</b> Tests (particularly property-based tests exploring nonce-uniqueness
/// invariants) can substitute a deterministic counter-based implementation so that failing
/// cases are reproducible. Production code must never use a deterministic implementation —
/// nonce reuse in AES-GCM catastrophically breaks confidentiality and authenticity.
/// </para>
/// <para>
/// <b>Thread-safety.</b> Implementations must be safe for concurrent use by multiple threads.
/// </para>
/// </remarks>
public interface IRandomBytesProvider
{
    /// <summary>
    /// Fills the provided span with cryptographically-secure random bytes.
    /// </summary>
    /// <param name="destination">The span to fill. Every byte is overwritten.</param>
    public void Fill(Span<byte> destination);
}
