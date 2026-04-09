using System.Security.Cryptography;

namespace Vellum;

/// <summary>
/// Default cryptographically-secure implementation of <see cref="IRandomBytesProvider"/>
/// that delegates to <see cref="RandomNumberGenerator.Fill(Span{byte})"/>.
/// </summary>
/// <remarks>
/// Registered automatically by <see cref="VellumServiceCollectionExtensions.AddVellum"/>
/// unless the consumer has already registered a different implementation.
/// </remarks>
public sealed class DefaultRandomBytesProvider : IRandomBytesProvider
{
    /// <inheritdoc />
    public void Fill(Span<byte> destination)
    {
        RandomNumberGenerator.Fill(destination);
    }
}
