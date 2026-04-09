using System.Security.Cryptography;

namespace Vellum.Tests.Fakes;

/// <summary>
/// Test double over <see cref="IRandomBytesProvider"/> that still uses
/// <see cref="RandomNumberGenerator"/> under the hood (so nonce uniqueness holds), but exposes
/// a counter so tests can assert how many times it was called.
/// </summary>
public sealed class CountingRandomBytesProvider : IRandomBytesProvider
{
    public int FillCalls { get; private set; }

    public void Fill(Span<byte> destination)
    {
        FillCalls++;
        RandomNumberGenerator.Fill(destination);
    }
}
