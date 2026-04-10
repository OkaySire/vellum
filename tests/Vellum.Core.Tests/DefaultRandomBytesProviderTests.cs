using FluentAssertions;
using Xunit;

namespace Vellum.Tests;

/// <summary>
/// L-7: thread-safety coverage for <see cref="DefaultRandomBytesProvider"/>.
/// </summary>
/// <remarks>
/// The underlying <see cref="System.Security.Cryptography.RandomNumberGenerator.Fill(System.Span{byte})"/>
/// is documented as thread-safe, but Vellum wraps it through an interface so we pin that
/// invariant here. A regression that introduced shared buffer reuse, locking, or non-thread-safe
/// field mutation would surface as an exception on one of the parallel iterations.
/// </remarks>
public sealed class DefaultRandomBytesProviderTests
{
    [Fact]
    public void Fill_ParallelCallers_DoNotThrowAndFillEveryBuffer()
    {
        DefaultRandomBytesProvider provider = new();

        const int parallelism = 100;
        const int iterationsPerThread = 50;
        Exception? firstFailure = null;

        Parallel.For(0, parallelism, i =>
        {
            // Allocate the 32-byte buffer once per thread, outside the inner loop, so the
            // stack footprint does not grow with iterationsPerThread (CA2014).
            Span<byte> buffer = stackalloc byte[32];
            try
            {
                for (int j = 0; j < iterationsPerThread; j++)
                {
                    provider.Fill(buffer);

                    // The chance of an all-zero 32-byte buffer from a CSRNG is 2^-256. If we
                    // ever see one, the provider is broken. This is the cheapest correctness
                    // check we can add per iteration.
                    bool anyNonZero = false;
                    for (int k = 0; k < buffer.Length; k++)
                    {
                        if (buffer[k] != 0)
                        {
                            anyNonZero = true;
                            break;
                        }
                    }

                    if (!anyNonZero)
                    {
                        throw new InvalidOperationException($"Fill produced an all-zero buffer on thread {i} iteration {j}.");
                    }
                }
            }
#pragma warning disable CA1031 // test captures any exception to surface the first failure
            catch (Exception ex)
#pragma warning restore CA1031
            {
                Interlocked.CompareExchange(ref firstFailure, ex, null);
            }
        });

        firstFailure.Should().BeNull("DefaultRandomBytesProvider.Fill must be thread-safe");
    }
}
