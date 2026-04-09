using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Vellum.InMemory;

/// <summary>
/// Registration helpers for the <see cref="InMemoryEncryptionKeyStore"/>.
/// </summary>
/// <remarks>
/// <para>
/// This extension wires up a process-local <see cref="IEncryptionKeyStore"/> that stores
/// wrapped Data Encryption Keys in memory. Intended for tests, samples, and local
/// development — state is lost on process restart.
/// </para>
/// <para>
/// For production persistence, reference <c>Vellum.EntityFrameworkCore</c> (or another
/// storage-backed package) and call its registration extension instead.
/// </para>
/// </remarks>
public static class InMemoryServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="InMemoryEncryptionKeyStore"/> as the <see cref="IEncryptionKeyStore"/>
    /// implementation, using a singleton lifetime so that all DI scopes in the process share
    /// the same in-memory state.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    /// <remarks>
    /// <para>
    /// <b>Lifetime choice.</b> The store is a singleton because the whole point of an
    /// in-memory implementation is to share state across DI scopes. There are no scoped
    /// dependencies, no <see cref="System.Net.Http.HttpClient"/>, and no
    /// <c>DbContext</c> — nothing that would force a transient lifetime. This differs from
    /// the typed-HttpClient bridge in <c>Vellum.Vault</c> (see <c>tasks/lessons.md</c> L16),
    /// which must be transient to follow the typed-client handler-rotation contract.
    /// </para>
    /// <para>
    /// <c>TryAdd</c> semantics are preserved: if the consuming application has already
    /// registered its own <see cref="IEncryptionKeyStore"/>, this call will not override it.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddInMemoryStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<InMemoryEncryptionKeyStore>();
        services.TryAddSingleton<IEncryptionKeyStore>(sp => sp.GetRequiredService<InMemoryEncryptionKeyStore>());

        return services;
    }
}
