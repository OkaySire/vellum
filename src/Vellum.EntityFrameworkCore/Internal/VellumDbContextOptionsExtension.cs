using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Vellum.EntityFrameworkCore.Internal;

/// <summary>
/// Carries <see cref="VellumEntityFrameworkOptions"/> on a <see cref="DbContextOptions"/>
/// instance so that <c>VellumModelBuilderExtensions.AddVellumEncryptionKeys</c> can
/// pull them back inside <c>DbContext.OnModelCreating</c> without a second literal.
/// </summary>
/// <remarks>
/// <para>
/// Registered via <c>VellumDbContextOptionsBuilderExtensions.UseVellum</c>. Not a service —
/// this extension contributes no services to the internal EF Core provider, only data.
/// The <see cref="ApplyServices(IServiceCollection)"/> implementation is intentionally empty.
/// </para>
/// <para>
/// Issue #9 (move options source to DI): this is the primary mechanism that lets consumers
/// configure Vellum options exactly once — on the <see cref="DbContextOptionsBuilder"/>
/// passed to <c>AddDbContext&lt;T&gt;</c> — and have those options flow through both the
/// model builder and the runtime store.
/// </para>
/// </remarks>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by VellumDbContextOptionsBuilderExtensions.UseVellum via AddOrUpdateExtension.")]
internal sealed class VellumDbContextOptionsExtension : IDbContextOptionsExtension
{
    public VellumDbContextOptionsExtension(VellumEntityFrameworkOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Options = options;
        Info = new ExtensionInfo(this);
    }

    public VellumEntityFrameworkOptions Options { get; }

    public DbContextOptionsExtensionInfo Info { get; }

    public void ApplyServices(IServiceCollection services)
    {
        // No services to contribute. The extension only carries data.
    }

    public void Validate(IDbContextOptions options)
    {
        // Structural validation runs inside IValidateOptions<VellumEntityFrameworkOptions>
        // (VellumEntityFrameworkOptionsValidator), which fires at host start via
        // ValidateOnStart. Nothing to assert here at DbContext build time.
    }

    private sealed class ExtensionInfo(VellumDbContextOptionsExtension extension)
        : DbContextOptionsExtensionInfo(extension)
    {
        private new VellumDbContextOptionsExtension Extension => (VellumDbContextOptionsExtension)base.Extension;

        public override bool IsDatabaseProvider => false;

        public override string LogFragment
        {
            get
            {
                VellumEntityFrameworkOptions options = Extension.Options;
                return string.Create(
                    CultureInfo.InvariantCulture,
                    $"Vellum(TableName={options.TableName}, SchemaName={options.SchemaName ?? "<default>"}, ScopeMaxLength={options.ScopeMaxLength})");
            }
        }

        public override int GetServiceProviderHashCode()
        {
            // Vellum does not contribute services to the internal EF Core provider, so
            // differences in Vellum options do not require a different service provider.
            return 0;
        }

        public override bool ShouldUseSameServiceProvider(DbContextOptionsExtensionInfo other)
        {
            // Same rationale as GetServiceProviderHashCode — no services contributed.
            return other is ExtensionInfo;
        }

        public override void PopulateDebugInfo(IDictionary<string, string> debugInfo)
        {
            ArgumentNullException.ThrowIfNull(debugInfo);
            debugInfo["Vellum:TableName"] = Extension.Options.TableName;
            debugInfo["Vellum:SchemaName"] = Extension.Options.SchemaName ?? string.Empty;
        }
    }
}
