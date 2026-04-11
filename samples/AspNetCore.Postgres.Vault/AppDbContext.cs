using Microsoft.EntityFrameworkCore;
using Vellum.EntityFrameworkCore;

namespace Vellum.Samples.AspNetCorePostgresVault;

/// <summary>
/// Application <see cref="DbContext"/> for the sample. Registers the Vellum
/// encryption key entity via <c>AddVellumEncryptionKeys(this)</c>, which pulls
/// the <see cref="VellumEntityFrameworkOptions"/> from the
/// <see cref="DbContextOptionsBuilder"/> that was configured with
/// <see cref="VellumDbContextOptionsBuilderExtensions.UseVellum{TContext}"/>
/// in <c>Program.cs</c> — no literal duplication.
/// </summary>
public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<SecretNote> SecretNotes => Set<SecretNote>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);

        modelBuilder.AddVellumEncryptionKeys(this);

        modelBuilder.Entity<SecretNote>(entity =>
        {
            entity.ToTable("secret_notes");
            entity.HasKey(n => n.Id);
            entity.Property(n => n.Ciphertext).IsRequired();
            entity.Property(n => n.Nonce).IsRequired();
            entity.Property(n => n.WrappedCiphertext).IsRequired();
            entity.Property(n => n.WrappedProviderVersion).IsRequired().HasMaxLength(512);
            entity.Property(n => n.KeyId).IsRequired();
            entity.Property(n => n.Scope).IsRequired().HasMaxLength(256);
        });
    }
}
