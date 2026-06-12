using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Vellum;
using Vellum.EntityFrameworkCore;
using Vellum.Samples.AspNetCorePostgresVault;
using Vellum.Vault;

// ---------------------------------------------------------------------------
// Vellum — ASP.NET Core + Npgsql + Vault Transit sample.
//
// A minimal web app that encrypts and decrypts "secret notes" using Vellum.
// Stack:
//   - AES-GCM via Vellum.Core
//   - HashiCorp Vault Transit as the KEK provider (Vellum.Vault)
//   - PostgreSQL as the key store (Vellum.EntityFrameworkCore + Npgsql)
//
// Run the sample with Vault + Postgres containers (see README.md for the
// docker-compose setup):
//   dotnet run --project samples/AspNetCore.Postgres.Vault
//   curl -X POST http://localhost:5000/notes -d '{"text":"hello"}' -H 'Content-Type: application/json'
//   curl http://localhost:5000/notes/<id>
// ---------------------------------------------------------------------------

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// 1. Database + Vellum EF store. Options flow via UseVellum on the
//    DbContextOptionsBuilder — the OnModelCreating call reads them back with no
//    second literal (issue #9).
string connectionString = builder.Configuration.GetConnectionString("App")
    ?? "Host=localhost;Port=5432;Database=vellum_sample;Username=postgres;Password=postgres";

builder.Services.AddDbContext<AppDbContext>(options => options
    .UseNpgsql(connectionString)
    .UseVellum(v =>
    {
        // Npgsql needs the PostgreSQL spelling of the filter.
        v.UniqueActiveIndexFilter = "\"IsActive\" = true";
        // Optional: rename the table / columns to match a snake_case convention.
        v.TableName = "vellum_encryption_keys";
    }));

builder.Services.AddEntityFrameworkCoreStore<AppDbContext>();

// 2. Vellum core.
builder.Services.AddVellum(opts => opts.DekCacheTtl = TimeSpan.FromMinutes(30));

// 3. HashiCorp Vault Transit KEK.
builder.Services.AddVaultProvider(opts =>
{
    opts.Address = builder.Configuration["Vault:Address"] ?? "http://localhost:8200";
    opts.Token   = builder.Configuration["Vault:Token"]   ?? "dev-root";
    opts.KeyName = builder.Configuration["Vault:KeyName"] ?? "vellum-sample-kek";
    // Dev-only: this sample talks to a local `vault server -dev` over plain HTTP on
    // loopback. NEVER set this in production — the Vault token and plaintext DEKs
    // would travel in cleartext. Use an https:// address instead.
    opts.AllowInsecureHttp = opts.Address.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
});

WebApplication app = builder.Build();

// Ensure schema exists for the sample (do NOT do this in real apps — use
// dotnet ef migrations add + dotnet ef database update).
using (IServiceScope scope = app.Services.CreateScope())
{
    AppDbContext ctx = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await ctx.Database.EnsureCreatedAsync();
}

// -----------------------------
// Minimal API: POST /notes, GET /notes/{id}
// -----------------------------
app.MapPost("/notes", async (
    [FromBody] CreateNoteRequest req,
    [FromServices] IPayloadEncryptor encryptor,
    [FromServices] AppDbContext db) =>
{
    EncryptedPayload envelope = await encryptor.EncryptAsync(
        Encoding.UTF8.GetBytes(req.Text),
        scope: "sample:global");

    SecretNote note = new()
    {
        Id = Guid.NewGuid(),
        Scope = "sample:global",
        Ciphertext = envelope.Ciphertext,
        Nonce = envelope.Nonce,
        WrappedCiphertext = envelope.WrappedDek.Ciphertext,
        WrappedProviderVersion = envelope.WrappedDek.ProviderVersion,
        KeyId = envelope.KeyId,
        FormatVersion = envelope.FormatVersion,
    };
    db.SecretNotes.Add(note);
    await db.SaveChangesAsync();

    return Results.Created($"/notes/{note.Id}", new { note.Id });
});

app.MapGet("/notes/{id:guid}", async (
    Guid id,
    [FromServices] IPayloadEncryptor encryptor,
    [FromServices] AppDbContext db) =>
{
    SecretNote? note = await db.SecretNotes.FindAsync(id);
    if (note is null)
    {
        return Results.NotFound();
    }

    EncryptedPayload envelope = new(
        Ciphertext: note.Ciphertext,
        Nonce: note.Nonce,
        WrappedDek: new WrappedKey(note.WrappedCiphertext, note.WrappedProviderVersion),
        KeyId: note.KeyId,
        FormatVersion: note.FormatVersion);

    // Version 2 envelopes are scope-bound: the same scope used at encryption time is
    // required to decrypt (wrong scope => AES-GCM tag failure, fail closed).
    byte[] plaintext = await encryptor.DecryptAsync(envelope, note.Scope);
    return Results.Ok(new { note.Id, Text = Encoding.UTF8.GetString(plaintext) });
});

app.Run();

public sealed record CreateNoteRequest(string Text);
