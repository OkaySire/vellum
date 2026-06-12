using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Vellum;
using Vellum.EntityFrameworkCore;
using Vellum.Rotation;
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
    opts.KeyName = builder.Configuration["Vault:KeyName"] ?? "vellum-sample-kek";

    // Auth: a fixed dev token by default; AppRole when Vault:AuthMethod=AppRole.
    // Prefer AppRole in production — tokens are re-acquired automatically instead of
    // expiring into a silent outage. Wire RoleId/SecretId via environment variables
    // (Vault__RoleId / Vault__SecretId) or a secret store, NEVER appsettings.json —
    // see the README's "Production auth: AppRole" section for the vault CLI setup.
    string authMethod = builder.Configuration["Vault:AuthMethod"] ?? nameof(VaultAuthMethod.Token);
    if (string.Equals(authMethod, nameof(VaultAuthMethod.AppRole), StringComparison.OrdinalIgnoreCase))
    {
        opts.AuthMethod = VaultAuthMethod.AppRole;
        opts.RoleId     = builder.Configuration["Vault:RoleId"]   ?? string.Empty;
        opts.SecretId   = builder.Configuration["Vault:SecretId"] ?? string.Empty;
    }
    else
    {
        opts.Token = builder.Configuration["Vault:Token"] ?? "dev-root";
    }

    // Dev-only: this sample talks to a local `vault server -dev` over plain HTTP on
    // loopback. NEVER set this in production — the Vault token and plaintext DEKs
    // would travel in cleartext. Use an https:// address instead.
    opts.AllowInsecureHttp = opts.Address.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
});

// 4. Background DEK rotation (Vellum.Rotation). Deliberately sample-friendly timings so
//    you can SEE a rotation happen while playing with the sample (README: "Watch a
//    rotation happen"): first tick ~10 s after start, then every minute, rotating any
//    active DEK older than 2 minutes. Production defaults are 24 h interval / 24 h max
//    DEK age / 1 min startup delay — just call AddVellumRotation() with no delegate.
builder.Services.AddVellumRotation(opts =>
{
    opts.RotationInterval = TimeSpan.FromMinutes(1);
    opts.MaxDekAge        = TimeSpan.FromMinutes(2);
    opts.StartupDelay     = TimeSpan.FromSeconds(10);
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

// -----------------------------
// Admin: the per-scope rewrap steps of the KEK-rotation runbook (docs/kek-rotation.md)
// as runnable code. In production both endpoints would sit behind authorization — they
// are open here only because the sample has no auth stack at all.
// -----------------------------

// Runbook step 2: rewrap the scope's STORED keys (active + historical) under the KEK
// provider's current key version, via Transit's /rewrap — plaintext DEKs never leave
// Vault. Idempotent: re-run the sweep until "failed" is 0.
app.MapPost("/admin/rewrap/{scope}", async (
    string scope,
    [FromServices] VellumRewrapService rewrapService) =>
{
    RewrapScopeResult result = await rewrapService.RewrapStoredKeysAsync(scope);
    return Results.Ok(result);
});

// Runbook step 3: every persisted envelope embeds its OWN copy of the wrapped DEK, so
// rewrapping the key store is not enough — each `secret_notes` row needs
// RewrapPayloadAsync too. Only the wrapped DEK changes; ciphertext, nonce, key id and
// format version are untouched. Idempotent: safe to re-run after a partial failure.
app.MapPost("/admin/rewrap-notes/{scope}", async (
    string scope,
    [FromServices] IPayloadEncryptor encryptor,
    [FromServices] AppDbContext db) =>
{
    List<SecretNote> notes = await db.SecretNotes
        .Where(n => n.Scope == scope)
        .ToListAsync();

    foreach (SecretNote note in notes)
    {
        EncryptedPayload envelope = new(
            Ciphertext: note.Ciphertext,
            Nonce: note.Nonce,
            WrappedDek: new WrappedKey(note.WrappedCiphertext, note.WrappedProviderVersion),
            KeyId: note.KeyId,
            FormatVersion: note.FormatVersion);

        EncryptedPayload rewrapped = await encryptor.RewrapPayloadAsync(envelope);

        note.WrappedCiphertext = rewrapped.WrappedDek.Ciphertext;
        note.WrappedProviderVersion = rewrapped.WrappedDek.ProviderVersion;
    }

    await db.SaveChangesAsync();
    return Results.Ok(new { Scope = scope, RewrappedNotes = notes.Count });
});

app.Run();

public sealed record CreateNoteRequest(string Text);
