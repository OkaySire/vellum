# Review Phase 1.1 + 1.2 — GO-WITH-FIXES

Date: 2026-04-09
Reviewer: csharp-developer agent via orchestrator

**Verdict**: GO-WITH-FIXES. Premiere sortie du nouveau runtime = qualite production.

---

## Ce qui est excellent (ne pas regresser)

- Build propre : 0 warnings, 0 errors, multi-target net8/9/10, `TreatWarningsAsErrors=true`, analyzers `AllEnabledByDefault`
- Les 12 lecons encodees dans les analyzers (pas juste documentees) :
  - `CA2007=error` (L5 ConfigureAwait)
  - `CA1848=error` (L10 LoggerMessage)
  - `CA1852=warning` (L12 sealed)
  - `var=error` (L11 explicit types)
- XML docs exhaustifs avec `<remarks>` pour les invariants securite, references croisees vers `tasks/lessons.md` L1/L2/L3 directement dans les contrats
- Scope opaque `string` partout — zero fuite de `BusInstanceId`/`OrganizationId`
- Records tous `sealed`, one type per file, zero `var`
- Conformite parfaite aux 12 lecons

---

## CRITIQUES — a fixer AVANT de commencer Core

### C1 — Version = 1.0.0 au lieu de 0.1.0-preview
**Fichier** : `Directory.Build.props` (metadata group, 23-37)
**Probleme** : Aucun `<Version>`, `<VersionPrefix>`, ou `<VersionSuffix>` declare. MSBuild tombe sur le defaut `1.0.0`. Le nupkg genere s'appelle `Vellum.Abstractions.1.0.0.nupkg`. Si `dotnet pack` accidentel → version brulee sur NuGet.
**Fix** : ajouter dans `Directory.Build.props` :
```xml
<VersionPrefix>0.1.0</VersionPrefix>
<VersionSuffix>preview.1</VersionSuffix>
```

### C2 — Source Link declare mais JAMAIS reference
**Fichiers** :
- `Directory.Packages.props:24-26` declare `Microsoft.SourceLink.GitHub 8.0.0`
- `src/Vellum.Abstractions/Vellum.Abstractions.csproj` ne reference JAMAIS le package

**Probleme** : `<PublishRepositoryUrl>true</PublishRepositoryUrl>` et `<EmbedUntrackedSources>true</EmbedUntrackedSources>` dans `Directory.Build.props:34-35` sont dead code sans Source Link actif. Les `.snupkg` shippes permettent le step-into IL mais PAS les fichiers `.cs` originaux depuis GitHub.
**Fix** : ajouter dans `Directory.Build.props` :
```xml
<ItemGroup Condition="'$(IsPackable)' == 'true'">
  <PackageReference Include="Microsoft.SourceLink.GitHub" PrivateAssets="All" />
</ItemGroup>
```

### C3 — EncryptedPayload n'est plus self-contained
**Fichier** : `src/Vellum.Abstractions/EncryptedPayload.cs:22-26`
**Probleme** : Le record n'a PAS de champ `WrappedDek`. Seulement `KeyId`. Upstream (`jacqcloud-buses/.../EncryptedPayload.cs:3-7`) avait `EncryptedDek` embarque directement. Les envelopes etaient self-contained : provider KEK seul suffit pour decrypt.

Pire : la XML doc `EncryptedPayload.cs:14` liste "wrapped DEK or a reference via KeyId" mais le record literallement n'a ni l'un ni l'autre des formats envelope-standards.

Forcer un lookup `IEncryptionKeyStore` a chaque decrypt :
- Casse l'abstraction AWS Encryption SDK / Tink style
- Force un round-trip DB par decrypt (ou duplication de `IDekManager` cache dans chaque consumer)
- Rend impossible les scenarios "decrypt portable" (envoyer une envelope par email, la decrypter ailleurs avec juste le KEK provider)

**Fix** : ajouter `WrappedKey WrappedDek` dans `EncryptedPayload`. Le `KeyId` peut rester pour audit/rotation tracking, mais `WrappedDek` devient source of truth pour decrypt.

### C4 — Asymetrie encrypt/decrypt
**Fichiers** : `src/Vellum.Abstractions/IPayloadEncryptor.cs:30,42` + `EncryptedPayload.cs`
**Probleme** :
- `EncryptedPayload` expose `NonceBase64` (string)
- `IPayloadEncryptor.DecryptAsync` prend `byte[] nonce` (raw)
- Encrypt path (`PayloadEncryptionResult`) retourne `byte[] Nonce` (raw)
- PAS d'overload `DecryptAsync(EncryptedPayload, ct)`

Resultat : l'envelope canonique ne peut pas etre passee directement au decrypt. Consumer force de convertir entre formats a la main. `PayloadEncryptionResult` et `EncryptedPayload` deviennent redondants et confus.

**Fix** : signatures symetriques :
```csharp
Task<EncryptedPayload> EncryptAsync(ReadOnlyMemory<byte> plaintext, string scope, CancellationToken ct = default);
Task<byte[]> DecryptAsync(EncryptedPayload payload, CancellationToken ct = default);
```
Retirer `PayloadEncryptionResult` (ou le positionner comme optimisation interne binaire). Overloads string en extension methods par-dessus.

---

## MAJEURES — a fixer pendant Phase 1.3 Core

### M1 — GetDekByKeyIdAsync sans scope
**Fichier** : `src/Vellum.Abstractions/IDekManager.cs:57`
**Probleme** : `GetDekByKeyIdAsync(Guid keyId)` sans parametre `scope`. `IEncryptionKeyStore.GetByIdAsync` pareil. Multi-tenant : un tenant pourrait decrypter les payloads d'un autre en devinant un `Guid`.
**Fix** : ajouter `string scope` + verification avant retour, OU documenter explicitement que `KeyId` est une capability et que le scope check est au call site.

### M2 — Pas de TimeProvider / IClock abstrait
**Probleme** : `EncryptionKey.CreatedAt` / `ExpiresAt` vont etre construits via `DateTimeOffset.UtcNow` dans Core. Tests deterministes impossibles. Property-based tests Phase 5 impossibles.
**Fix** : utiliser `System.TimeProvider` (built-in net8+, pas de package supplementaire). Documenter la registration DI.

### M3 — Pas de IRandomBytesProvider
**Probleme** : Nonce generation va appeler `RandomNumberGenerator.Fill` directement dans `PayloadEncryptor`. Impossible de tester les invariants d'unicite des nonces en property-based.
**Fix** : abstraire :
```csharp
public interface IRandomBytesProvider
{
    void Fill(Span<byte> destination);
}
```
Implementation par defaut wrappe `RandomNumberGenerator.Fill`. Tests substituent un counter deterministe.

### M4 — Pas de support binary plaintext
**Fichier** : `src/Vellum.Abstractions/IPayloadEncryptor.cs:30`
**Probleme** : Seul `string plaintext` supporte. Upstream `IEncryptionService.EncryptAsync(byte[] plaintext, ...)` supportait le binaire. Use cases reels : files, protobuf, BSON → force base64 (+33% overhead).
**Fix** : remplacer par `ReadOnlyMemory<byte>` comme primaire, extensions string par-dessus.

### M5 — Types de retour inconsistents dans IDekManager
**Fichier** : `src/Vellum.Abstractions/IDekManager.cs:27,57`
**Probleme** : `GetActiveDekAsync` retourne `ActiveDek` (contient KeyId), `GetDekByKeyIdAsync` retourne juste `byte[]`. Asymetrique.
**Fix** : soit renommer `ActiveDek` → `Dek` et l'utiliser partout, soit unifier avec un record `Dek(byte[] Key, Guid KeyId)`.

### M6 — Pas de ActiveExistsAsync predicate
**Fichier** : `src/Vellum.Abstractions/IEncryptionKeyStore.cs`
**Probleme** : Le pattern double-check race-safe fait 2 reads complets dans le happy path. Un `Task<bool> ActiveExistsAsync(scope, ct)` serait plus leger pour le check d'existence.
**Fix** : optionnel, defer possible.

### M7 — Tous en Task<T>, pas ValueTask<T>
**Fichier** : Tous les 4 interfaces, notamment `IDekManager.GetActiveDekAsync/GetDekByKeyIdAsync`
**Probleme** : Cache hits dans `DekManager` sont le hot path et sync. `Task<ActiveDek>` alloue par call meme en cache hit. A haut QPS, mesurable.
**Fix** : `ValueTask<T>` sur les methodes cache-first. Documenter l'attente "cache-hit-is-sync" dans XML.

### M8 — Pas de projet tests/Vellum.Abstractions.Tests
**Probleme** : `tests/` vide. Meme un smoke test minimal validerait l'infrastructure de test multi-target avant que Core ne landing.
**Fix** : ajouter `tests/Vellum.Abstractions.Tests/` avec 5 tests smoke (value equality, null guards, loadable sur chaque TFM) AVANT Phase 1.3.

### M9 — EncryptionKey.WrappedDek mal aligne avec WrappedKey
**Fichier** : `src/Vellum.Abstractions/EncryptionKey.cs:28`
**Probleme** : `EncryptionKey` stocke `string WrappedDek` + `int ProviderVersion` flat, alors que `WrappedKey` (qui est ce que `IKeyEncryptionProvider.WrapAsync` retourne) contient les deux. Divergence entre les 2 representations. Mismatches silencieux possibles.
**Fix** : `EncryptionKey.WrappedDek` devient `WrappedKey WrappedKey` — single source of truth.

### M10 — IsEnabled perdu depuis upstream
**Probleme** : `jacqcloud-buses/.../IPayloadEncryptor.cs:7` a `bool IsEnabled { get; }`. Vellum l'a perdu. Utilise pour le feature flag "encryption on/off" par deploiement. Bloque le dogfood Jacquouille Phase 2.
**Fix** : soit restaurer `IsEnabled`, soit documenter "Vellum est toujours on, si vous ne voulez pas d'encryption, n'appelez pas". Le dernier est plus clean mais casse la migration upstream.

---

## MINEURES — nice to have

### N1 — UnwrapAsync retourne byte[]
Envisager `OwnedKey : IDisposable` qui zero-out on dispose. Defer.

### N2 — Pas de doc cancellation
Aucune interface ne documente comment les implementations throwent sur `CancellationToken`. Ajouter `<exception cref="OperationCanceledException">`.

### N3 — .editorconfig manque des regles analyzer utiles
- `CA1062=error` (validate public args)
- `CA2016=error` (forward CancellationToken)
- `CA1849=error` (call async methods when in async)
- `CA1305=error` (specify IFormatProvider)

### N4 — RotateDekAsync retourne Task, pas Task<ActiveDek>
Apres rotation, le caller veut la nouvelle DEK active. Retourner la nouvelle epargne un `GetActiveDekAsync` redondant.

### N5 — EncryptionKey.IsActive mutable semantics
Documenter explicitement que `EncryptionKey` est un snapshot immutable. Pour rotation, creer une nouvelle instance.

### N6 — Vellum.slnx manque tests/ et samples/
Declarer les 2 dossiers maintenant meme vides.

### N7 — csproj minimal
Ajouter `<PackageReleaseNotes>See CHANGELOG.md</PackageReleaseNotes>` et `<NeutralLanguage>en</NeutralLanguage>`.

### N8 — CRITIQUE pour portabilite cloud : int ProviderVersion
**Fichier** : `src/Vellum.Abstractions/EncryptionKey.cs:29` + `WrappedKey.cs:22-23`
**Probleme** : `int ProviderVersion` est Vault-shaped (numerique). AWS KMS retourne des ARN, Azure KV retourne des URLs avec GUID, GCP KMS retourne des resource paths. `int` ne survivra pas a ces providers.
**Fix** : changer en `string ProviderVersion` pour genericite.

### N9 — Exceptions documentees incompletes
**Fichier** : `src/Vellum.Abstractions/IKeyEncryptionProvider.cs:36-37,46-47`
Documenter aussi `OperationCanceledException` et `CryptographicException`.

### N10 — Naming constants desaligne avec regle globale
**Fichier** : `.editorconfig:104-110`
Regle globale utilisateur : "`_camelCase` pour private, `PascalCase` pour public". Le `.editorconfig` force `PascalCase` pour toutes les constantes. Surfacera quand Core aura des `const int _nonceSize = 12;` style.
**Fix** : aligner l'editorconfig avec la regle globale.

---

## Missing pieces — a creer avant ou pendant Core

| Item | Pour quoi |
|------|-----------|
| `TimeProvider` ou `IClock` | Construction `EncryptionKey.CreatedAt/ExpiresAt` dans Core |
| `IRandomBytesProvider` | Generation nonces dans `PayloadEncryptor` |
| `VellumOptions` shape | Phase 1.3 todo mentionne `DekCacheTtl`, pas encore d'options sketchees |
| `tests/Vellum.Abstractions.Tests` | Smoke tests pour valider l'infra test avant Core |
| `WrappedKey` ↔ `EncryptionKey` reconciliation | C3 + M9 |
| `EncryptedPayload.WrappedDek` field | C3 |
| Source Link `<PackageReference>` | C2 |
| `<VersionPrefix>` | C1 |
| Dossiers `tests/` et `samples/` dans slnx | N6 |

---

## Conformite lecons

| Lecon | Compliance | Notes |
|-------|-----------|-------|
| L1 — IgnoreQueryFilters | ✅ | `IEncryptionKeyStore.cs:11-17` explicite avec cross-ref lessons.md |
| L2 — Race-safe creation | ✅ | `IEncryptionKeyStore.cs:46-58` + `IDekManager.cs:14-19` |
| L3 — Cloned arrays | ✅ | `ActiveDek.cs:14-18` mandate clone-before-return |
| L4 — No custom crypto | ✅ | Zero crypto dans Abstractions, README + SECURITY.md restent |
| L5 — ConfigureAwait(false) | ✅ analyzer | `.editorconfig:76` CA2007=error |
| L6 — Fail closed | ✅ | Documente dans les 3 interfaces principales |
| L7 — Static warnings | n/a | Phase 1.5 |
| L8 — One type per file | ✅ | 9 fichiers, 9 types, noms matchent |
| L9 — Primary constructors | n/a | Pas de classes DI dans Abstractions |
| L10 — LoggerMessage | n/a enforced | `.editorconfig:79` CA1848=error pour futur |
| L11 — No var | ✅ | Enforced + zero usage manuel |
| L12 — Sealed by default | ✅ | 5 records sealed, CA1852=warning |

---

## Action plan Phase 1.3

1. **Fix C1-C4 AVANT de toucher Core** — C3 surtout, car Core sera ecrit sur les structures actuelles
2. **Pendant Core, integrer les M1-M10** au fur et a mesure — ce ne sont pas des reworks complets
3. **Creer `tests/Vellum.Abstractions.Tests` smoke** avant Core landing
4. **Ajouter `TimeProvider` et `IRandomBytesProvider` abstractions** comme pre-requis Core
5. **Ne PAS regresser** sur les bons points : analyzers stricts, XML docs, scope opaque, sealed, one-per-file
