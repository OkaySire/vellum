# Vellum — Lessons learned

Lecons heritees du travail sur `jacqcloud-buses` (source du code) et leçons propres a Vellum.

---

## Heritees de jacqcloud-buses (DEK/KEK fix v0.1.60-v0.1.63)

### L1 — `IgnoreQueryFilters()` est obligatoire sur les lectures DEK

**Contexte** : `GetActiveAsync` etait la seule methode de lecture sans `.IgnoreQueryFilters()`. Quand le catch-23505 (unique violation) re-lisait la cle du gagnant, le tenant query filter pouvait retourner null, faisant croire qu'il n'y avait pas de DEK actif.

**Regle** : **TOUTES** les lectures dans `IEncryptionKeyStore` EF Core doivent utiliser `IgnoreQueryFilters()`. Les DEKs sont infrastructure, pas domaine — ils ne doivent JAMAIS etre filtres par tenant query filter.

**Application** : dans `Vellum.EntityFrameworkCore`, chaque query doit chainer `.IgnoreQueryFilters()` avant `.FirstOrDefaultAsync()`.

---

### L2 — Race conditions sur DEK creation necessitent 4 couches de defense (ou advisory lock)

**Contexte** : Deux requetes paralleles sur le meme scope peuvent tenter de creer un DEK simultanement. L'evolution des defenses :
- v0.1.60 : catch 23505 (unique violation) + re-read winner
- v0.1.61 : detach failed entity from DbContext
- v0.1.62 : double-check before INSERT
- v0.1.63 : IgnoreQueryFilters (ROOT CAUSE, voir L1)

**Regle** : Pour v0.1 de Vellum, garder les 4 couches de defense (elles ont fait leurs preuves). Pour v1.0, evaluer `pg_advisory_xact_lock` qui remplacerait elegamment les 4 couches par un lock distribue.

**Application** : dans `EfCoreEncryptionKeyStore.CreateAsync`, pattern :
```csharp
// 1. Double-check : est-ce qu'un DEK actif existe deja ?
// 2. INSERT avec try/catch sur DbUpdateException (23505)
// 3. En cas de 23505 : Detach l'entite failed du DbContext
// 4. Re-read le gagnant avec IgnoreQueryFilters()
```

---

### L3 — Memory zeroing requires cloned arrays

**Contexte** : Si on retourne directement le `byte[] Key` cache depuis `GetActiveDekAsync`, et que le caller zero-out le key, le cache est corrompu. Les prochains callers recoivent un tableau de zeros.

**Regle** : Toujours cloner les byte arrays sensibles avant de les retourner depuis un cache. Le caller est libre de zero-out sa copie sans impact sur le cache.

**Application** : dans `DekManager.GetActiveDekAsync`, retourner `new ActiveDek((byte[])cachedKey.Clone(), keyId)`.

---

## Propres a Vellum

### L4 — Ne JAMAIS inventer de crypto

**Regle** : Vellum n'implemente aucune primitive cryptographique. Uniquement `System.Security.Cryptography.AesGcm`. Si quelqu'un suggere "implementons X parce que c'est plus efficace", la reponse est NON.

**Rationale** : Les bugs crypto sont catastrophiques et silencieux. Le seul moyen de ne pas en ecrire est de ne pas ecrire de crypto.

---

### L5 — `ConfigureAwait(false)` partout dans le code library

**Regle** : Vellum est une bibliotheque, pas une application. Chaque `await` doit utiliser `.ConfigureAwait(false)` pour eviter le sync context deadlock dans les consumers (particulierement les legacy ASP.NET apps).

---

### L6 — Fail closed, jamais fail open

**Regle** : Si Vellum ne peut pas resoudre une cle, wrap ou unwrap, il doit throw. Jamais retourner le plaintext ou silently skip l'encryption.

**Rationale** : Un fail open donne l'illusion que l'encryption fonctionne alors que les donnees sont en clair. C'est pire que pas d'encryption du tout parce que ca donne une fausse confiance.

---

### L7 — `Vellum.Static` doit crier qu'il est insecure

**Regle** : Le provider `StaticKeyEncryptionProvider` est pour dev uniquement. Il doit :
- XML doc avec `<remarks>` en majuscules : "INSECURE, DEVELOPMENT USE ONLY"
- Log un warning au demarrage quand instancie
- README avec encart rouge avertissement
- Jamais etre le provider par defaut

---

### L8 — One type per file, file name matches type name

**Regle** : Chaque fichier `.cs` contient exactement UN type public (class, record, struct, interface). Le nom du fichier correspond exactement au nom du type.

**Application** : Pas de `Interfaces.cs` avec plusieurs interfaces dedans. Chaque interface dans son propre fichier.

---

### L9 — Primary constructors partout ou possible

**Regle** : C# 12+ primary constructors pour toutes les classes avec dependencies. Pas de `private readonly ILogger<X> _logger; public X(ILogger<X> logger) { _logger = logger; }`.

**Pattern** :
```csharp
public sealed partial class DekManager(
    IKeyEncryptionProvider provider,
    IEncryptionKeyStore store,
    IMemoryCache cache,
    ILogger<DekManager> logger) : IDekManager
{
    // methods
}
```

---

### L10 — LoggerMessage source generators, jamais `_logger.LogXxx(...)` direct

**Regle** : Toutes les classes qui loggent utilisent `[LoggerMessage]` attribute. Aucun appel direct a `_logger.LogInformation(...)` etc.

**Pattern** :
```csharp
public sealed partial class DekManager : IDekManager
{
    [LoggerMessage(Level = LogLevel.Information, Message = "Creating new DEK for scope {Scope}")]
    private static partial void LogCreatingDek(ILogger logger, string scope);
}
```

---

### L11 — NEVER use `var`, always explicit types

**Regle** : Types explicites partout. Pas de `var`, meme pour les types evidents.

**Rationale** : Les review sont plus faciles, les diffs plus clairs, les erreurs de type visibles immediatement.

---

### L12 — Sealed by default

**Regle** : Chaque class est `sealed` sauf justification explicite. Vellum ne supporte pas l'heritage de ses implementations — les consumers doivent implementer les interfaces, pas heriter des classes.

---

### L13 — Records avec `byte[]` : equality manuelle obligatoire

**Regle** : Un `record` qui contient un champ `byte[]` (ou `Memory<byte>`) ne peut PAS se reposer sur l'equality auto-generee du compilateur. Le compilateur compare les byte[] par reference (`ReferenceEquals`), ce qui donne des faux negatifs : deux instances avec le meme contenu ne sont pas egales.

**Application** : Override `Equals(T?)` et `GetHashCode()` manuellement, en utilisant :
- `field.AsSpan().SequenceEqual(other.field)` pour comparer les byte[]
- `HashCode.AddBytes(field)` pour hasher les byte[] (net6+)

**Exemple dans Vellum** : `EncryptedPayload` (cf. `src/Vellum.Abstractions/EncryptedPayload.cs`) a `byte[] Ciphertext` et `byte[] Nonce`. Sans override, le test `EncryptedPayload_ValueEquality_StructuralOverByteArrays` echoue parce que deux envelopes avec ciphertext identique mais instances byte[] differentes ne seraient pas egales.

**Rationale** : Les envelopes, identifiants, hash, etc. sont des value objects par definition. Si on les serialise/deserialise depuis une DB, les byte[] sont des nouvelles instances. L'equality de reference cree des bugs silencieux dans les caches, les tests, les Equals-based collections.

---

### L15 — Cache by opaque identifier doit etre partitionne par scope

**Contexte** : `DekManager` caches unwrapped DEKs both by `scope` (for `GetActiveDekAsync`)
and by `keyId` (for `GetDekByKeyIdAsync`). A first implementation used `$"dek-by-id:{keyId}"`
as the cache key — no scope inside. Consequence: if tenant A fetches keyId X for scope
`tenant:A`, that unwrapped DEK ends up in the cache. If tenant B later calls
`GetDekByKeyIdAsync(X, "tenant:B")`, the cache hit fires BEFORE the scope check, and the
method returns a plaintext DEK belonging to another tenant. The scope check on the slow path
is not enough — the fast path short-circuits it.

**Regle** : Tout cache qui indexe par identifiant opaque dans un contexte multi-tenant
**doit** inclure le scope dans la cle de cache, pas seulement verifier le scope sur la
slow path. Pour Vellum, c'est : `$"vellum:dek:id:{scope}:{keyId}"`.

**Application** : `DekManager.BuildKeyIdCacheKey(Guid keyId, string scope)` inclut le scope
— voir le test `GetDekByKeyIdAsync_CacheKey_IsScopePartitioned` qui pin le contrat.

**Rationale** : Les lookups par identifiant sont vulnerables au guessing. Meme si un attaquant
ne peut pas lire la DB pour extraire un `keyId`, un leak via logs / metrics / debug dumps / URLs
est realiste. Si le cache est scope-partitionne, un attaquant qui devine le keyId d'un autre
tenant ne peut **pas** le recuperer — le cache va miss, la store va miss (elle verifie aussi
le scope), et la requete echoue fail-closed.

---

### L14 — ProviderVersion doit etre `string`, pas `int`, pour portabilite cloud

**Regle** : Tout champ qui identifie une version/ARN/path d'une cle KEK doit etre `string`, jamais `int`. Les providers cloud ne rentrent pas dans un int :
- HashiCorp Vault Transit : `"1"`, `"2"`, ... (ok pour int, mais on paye le cast)
- AWS KMS : ARN complet (`arn:aws:kms:us-east-1:111122223333:key/abc-def-123`)
- Azure Key Vault : URL avec GUID (`https://kv.vault.azure.net/keys/my-key/0123456789abcdef0123456789abcdef`)
- GCP KMS : resource path (`projects/proj/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1`)

**Application** : `WrappedKey.ProviderVersion` et toute propriete equivalente sont `string ProviderVersion`. Le champ est opaque : Vellum le round-trip verbatim au provider sans jamais le parser.

**Rationale** : Un `int` verrouille Vellum a Vault. Un `string` ouvre la porte a tous les providers cloud sans breaking change. Decouvrir ca apres coup = breaking change public + migration guide. Decouvrir ca en Phase 1.2 = 1 commit trivial.
