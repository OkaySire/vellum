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

### L16 — Typed HttpClient expose via bridge : Transient, pas Singleton

**Contexte** : En Phase 1.4 (Vellum.Vault), le brief de l'orchestrateur recommandait de bridger
`IKeyEncryptionProvider` vers le typed client `VaultKeyEncryptionProvider` via
`services.TryAddSingleton<IKeyEncryptionProvider>(sp => sp.GetRequiredService<VaultKeyEncryptionProvider>())`.
Problème : `AddHttpClient<TClient>` enregistre `TClient` en **Transient** pour une raison
précise — la rotation des handlers. `IHttpClientFactory` rotate l'inner `HttpMessageHandler`
toutes les 2 minutes par défaut (pour repérer les changements DNS). Si on capture un
`VaultKeyEncryptionProvider` singleton, il conserve à vie le `HttpClient` qui pointe vers un
handler qui sera un jour disposed (ou pointera vers une IP DNS périmée).

**Regle** : Le bridge doit respecter le lifetime du typed client. Comme
`AddHttpClient<TClient>` enregistre `TClient` transient, on fait
`services.TryAddTransient<IKeyEncryptionProvider>(sp => sp.GetRequiredService<VaultKeyEncryptionProvider>())`.
Chaque résolution via le DI obtient une nouvelle instance du provider avec un `HttpClient`
frais de la factory.

**Application** : `src/Vellum.Vault/VaultServiceCollectionExtensions.cs:56` — deviation
documentée du brief. Même pattern pour AzureKeyVault / AwsKms / GcpKms (Phase 3) :
typed HttpClient + bridge transient, jamais singleton.

**Rationale** : Le pattern "inject HttpClient via typed client" est fondamentalement transient.
Singleton + typed client = mémoire qui explose (via handler pool rétention) ou DNS obsolète.
Si un futur besoin exige singleton (par ex. état coûteux à construire), alors injecter
`IHttpClientFactory` et `CreateClient()` à chaque appel — mais pas via le pattern typed.

---

### L17 — `Uri.ToString()` décanonicalise `%20` → espace (piège de test d'URL)

**Contexte** : Un test Phase 1.4 vérifiait que `Uri.EscapeDataString("my key/with spaces")`
produit `my%20key%2Fwith%20spaces` dans l'URL envoyée à Vault. Le test comparait
`request.RequestUri!.ToString()` à `"http://vault.test:8200/v1/transit/encrypt/my%20key%2Fwith%20spaces"`
et échouait parce que `Uri.ToString()` affichait `"my key%2Fwith spaces"` — les `%20` avaient
été décodés en espaces littéraux pour l'affichage, tandis que `%2F` (slash) restait escape
parce que `/` est un caractère réservé du path.

**Regle** : Pour vérifier la forme **on-the-wire** d'une URL dans un test, toujours utiliser
`Uri.AbsoluteUri` (ou `Uri.PathAndQuery` pour la partie relative), **jamais** `Uri.ToString()`.
`ToString()` est le formulaire d'affichage humain qui canonicalise les sequences %HH "sures".

**Application** : `tests/Vellum.Vault.Tests/VaultKeyEncryptionProviderTests.cs:112` —
`handler.CapturedRequests[0].RequestUri!.AbsoluteUri.Should().Be(...)` et non `.ToString()`.

**Rationale** : Ce qui compte en sécurité URL est la forme envoyée sur le réseau, pas
l'affichage. `AbsoluteUri` garantit la forme encodée identique à ce que le serveur reçoit.
Si un test passe avec `ToString()`, il ne valide rien du comportement réel du client HTTP.

---

### L18 — `TryAddEnumerable` factory-overload = "indistinguishable" error

**Contexte** : En Phase 1.5 (Vellum.Static), pour contourner CA1812 sur `StaticOptionsValidator`
(internal class non-détecté comme instancié par l'analyzer), j'ai tenté la factory-overload :
```csharp
services.TryAddEnumerable(
    ServiceDescriptor.Singleton<IValidateOptions<StaticOptions>>(_ => new StaticOptionsValidator()));
```
L'analyzer voyait le `new`, CA1812 était heureux. Mais à l'exécution, `TryAddEnumerable` jette
`System.ArgumentException: Implementation type cannot be 'IValidateOptions<StaticOptions>'
because it is indistinguishable from other services registered for 'IValidateOptions<StaticOptions>'.`

**Regle** : `TryAddEnumerable` **exige** un `implementationType` distinct (type-parameter overload
`TryAddEnumerable(ServiceDescriptor.Singleton<TService, TImpl>())` ou
`ServiceDescriptor.Singleton<TService>(typeof(TImpl))`). Il utilise
`ImplementationType` pour dédupliquer les registrations et la factory-overload laisse ce champ
null — rendant la registration "indistinguable" des autres et refusée.

**Application** : pour contourner CA1812 sur un validator DI-instancié, utiliser la type-param
overload et suppresser CA1812 via `[SuppressMessage("Performance", "CA1812", Justification = …)]`
sur la classe validator. Voir `src/Vellum.Static/Internal/StaticOptionsValidator.cs` et la
registration dans `StaticServiceCollectionExtensions.cs`.

**Rationale** : `TryAddEnumerable` est conçu pour les patterns "plusieurs implémentations distinctes
du même service" (e.g. plusieurs `IValidateOptions<T>`) et la déduplication repose sur le type
concret. Une factory anonyme n'a pas d'identité typée — le container ne peut pas savoir si une
factory équivalente existe déjà et il refuse plutôt que de permettre des doublons silencieux.

---

### L19 — Namespace `Vellum.Static` et CA1716 (VB keyword collision)

**Contexte** : Le package `Vellum.Static` fait collision avec le keyword VB `Static`. CA1716
déclenche au build. On ne peut pas renommer le package (le nom est visible aux consommateurs
et communique l'intention "dev-only"), et on ne peut pas renommer que la namespace sans rendre
le DI moins évident (`Vellum.Providers.Static.AddStaticProvider` reste collision-aware).

**Regle** : Quand un nom de package contient intentionnellement un mot réservé d'un autre
langage .NET (VB, F#, …), suppresser CA1716 via `<NoWarn>$(NoWarn);CA1716</NoWarn>` au
niveau du csproj et documenter le raisonnement dans un commentaire XML du même bloc.
Ne PAS suppresser globalement dans `Directory.Build.props` — la suppression doit rester
locale au package concerné.

**Application** : `src/Vellum.Static/Vellum.Static.csproj` `<NoWarn>` avec commentaire explicite.

**Rationale** : CA1716 protège la cohabitation cross-langage, mais pour les packages dev-only
où le nom porte un message sémantique (`Vellum.Static` = « attention dev »), le wart d'interop
VB est accepté. La suppression locale évite de relaxer la règle globalement.

---

### L20 — Tester `ValidateOnStart()` sans dépendance Microsoft.Extensions.Hosting

**Contexte** : En Phase 1.5, vouloir tester que `ValidateOnStart()` est correctement câblé
dans l'extension DI. Le réflexe est de créer un `HostApplicationBuilder` et d'appeler `host.StartAsync()` —
mais cela fait dépendre le projet de test de `Microsoft.Extensions.Hosting` (un gros package
avec Hosted Services, Lifetime, etc.), ajoutant une dépendance non-nécessaire à un projet de test
unitaire qui ne veut tester qu'une chose : "la validation run-on-start est câblée".

**Regle** : Tester `ValidateOnStart()` via `IStartupValidator` directement, sans Host :
```csharp
using ServiceProvider sp = services.BuildServiceProvider();
IStartupValidator validator = sp.GetRequiredService<IStartupValidator>();
Action act = validator.Validate;
act.Should().Throw<OptionsValidationException>();
```
`IStartupValidator` est public dans `Microsoft.Extensions.Options` (pas `Hosting`). Il est enregistré
par `.ValidateOnStart()` et est exactement ce que `HostedServiceExecutor` appelle au démarrage.
Pas de Host = test isolé, pas de surface de dépendance.

**Application** : `tests/Vellum.Static.Tests/StaticServiceCollectionExtensionsTests.cs`
`AddStaticProvider_ValidateOnStart_RegistersStartupValidator`.

**Rationale** : Le test valide le contrat ("cette extension appelle `.ValidateOnStart()`")
et le comportement observable ("l'IStartupValidator jette sur config invalide"), sans ramener
toute la machinerie de Hosting. Plus rapide à compiler, plus facile à comprendre, et portable
à tout projet de test qui ne veut pas `Microsoft.Extensions.Hosting`.

---

### L21 — SQLite `:memory:` partage via `SqliteConnection` unique : impossible en concurrent DbContext

**Contexte** : En Phase 1.7 (Vellum.EntityFrameworkCore), le test critique `ConcurrentCreateAsync_SameScope_OnlyOneWinner_ViaUniqueIndex` lance 8 stores en parallele pour prouver que le filtered unique index + DbUpdateException catch + re-read winner tient sous la course. Premiere tentative : une seule `SqliteConnection` en `:memory:` partagee entre tous les contextes. Echec : `SqliteException Error 5 "unable to delete/modify user-function due to active statements"`. EF Core's `SqliteRelationalConnection` appelle `CreateFunction` pour enregistrer ses fonctions custom a chaque initialisation de context ; quand plusieurs contextes se bootstrap en parallele sur la meme connexion, le 2e `CreateFunction` se heurte aux statements actifs du 1er.

Deuxieme tentative : `Data Source=file:vellum-test-{Guid}?mode=memory&cache=shared` avec connection-per-context. Echec : `SqliteException Error 1 "no such table"`. Le mode `cache=shared` de Microsoft.Data.Sqlite a des quirks avec le connection pool et ne route pas systematiquement deux connexions distinctes vers la meme db in-memory.

Troisieme tentative (celle qui marche) : fichier temporaire sur disque, `Data Source={tempPath};Pooling=False`, chaque `TestDbContext` ouvre sa propre connexion au meme fichier. SQLite gere nativement N connexions sur un fichier, les schemas sont stables, le temp file est efface en `DisposeAsync` apres `SqliteConnection.ClearAllPools()`.

**Regle** : Pour tester de la vraie concurrence EF Core sur SQLite, utiliser un fichier temporaire partage entre contextes, pas `:memory:`. `:memory:` marche tres bien pour un seul context mais pas pour du concurrent multi-context. Le cout disk I/O d'un temp SQLite est negligeable pour un test unitaire.

**Application** : `tests/Vellum.EntityFrameworkCore.Tests/Fixtures/TestHarness.cs` — le harness cree un `Path.GetTempPath()/vellum-test-{Guid}.sqlite`, le partage entre tous les contextes, et le supprime en dispose. `Pooling=False` + `SqliteConnection.ClearAllPools()` garantissent que le handle est relache avant le `File.Delete`.

**Rationale** : SQLite est fundamentally une lib mono-connexion pour `:memory:` (la db "appartient" a la connexion). Les tests unitaires de concurrence ont besoin de multi-connexion, donc il faut un fichier. Le temp file se detruit automatiquement, c'est transparent, et ca reproduit fidelement le comportement concurrent de n'importe quel autre provider relationnel.

---

### L22 — `IModelCacheKeyFactory` unique-par-appel casse les concurrents EF Core

**Contexte** : En Phase 1.7, pour permettre a differents tests d'utiliser des `VellumEntityFrameworkOptions` differentes sur le meme `TestDbContext` CLR type, premiere tentative : injecter un `IModelCacheKeyFactory` qui retourne un `Guid.NewGuid()` a chaque appel, forcant EF Core a rebuild le modele par context. Les tests sequentiels passent tous. Mais le test concurrent (8 contextes en parallele partageant le meme temp file) echoue avec `no such table`.

Cause racine : quand chaque DbContext doit rebuild son model from scratch sous charge concurrente, EF Core semble perdre la synchronisation avec l'etat du schema physique. Le model rebuild n'est pas une operation pure — il touche le service provider interne et interagit avec le query compiler cache. Sous concurrence, au moins un des contextes voit un model/schema desynchronises et jette `no such table` alors que le fichier contient bien la table.

**Regle** : Ne PAS utiliser un `IModelCacheKeyFactory` qui retourne une cle unique a chaque appel dans les tests qui exercent de la concurrence EF Core. Le model cache est la pour une raison. Si un test a besoin d'options differentes, **creer une autre classe `DbContext`** — EF Core cache le model par CLR type, donc deux types donnent deux models isoles sans casser le cache ni la concurrence.

**Application** : `tests/Vellum.EntityFrameworkCore.Tests/Fixtures/FilterOverrideTestDbContext.cs` — classe dediee au test `VellumEntityFrameworkOptions_FilterOverride_AppliedToModel`, avec son propre slot statique `VellumOptions`. Le `TestDbContext` principal garde ses options constantes, ce qui permet au model cache de fonctionner normalement et au test concurrent de passer.

**Rationale** : Le model cache est critique dans EF Core. Tout mecanisme qui le contourne (factory non-deterministe, reflection sur le ModelBuilder, etc.) expose des races que l'equipe EF Core n'a jamais eu a considerer parce que le model est concu pour etre construit une fois par type. La bonne granularite d'isolation pour des options EF differentes = une classe DbContext par configuration, pas un cache factory custom.

---

### L23 — EF Core `EF1001` analyzer se declenche sur nos propres `.Internal.*` namespaces

**Contexte** : En Phase 1.7, l'internal entity `EncryptionKeyRecord` est place dans `Vellum.EntityFrameworkCore.Internal` (convention .NET pour "ne pas consommer depuis l'exterieur"). Le projet de source compile propre. Les tests, qui consomment ce type via `InternalsVisibleTo`, jettent `warning EF1001: Vellum.EntityFrameworkCore.Internal.EncryptionKeyRecord is an internal API that supports the Entity Framework Core infrastructure and not subject to the same compatibility standards as public APIs.`

Cause : l'analyzer EF Core `InternalUsageDiagnosticAnalyzer` checke conventionnellement tout type dont le namespace contient `.Internal.` ou se termine par `.Internal`, pour proteger les consommateurs des internes EF Core eux-memes. La regle tire faussement sur les internals de notre propre package quand ils sont consommes depuis un autre assembly (comme un projet de test).

**Regle** : Supprimer `EF1001` localement dans les projets qui consomment legitimement leurs propres types internes via `InternalsVisibleTo`. La suppression doit rester locale (csproj du projet concerne, pas `Directory.Build.props`) pour ne pas masquer des usages fautifs des vrais internes EF Core ailleurs dans la solution.

**Application** : `tests/Vellum.EntityFrameworkCore.Tests/Vellum.EntityFrameworkCore.Tests.csproj` — `<NoWarn>$(NoWarn);...;EF1001</NoWarn>` avec commentaire expliquant pourquoi.

**Rationale** : L'alternative serait de renommer le namespace pour eviter la convention (`.Persistence`, `.Storage`, ...). Mais `.Internal` porte un message semantique correct pour d'autres consommateurs (IDE, outils d'analyse, conventions .NET generales) et perdre ce signal pour contourner une regle d'analyzer est un mauvais trade.

---

### L14 — ProviderVersion doit etre `string`, pas `int`, pour portabilite cloud

**Regle** : Tout champ qui identifie une version/ARN/path d'une cle KEK doit etre `string`, jamais `int`. Les providers cloud ne rentrent pas dans un int :
- HashiCorp Vault Transit : `"1"`, `"2"`, ... (ok pour int, mais on paye le cast)
- AWS KMS : ARN complet (`arn:aws:kms:us-east-1:111122223333:key/abc-def-123`)
- Azure Key Vault : URL avec GUID (`https://kv.vault.azure.net/keys/my-key/0123456789abcdef0123456789abcdef`)
- GCP KMS : resource path (`projects/proj/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1`)

**Application** : `WrappedKey.ProviderVersion` et toute propriete equivalente sont `string ProviderVersion`. Le champ est opaque : Vellum le round-trip verbatim au provider sans jamais le parser.

**Rationale** : Un `int` verrouille Vellum a Vault. Un `string` ouvre la porte a tous les providers cloud sans breaking change. Decouvrir ca apres coup = breaking change public + migration guide. Decouvrir ca en Phase 1.2 = 1 commit trivial.
