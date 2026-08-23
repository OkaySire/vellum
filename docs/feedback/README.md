# Retours d'intégration

Rapports écrits par des équipes qui intègrent Vellum, **conservés datés et non modifiés**.

## Pourquoi les garder

Un rapport de première intégration ne se reproduit pas. Il est écrit par quelqu'un qui ne connaît pas
encore la bibliothèque, au moment où les frictions mordent — et cette ignorance est précisément ce
qu'on ne peut plus simuler une fois qu'on la connaît. Le corriger après coup, ou le résumer en une
liste de tickets, détruit la seule chose qu'il apporte.

⇒ Donc : **on ne les édite pas**, même quand les points sont réglés. On ajoute l'état de suivi à côté.

## Rapports

| date | intégrateur | version évaluée | suivi |
|---|---|---|---|
| 2026-07 | `jacqcloud-buses` | 0.1.0-preview.1 | [état ci-dessous](#suivi--2026-07-jacqcloud-buses) |

---

## Suivi — 2026-07 `jacqcloud-buses`

Dix demandes concrètes, classées par valeur par l'auteur. État mesuré dans `main` au 2026-08-23
(0.2.0) :

| # | demande | état |
|---|---|---|
| 1 | publier un dossier `samples/` | ✅ six échantillons |
| 2 | quickstart dans le README (remplacer « coming soon ») | ✅ `## Quickstart` |
| 3 | surcharges de noms de colonnes | ✅ `VellumEntityFrameworkOptionsAttribute` (`TableName`, `IsActiveColumnName`, …) |
| 4 | documenter le motif « chiffrement derrière un drapeau » | ✅ `samples/FeatureFlagged` |
| 5 | cache de DEK au déchiffrement | ✅ `VellumDekCache` + `samples/CachingDecrypt` |
| 6 | documenter le pont d'options consommateur → Vellum | ✅ `docs/consumer-options-bridging.md` |
| 7 | API fluide `VellumBuilder` pour `AddVellum` | ❌ absent |
| 8 | versionner l'entité EF (`SchemaVersion`) | ❌ absent |
| 9 | source d'options de `AddVellumEncryptionKeys` depuis l'injection | ✅ prend le `DbContext` |
| 10 | livrer `Vellum.Rotation` et `Vellum.AspNetCore` | ◐ `Vellum.Rotation` existe, `Vellum.AspNetCore` non |

⇒ **Sept sur dix traitées**, dont les deux que l'auteur décrivait comme les plus coûteuses : le
« plus gros accroc de l'intégration » (#9) et le « plus gros manque fonctionnel » (#5).

⇒ **Trois restent ouvertes** — #7, #8, et la moitié de #10. Aucune n'a été refusée ; elles n'ont
simplement pas encore été faites, et ce tableau est le seul endroit où elles sont écrites.

### ⚠️ Ce rapport a failli disparaître

Il vivait sur `feature/vellum-migration` dans `jacqcloud-buses`, branche fermée le 2026-08-23 — à
raison, la migration ayant atterri autrement. Le fichier n'existait nulle part ailleurs et la branche
distante était supprimée ; `backend` l'a extrait d'une branche locale qui survivait encore, et l'a
proposé plutôt que de le garder dans un `tasks/` gitignoré.

⇒ **Un retour d'intégration ne doit pas vivre dans le dépôt de l'intégrateur.** Il y est attaché au
travail qui l'a produit, donc supprimé avec lui. Sa place est chez le destinataire, versionné — d'où
ce dossier.
