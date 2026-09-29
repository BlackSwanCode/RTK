# Rapport technique — Red Team Toolkit (RTK)
### Synthèse v1 + v2 pour démarrage de développement, complétée par une revue de l'implémentation V4/V5
**Date :** 28 septembre 2026 (synthèse initiale) — mise à jour 29 septembre 2026 (revue du code livré)

> **Note sur cette mise à jour.** Les sections 1 à 6 ci-dessous constituent le rapport initial (analyse des documents v1/v2, avant tout code). Une nouvelle section 7 a été ajoutée après revue du dépôt effectivement livré (version 0.5.0, tag interne « V4/V5 ») : elle documente ce qui a été implémenté par rapport à la matrice des 20 vecteurs, et liste les écarts constatés entre les recommandations initiales et le code actuel.

---

## 1. Résumé exécutif

Les deux documents fournis sont cohérents et complémentaires :

- **v1** définit le **protocole** — cadre méthodologique (RoE, phases de mission), 8 domaines de sécurité (secrets, buckets, IAM, réseau, LLM/MCP, code source, audit, conformité GIS/Météo), et une **matrice de 20 vecteurs de test** (RTK-01 à RTK-20) servant de backlog.
- **v2** transforme ce backlog en **guide de développement** : architecture cible, schéma de données unifié (Findings Store), spécification module par module, planning de sprints.

Le projet est un **toolkit d'audit offensif défensif** (Red Team) ciblant une infrastructure cloud AWS/GCP hébergeant des services GIS/Météo avec une architecture LLM+MCP. Aucune ambiguïté sur l'usage : chaque module est explicitement cadré par des RoE (Rules of Engagement), des garde-fous anti-production, et une distinction claire simulation/attaque réelle.

**Verdict sur la v2** : l'analyse critique qu'elle fait de la v1 est juste (absence de contrats d'interface, sous-spécification du vecteur GIS/Météo, ordre de développement du Findings Store). Ce rapport reprend son architecture comme base de référence et l'enrichit là où des zones grises subsistent avant codage.

---

## 2. Ce qui est déjà bien spécifié (v2) — à ne pas re-discuter

| Élément | Statut |
|---|---|
| Arborescence du dépôt (`rtk/core`, `modules`, `harness`, `corpus`, `proxy`, `reporting`) | ✅ Prête à l'emploi |
| Stack technique (Python 3.11+, Poetry, Typer, Pydantic v2, Rich) | ✅ Cohérente, pas de changement recommandé |
| Schéma `Finding` (Pydantic) | ✅ Bonne base — voir §4 pour compléments |
| Ordre de développement (Findings Store en premier) | ✅ Confirmé, correct |
| Découpage des 20 modules RTK-01→20 | ✅ Correct, aligné sur la matrice v1 |
| Planning en 5 sprints | ✅ Réaliste comme point de départ |

---

## 3. Zones à clarifier avant le sprint S1

Ce sont les points où v1/v2 laissent une ambiguïté d'implémentation qui coûterait cher à corriger après coup.

### 3.1 Scope parser — format d'entrée non défini
v2 mentionne un "Parseur Rules of Engagement" mais ne précise ni le format ni le schéma. Recommandation :
- Format YAML unique (`scope.yaml`) versionné avec le corpus, validé par un modèle Pydantic `ScopeDefinition` contenant : `accounts` (AWS account IDs / GCP project IDs autorisés), `domains`, `ip_ranges`, `excluded_resources`, `engagement_window` (start/end), `kill_switch_contacts`, `authorized_modules` (liste blanche de RTK-XX activables), `env_tag_required` (ex : `env=redteam-test` — condition bloquante, cf. alerte senior #2 de la v2).
- Chaque module actif doit valider son `target` contre ce scope **avant** toute exécution, pas seulement au démarrage du harnais — sinon un run multi-cibles peut déraper sur une ressource hors scope en cours d'exécution.

### 3.2 Findings Store — précisions manquantes sur le schéma
Le schéma `Finding` de la v2 est fonctionnel mais incomplet pour un usage multi-mission :
- Ajouter `mission_id` (uuid) pour cloisonner les findings entre engagements — actuellement rien n'empêche un mélange de données entre deux clients.
- `evidence_ref` pointe vers un "blob chiffré" mais le mécanisme de clé n'est pas défini : préciser dès S1 si la clé de chiffrement est dérivée du `mission_id` (recommandé, permet la purge par simple suppression de clé plutôt que réécriture de la base).
- `correlation: dict` est trop peu typé pour un champ qui alimente directement RTK-18 (MTTD) — définir un sous-modèle `CorrelationRefs {cloudtrail_event_id, audit_log_id, mcp_session_id, mcp_call_id}`.

### 3.3 Proxy MCP — mode `poison` et double vérification d'environnement
La v2 identifie elle-même le risque majeur (alerte senior #2) : un mauvais routage réseau pourrait exposer le mode `poison` à un environnement de production. Ceci doit être un item de code, pas seulement une note :
- Le proxy doit **refuser de démarrer** en mode `poison` ou `enforce` si le tag `env` (AWS) / label `environment` (GCP) de la cible ne correspond pas exactement à une valeur allowlistée dans le scope (`env=redteam-test` par exemple), vérifiée par un appel API réel (pas une simple lecture de config statique) à chaque connexion, pas seulement au démarrage.
- Ce contrôle doit lui-même écrire un finding `info` de confirmation à chaque session — traçabilité du garde-fou lui-même.

### 3.4 RTK-10/11 — génération du corpus indirect métier
C'est le point que la v2 identifie comme le plus différenciant mais elle ne livre qu'un seul exemple (GeoJSON). Avant le sprint S2, il faut décider :
- Qui écrit les générateurs de payloads par format (GeoJSON, GML, TIFF/NetCDF metadata, WMS legend, CSV) — compétence mixte sécurité + formats géospatiaux, probablement le goulot d'étranglement du planning.
- Un format de corpus commun (le YAML proposé est bon) mais il manque un champ `harm_category` ou `technique` pour permettre l'agrégation de résultats par technique d'attaque (utile pour le rapport final et pour suivre l'évolution des garde-fous dans le temps).

### 3.5 RTK-17 (dependency confusion) — statut de développement
La v2 pose correctement le risque juridique mais ce module devrait être **développé désactivé par défaut**, avec un flag explicite `--i-have-written-authorization` requis en plus de l'autorisation RoE générale, et un test qui vérifie que le nom de package canary n'entre en collision avec aucun package public existant avant publication (pas seulement "non guessable" — vérifiable automatiquement via une requête à l'index PyPI).

---

## 4. Schéma `Finding` révisé (proposition de départ pour S1)

```python
# core/findings/schema.py
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID
from pydantic import BaseModel

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class Exploitability(str, Enum):
    confirmed = "confirmed"
    probable = "probable"
    theoretical = "theoretical"

class Target(BaseModel):
    cloud: str  # "aws" | "gcp"
    account_id: str
    region: str | None = None
    resource_arn: str | None = None

class AttackSpec(BaseModel):
    payload: str
    request: dict | None = None
    headers: dict | None = None
    technique: str | None = None  # ex: "prompt_injection.indirect.geojson"

class Observed(BaseModel):
    summary: str          # tronqué à 4 Ko
    full_hash: str         # SHA-256 du contenu complet
    tool_calls_triggered: list[str] = []

class CorrelationRefs(BaseModel):
    cloudtrail_event_id: str | None = None
    audit_log_id: str | None = None
    mcp_session_id: str | None = None
    mcp_call_id: str | None = None

class Finding(BaseModel):
    id: UUID
    mission_id: UUID
    timestamp_utc: datetime
    module: str
    vector: str  # référence matrice v1, ex: "11"
    severity: Severity
    exploitability: Exploitability
    simulated_attack: bool
    target: Target
    attack: AttackSpec
    observed: Observed
    expected_defense: str
    defense_bypassed: bool
    evidence_ref: str | None = None
    correlation: CorrelationRefs = CorrelationRefs()
    mttd: timedelta | None = None
```

---

## 5. Ordre de développement recommandé (affiné vs. planning v2)

| Étape | Contenu | Ajout par rapport à la v2 |
|---|---|---|
| **S0 (pré-sprint, 1-2j)** | `ScopeDefinition` Pydantic + validation CLI (`rtk scope validate`) | Absent de la v2 ; bloquant pour tout module réel |
| **S1** | Findings Store (schéma révisé §4), Logger, RTK-20, RTK-07 | Identique v2 + schéma enrichi |
| **S2** | Proxy MCP avec garde-fou d'environnement en dur (§3.3), RTK-10/11 (corpus initial réduit : 10 cas/catégorie pour valider le pipeline avant scale-up) | Garde-fou anticipé, corpus réduit pour valider la mécanique avant d'investir dans la génération de contenu |
| **S3** | RTK-01, RTK-04, RTK-08, RTK-13 | Identique v2 |
| **S4** | RTK-06, RTK-16, RTK-17 (désactivé par défaut), RTK-12, RTK-14, RTK-15 | RTK-17 isolé derrière son flag |
| **S5** | RTK-18, RTK-19, Reporting, durcissement | Identique v2 |

---

## 6. Prochaine étape suggérée

La v2 proposait de générer le squelette du dépôt (arborescence + fichiers core). Vu les clarifications ci-dessus, l'ordre logique est :

1. Valider/amender le schéma `Finding` révisé (§4) et le format `scope.yaml` (§3.1).
2. Générer le squelette du dépôt avec ces schémas déjà intégrés (Pydantic models, CLI Typer `rtk scope validate` / `rtk run` stubs, config Poetry).
3. Implémenter le Findings Store (SQLCipher) comme premier livrable testable.

Dis-moi si tu veux que je génère directement ce squelette de dépôt.

---

## 7. Revue de l'implémentation livrée (dépôt V4/V5, `pyproject.toml` v0.5.0)

Le squelette suggéré au §6 a bien été généré et largement dépassé : le dépôt livré ne contient pas seulement les fondations (scope, Findings Store, CLI) mais également 10 des 20 modules de la matrice v1, un proxy MCP fonctionnel avec mode `poison`, un harnais de corpus LLM, un coffre-fort de preuves chiffrées et une suite de 24 tests. Cette section fait le point sur ce qui est réellement en place, et sur les écarts par rapport aux recommandations des §3-5.

### 7.1 Couverture de la matrice des 20 vecteurs

| Vecteur | Statut | Module |
|---|---|---|
| RTK-01 (secrets Git) | ✅ Implémenté | `rtk.modules.secrets.multi_repo_scan` (wrapper `gitleaks`) |
| RTK-02 (fuite d'erreurs) | ✅ Implémenté | `rtk.modules.secrets.error_leakage` |
| RTK-03 (extraction secrets via LLM) | ❌ Non implémenté | Identifié comme critique dans *Evolution RTK by Qwen.md* |
| RTK-04 (buckets publics) | ✅ Implémenté | `rtk.modules.buckets.enum_buckets` (AWS/GCP), `azure_enum` (Azure) |
| RTK-05 (CORS/traversée) | ✅ Implémenté | `rtk.modules.buckets.cors_traversal` |
| RTK-06 (privesc IAM) | ✅ Implémenté | `rtk.modules.iam.privesc_paths` |
| RTK-07 (wildcards IAM) | ✅ Implémenté | `rtk.modules.iam.wildcard_policies` |
| RTK-08 (surface externe) | ✅ Implémenté | `rtk.modules.network.external_surface` |
| RTK-09 (contournement WAF) | ❌ Non implémenté | |
| RTK-10/11 (corpus LLM direct/indirect) | ✅ Amorcé | Harnais générique (`harness/corpus_runner.py`) + 2 cas YAML (direct + GeoJSON indirect) — le §3.4 recommandait un corpus élargi par format, non encore livré |
| RTK-12 (agentivité excessive) | ❌ Non implémenté | |
| RTK-13 (dérive schémas d'outils) | ✅ Implémenté | `rtk.modules.llm_mcp.tool_poisoning_watch` |
| RTK-14 (canaux d'exfiltration) | ✅ Implémenté | `rtk.modules.llm_mcp.exfil_channels` |
| RTK-15 (DoS économique) | ❌ Non implémenté | |
| RTK-16 (signature artefacts) | ❌ Non implémenté | |
| RTK-17 (dependency confusion) | ❌ Non implémenté | Le garde-fou `--i-have-written-authorization` recommandé au §3.5 n'a donc pas encore de code à protéger |
| RTK-18 (MTTD) | ✅ Implémenté (partiel) | `rtk.modules.audit.mttd_closed_loop` — boucle de corrélation CloudTrail, AWS uniquement |
| RTK-19 (angles morts journalisation) | ❌ Non implémenté | |
| RTK-20 (OGC anonyme) | ✅ Implémenté | `rtk.modules.gis_meteo.ogc_anonymous_access` |

**Bilan : 10/20 vecteurs couverts**, concentrés sur les domaines secrets, buckets, IAM, réseau (partiel) et LLM/MCP (partiel). Les vecteurs manquants sont exactement ceux identifiés comme prioritaires dans *Evolution RTK by Qwen.md* (RTK-03, RTK-08 était fait, RTK-09, RTK-12, RTK-15, RTK-16, RTK-17, RTK-19) — cette feuille de route reste donc un guide valide pour la suite.

### 7.2 Recommandations du §3 : ce qui a été suivi

| Recommandation (§3) | Statut dans le code livré |
|---|---|
| §3.1 — `ScopeDefinition` Pydantic + `rtk scope validate` | ✅ Fait. `rtk/core/scope/schema.py` + commande `rtk scope`. Validation appelée par `assert_in_scope()` à chaque exécution de module (`rtk run`), pas seulement au démarrage du harnais — conforme à la recommandation. |
| §3.2 — `mission_id` sur `Finding` | ✅ Fait. |
| §3.2 — sous-modèle `CorrelationRefs` typé | ⚠️ Partiel. Le champ `correlation` du schéma livré (`rtk/core/findings/schema.py`) est resté un `dict` libre, pas le sous-modèle Pydantic `CorrelationRefs {cloudtrail_event_id, audit_log_id, mcp_session_id, mcp_call_id}` proposé au §4. À corriger si RTK-18/19 doivent s'appuyer dessus de façon fiable. |
| §3.2 — clé de chiffrement dérivée du `mission_id` | ✅ Fait, mais pas au niveau du Findings Store lui-même — voir §7.3. |
| §3.3 — proxy refuse `poison`/`enforce` sans vérification de tag d'environnement en dur | ✅ Fait pour `poison` (fail-closed, `verify_env_tag`). Le mode `enforce` n'a en revanche pas cette contrainte — il n'en a pas besoin au même degré (bloquant, pas injectant), mais ce n'est pas documenté comme un choix explicite. |
| §3.3 — finding `info` de confirmation du garde-fou à chaque session | ⚠️ Non retrouvé. Le succès de `verify_env_tag()` est journalisé (log JSON) mais n'émet pas de `Finding` dédié dans le Findings Store, contrairement à la recommandation de traçabilité. |
| §3.5 — RTK-17 désactivé par défaut avec flag dédié | — Sans objet : RTK-17 n'est pas encore implémenté. |

### 7.3 Constats sur l'implémentation actuelle (à traiter avant durcissement)

Ces points ont été relevés en lisant le code source livré ; ils n'étaient pas anticipés dans l'analyse v1/v2 initiale.

1. **Collision de module `rtk/core/logging`.** Le dépôt contient à la fois un fichier `rtk/core/logging.py` (formatter JSON simple, sans masquage) et un package `rtk/core/logging/__init__.py` + `logger.py` (formatter avec masquage de secrets AWS/GCP/tokens génériques). Python résout systématiquement l'import vers le **package**, rendant `logging.py` totalement mort (jamais exécuté). Ce n'est pas bloquant fonctionnellement — le formatter avec masquage est bien celui utilisé partout — mais c'est une source de confusion pour la maintenance et doit être nettoyé (suppression du fichier orphelin `logging.py`).

2. **Clé de chiffrement du Findings Store en dur.** `FindingsStore.__init__` utilise par défaut `encryption_key: str = "rtk-dev-key"` (`rtk/core/findings/store.py`). Le mécanisme de dérivation de clé par mission recommandé au §3.2 a bien été implémenté, mais dans `rtk/core/evidence/vault.py` (coffre-fort de preuves, AES-GCM + scrypt) — **pas** dans le Findings Store SQLCipher lui-même, qui reste le stockage principal des `Finding`. Avant tout usage sur des données réelles, la clé SQLCipher doit être externalisée (variable d'environnement ou dérivation par `mission_id`, comme c'est déjà fait pour le vault).

3. **Incohérence potentielle dans `rtk proxy` en mode `poison`.** La commande construit un `Target` synthétique à partir du hostname de l'URL MCP cible (`account_id = hostname sans points, tronqué à 12 caractères`) avant d'appeler `assert_in_scope()`, puis appelle séparément `verify_env_tag()` sur ce même objet. Rien ne garantit que cet `account_id` dérivé corresponde au compte cloud réel hébergeant le serveur MCP visé — la vérification de scope et la vérification de tag portent donc potentiellement sur une identité de compte approximative. Un test existant (`tests/test_v4.py::test_poison_refusal_without_env_tag`) documente déjà cette limite dans son docstring. Recommandation : exiger que `rtk proxy` prenne un `Target` explicite (comme le fait `rtk run`) plutôt que de le déduire de l'URL.

4. **`correlation` non typé** (cf. §7.2) — limite la fiabilité de RTK-18 (MTTD) et du futur RTK-19 (angles morts de journalisation), qui doivent tous deux pouvoir retrouver de façon fiable les références de corrélation (CloudTrail, session MCP) associées à un `Finding`.

5. **Deux schémas `Finding` coexistent dans les documents source** : celui proposé au §4 de ce rapport (avec `CorrelationRefs` typé) et celui réellement implémenté dans `rtk/core/findings/schema.py` (avec `atlas_technique`, `owasp_llm`, `chain_hash`, contrainte de cohérence sur les sévérités hautes). Le schéma implémenté est une évolution légitime et plus riche que la proposition initiale sur certains points (traçabilité MITRE ATLAS / OWASP LLM Top 10, hash chain), mais a abandonné le typage strict de `correlation`. Le §4 de ce rapport doit être considéré comme obsolète et remplacé par une future revue du schéma tel qu'implémenté.

### 7.4 Prochaine étape suggérée (mise à jour)

1. Corriger les points du §7.3, en priorité la clé de chiffrement en dur du Findings Store et la construction du `Target` dans `rtk proxy`.
2. Typer `correlation` en `CorrelationRefs` et faire consommer ce sous-modèle par `audit.mttd_closed_loop`.
3. Poursuivre la couverture de la matrice en suivant les priorités de *Evolution RTK by Qwen.md* : RTK-03 (extraction de secrets via le LLM) et RTK-12 (agentivité excessive) en premier, car ils touchent directement le cœur métier LLM+MCP et bloquent un reporting de mission complet sur ce périmètre.
4. Étendre le corpus `corpus/llm_mcp/` au-delà des deux cas actuels (direct + GeoJSON indirect) avant de considérer RTK-10/11 comme couverts en profondeur.
