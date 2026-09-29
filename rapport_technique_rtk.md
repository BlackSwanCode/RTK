# Rapport technique — Red Team Toolkit (RTK)
### Synthèse v1 + v2 pour démarrage de développement
**Date :** 28 septembre 2026

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
