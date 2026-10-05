# RTK × GCP — Catalogue de scénarios de test (lab sandbox)

> Tous les scénarios supposent : exécution de RTK **en local**, cible déployée sur un **projet GCP sandbox dédié**, `scope.yaml` listant ce projet, et nettoyage systématique après la fenêtre d'engagement.

## Vue d'ensemble

| # | Module RTK | Item GCP ciblé | Sévérité typique du finding |
| --- | --- | --- | --- |
| 1 | `buckets.enum_buckets` (RTK-04) | Bucket GCS public (`allUsers:objectViewer`) | high |
| 2 | `buckets.cors_traversal` (RTK-05) | Mini API Cloud Run devant des fichiers (CORS + traversée) | high / critical |
| 3 | `gis_meteo.ogc_anonymous_access` (RTK-20) | GeoServer sur Cloud Run, couche nommée « sensible » | high |
| 4 | `secrets.multi_repo_scan` (RTK-01) | Dépôt Cloud Source Repositories avec clé de SA committée | critical |
| 5 | `secrets.error_leakage` (RTK-02) | Cloud Run / Cloud Functions renvoyant des stack traces en 500 | high |
| 6 | `iam.wildcard_policies` (RTK-07) | Export JSON d'un rôle IAM GCP personnalisé trop permissif | high |
| 7 | `network.external_surface` (RTK-08) | Sous-domaine Cloud Run exposant un endpoint MCP/WMS oublié | medium / high |
| 8 | `llm_mcp.tool_poisoning_watch` (RTK-13) | Serveur MCP (FastMCP) sur Cloud Run, dérive de schéma d'outil | info/high |
| 9 | `llm_mcp.exfil_channels` (RTK-14) | Même serveur MCP, outil `http_get` sans allowlist de sortie | critical |

Les scénarios 1 à 3 ont été détaillés plus haut dans la conversation (bucket public, CORS/traversée, WMS anonyme) — ils ne sont pas repris ici en intégral, seulement rappelés dans le tableau ci-dessus pour la vue d'ensemble.

---

## 4. `secrets.multi_repo_scan` — clé de service account committée puis supprimée

**Description.** `gitleaks` scanne l'historique Git complet (y compris les commits supprimés). Scénario classique : un développeur commit une clé JSON de service account, s'en rend compte, et fait un nouveau commit qui la supprime — en pensant le secret disparu.

**Cible GCP à déployer :**

```bash
# Créer un repo Cloud Source Repositories de lab
gcloud source repos create lab-rtk-secrets --project=VOTRE_PROJET_GCP_SANDBOX

# Créer une clé de SA factice dédiée au lab (jamais une vraie clé de prod)
gcloud iam service-accounts create lab-decoy-sa --project=VOTRE_PROJET_GCP_SANDBOX
gcloud iam service-accounts keys create decoy-key.json \
  --iam-account=lab-decoy-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com

git clone https://source.developers.google.com/p/VOTRE_PROJET_GCP_SANDBOX/r/lab-rtk-secrets
cd lab-rtk-secrets
cp ../decoy-key.json config/credentials.json
git add . && git commit -m "add gcp credentials (oops)"
git rm config/credentials.json
git commit -m "remove credentials"   # <- le secret reste dans l'historique
git push origin main

# IMPORTANT : révoquer/supprimer la clé réelle côté IAM tout de suite après,
# le but est de tester la détection du commit, pas de laisser une clé active.
gcloud iam service-accounts keys delete <KEY_ID> \
  --iam-account=lab-decoy-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com
```

**Shell RTK :**

```bash
git clone https://source.developers.google.com/p/VOTRE_PROJET_GCP_SANDBOX/r/lab-rtk-secrets repos/lab-rtk-secrets

poetry run rtk run secrets.multi_repo_scan \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --repos-dir repos/
```

(nécessite le binaire `gitleaks` dans le `PATH`)

**Logs côté cible :** Cloud Logging → `resource.type="audited_resource"` pour les événements `google.devtools.source.v1.*`, ou simplement l'historique des pushs dans la console Cloud Source Repositories.

---

## 5. `secrets.error_leakage` — stack trace exposant une ARN/clé dans une 500

**Description.** Le module fuzze une liste d'endpoints avec des payloads malformés (JSON invalide, injection SQL basique, header forgé, payload surdimensionné) et grep les réponses 5xx à la recherche de secrets (clé API GCP `AIza...`, ARN AWS, chemins `/etc/secrets/`, patterns génériques `password=`/`token=`).

**Cible GCP à déployer :** Cloud Run (ou Cloud Functions) avec le mode debug Flask laissé actif par erreur.

```python
# app.py — fixture de lab volontairement mal configurée
from flask import Flask, request
app = Flask(__name__)

FAKE_API_KEY = "AIzaSyDECOY1234567890abcdefghijklmno12"  # valeur factice, pas une vraie clé

@app.route("/process", methods=["POST"])
def process():
    data = request.get_json()  # lève une exception si JSON invalide -> stack trace exposée
    return {"id": data["id"]}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)  # <- la faute : debug=True en "prod"
```

```bash
gcloud run deploy error-leak-lab \
  --source . --region europe-west1 --allow-unauthenticated \
  --set-env-vars "GCP_API_KEY=$FAKE_API_KEY" \
  --labels redteam=authorized,engagement=eng-2026-lab-gcp
```

**Shell RTK :**

```bash
poetry run rtk run secrets.error_leakage \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --endpoints "https://error-leak-lab-xxxxx-ew.a.run.app/process"
```

**Logs côté cible :** `gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="error-leak-lab" AND severity>=ERROR'` — vous y verrez les tracebacks Flask correspondant aux 4 payloads de fuzzing envoyés.

---

## 6. `iam.wildcard_policies` — rôle IAM GCP personnalisé trop permissif

**Description.** Ce module est cloud-agnostique : il lit des fichiers JSON de policies au format IAM (`Statement`/`Action`/`Resource`) dans un répertoire local et flague les wildcards dangereux. Il n'appelle aucune API cloud. Pour un lab GCP, l'astuce consiste à exporter un **rôle personnalisé** GCP et à le reformater dans le schéma attendu par le module (style AWS), ou à committer volontairement une policy Terraform/JSON mal conçue destinée à GCP.

**Cible GCP à déployer :**

```bash
cat > role-def.yaml << 'EOF'
title: "LabOverPermissiveRole"
stage: "GA"
includedPermissions:
  - "*"
EOF
gcloud iam roles create labOverPermissive \
  --project=VOTRE_PROJET_GCP_SANDBOX --file=role-def.yaml
```

**Configuration RTK** — reformater la policy exportée au format attendu par le module (`Statement[].Action[]`, `Resource[]`) :

```bash
mkdir policies
cat > policies/lab-role.json << 'EOF'
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["*"],
      "Resource": ["*"]
    }
  ]
}
EOF
```

**Shell RTK :**

```bash
poetry run rtk run iam.wildcard_policies \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --policies-dir policies/
```

**Logs côté cible :** ce scan est purement local (pas de requête réseau vers GCP), donc pas de log GCP à consulter côté scan lui-même — en revanche, `gcloud logging read 'protoPayload.methodName="google.iam.admin.v1.CreateRole"'` montre la création du rôle de lab, utile pour la traçabilité de l'engagement.

---

## 7. `network.external_surface` — endpoint MCP oublié sur un sous-domaine

**Description.** Énumère les sous-domaines (via `subfinder`, si installé) puis fingerprint chaque endpoint trouvé pour détecter un serveur MCP, une API LLM ou un service WMS exposé par erreur.

**Cible GCP à déployer :**

```bash
# Mapper un sous-domaine custom vers un service Cloud Run (nécessite un domaine vérifié)
gcloud run domain-mappings create \
  --service=geoserver-lab \
  --domain=forgotten-wms.votredomaine-lab.example.com \
  --region=europe-west1
```

Réutilisez aussi `legacy-tile-server` (scénario 2) ou `geoserver-lab` (scénario 3) comme cibles de fingerprinting — le module est conçu pour (re)découvrir des services que vous avez déjà déployés mais "oubliés".

**Shell RTK :**

```bash
poetry run rtk run network.external_surface \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --domains "votredomaine-lab.example.com"
```

> Le domaine doit figurer dans `scope.yaml → domains`.

**Logs côté cible :** logs Cloud Run du service mappé (mêmes requêtes `gcloud logging read` que pour les scénarios 2/3).

---

## 8 & 9. `llm_mcp.tool_poisoning_watch` + `llm_mcp.exfil_channels` — serveur MCP sur Cloud Run

**Description commune.** Les deux modules ciblent un serveur MCP exposé en HTTP/JSON-RPC (`tools/list`, `tools/call`) :

- RTK-13 détecte une dérive de schéma d'un outil entre deux scans (baseline vs courant) — utile pour simuler un *tool poisoning* après coup.
- RTK-14 teste si un outil `http_get` exposé par le serveur MCP peut être détourné pour exfiltrer des données vers une URL arbitraire.

**Cible GCP à déployer :** petit serveur MCP de lab (ex. basé sur `fastmcp`) exposant un outil `http_get` sans allowlist de domaines de sortie — représentatif d'un garde-fou manquant.

```python
# mcp_server.py — fixture de lab
from fastmcp import FastMCP
import httpx

mcp = FastMCP("lab-mcp-server")

@mcp.tool()
def http_get(url: str) -> str:
    # Vulnérabilité volontaire : aucune vérification de domaine de sortie
    return httpx.get(url, timeout=5.0).text[:500]

if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8080)
```

```bash
gcloud run deploy mcp-lab \
  --source . --region europe-west1 --allow-unauthenticated \
  --labels redteam=authorized,engagement=eng-2026-lab-gcp
```

**Shell RTK — RTK-13 (baseline puis re-scan après modification du serveur) :**

```bash
# Premier passage : établit la baseline
poetry run rtk run llm_mcp.tool_poisoning_watch \
  --target "$TARGET" --scope scope.yaml --db ./missions/eng-001.db --mission-id $MISSION_ID \
  --mcp-endpoint "https://mcp-lab-xxxxx-ew.a.run.app" --baseline-file baseline.json

# Modifiez la description/schéma de l'outil http_get dans mcp_server.py, redéployez, puis :
poetry run rtk run llm_mcp.tool_poisoning_watch \
  --target "$TARGET" --scope scope.yaml --db ./missions/eng-001.db --mission-id $MISSION_ID \
  --mcp-endpoint "https://mcp-lab-xxxxx-ew.a.run.app" --baseline-file baseline.json
```

**Shell RTK — RTK-14 (le `listener_url` doit être déclaré dans `scope.yaml → domains`) :**

```bash
# Déployer un listener de lab (ex: webhook.site privé ou un second Cloud Run minimal qui logue les requêtes)
poetry run rtk run llm_mcp.exfil_channels \
  --target "$TARGET" --scope scope.yaml --db ./missions/eng-001.db --mission-id $MISSION_ID \
  --mcp-endpoint "https://mcp-lab-xxxxx-ew.a.run.app" \
  --listener-url "https://votredomaine-lab.example.com/collector"
```

**Logs côté cible :** logs Cloud Run du service `mcp-lab`, + logs du listener pour confirmer la réception effective du callback d'exfiltration (preuve que `http_get` a bien fait sortir la requête).

---

## Modules non applicables à un lab 100 % GCP

| Module | Raison |
| --- | --- |
| `iam.privesc_paths` (RTK-06) | Code `boto3`/AWS IAM explicite ; retourne vide (`skip_non_aws`) si `target.cloud != "aws"`. |
| `audit.mttd_closed_loop` | Corrèle les findings avec AWS CloudTrail via `boto3` ; aucun équivalent GCP (Cloud Audit Logs) codé dans ce module en l'état. |

Ces deux modules restent utiles si vous testez un jour une architecture multi-cloud incluant un compte AWS réel dans le scope.

---

## Rappel : hygiène de lab

- Un seul projet GCP **sandbox**, jamais de données réelles.
- Toutes les ressources labellisées `redteam=authorized` + `engagement=<id>` pour un nettoyage facile (`gcloud ... list --filter="labels.engagement=eng-2026-lab-gcp"`).
- `scope.yaml` à jour (`authorized_modules`, fenêtre temporelle) avant chaque nouvelle série de tests.
- Suppression des ressources et révocation des clés de service account factices en fin de session.