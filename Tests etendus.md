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
| 10 | `iam.sa_impersonation_chain` (RTK-09) | Chaîne d'usurpation d'identité de compte de service (Token Creator) | critical |
| 11 | `bigquery.public_dataset` (RTK-11) | Dataset BigQuery (logs d'entraînement LLM) accessible à `allUsers` | critical |
| 12 | `vertex_ai.unauthenticated_endpoint` (RTK-12) | Endpoint Vertex AI déployé sans authentification (quota theft / prompt injection) | high |
| 13 | `cloud_sql.public_no_ssl` (RTK-17) | Instance Cloud SQL avec IP publique, réseau 0.0.0.0/0 et SSL non requis | critical |
| 14 | `secret_manager.overexposed_access` (RTK-19) | Rôle `secretAccessor` accordé à `allUsers` ou à un SA trop large | critical |
| 15 | `artifact_registry.public_image` (RTK-16) | Image de conteneur publique contenant des variables d'environnement sensibles | high |
| 16 | `workload_identity.permissive_trust` (RTK-18) | Fédération d'identité avec condition d'attribut trop permissive | critical |
| 17 | `cloud_run.metadata_ssrf` (RTK-21) | SSRF vers `http://metadata.google.internal` pour exfiltrer le jeton du SA | critical |
| 18 | `llm_mcp.command_injection` (RTK-22) | Injection de commande via les arguments d'un outil MCP (ex: `exec_shell`) | critical |
| 19 | `kms.decryptor_wildcard` (RTK-15) | Clé KMS avec `cryptoKeyDecrypter` accordé à `allUsers` ou `allAuthenticatedUsers` | high |
| 20 | `cloud_functions.env_leakage` (RTK-10) | Cloud Function (2nd gen) exposant ses variables d'environnement via une route de santé | high |

## Prérequis communs (scénarios 1 à 20)

```bash
git clone <votre repo> rtk && cd rtk
poetry install --with gcp
gcloud auth login
gcloud config set project VOTRE_PROJET_GCP_SANDBOX
```

`scope.yaml` commun (à compléter dans `authorized_modules` au fur et à mesure) :

```yaml
engagement_id: "ENG-2026-LAB-GCP"
accounts:
  gcp: ["VOTRE_PROJET_GCP_SANDBOX"]
domains: ["votredomaine-lab.example.com"]
ip_ranges: []
excluded_resources: []
engagement_window:
  start: "2026-10-04T00:00:00Z"
  end: "2026-10-18T23:59:59Z"
authorized_modules:
  - "rtk.modules.buckets.enum_buckets"
  - "rtk.modules.buckets.cors_traversal"
  - "rtk.modules.gis_meteo.ogc_anonymous_access"
  - "rtk.modules.secrets.multi_repo_scan"
  - "rtk.modules.secrets.error_leakage"
  - "rtk.modules.iam.wildcard_policies"
  - "rtk.modules.iam.sa_impersonation_chain"
  - "rtk.modules.network.external_surface"
  - "rtk.modules.llm_mcp.tool_poisoning_watch"
  - "rtk.modules.llm_mcp.exfil_channels"
  - "rtk.modules.llm_mcp.command_injection"
  - "rtk.modules.bigquery.public_dataset"
  - "rtk.modules.vertex_ai.unauthenticated_endpoint"
  - "rtk.modules.cloud_sql.public_no_ssl"
  - "rtk.modules.secret_manager.overexposed_access"
  - "rtk.modules.artifact_registry.public_image"
  - "rtk.modules.workload_identity.permissive_trust"
  - "rtk.modules.cloud_run.metadata_ssrf"
  - "rtk.modules.kms.decryptor_wildcard"
  - "rtk.modules.cloud_functions.env_leakage"
env_tag_required: "redteam-test"
```

```bash
mkdir -p missions
poetry run rtk scope scope.yaml
MISSION_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
TARGET='{"cloud":"gcp","account_id":"VOTRE_PROJET_GCP_SANDBOX","region":"europe-west1"}'
```

---

## 10. `iam.sa_impersonation_chain` (RTK-09) — Chaîne d'usurpation d'identité de compte de service

**Description.** Détecte si un compte de service (SA) disposant de droits minimaux possède le rôle `roles/iam.serviceAccountTokenCreator` sur un autre SA disposant de droits élevés (ex: Owner ou Editor), permettant une élévation de privilèges horizontale ou verticale.

**Service à déployer sur GCP :**
```bash
# SA de bas niveau (celui que l'attaquant compromet)
gcloud iam service-accounts create low-priv-sa --display-name="Low Priv SA"

# SA de haut niveau (la cible)
gcloud iam service-accounts create high-priv-sa --display-name="High Priv SA"
gcloud projects add-iam-policy-binding VOTRE_PROJET_GCP_SANDBOX \
  --member="serviceAccount:high-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com" \
  --role="roles/editor"

# La mauvaise config : donner le droit d'usurpation au SA de bas niveau
gcloud iam service-accounts add-iam-policy-binding \
  high-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com \
  --member="serviceAccount:low-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountTokenCreator"
```

**Configuration RTK / shell d'invocation :**
```bash
poetry run rtk run iam.sa_impersonation_chain \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID
```

**Logs côté cible :**
```bash
gcloud logging read 'protoPayload.methodName="google.iam.credentials.v1.GenerateAccessToken"' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=20
```

---

## 11. `bigquery.public_dataset` (RTK-11) — Dataset BigQuery accessible publiquement

**Description.** Identifie les datasets BigQuery contenant des tables sensibles (ex: `training_logs`, `user_pii`, `gis_coordinates`) dont les permissions IAM accordent le rôle `roles/bigquery.dataViewer` à `allUsers` ou `allAuthenticatedUsers`.

**Service à déployer sur GCP :**
```bash
bq mk --dataset --location=EU --description "Lab dataset" VOTRE_PROJET_GCP_SANDBOX:lab_dataset

# Création d'une table factice
echo '{"user_id": 1, "prompt": "secret data"}' > data.json
bq load --source_format=NEWLINE_DELIMITED_JSON VOTRE_PROJET_GCP_SANDBOX:lab_dataset.training_logs data.json

# La mauvaise config : accès public en lecture
bq add-iam-policy-binding VOTRE_PROJET_GCP_SANDBOX:lab_dataset \
  --member="allUsers" \
  --role="roles/bigquery.dataViewer"
```

**Configuration RTK / shell d'invocation :**
```bash
poetry run rtk run bigquery.public_dataset \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --sensitive-patterns "training,pii,secret,coordinates"
```

**Logs côté cible :**
```bash
gcloud logging read 'resource.type="bigquery_dataset" AND protoPayload.methodName="jobservice.jobcompleted"' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=20
```

---

## 12. `vertex_ai.unauthenticated_endpoint` (RTK-12) — Endpoint Vertex AI non authentifié

**Description.** Détecte les endpoints Vertex AI (modèles personnalisés ou foundation models) déployés avec l'option "Allow unauthenticated invocations" activée, exposant le modèle à des attaques par injection de prompt, à l'extraction de modèle ou à un vol de quota.

**Service à déployer sur GCP :**
```bash
# Déploiement d'un modèle factice (ou d'un modèle public comme un petit LLM) avec accès non authentifié
gcloud ai endpoints create --display-name="lab-unauth-endpoint" --region=europe-west1
ENDPOINT_ID=$(gcloud ai endpoints list --region=europe-west1 --format="value(ENDPOINT_ID)" | head -n 1)

# Note: Dans un vrai lab, on déploierait un modèle custom. Ici, on simule la configuration IAM.
gcloud ai endpoints add-iam-policy-binding $ENDPOINT_ID \
  --region=europe-west1 \
  --member="allUsers" \
  --role="roles/aiplatform.user"
```

**Configuration RTK / shell d'invocation :**
```bash
poetry run rtk run vertex_ai.unauthenticated_endpoint \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --region europe-west1
```

**Logs côté cible :**
```bash
gcloud logging read 'resource.type="aiplatform.googleapis.com/Endpoint" AND severity>=WARNING' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=20
```

---

## 13. `cloud_sql.public_no_ssl` (RTK-17) — Instance Cloud SQL exposée sans SSL

**Description.** Recherche les instances Cloud SQL (PostgreSQL/MySQL) configurées avec une adresse IP publique, autorisant les connexions depuis `0.0.0.0/0` et n'exigeant pas de connexions SSL, ce qui permet des attaques par écoute réseau ou brute-force.

**Service à déployer sur GCP :**
```bash
gcloud sql instances create lab-db \
  --database-version=POSTGRES_15 \
  --cpu=1 --memory=4GB \
  --region=europe-west1 \
  --root-password=LabPassword123! \
  --authorized-networks=0.0.0.0/0 \
  --require-ssl=false \
  --labels=redteam=authorized,engagement=eng-2026-lab-gcp
```

**Configuration RTK / shell d'invocation :**
```bash
poetry run rtk run cloud_sql.public_no_ssl \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID
```

**Logs côté cible :**
```bash
gcloud logging read 'resource.type="cloudsql_database" AND protoPayload.methodName="cloudsql.instances.update"' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=10
```

---

## 14. `secret_manager.overexposed_access` (RTK-19) — Accès non restreint aux secrets

**Description.** Vérifie si des secrets dans Secret Manager ont des politiques IAM permettant à `allUsers`, `allAuthenticatedUsers` ou à des comptes de service non liés à l'application d'accéder aux versions des secrets (`roles/secretmanager.secretAccessor`).

**Service à déployer sur GCP :**
```bash
gcloud secrets create lab-api-key --replication-policy="automatic"
echo -n "sk-fake-llm-api-key-12345" | gcloud secrets versions add lab-api-key --data-file=-

# La mauvaise config : accès public au secret
gcloud secrets add-iam-policy-binding lab-api-key \
  --member="allAuthenticatedUsers" \
  --role="roles/secretmanager.secretAccessor"
```

**Configuration RTK / shell d'invocation :**
```bash
poetry run rtk run secret_manager.overexposed_access \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID
```

**Logs côté cible :**
```bash
gcloud logging read 'resource.type="secretmanager.googleapis.com/Secret" AND protoPayload.methodName="google.cloud.secretmanager.v1.AccessSecretVersion"' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=20
```

---

## 15. `artifact_registry.public_image` (RTK-16) — Image de conteneur publique

**Description.** Identifie les dépôts Artifact Registry configurés pour permettre la lecture publique (`roles/artifactregistry.reader` à `allUsers`), risquant d'exposer des images contenant des secrets codés en dur ou des vulnérabilités non corrigées.

**Service à déployer sur GCP :**
```bash
gcloud artifacts repositories create lab-repo \
  --repository-format=docker \
  --location=europe-west1 \
  --description="Lab public repo"

# Push d'une image factice (préalablement buildée localement)
# docker build -t europe-west1-docker.pkg.dev/VOTRE_PROJET_GCP_SANDBOX/lab-repo/vulnerable-app:latest .
# docker push europe-west1-docker.pkg.dev/VOTRE_PROJET_GCP_SANDBOX/lab-repo/vulnerable-app:latest

# La mauvaise config : lecture publique
gcloud artifacts repositories add-iam-policy-binding lab-repo \
  --location=europe-west1 \
  --member="allUsers" \
  --role="roles/artifactregistry.reader"
```

**Configuration RTK / shell d'invocation :**
```bash
poetry run rtk run artifact_registry.public_image \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --region europe-west1
```

---

## 16. `workload_identity.permissive_trust` (RTK-18) — Fédération d'identité mal configurée

**Description.** Analyse les pools d'identité de charge de travail (Workload Identity Federation) pour détecter des conditions d'attribut trop permissives (ex: `google.subject` ou `attribute.repository` non restreints), permettant à un attaquant externe d'usurper l'identité d'un compte de service GCP.

**Service à déployer sur GCP :**
```bash
gcloud iam workload-identity-pools create "lab-pool" \
  --project="VOTRE_PROJET_GCP_SANDBOX" \
  --location="global" \
  --display-name="Lab Pool"

gcloud iam workload-identity-pools providers create-oidc "lab-provider" \
  --project="VOTRE_PROJET_GCP_SANDBOX" \
  --location="global" \
  --workload-identity-pool="lab-pool" \
  --display-name="Lab Provider" \
  --attribute-mapping="google.subject=assertion.sub" \
  --issuer-uri="https://accounts.google.com"

# La mauvaise config : accorder le droit d'usurpation à tout le monde via ce provider
gcloud iam service-accounts add-iam-policy-binding \
  low-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/VOTRE_PROJET_GCP_SANDBOX/locations/global/workloadIdentityPools/lab-pool/*"
```

**Configuration RTK / shell d'invocation :**
```bash
poetry run rtk run workload_identity.permissive_trust \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID
```

---

## 17. `cloud_run.metadata_ssrf` (RTK-21) — SSRF vers le serveur de métadonnées GCP

**Description.** Teste si une application Cloud Run est vulnérable à une attaque SSRF (Server-Side Request Forgery) permettant d'interroger le serveur de métadonnées GCP (`http://metadata.google.internal/computeMetadata/v1/`) pour exfiltrer le jeton d'identité du compte de service attaché.

**Service à déployer sur GCP :**
```bash
# app.py — fixture de lab volontairement vulnérable au SSRF
cat > ssrf_app.py << 'EOF'
from flask import Flask, request, Response
import urllib.request

app = Flask(__name__)

@app.route("/fetch", methods=["GET"])
def fetch():
    url = request.args.get("url", "")
    if not url:
        return "Missing URL", 400
    try:
        # Vulnérabilité : pas de validation de l'URL cible
        req = urllib.request.Request(url, headers={"Metadata-Flavor": "Google"})
        with urllib.request.urlopen(req) as response:
            return Response(response.read(), mimetype="text/plain")
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
EOF

gcloud run deploy ssrf-lab \
  --source . --region europe-west1 --allow-unauthenticated \
  --labels redteam=authorized,engagement=eng-2026-lab-gcp
```

**Configuration RTK / shell d'invocation :**
```bash
SSRF_URL=$(gcloud run services describe ssrf-lab --region europe-west1 --format='value(status.url)')

poetry run rtk run cloud_run.metadata_ssrf \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --endpoint "$SSRF_URL/fetch"
```

**Logs côté cible :**
```bash
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="ssrf-lab" AND httpRequest.requestUrl:"metadata.google.internal"' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=20
```

---

## 18. `llm_mcp.command_injection` (RTK-22) — Injection de commande via un outil MCP

**Description.** Étend les tests MCP (RTK-13/14) en vérifiant si les arguments passés à un outil MCP (ex: `execute_script`, `query_db`) sont correctement assainis. Une mauvaise validation peut mener à une injection de commande OS ou à une injection NoSQL/SQL.

**Service à déployer sur GCP :**
```bash
# mcp_injection.py — fixture de lab vulnérable
cat > mcp_injection.py << 'EOF'
from fastmcp import FastMCP
import subprocess

mcp = FastMCP("lab-mcp-injection")

@mcp.tool()
def ping_host(hostname: str) -> str:
    # Vulnérabilité volontaire : concaténation directe dans shell=True
    result = subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True, text=True)
    return result.stdout or result.stderr

if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8080)
EOF

gcloud run deploy mcp-injection-lab \
  --source . --region europe-west1 --allow-unauthenticated \
  --labels redteam=authorized,engagement=eng-2026-lab-gcp
```

**Configuration RTK / shell d'invocation :**
```bash
MCP_INJ_URL=$(gcloud run services describe mcp-injection-lab --region europe-west1 --format='value(status.url)')

poetry run rtk run llm_mcp.command_injection \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --mcp-endpoint "$MCP_INJ_URL" \
  --tool-name "ping_host" \
  --payloads "127.0.0.1; id", "127.0.0.1 | cat /etc/passwd"
```

---

## 19. `kms.decryptor_wildcard` (RTK-15) — Permissions de déchiffrement KMS trop larges

**Description.** Vérifie si des clés Cloud KMS critiques ont le rôle `roles/cloudkms.cryptoKeyDecrypter` accordé à `allUsers`, `allAuthenticatedUsers` ou à des comptes de service non liés, compromettant la confidentialité des données chiffrées.

**Service à déployer sur GCP :**
```bash
gcloud kms keyrings create lab-keyring --location=europe-west1
gcloud kms keys create lab-key --location=europe-west1 --keyring=lab-keyring --purpose=encryption

# La mauvaise config : accès public au déchiffrement
gcloud kms keys add-iam-policy-binding lab-key \
  --location=europe-west1 \
  --keyring=lab-keyring \
  --member="allAuthenticatedUsers" \
  --role="roles/cloudkms.cryptoKeyDecrypter"
```

**Configuration RTK / shell d'invocation :**
```bash
poetry run rtk run kms.decryptor_wildcard \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --region europe-west1
```

---

## 20. `cloud_functions.env_leakage` (RTK-10) — Fuite de variables d'environnement

**Description.** Détecte les Cloud Functions (2nd gen) qui exposent involontairement leurs variables d'environnement (contenant potentiellement des clés API, des chaînes de connexion DB) via des routes de débogage, des messages d'erreur ou des dumps de configuration.

**Service à déployer sur GCP :**
```bash
# index.js — fixture de lab vulnérable
cat > index.js << 'EOF'
const functions = require('@google-cloud/functions-framework');

functions.http('helloEnv', (req, res) => {
  // Vulnérabilité volontaire : exposition de toutes les variables d'environnement
  res.status(200).send(JSON.stringify(process.env, null, 2));
});
EOF

gcloud functions deploy lab-env-leak \
  --gen2 \
  --runtime=nodejs20 \
  --region=europe-west1 \
  --source=. \
  --entry-point=helloEnv \
  --trigger-http \
  --allow-unauthenticated \
  --set-env-vars="DB_PASSWORD=SuperSecretLabPassword123,API_KEY=sk-lab-12345" \
  --labels=redteam=authorized,engagement=eng-2026-lab-gcp
```

**Configuration RTK / shell d'invocation :**
```bash
CF_URL=$(gcloud functions describe lab-env-leak --region=europe-west1 --gen2 --format='value(serviceConfig.uri)')

poetry run rtk run cloud_functions.env_leakage \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --endpoints "$CF_URL"
```

---

## Modules non applicables à un lab 100 % GCP

| Module | Raison |
| --- | --- |
| `iam.privesc_paths` (RTK-06) | Code `boto3`/AWS IAM explicite ; retourne vide (`skip_non_aws`) si `target.cloud != "aws"`. |
| `audit.mttd_closed_loop` | Corrèle les findings avec AWS CloudTrail via `boto3` ; aucun équivalent GCP (Cloud Audit Logs) codé dans ce module en l'état. |

Ces deux modules restent utiles si vous testez un jour une architecture multi-cloud incluant un compte AWS réel dans le scope.

---

## Consultation groupée des résultats RTK

```bash
poetry run rtk findings --db ./missions/eng-001.db --mission-id $MISSION_ID
poetry run rtk report --db ./missions/eng-001.db --mission-id $MISSION_ID --output rapport.html
```

## Nettoyage après tests (étendu)

```bash
# Buckets & Storage
gsutil -m rm -r gs://acme-dev-backup

# Cloud Run Services
gcloud run services delete legacy-tile-server --region europe-west1 -q
gcloud run services delete geoserver-lab --region europe-west1 -q
gcloud run services delete error-leak-lab --region europe-west1 -q
gcloud run services delete mcp-lab --region europe-west1 -q
gcloud run services delete ssrf-lab --region europe-west1 -q
gcloud run services delete mcp-injection-lab --region europe-west1 -q

# Cloud Functions
gcloud functions delete lab-env-leak --region=europe-west1 -q

# IAM & Service Accounts
gcloud iam roles delete labOverPermissive --project=VOTRE_PROJET_GCP_SANDBOX -q
gcloud iam service-accounts delete lab-decoy-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com -q
gcloud iam service-accounts delete low-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com -q
gcloud iam service-accounts delete high-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com -q

# BigQuery
bq rm -f -r -d VOTRE_PROJET_GCP_SANDBOX:lab_dataset

# Cloud SQL
gcloud sql instances delete lab-db --project=VOTRE_PROJET_GCP_SANDBOX -q

# Secret Manager & KMS
gcloud secrets delete lab-api-key --project=VOTRE_PROJET_GCP_SANDBOX -q
gcloud kms keys versions destroy 1 --key=lab-key --keyring=lab-keyring --location=europe-west1 -q

# Artifact Registry & Source Repos
gcloud artifacts repositories delete lab-repo --location=europe-west1 -q
gcloud source repos delete lab-rtk-secrets --project=VOTRE_PROJET_GCP_SANDBOX -q

# Workload Identity
gcloud iam workload-identity-pools delete "lab-pool" --project="VOTRE_PROJET_GCP_SANDBOX" --location="global" -q
```

## Rappel : hygiène de lab

- Un seul projet GCP **sandbox**, jamais de données réelles ou de production.
- Toutes les ressources labellisées `redteam=authorized` + `engagement=<id>` pour un nettoyage facile (`gcloud ... list --filter="labels.engagement=eng-2026-lab-gcp"`).
- `scope.yaml` à jour (`authorized_modules`, fenêtre temporelle) avant chaque nouvelle série de tests.
- Suppression des ressources et révocation des clés de service account factices en fin de session.
- **Ne jamais** exécuter ces scénarios sur un projet de production, même avec de bonnes intentions.
```


