
### 🛠️ Prérequis communs (adaptés à votre installation)
Avant de commencer, assurez-vous d'avoir défini ces variables dans votre Cloud Shell. Elles seront réutilisées partout :
```bash
# 1. Cloner et installer (ce que vous avez déjà fait)
git clone https://github.com/BlackSwanCode/RTK.git && cd RTK
pip install -e .

# 2. Authentification et projet cible
gcloud auth login
gcloud config set project VOTRE_PROJET_GCP_SANDBOX

# 3. Variables d'environnement pour les commandes RTK
export TARGET='{"cloud":"gcp","account_id":"VOTRE_PROJET_GCP_SANDBOX","region":"europe-west1"}'
export MISSION_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
```
*Note : Assurez-vous que votre fichier `scope.yaml` est bien configuré avec votre projet et la fenêtre d'engagement comme indiqué dans le fichier source.*

---

### Scénario 1 : `buckets.enum_buckets` (RTK-04) — Bucket GCS public oublié
**Objectif pédagogique** : Comprendre comment une mauvaise configuration IAM au niveau d'un bucket Cloud Storage permet une lecture anonyme de fichiers.

**Analyse des commandes Cloud Shell** :
- `gsutil mb -l europe-west1 gs://$BUCKET` : Crée le bucket (*make bucket*).
- `echo ... > decoy.txt` et `gsutil cp ...` : Crée et téléverse un fichier leurre.
- `gsutil uniformbucketlevelaccess set on ...` : Active le contrôle d'accès uniforme (bonne pratique, mais neutre ici).
- `gsutil iam ch allUsers:objectViewer gs://$BUCKET` : **LA FAILLE**. Cette commande accorde le rôle `objectViewer` (lecture) à `allUsers` (c'est-à-dire tout le monde sur Internet, sans authentification).
- `gsutil label ch ...` : Ajoute des étiquettes pour identifier et nettoyer facilement ces ressources plus tard.

**🌐 Test manuel via navigateur** :
Ouvrez simplement un nouvel onglet et collez l'URL publique du fichier :
`https://storage.googleapis.com/acme-dev-backup/decoy.txt`
*Résultat attendu* : Le navigateur affiche directement le texte `decoy-internal-report`, prouvant que le fichier est lisible par n'importe qui.

**⚙️ Invocation RTK (adaptée)** :
```bash
rtk run buckets.enum_buckets \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --org acme \
  --envs dev,staging,prod
```
*Explication* : RTK va générer des combinaisons de noms (ex: `acme-dev-backup`, `acme-prod-logs`) et tenter des requêtes HTTP anonymes pour voir lesquelles répondent avec un statut 200 OK.

---

### Scénario 2 : `buckets.cors_traversal` (RTK-05) — CORS permissif + Traversée de chemin
**Objectif pédagogique** : Un service Cloud Run mal configuré peut refléter des en-têtes CORS de manière dangereuse ET souffrir de traversée de répertoire (`../`).

**Analyse des commandes Cloud Shell** :
- Le script Python (`app.py`) contient deux failles volontaires : 
  1. `resp.headers["Access-Control-Allow-Origin"] = origin` + `Credentials: true` : Accepte n'importe quel site web comme origine de confiance.
  2. `send_from_directory(BASE_DIR, filepath)` : Ne nettoie pas la variable `filepath`, permettant d'utiliser `../` pour sortir du dossier `/tiles`.
- `gcloud builds submit` et `gcloud run deploy` : Compilent l'image Docker et la déploient en tant que service web public (`--allow-unauthenticated`).

**🌐 Test manuel via navigateur** :
1. **Traversée** : Dans la barre d'adresse, utilisez l'encodage URL pour contourner la normalisation du navigateur :  
   `https://<URL_DU_SERVICE>/tiles/..%2f..%2fsecret.txt`  
   *Résultat* : Le navigateur affiche `TOP-SECRET-DECOY`.
2. **CORS** : Ouvrez les Outils de développement (F12) > Onglet "Console". Collez ce code pour simuler une requête depuis un site malveillant :
   ```javascript
   fetch('https://<URL_DU_SERVICE>/tile_1_1.png', {credentials: 'include', headers: {'Origin': 'https://evil.com'}})
     .then(r => console.log("CORS Autorisé!", r.headers.get('access-control-allow-credentials')))
   ```
   *Résultat* : La console affiche `CORS Autorisé! true`.

**⚙️ Invocation RTK (adaptée)** :
Créez d'abord un fichier `buckets.json` :
```json
[{"name": "legacy-tile-server", "cloud": "gcp", "region": "europe-west1", "url": "https://<URL_DU_SERVICE>/tile_1_1.png"}]
```
```bash
rtk run buckets.cors_traversal \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --buckets-file buckets.json
```

---

### Scénario 3 : `gis_meteo.ogc_anonymous_access` (RTK-20) — Couche WMS sensible exposée
**Objectif pédagogique** : Les services cartographiques (GeoServer) sont souvent exposés publiquement avec des jeux de données internes non protégés.

**Analyse des commandes Cloud Shell** :
- `gcloud run deploy ... kartoza/geoserver` : Déploie une image Docker officielle de GeoServer.
- Les commandes `curl -u admin:ChangeMeLab123! -XPOST ...` : Utilisent l'API REST de GeoServer (authentifiée) pour créer automatiquement un espace de travail (`lab`), un magasin de données, et publient une couche nommée `donnees_rgpd_employes`. Ce nom est choisi car il correspond aux motifs sensibles (`rgpd`) recherchés par RTK.

**🌐 Test manuel via navigateur** :
1. Vérifiez que le service est accessible : ouvrez `https://<URL_GEOSERVER>/geoserver/web` (vous verrez l'interface d'admin).
2. Testez l'accès anonyme aux données : ouvrez  
   `https://<URL_GEOSERVER>/geoserver/lab/wfs?service=WFS&version=2.0.0&request=GetFeature&typeNames=lab:donnees_rgpd_employes`  
   *Résultat* : Le navigateur affiche un document XML contenant les "données sensibles", sans demander aucun mot de passe.

**⚙️ Invocation RTK (adaptée)** :
```bash
export GS_URL=$(gcloud run services describe geoserver-lab --region europe-west1 --format='value(status.url)')
rtk run gis_meteo.ogc_anonymous_access \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --ogc-endpoints "$GS_URL/geoserver/lab/wfs"
```

---

### Scénario 4 : `secrets.multi_repo_scan` (RTK-01) — Clé de Service Account committée puis supprimée
**Objectif pédagogique** : Supprimer un fichier secret dans un nouveau commit **ne l'efface pas** de l'historique Git. Les outils de scan d'historique peuvent le retrouver.

**Analyse des commandes Cloud Shell** :
- `gcloud source repos create` : Crée un dépôt Git géré par GCP.
- `gcloud iam service-accounts keys create decoy-key.json` : Génère une vraie clé JSON (factice pour le lab).
- La séquence `git add`/`commit` (ajout), puis `git rm`/`commit` (suppression) simule l'erreur classique du développeur qui se ravise.
- `gcloud iam service-accounts keys delete ...` : **Très important**. On révoque la clé côté GCP pour qu'elle soit inutilisable, mais elle reste visible dans l'historique Git pour que RTK puisse la détecter.

**🌐 Test manuel via navigateur** :
Allez dans la Console GCP > "Cloud Source Repositories". Sélectionnez le dépôt `lab-rtk-secrets`. Cliquez sur l'onglet "Historique". Vous verrez le commit `"add gcp credentials (oops)"`. Cliquez dessus, puis sur le fichier `config/credentials.json`. Vous verrez la clé en clair, prouvant qu'elle est toujours lisible dans l'historique.

**⚙️ Invocation RTK (adaptée)** :
*Prérequis* : Assurez-vous que l'outil `gitleaks` est installé sur votre système (`sudo apt install gitleaks` ou via binaire).
```bash
mkdir -p repos
git clone https://source.developers.google.com/p/VOTRE_PROJET_GCP_SANDBOX/r/lab-rtk-secrets repos/lab-rtk-secrets

rtk run secrets.multi_repo_scan \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --repos-dir repos/
```

---

### Scénario 5 : `secrets.error_leakage` (RTK-02) — Stack trace exposant une clé dans une erreur 500
**Objectif pédagogique** : Une application en mode `debug=True` (ou équivalent) renvoie des traces d'exécution complètes en cas d'erreur, divulguant souvent des variables d'environnement ou des secrets.

**Analyse des commandes Cloud Shell** :
- Le fichier `app.py` définit une variable `FAKE_API_KEY` et utilise `debug=True` dans `app.run()`.
- La fonction `process()` appelle `request.get_json()` sans bloc `try/except`. Si le JSON est invalide, Flask lève une exception et, à cause du mode debug, renvoie la page HTML d'erreur complète avec la trace.

**🌐 Test manuel via navigateur** :
Ouvrez les Outils de développement (F12) > Onglet "Console" du navigateur. Collez ce script pour envoyer un JSON invalide au endpoint :
```javascript
fetch('https://<URL_DU_SERVICE>/process', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: 'ceci n est pas un json valide {'
}).then(r => r.text()).then(html => console.log(html));
```
*Résultat* : La console affichera le code HTML de la page d'erreur Flask, dans laquelle vous pourrez lire en clair `FAKE_API_KEY = "AIzaSyDECOY1234567890abcdefghijklmno12"`.

**⚙️ Invocation RTK (adaptée)** :
```bash
export ERROR_URL=$(gcloud run services describe error-leak-lab --region europe-west1 --format='value(status.url)')
rtk run secrets.error_leakage \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --endpoints "$ERROR_URL/process"
```

---

### Scénario 6 : `iam.wildcard_policies` (RTK-07) — Rôle IAM personnalisé trop permissif
**Objectif pédagogique** : Détecter les politiques d'autorisation qui utilisent des caractères génériques (`"*"`), accordant potentiellement tous les droits sur toutes les ressources.

**Analyse des commandes Cloud Shell** :
- `role-def.yaml` : Définit un rôle personnalisé avec `includedPermissions: ["*"]`.
- `gcloud iam roles create` : Crée ce rôle dans le projet.
- *Note* : RTK-07 est un analyseur statique local. Il ne scanne pas directement l'API GCP, mais analyse des fichiers JSON de politiques. Nous créons donc manuellement un fichier JSON qui représente ce rôle pour le scanner.

**🌐 Test manuel via navigateur** :
Allez dans la Console GCP > "IAM et administration" > "Rôles". Filtrez avec le mot-clé `LabOverPermissive`. Cliquez sur le rôle. Dans la liste des autorisations, vous verrez qu'il possède des centaines de permissions, ou une mention indiquant un accès générique, confirmant le risque.

**⚙️ Invocation RTK (adaptée)** :
Créez d'abord le fichier de politique à analyser :
```bash
mkdir -p policies
cat > policies/lab-role.json << 'EOF'
{
  "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]
}
EOF

rtk run iam.wildcard_policies \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --policies-dir policies/
```

---

### Scénario 7 : `network.external_surface` (RTK-08) — Endpoint oublié sur un sous-domaine
**Objectif pédagogique** : Les mappages de domaine personnalisés sur des services serverless (Cloud Run) sont souvent oubliés après la fin d'un projet, laissant une surface d'attaque externe ouverte.

**Analyse des commandes Cloud Shell** :
- `gcloud run domain-mappings create` : Associe un nom de domaine personnalisé (`forgotten-wms.votredomaine-lab.example.com`) au service `geoserver-lab` déjà déployé. Cela simule un sous-domaine "oublié" pointant vers une ressource interne.

**🌐 Test manuel via navigateur** :
Ouvrez simplement `https://forgotten-wms.votredomaine-lab.example.com` dans votre navigateur.  
*Résultat* : Vous tomberez sur la page d'accueil de GeoServer, prouvant que ce sous-domaine est actif et expose le service au monde entier.

**⚙️ Invocation RTK (adaptée)** :
```bash
rtk run network.external_surface \
  --target "$TARGET" \
  --scope scope.yaml \
  --db ./missions/eng-001.db \
  --mission-id $MISSION_ID \
  --domains "votredomaine-lab.example.com"
```
*Note* : RTK utilisera des outils comme `subfinder` pour découvrir ce sous-domaine, puis le "fingerprintera" pour identifier qu'il s'agit d'un service GeoServer/WMS.

---

### Scénarios 8 & 9 : `llm_mcp.tool_poisoning_watch` (RTK-13) et `exfil_channels` (RTK-14)
**Objectif pédagogique** : Les serveurs MCP (Model Context Protocol) exposent des "outils" (fonctions) aux LLM. Si un outil comme `http_get` n'a pas de liste blanche (allowlist) de domaines, il peut être détourné pour du SSRF ou de l'exfiltration de données.

**Analyse des commandes Cloud Shell** :
- `mcp_server.py` : Utilise `fastmcp` pour créer un outil `http_get` qui prend une URL en paramètre et en renvoie le contenu. Aucune validation de l'URL n'est effectuée.
- `gcloud run deploy` : Rend ce serveur accessible publiquement.

**🌐 Test manuel via navigateur** :
Les serveurs MCP utilisent JSON-RPC via POST. Vous pouvez le tester via la Console du navigateur (F12) :
```javascript
fetch('https://<URL_MCP_SERVER>/', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    jsonrpc: "2.0",
    method: "tools/call",
    params: {name: "http_get", arguments: {url: "https://example.com"}},
    id: 1
  })
}).then(r => r.json()).then(console.log);
```
*Résultat* : La console affichera la réponse JSON contenant le code HTML de `example.com`, prouvant que le serveur a effectué la requête en votre nom (vecteur d'exfiltration ou SSRF).

**⚙️ Invocation RTK (adaptée)** :
```bash
export MCP_URL=$(gcloud run services describe mcp-lab --region europe-west1 --format='value(status.url)')

# RTK-13 : Détection de dérive de schéma (Poisoning)
rtk run llm_mcp.tool_poisoning_watch \
  --target "$TARGET" --scope scope.yaml --db ./missions/eng-001.db --mission-id $MISSION_ID \
  --mcp-endpoint "$MCP_URL" --baseline-file baseline.json

# RTK-14 : Test d'exfiltration (assurez-vous que listener_url est dans le scope.yaml)
rtk run llm_mcp.exfil_channels \
  --target "$TARGET" --scope scope.yaml --db ./missions/eng-001.db --mission-id $MISSION_ID \
  --mcp-endpoint "$MCP_URL" \
  --listener-url "https://votredomaine-lab.example.com/collector"
```

---

### 🧹 Nettoyage systématique (Hygiène de lab)
Une fois vos tests terminés, il est crucial de détruire les ressources pour éviter des frais GCP inutiles et maintenir un environnement propre. Exécutez ces commandes dans le Cloud Shell :

```bash
# 1. Supprimer les buckets Cloud Storage
gsutil -m rm -r gs://acme-dev-backup
gsutil -m rm -r gs://acme-logs-sink

# 2. Supprimer les services Cloud Run
gcloud run services delete legacy-tile-server --region europe-west1 -q
gcloud run services delete geoserver-lab --region europe-west1 -q
gcloud run services delete error-leak-lab --region europe-west1 -q
gcloud run services delete mcp-lab --region europe-west1 -q

# 3. Supprimer le dépôt de code et les rôles/comptes de service
gcloud source repos delete lab-rtk-secrets --project=VOTRE_PROJET_GCP_SANDBOX -q
gcloud iam roles delete labOverPermissive --project=VOTRE_PROJET_GCP_SANDBOX -q
gcloud iam service-accounts delete lab-decoy-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com -q
```

### 💡 Conseils pour la suite
1. **Lisez les logs** : Après chaque exécution RTK, utilisez les commandes `gcloud logging read` fournies dans le document. Cela vous apprendra à faire le lien entre l'action de l'outil d'attaque et la trace laissée dans les systèmes de défense (Cloud Logging).
2. **Adaptez les URLs** : Remplacez toujours les placeholders comme `<URL_DU_SERVICE>` par les vraies URLs renvoyées par vos commandes `gcloud run deploy`.
3. **Sécurité** : Ne modifiez jamais ce script pour cibler un projet de production. L'isolation dans un projet "sandbox" dédié est la règle d'or du Red Teaming responsable.

