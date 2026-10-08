# ☁️ Lab Red/Blue Team sur GCP — Édition commentée pour Admins Unix

> **Public visé** : administrateur Unix/Linux à l'aise avec le shell, `chmod`, `sudo`, `iptables`, `journalctl`… mais qui découvre Google Cloud Platform.
> **Principe** : le tutoriel d'origine est conservé tel quel (blocs de code et 💡 notes). Les **commentaires pédagogiques** sont ajoutés dans des **encadrés colorés** distincts.

---

## 🎨 Comment lire ce document

| Élément | Signification |
|---|---|
| ```` ```bash ```` | 🖥️ Commandes **d'origine** (à copier-coller dans Cloud Shell) |
| 💡 **Note d'administration GCP** | 📝 Notes d'origine du tutoriel |
| > [!NOTE] 🔎 **Décryptage** | 🟦 **Explication** ligne à ligne de ce que fait chaque commande |
| > [!TIP] 🐧 **Analogie Unix** | 🟩 **Équivalent Unix** pour faire le lien avec ce que vous connaissez |
| > [!WARNING] 🎯 **La faille** | 🟧 **Mauvaise configuration volontaire** (le but du lab Red Team) |
| > [!IMPORTANT] 🛡️ **Côté Blue Team** | 🟪 **Comment corriger / détecter** en production |
| > [!CAUTION] 💸 **Attention** | 🟥 **Pièges, coûts, actions irréversibles** |

> [!NOTE]
> Les encadrés `[!NOTE]`, `[!TIP]`, `[!WARNING]`, `[!IMPORTANT]` et `[!CAUTION]` s'affichent en couleur sur GitHub, GitLab, VS Code (aperçu), Obsidian, etc. Ailleurs, ils apparaissent comme de simples citations (le contenu reste lisible).

---

## 📖 Mini-glossaire GCP ↔ Unix

| Concept GCP | Ce que c'est | Équivalent Unix / réseau |
|---|---|---|
| **Projet** (*project*) | Conteneur logique de toutes les ressources, avec sa facturation et ses droits | Un serveur / une VM dédiée, ou un `chroot` géant |
| **Région** (`europe-west1`) | Localisation géographique des ressources (Belgique) | Le datacenter / la baie où se trouve la machine |
| **IAM** | Système de gestion des droits (qui peut faire quoi sur quoi) | `/etc/sudoers` + permissions de fichiers + ACL, le tout centralisé |
| **Principal / Membre** | Une identité : utilisateur, groupe, compte de service… | Un `uid` / `gid` |
| **Rôle** | Un paquet de permissions (ex. `roles/storage.objectViewer`) | Un groupe `sudoers` préfabriqué (alias de commandes) |
| **Binding (liaison IAM)** | « Tel principal a tel rôle sur telle ressource » | Une ligne de `sudoers` ou un `setfacl` |
| **Compte de service (SA)** | Identité non humaine pour applications | Un utilisateur système (`www-data`, `postgres`) sans mot de passe |
| **Labels** | Étiquettes `clé=valeur` posées sur les ressources | Des tags / un préfixe de nommage, filtrables |
| **Bucket (GCS)** | Espace de stockage d'objets (fichiers) | Un répertoire exporté, façon S3 / NFS HTTP |
| **Cloud Run** | Exécute un conteneur Docker sans gérer de serveur | `docker run` derrière un reverse-proxy HTTPS géré |
| **Cloud Functions** | Exécute un bout de code déclenché par un événement | Un script CGI / un hook |
| **Secret Manager** | Coffre-fort pour mots de passe et clés d'API | Un `vault` centralisé avec audit |
| **KMS** | Gestion de clés de chiffrement | Un HSM / GPG-agent managé |
| **Cloud Logging** | Agrégation centralisée de logs | `rsyslog` + `journalctl` + `grep` centralisés |
| **`allUsers`** | **Tout Internet**, sans authentification | `chmod o+r` + serveur web ouvert au monde |
| **`allAuthenticatedUsers`** | **N'importe quel compte Google** (même un Gmail perso !) | « Tout le monde ayant un compte quelque part » |

> [!TIP]
> 🐧 **Cloud Shell** : c'est un petit terminal Debian/Ubuntu hébergé dans votre navigateur (bouton `>_` en haut à droite de la console GCP). Il est **déjà authentifié** avec votre compte Google, et embarque `gcloud`, `gsutil`, `bq`, `git`, `docker`, `python3`… Vous êtes sur une vraie machine Linux (≈ 5 Go persistants dans `$HOME`).

---

## 🛡️ 1. Initialisation de l'Environnement Sandbox (Prérequis)

Toute bonne administration GCP commence par une isolation stricte. Ces commandes préparent un environnement de test dédié, évitant tout impact sur la production.

```bash
# 1. Clonage et installation de l'outillage RTK avec le support GCP
git clone <votre repo> rtk && cd rtk
poetry install --with gcp

# 2. Authentification et ciblage du projet sandbox (à remplacer par votre ID de projet)
gcloud auth login
gcloud config set project VOTRE_PROJET_GCP_SANDBOX

# 3. Génération d'un ID de mission unique pour le traçage
MISSION_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
TARGET='{"cloud":"gcp","account_id":"VOTRE_PROJET_GCP_SANDBOX","region":"europe-west1"}'
```

> [!NOTE]
> 🔎 **Décryptage**
>
> | Commande | Ce qu'elle fait |
> |---|---|
> | `git clone <votre repo> rtk && cd rtk` | Télécharge le dépôt de l'outil RTK dans `./rtk` puis entre dedans. Le `&&` n'exécute `cd` que si le clone a réussi. |
> | `poetry install --with gcp` | **Poetry** est le gestionnaire de dépendances Python (≈ `apt`/`pip` + `venv` pour un projet). `--with gcp` installe en plus le *groupe optionnel* de dépendances « gcp » défini dans `pyproject.toml` (bibliothèques Google). |
> | `gcloud auth login` | Ouvre un flux OAuth pour connecter `gcloud` à votre compte Google. Il affiche une URL, vous collez en retour un code de validation. |
> | `gcloud config set project …` | Définit le **projet par défaut** de toutes les commandes suivantes (stocké dans `~/.config/gcloud/`). Évite de répéter `--project` partout. |
> | `MISSION_ID=$(python3 -c "…uuid4()…")` | Génère un identifiant aléatoire (UUID v4) et le stocke dans une **variable shell**. Sert de « numéro de ticket » pour retrouver les traces de l'exercice. |
> | `TARGET='{…}'` | Variable contenant une **description JSON** de la cible (cloud, projet, région), probablement consommée par l'outil RTK. |

> [!TIP]
> 🐧 **Analogie Unix** : `gcloud config set project` ≈ `export KUBECONFIG=…` ou `ssh` vers le bon serveur : toutes les commandes suivantes partent sur *cette* cible. Vérifiez à tout moment avec :
> ```bash
> gcloud config list          # affiche projet, compte, région actifs
> gcloud projects list        # liste les projets auxquels vous avez accès
> ```

> [!CAUTION]
> 💸 **Attention**
> - Dans **Cloud Shell**, vous êtes déjà authentifié : `gcloud auth login` est généralement inutile (il sert surtout sur votre poste local).
> - `MISSION_ID` et `TARGET` sont de **simples variables** : elles disparaissent si la session Cloud Shell se ferme. Pensez à les `export` ou à les noter.
> - **Prérequis oublié** : GCP désactive les API par défaut. Avant de commencer, activez celles dont vous aurez besoin :
>   ```bash
>   gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
>     artifactregistry.googleapis.com cloudfunctions.googleapis.com \
>     secretmanager.googleapis.com cloudkms.googleapis.com \
>     sqladmin.googleapis.com bigquery.googleapis.com \
>     iamcredentials.googleapis.com
>   ```
>   Analogie : c'est un `systemctl enable --now` pour chaque service avant de pouvoir l'utiliser. Il faut aussi un **compte de facturation** rattaché au projet.

💡 **Note d'administration GCP** : L'utilisation de `gcloud config set project` est une bonne pratique pour éviter d'exécuter des commandes destructrices sur le mauvais projet. L'ajout de `labels` (étiquettes) à chaque ressource créée est **obligatoire** dans un environnement professionnel pour le suivi de la facturation et le nettoyage automatisé.

---

## 📦 2. Stockage : Cloud Storage (GCS)

**Objectif** : Comprendre les risques des buckets publics et l'importance des journaux d'accès (Access Logs).

### Commandes de déploiement (Scénario de test)
```bash
ORG="acme"; ENV="dev"; SUFFIX="backup"
BUCKET="${ORG}-${ENV}-${SUFFIX}"

# Création du bucket et ajout d'un fichier leurre
gsutil mb -l europe-west1 gs://$BUCKET
echo "decoy-internal-report" > decoy.txt
gsutil cp decoy.txt gs://$BUCKET/decoy.txt

# Activation de l'accès uniforme (bonne pratique) MAIS ouverture dangereuse à "allUsers"
gsutil uniformbucketlevelaccess set on gs://$BUCKET
gsutil iam ch allUsers:objectViewer gs://$BUCKET

# Étiquetage pour le suivi (Hygiène de lab)
gsutil label ch -l redteam:authorized gs://$BUCKET
gsutil label ch -l engagement:eng-2026-lab-gcp gs://$BUCKET

# Configuration des journaux d'accès (Access Logs) pour l'audit
gsutil mb -l europe-west1 gs://${ORG}-logs-sink
gsutil iam ch group:cloud-storage-analytics@google.com:objectCreator gs://${ORG}-logs-sink
gsutil logging set on -b gs://${ORG}-logs-sink gs://$BUCKET
```

> [!NOTE]
> 🔎 **Décryptage**
>
> | Commande | Ce qu'elle fait |
> |---|---|
> | `ORG=…; ENV=…; SUFFIX=…` / `BUCKET=…` | Variables shell classiques. Résultat : `BUCKET="acme-dev-backup"`. |
> | `gsutil mb -l europe-west1 gs://$BUCKET` | **m**ake **b**ucket : crée le bucket. `-l` = *location* (région). Le préfixe `gs://` est le « schéma d'URL » de Cloud Storage (comme `s3://`). |
> | `echo … > decoy.txt` | Crée localement un fichier « leurre » (honeypot) au contenu fictif. |
> | `gsutil cp decoy.txt gs://$BUCKET/…` | Copie le fichier vers le bucket. Syntaxe identique à `cp`. |
> | `gsutil uniformbucketlevelaccess set on …` | Active l'**UBLA** : seules les règles **IAM** comptent, les anciennes **ACL** par objet sont ignorées. Plus simple à auditer. |
> | `gsutil iam ch allUsers:objectViewer …` | `iam ch` = *change* la politique IAM. Ajoute la liaison « **tout Internet** (`allUsers`) a le rôle **lecteur d'objets** (`objectViewer`) ». |
> | `gsutil label ch -l clé:valeur …` | Pose une **étiquette** sur le bucket (`-l` = label). Ici `redteam:authorized` et `engagement:eng-2026-lab-gcp`. |
> | `gsutil mb … gs://${ORG}-logs-sink` | Crée un **second bucket** destiné à recevoir les journaux d'accès du premier. |
> | `gsutil iam ch group:cloud-storage-analytics@google.com:objectCreator …` | Autorise le **service interne de Google** (groupe `cloud-storage-analytics`) à *écrire* des logs dans ce bucket (sinon il ne pourrait pas déposer ses fichiers). |
> | `gsutil logging set on -b gs://…-logs-sink gs://$BUCKET` | Active la journalisation des accès : `-b` désigne le bucket de destination. Google y déposera des fichiers CSV (usage et stockage). |

> [!TIP]
> 🐧 **Analogie Unix**
> - Un bucket n'est **pas** un filesystem : pas de vrais dossiers, juste des objets dont le nom contient des `/`.
> - `allUsers:objectViewer` ≈ `chmod o+r` **sur tout le contenu** + un `autoindex on;` Nginx : n'importe qui peut lister et télécharger via `https://storage.googleapis.com/acme-dev-backup/decoy.txt`.
> - Les labels sont comparables à des **tags** (`#redteam`) que l'on pourra filtrer pour tout supprimer d'un coup.

> [!WARNING]
> 🎯 **La faille** : le bucket est **volontairement public en lecture**. Test Red Team : depuis n'importe quelle machine, sans identifiants, essayez
> ```bash
> curl https://storage.googleapis.com/acme-dev-backup/decoy.txt
> ```
> Les noms de buckets prévisibles (`société-env-backup`) sont des cibles classiques de recherche automatisée.

> [!CAUTION]
> 💸 **Attention**
> - Les noms de bucket sont **uniques mondialement** : `acme-dev-backup` est probablement déjà pris. Ajoutez un suffixe personnel (ex. `acme-dev-backup-x7q2`).
> - Une **politique d'organisation** (« Public Access Prevention » / partage restreint au domaine) peut **bloquer** l'ouverture à `allUsers` : c'est une bonne chose en production.
> - `gsutil` est un outil *historique* : Google recommande désormais `gcloud storage` (ex. `gcloud storage buckets create gs://$BUCKET --location=europe-west1`). Les deux fonctionnent.
> - La journalisation par `gsutil logging` est l'ancien mécanisme. Le moderne = **Cloud Audit Logs** (voir §6).

💡 **Note d'administration GCP** : `uniformbucketlevelaccess` (UBLA) est recommandé par Google pour désactiver les ACLs héritées complexes. Cependant, UBLA n'empêche pas d'accorder `roles/storage.objectViewer` à `allUsers`. La surveillance via `gsutil logging` est cruciale pour détecter les exfiltrations.

> [!IMPORTANT]
> 🛡️ **Côté Blue Team** : contrôlez qui a accès à un bucket avec
> ```bash
> gsutil iam get gs://$BUCKET            # affiche la politique IAM (cherchez allUsers)
> gsutil pap set enforced gs://$BUCKET   # interdit définitivement l'accès public
> ```

---

## 💻 3. Calcul Serverless : Cloud Run & Cloud Functions

**Objectif** : Illustrer les dangers des services exposés publiquement (`--allow-unauthenticated`) et des fuites d'informations.

> [!TIP]
> 🐧 **Comprendre « serverless »** : vous fournissez un conteneur (Cloud Run) ou une fonction (Cloud Functions) ; Google s'occupe de la VM, de l'OS, du TLS, du load-balancing et du scaling (même jusqu'à zéro instance). Vous obtenez une **URL HTTPS publique** du type `https://nom-xxxx-ew.a.run.app`. Pensez à `docker run -p` + Nginx + Let's Encrypt, **entièrement géré**.

### Scénario A : Service Cloud Run vulnérable (CORS & Traversée de chemin)
```bash
# Construction et déploiement de l'image (après création du Dockerfile et app.py)
gcloud builds submit --tag gcr.io/VOTRE_PROJET_GCP_SANDBOX/legacy-tile-server
gcloud run deploy legacy-tile-server \
  --image gcr.io/VOTRE_PROJET_GCP_SANDBOX/legacy-tile-server \
  --region europe-west1 \
  --allow-unauthenticated \
  --labels redteam=authorized,engagement=eng-2026-lab-gcp
```

> [!NOTE]
> 🔎 **Décryptage**
>
> | Élément | Ce qu'il fait |
> |---|---|
> | `gcloud builds submit --tag …` | Envoie le contenu du **répertoire courant** (avec `Dockerfile` + `app.py`) à **Cloud Build**, qui exécute l'équivalent de `docker build` + `docker push`. `--tag` = nom complet de l'image dans le registre. |
> | `gcr.io/PROJET/legacy-tile-server` | Adresse de l'image dans le registre de conteneurs Google (format `registre/projet/image`). |
> | `gcloud run deploy legacy-tile-server` | Crée (ou met à jour) le service Cloud Run de ce nom. |
> | `--image …` | L'image à exécuter. |
> | `--region europe-west1` | Région d'exécution. |
> | `--allow-unauthenticated` | Ajoute la liaison IAM `allUsers` → `roles/run.invoker` : **n'importe qui sur Internet peut appeler l'URL**. |
> | `--labels k=v,k=v` | Étiquettes de suivi (notez la syntaxe `clé=valeur` séparée par des virgules, différente de `gsutil`). |
> | `\` en fin de ligne | Simple continuation de ligne shell. |

> [!WARNING]
> 🎯 **La faille** : l'application (`app.py`) contient volontairement des défauts (CORS trop permissif, **traversée de chemin** de type `../../etc/passwd`) **et** elle est ouverte à tout Internet. Ce sont deux faiblesses qui se cumulent.

> [!CAUTION]
> 💸 **Attention** : `gcr.io` (Container Registry) est **déprécié** au profit d'**Artifact Registry** (`europe-west1-docker.pkg.dev/PROJET/REPO/image`). Le teardown du §7 mentionne d'ailleurs un dépôt `lab-repo`.

### Scénario B : GeoServer sur Cloud Run (Exposition de données SIG)
```bash
gcloud run deploy geoserver-lab \
  --image docker.io/kartoza/geoserver:2.25.1 \
  --region europe-west1 \
  --memory 2Gi \
  --set-env-vars GEOSERVER_ADMIN_USER=admin,GEOSERVER_ADMIN_PASSWORD=ChangeMeLab123! \
  --allow-unauthenticated \
  --labels redteam=authorized,engagement=eng-2026-lab-gcp
```

> [!NOTE]
> 🔎 **Décryptage**
>
> | Élément | Ce qu'il fait |
> |---|---|
> | `--image docker.io/kartoza/geoserver:2.25.1` | Déploie une image **publique existante** (GeoServer, serveur de données cartographiques/SIG) au lieu d'en construire une. Le tag `:2.25.1` fige la version. |
> | `--memory 2Gi` | Alloue 2 Gio de RAM au conteneur (GeoServer, basé sur Java, est gourmand). |
> | `--set-env-vars K=V,K=V` | Injecte des **variables d'environnement** dans le conteneur, ici l'identifiant et le mot de passe admin. |

> [!WARNING]
> 🎯 **La faille** : interface d'administration GeoServer **exposée à Internet** avec un **mot de passe faible et visible en clair** dans la commande (donc dans l'historique shell et dans la console GCP).

> [!IMPORTANT]
> 🛡️ **Côté Blue Team** : stockez les mots de passe dans **Secret Manager** et référencez-les avec `--set-secrets GEOSERVER_ADMIN_PASSWORD=mon-secret:latest`. Ne passez jamais un mot de passe en clair en ligne de commande (il finit dans `~/.bash_history`).

> [!CAUTION]
> 💸 **Attention** : selon les restrictions de votre projet, Cloud Run peut exiger que l'image provienne d'**Artifact Registry** (un dépôt « remote » peut servir de miroir de Docker Hub). Si le déploiement échoue sur ce point, c'est la raison probable.

### Scénario C : Fuite de variables d'environnement (Cloud Functions 2nd Gen)
```bash
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

> [!NOTE]
> 🔎 **Décryptage**
>
> | Option | Ce qu'elle fait |
> |---|---|
> | `functions deploy lab-env-leak` | Déploie une fonction nommée `lab-env-leak`. |
> | `--gen2` | Utilise la **2ᵉ génération** (construite sur Cloud Run, plus puissante). |
> | `--runtime=nodejs20` | Environnement d'exécution : Node.js 20. |
> | `--source=.` | Le code source est dans le **répertoire courant** (ex. `index.js` + `package.json`). |
> | `--entry-point=helloEnv` | Nom de la **fonction exportée** à appeler à chaque requête. |
> | `--trigger-http` | Déclenchement par requête HTTP (la fonction reçoit une URL). |
> | `--allow-unauthenticated` | Appelable sans authentification (même mécanisme que Cloud Run). |
> | `--set-env-vars` | Variables d'environnement, ici de faux secrets. |

> [!WARNING]
> 🎯 **La faille** : la fonction `helloEnv` renvoie (volontairement) ses variables d'environnement. Un appel anonyme `curl <URL_de_la_fonction>` révèle `DB_PASSWORD` et `API_KEY`.

> [!TIP]
> 🐧 **Analogie Unix** : c'est un script CGI qui exécuterait `printenv` ou `phpinfo()` et l'afficherait à n'importe quel visiteur.

> [!CAUTION]
> 💸 **Attention** : le code de la fonction (`helloEnv`) n'est **pas fourni** dans ce tutoriel : il faut le créer dans le répertoire courant avant de lancer la commande.

💡 **Note d'administration GCP** : L'indicateur `--allow-unauthenticated` transforme un service privé en endpoint public mondial. En production, utilisez toujours l'authentification IAM (`--no-allow-unauthenticated`) et des Identity-Aware Proxy (IAP) pour les accès internes.

> [!IMPORTANT]
> 🛡️ **Côté Blue Team** : pour appeler un service **privé**, le client présente un jeton d'identité :
> ```bash
> curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" https://URL_DU_SERVICE
> ```

---

## 🔑 4. Identité et Accès : IAM & Workload Identity

**Objectif** : Démontrer comment des chaînes d'usurpation d'identité (Privilege Escalation) se forment via des permissions mal délimitées.

> [!TIP]
> 🐧 **Le modèle IAM en une phrase** : *« Le **principal** P a le **rôle** R sur la **ressource** X »*. C'est une ligne de `sudoers` généralisée à toutes les ressources du cloud. Les liaisons peuvent se poser à plusieurs niveaux (organisation → dossier → projet → ressource) et **sont héritées vers le bas**.
>
> Un **compte de service (SA)** est une identité pour programmes (≈ `www-data`). Fait important : **un SA est aussi une ressource** sur laquelle on peut donner des droits à d'autres (par exemple le droit de *se faire passer pour lui*, ≈ `sudo -u`).

### Scénario A : Chaîne d'usurpation de compte de service (SA)
```bash
# Création des comptes de service
gcloud iam service-accounts create low-priv-sa --display-name="Low Priv SA"
gcloud iam service-accounts create high-priv-sa --display-name="High Priv SA"

# Attribution d'un rôle puissant au SA "haut niveau"
gcloud projects add-iam-policy-binding VOTRE_PROJET_GCP_SANDBOX \
  --member="serviceAccount:high-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com" \
  --role="roles/editor"

# LA FAILLE : Donner au SA "bas niveau" le droit de générer des jetons pour le SA "haut niveau"
gcloud iam service-accounts add-iam-policy-binding \
  high-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com \
  --member="serviceAccount:low-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountTokenCreator"
```

> [!NOTE]
> 🔎 **Décryptage**
>
> | Commande | Ce qu'elle fait |
> |---|---|
> | `gcloud iam service-accounts create low-priv-sa` | Crée un SA dont l'e-mail sera `low-priv-sa@PROJET.iam.gserviceaccount.com`. `--display-name` = nom lisible dans la console. |
> | `gcloud projects add-iam-policy-binding PROJET` | Ajoute une liaison IAM **au niveau du projet entier**. |
> | `--member="serviceAccount:…"` | Le **principal** concerné (préfixe de type : `user:`, `group:`, `serviceAccount:`…). |
> | `--role="roles/editor"` | Rôle **basique** « Éditeur » : lecture/écriture sur *presque toutes* les ressources du projet. Très large ! |
> | `gcloud iam service-accounts add-iam-policy-binding high-priv-sa@… ` | Cette fois la liaison se pose **sur le compte de service lui-même** (la ressource), pas sur le projet. |
> | `roles/iam.serviceAccountTokenCreator` | Permet de **fabriquer des jetons d'accès** au nom du SA cible, donc de **devenir** ce SA. |

> [!WARNING]
> 🎯 **La faille (chaîne d'élévation de privilèges)** :
> ```
> low-priv-sa  ──(TokenCreator)──►  high-priv-sa  ──(Editor)──►  tout le projet
> ```
> `low-priv-sa` n'a *aucun* droit direct, mais peut **emprunter l'identité** de `high-priv-sa`, qui est Éditeur. En pratique, `low-priv-sa` est donc Éditeur. Test Red Team :
> ```bash
> gcloud auth print-access-token \
>   --impersonate-service-account=high-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com
> ```

> [!TIP]
> 🐧 **Analogie Unix** : `low-priv-sa` n'est pas root, mais `sudoers` contient `low-priv-sa ALL=(high-priv-sa) NOPASSWD: ALL`, et `high-priv-sa` est lui-même admin. Les chaînes d'usurpation sont l'équivalent cloud des **chaînes de `sudo -u`**.

### Scénario B : Fédération d'identité mal configurée (Workload Identity)
```bash
gcloud iam workload-identity-pools create "lab-pool" \
  --project="VOTRE_PROJET_GCP_SANDBOX" --location="global" --display-name="Lab Pool"

gcloud iam workload-identity-pools providers create-oidc "lab-provider" \
  --project="VOTRE_PROJET_GCP_SANDBOX" --location="global" \
  --workload-identity-pool="lab-pool" --display-name="Lab Provider" \
  --attribute-mapping="google.subject=assertion.sub" \
  --issuer-uri="https://accounts.google.com"

# LA FAILLE : Le caractère générique '*' permet à n'importe quel sujet de ce pool d'usurper le SA
gcloud iam service-accounts add-iam-policy-binding \
  low-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/VOTRE_PROJET_GCP_SANDBOX/locations/global/workloadIdentityPools/lab-pool/*"
```

> [!TIP]
> 🐧 **Comprendre la « Workload Identity Federation »** : elle permet à une application **extérieure** à GCP (GitHub Actions, AWS, un serveur OIDC…) d'obtenir un accès GCP **sans clé JSON de longue durée**. L'application présente un jeton signé par son fournisseur d'identité ; GCP l'échange contre un accès temporaire à un SA. Analogie : **authentification SSH par certificat** plutôt que par mot de passe partagé.

> [!NOTE]
> 🔎 **Décryptage**
>
> | Élément | Ce qu'il fait |
> |---|---|
> | `workload-identity-pools create "lab-pool"` | Crée un **pool** : le « carnet d'adresses » des identités externes acceptées. `--location=global` est obligatoire pour ce type de ressource. |
> | `providers create-oidc "lab-provider"` | Déclare un **fournisseur d'identité OIDC** dans ce pool (protocole standard d'authentification basé sur des jetons JWT). |
> | `--issuer-uri="https://accounts.google.com"` | L'émetteur de confiance des jetons : ici Google lui-même (très large : tout compte Google peut obtenir un jeton valable). |
> | `--attribute-mapping="google.subject=assertion.sub"` | Traduit le contenu du jeton externe : l'identité GCP (`google.subject`) prend la valeur de la revendication `sub` du jeton. |
> | `--role="roles/iam.workloadIdentityUser"` | Rôle autorisant à **agir comme** le SA via la fédération. |
> | `--member="principalSet://…/lab-pool/*"` | Désigne un **ensemble** de principaux : ici `*` = **toutes les identités du pool**. |

> [!WARNING]
> 🎯 **La faille** : le `*` autorise **n'importe quelle identité du pool** à devenir `low-priv-sa`. Combiné au Scénario A, la chaîne devient : *n'importe quel jeton OIDC de l'émetteur → low-priv-sa → high-priv-sa → Éditeur du projet*.

> [!CAUTION]
> 💸 **Attention**
> - Dans les liaisons `principalSet://…`, GCP attend normalement le **numéro** du projet (ex. `123456789012`) et non son **ID** textuel. Récupérez-le avec :
>   ```bash
>   gcloud projects describe VOTRE_PROJET_GCP_SANDBOX --format="value(projectNumber)"
>   ```
> - Les fournisseurs OIDC récents exigent souvent une **condition d'attribut** (`--attribute-condition`) : un bon réflexe à adopter, justement pour éviter ce scénario.

💡 **Note d'administration GCP** : Le rôle `roles/iam.serviceAccountTokenCreator` est l'un des plus dangereux de GCP. Il doit être accordé avec une condition IAM (ex: `resource.name == '...'`) et jamais avec des caractères génériques (`*`) dans les pools d'identité de charge de travail.

> [!IMPORTANT]
> 🛡️ **Côté Blue Team** : inspectez qui peut usurper un SA :
> ```bash
> gcloud iam service-accounts get-iam-policy high-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com
> ```
> Cherchez `serviceAccountTokenCreator`, `serviceAccountUser` et `workloadIdentityUser`.

---

## 🗄️ 5. Données et IA : BigQuery, Cloud SQL, Secret Manager & KMS

**Objectif** : Sécuriser les données au repos et en transit, et éviter l'exposition publique de jeux de données ou de clés.

### Scénario A : Dataset BigQuery public
```bash
bq mk --dataset --location=EU --description "Lab dataset" VOTRE_PROJET_GCP_SANDBOX:lab_dataset
echo '{"user_id": 1, "prompt": "secret data"}' > data.json
bq load --source_format=NEWLINE_DELIMITED_JSON VOTRE_PROJET_GCP_SANDBOX:lab_dataset.training_logs data.json

# LA FAILLE : Accès public en lecture
bq add-iam-policy-binding VOTRE_PROJET_GCP_SANDBOX:lab_dataset \
  --member="allUsers" --role="roles/bigquery.dataViewer"
```

> [!NOTE]
> 🔎 **Décryptage**
>
> | Commande | Ce qu'elle fait |
> |---|---|
> | `bq mk --dataset --location=EU …:lab_dataset` | **BigQuery** est l'entrepôt de données SQL de Google. Un *dataset* est l'équivalent d'une **base de données** (conteneur de tables). `EU` = emplacement multi-régions européen. |
> | `echo '{…}' > data.json` | Fichier JSON d'une ligne simulant des journaux de prompts d'IA contenant des données sensibles. |
> | `bq load --source_format=NEWLINE_DELIMITED_JSON … data.json` | Charge le fichier dans la **table** `training_logs` (créée à la volée). *NDJSON* = un objet JSON par ligne. |
> | `bq add-iam-policy-binding … --member="allUsers" --role="roles/bigquery.dataViewer"` | Rend les données **lisibles par tout Internet**. |

> [!TIP]
> 🐧 **Analogie Unix** : c'est comme un `GRANT SELECT ON lab_dataset.* TO PUBLIC` sur une base PostgreSQL ouverte, **sans même un mot de passe**.

> [!WARNING]
> 🎯 **La faille** : des données censées être confidentielles (prompts, logs d'entraînement d'une IA) sont lisibles anonymement.

### Scénario B : Cloud SQL exposé sans SSL
```bash
gcloud sql instances create lab-db \
  --database-version=POSTGRES_15 --cpu=1 --memory=4GB \
  --region=europe-west1 --root-password=LabPassword123! \
  --authorized-networks=0.0.0.0/0 \
  --require-ssl=false \
  --labels=redteam=authorized,engagement=eng-2026-lab-gcp
```

> [!NOTE]
> 🔎 **Décryptage**
>
> | Option | Ce qu'elle fait |
> |---|---|
> | `sql instances create lab-db` | **Cloud SQL** = bases de données managées (PostgreSQL, MySQL, SQL Server). Crée une instance nommée `lab-db`. |
> | `--database-version=POSTGRES_15` | Moteur et version : PostgreSQL 15. |
> | `--cpu=1 --memory=4GB` | Dimensionnement de la machine sous-jacente. |
> | `--root-password=…` | Mot de passe de l'utilisateur administrateur (`postgres`), ici faible et en clair. |
> | `--authorized-networks=0.0.0.0/0` | Liste blanche d'adresses IP autorisées à se connecter à l'IP publique. `0.0.0.0/0` = **toute l'Internet**. |
> | `--require-ssl=false` | N'impose **pas** le chiffrement TLS pour les connexions. |

> [!TIP]
> 🐧 **Analogie Unix** : c'est un `pg_hba.conf` avec `host all all 0.0.0.0/0 md5` (au lieu de `hostssl`), plus un `iptables -A INPUT -p tcp --dport 5432 -j ACCEPT` sans restriction de source.

> [!CAUTION]
> 💸 **Attention**
> - Cloud SQL est **facturé à l'heure** tant que l'instance existe (même inactive) : supprimez-la dès la fin du lab.
> - L'option `--require-ssl` est **dépréciée** dans les versions récentes de `gcloud` au profit de `--ssl-mode` (ex. `ALLOW_UNENCRYPTED_AND_ENCRYPTED` pour la faille, `ENCRYPTED_ONLY` pour la correction). Si la commande échoue, testez cette variante.
> - La création prend plusieurs minutes.

> [!IMPORTANT]
> 🛡️ **Côté Blue Team** : préférez une **IP privée** + le **Cloud SQL Auth Proxy**, qui chiffre et authentifie par IAM (plus de liste d'IP à gérer).

### Scénario C : Secret Manager et KMS sur-exposés
```bash
# Secret Manager
gcloud secrets create lab-api-key --replication-policy="automatic"
echo -n "sk-fake-llm-api-key-12345" | gcloud secrets versions add lab-api-key --data-file=-
gcloud secrets add-iam-policy-binding lab-api-key \
  --member="allAuthenticatedUsers" --role="roles/secretmanager.secretAccessor"

# Cloud KMS
gcloud kms keyrings create lab-keyring --location=europe-west1
gcloud kms keys create lab-key --location=europe-west1 --keyring=lab-keyring --purpose=encryption
gcloud kms keys add-iam-policy-binding lab-key \
  --location=europe-west1 --keyring=lab-keyring \
  --member="allAuthenticatedUsers" --role="roles/cloudkms.cryptoKeyDecrypter"
```

> [!NOTE]
> 🔎 **Décryptage**
>
> | Commande | Ce qu'elle fait |
> |---|---|
> | `gcloud secrets create lab-api-key --replication-policy="automatic"` | Crée un **secret** (le conteneur nommé). `automatic` = Google choisit la réplication géographique. |
> | `echo -n "…" \| gcloud secrets versions add … --data-file=-` | Ajoute une **version** (la valeur) au secret. `echo -n` n'ajoute pas de retour à la ligne ; `--data-file=-` signifie « lire sur l'entrée standard » (convention Unix du `-`). Le secret n'apparaît ainsi pas dans l'historique shell… sauf ici, car la valeur est dans le `echo` ! |
> | `secrets add-iam-policy-binding … --member="allAuthenticatedUsers" --role="roles/secretmanager.secretAccessor"` | Autorise **tout titulaire d'un compte Google** à **lire la valeur** du secret. |
> | `gcloud kms keyrings create lab-keyring` | Crée un **trousseau** de clés (conteneur logique rattaché à une région). |
> | `gcloud kms keys create lab-key --purpose=encryption` | Crée une **clé de chiffrement symétrique** dans le trousseau. La clé elle-même ne quitte jamais le service KMS. |
> | `kms keys add-iam-policy-binding … cryptoKeyDecrypter` | Autorise le **déchiffrement** avec cette clé à tout compte Google. |

> [!TIP]
> 🐧 **Analogie Unix**
> - Secret Manager ≈ un **HashiCorp Vault** managé : versions, audit, contrôle d'accès fin.
> - KMS ≈ un **HSM** : on ne récupère jamais la clé, on lui **demande** de chiffrer/déchiffrer.
> - `allAuthenticatedUsers` ≠ « utilisateurs de mon organisation » ! C'est **n'importe qui possédant un compte Google**, y compris un Gmail créé il y a 5 minutes.

> [!WARNING]
> 🎯 **La faille** : le secret est lisible et la clé utilisable par n'importe quel compte Google. Test Red Team avec un autre compte :
> ```bash
> gcloud secrets versions access latest --secret=lab-api-key --project=VOTRE_PROJET_GCP_SANDBOX
> ```

> [!CAUTION]
> 💸 **Attention** : dans KMS, **un trousseau et une clé ne peuvent jamais être supprimés** : on peut seulement détruire leurs *versions*. C'est voulu (protection contre l'effacement accidentel). Un nom de trousseau est donc « consommé » pour toujours dans ce projet/région.

💡 **Note d'administration GCP** : Les données dans BigQuery, Cloud SQL et Secret Manager sont privées par défaut. L'exposition provient presque toujours d'une liaison IAM manuelle erronée (`allUsers` ou `allAuthenticatedUsers`) ou d'une règle de pare-feu/réseau trop permissive (`0.0.0.0/0`).

---

## 🔍 6. Observabilité et Audit : Cloud Logging

Un administrateur GCP doit savoir comment vérifier si ces failles sont exploitées. Voici les commandes d'audit extraites des scénarios, utilisant l'outil `gcloud logging read`.

> [!TIP]
> 🐧 **Cloud Logging, c'est quoi ?** L'équivalent d'un `rsyslog` centralisé, avec un moteur de requêtes. `gcloud logging read '<FILTRE>'` joue le rôle de `journalctl | grep`, mais avec un **langage de filtre structuré**. Un journal d'audit GCP (*Cloud Audit Log*) contient, pour chaque appel d'API : **qui** (`authenticationInfo`), **quoi** (`methodName`), **sur quoi** (`resourceName`), **d'où** (`callerIp`).

```bash
# 1. Audit des accès anonymes à Cloud Storage (nécessite l'activation des Data Access Audit Logs)
gcloud logging read 'resource.type="gcs_bucket" AND protoPayload.methodName=("storage.objects.list" OR "storage.objects.get")' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=50

# 2. Audit des requêtes Cloud Run (détection de payloads de traversée ou de SSRF)
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="legacy-tile-server"' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=50 --format=json

# 3. Audit des tentatives d'usurpation d'identité (Token Creator)
gcloud logging read 'protoPayload.methodName="google.iam.credentials.v1.GenerateAccessToken"' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=20

# 4. Audit des accès aux secrets
gcloud logging read 'resource.type="secretmanager.googleapis.com/Secret" AND protoPayload.methodName="google.cloud.secretmanager.v1.AccessSecretVersion"' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=20

# 5. Détection spécifique de requêtes SSRF vers le serveur de métadonnées GCP
gcloud logging read 'resource.type="cloud_run_revision" AND httpRequest.requestUrl:"metadata.google.internal"' \
  --project=VOTRE_PROJET_GCP_SANDBOX --limit=20
```

> [!NOTE]
> 🔎 **Décryptage**
>
> **Syntaxe du filtre** : `champ="valeur"` (égalité), `champ:"texte"` (**contient**), `AND` / `OR` / `NOT`, parenthèses pour grouper.
> **Options communes** : `--project` (projet interrogé), `--limit` (nombre max d'entrées, les plus récentes d'abord), `--format=json` (sortie brute exploitable avec `jq`).
>
> | # | Ce que la requête cherche | Pourquoi c'est utile |
> |---|---|---|
> | 1 | `gcs_bucket` + méthodes `storage.objects.list` / `.get` | Qui **liste ou télécharge** des fichiers du bucket (détecter l'exfiltration). Sans authentification, le principal apparaît comme `anonymous`. |
> | 2 | Logs HTTP du service Cloud Run `legacy-tile-server` | Voir les **URL appelées** : on y repère des motifs comme `../../` (traversée de chemin). `--format=json` donne tous les champs. |
> | 3 | `GenerateAccessToken` (API *IAM Credentials*) | Trace chaque **emprunt d'identité** : un SA qui génère un jeton pour un autre = chaîne du §4A. |
> | 4 | `AccessSecretVersion` (Secret Manager) | Qui **a lu la valeur** d'un secret, et quand. |
> | 5 | Requêtes dont l'URL **contient** `metadata.google.internal` | Détecte les **tentatives de SSRF** : l'attaquant tente de faire contacter par l'application le serveur de métadonnées (`169.254.169.254`) qui délivre des jetons du compte de service. |

> [!CAUTION]
> 💸 **Attention**
> - La requête **n°5** repère un motif dans l'**URL entrante** consignée par Cloud Run (la charge malveillante envoyée *par l'attaquant*). Elle ne voit pas la requête sortante de l'application vers le serveur de métadonnées.
> - Les requêtes **1** et **4** ne renvoient des résultats que si les **Data Access Audit Logs** sont activés (voir la note ci-dessous).
> - Les journaux ont un délai d'apparition de quelques secondes à quelques minutes.

💡 **Note d'administration GCP** : Par défaut, les "Data Access Audit Logs" (qui enregistrent qui lit quelles données) sont **désactivés** pour ne pas générer de coûts/factures inutiles. Un administrateur doit les activer explicitement dans `IAM & Admin > Audit Logs` pour les services critiques comme GCS ou BigQuery.

> [!IMPORTANT]
> 🛡️ **Côté Blue Team** : transformez ces requêtes en **alertes** permanentes (*log-based alerts*) ou exportez-les vers BigQuery/Pub/Sub via un **sink** :
> ```bash
> gcloud logging sinks create audit-sink \
>   bigquery.googleapis.com/projects/VOTRE_PROJET_GCP_SANDBOX/datasets/audit_logs \
>   --log-filter='protoPayload.methodName="google.iam.credentials.v1.GenerateAccessToken"'
> ```
> (Analogie : l'équivalent d'un `rsyslog` qui redirige certains motifs vers un SIEM.)

---

## 🧹 7. Procédure de Nettoyage (Teardown)

Une compétence essentielle en administration GCP est la capacité à détruire proprement les ressources pour éviter les "fuites de coûts" (billing leaks). Voici le script de nettoyage complet consolidé à partir des deux fichiers.

```bash
# 1. Stockage
gsutil -m rm -r gs://acme-dev-backup
gsutil -m rm -r gs://acme-logs-sink

# 2. Services Cloud Run
gcloud run services delete legacy-tile-server --region europe-west1 -q
gcloud run services delete geoserver-lab --region europe-west1 -q
gcloud run services delete error-leak-lab --region europe-west1 -q
gcloud run services delete mcp-lab --region europe-west1 -q
gcloud run services delete ssrf-lab --region europe-west1 -q
gcloud run services delete mcp-injection-lab --region europe-west1 -q

# 3. Cloud Functions
gcloud functions delete lab-env-leak --region=europe-west1 -q

# 4. IAM & Comptes de service
gcloud iam roles delete labOverPermissive --project=VOTRE_PROJET_GCP_SANDBOX -q
gcloud iam service-accounts delete lab-decoy-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com -q
gcloud iam service-accounts delete low-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com -q
gcloud iam service-accounts delete high-priv-sa@VOTRE_PROJET_GCP_SANDBOX.iam.gserviceaccount.com -q

# 5. Données (BigQuery, Cloud SQL, Secrets, KMS)
bq rm -f -r -d VOTRE_PROJET_GCP_SANDBOX:lab_dataset
gcloud sql instances delete lab-db --project=VOTRE_PROJET_GCP_SANDBOX -q
gcloud secrets delete lab-api-key --project=VOTRE_PROJET_GCP_SANDBOX -q
gcloud kms keys versions destroy 1 --key=lab-key --keyring=lab-keyring --location=europe-west1 -q

# 6. Artefacts et Code Source
gcloud artifacts repositories delete lab-repo --location=europe-west1 -q
gcloud source repos delete lab-rtk-secrets --project=VOTRE_PROJET_GCP_SANDBOX -q

# 7. Workload Identity
gcloud iam workload-identity-pools delete "lab-pool" --project="VOTRE_PROJET_GCP_SANDBOX" --location="global" -q
```

> [!NOTE]
> 🔎 **Décryptage**
>
> | Commande | Ce qu'elle fait |
> |---|---|
> | `gsutil -m rm -r gs://BUCKET` | `rm -r` : supprime récursivement **tous les objets puis le bucket lui-même**. `-m` = traitement **parallèle** (multi-thread), plus rapide. |
> | `gcloud run services delete … -q` | Supprime un service Cloud Run. `-q` (`--quiet`) **supprime les demandes de confirmation** (équivalent de `rm -f` / `apt -y`). |
> | `gcloud functions delete …` | Supprime la fonction. |
> | `gcloud iam roles delete` | Supprime un **rôle personnalisé** (il passe d'abord en état « supprimé » pendant 7 jours avant effacement définitif). |
> | `gcloud iam service-accounts delete …` | Supprime les comptes de service (et donc les liaisons qui les citent deviennent orphelines). |
> | `bq rm -f -r -d PROJET:dataset` | Supprime le dataset : `-d` (dataset), `-r` (récursif, avec ses tables), `-f` (sans confirmation). |
> | `gcloud sql instances delete lab-db` | Détruit l'instance de base de données et ses données. |
> | `gcloud secrets delete …` | Supprime le secret et **toutes** ses versions. |
> | `gcloud kms keys versions destroy 1 …` | Programme la **destruction de la version 1** de la clé (délai de grâce de 24 h par défaut). Le trousseau et la clé *subsistent*. |
> | `gcloud artifacts repositories delete` | Supprime un dépôt d'images/paquets. |
> | `gcloud source repos delete` | Supprime un dépôt Git hébergé (Cloud Source Repositories). |
> | `gcloud iam workload-identity-pools delete` | Supprime le pool de fédération (soft-delete de 30 jours). |

> [!CAUTION]
> 💸 **Attention**
> - Ces commandes sont **irréversibles** (`-q` supprime toute confirmation) : relancez d'abord `gcloud config list` pour vérifier que vous êtes dans le **bon projet**.
> - Certaines ressources listées (`error-leak-lab`, `mcp-lab`, `ssrf-lab`, `mcp-injection-lab`, `lab-decoy-sa`, `labOverPermissive`, `lab-repo`, `lab-rtk-secrets`) proviennent **d'autres scénarios** non détaillés ici. Une erreur « NOT_FOUND » sur ces lignes est donc **normale et sans gravité**.
> - Les bindings IAM posés au niveau projet (ex. `roles/editor` pour `high-priv-sa`) deviennent orphelins après suppression du SA : repérez-les avec `gcloud projects get-iam-policy` (entrées `deleted:serviceAccount:…`).

> [!TIP]
> 🐧 **Astuces de nettoyage**
>
> **Lister les ressources par label** (grâce à l'hygiène d'étiquetage) :
> ```bash
> gcloud run services list --filter="labels.engagement=eng-2026-lab-gcp"
> gcloud sql instances list --filter="settings.userLabels.engagement=eng-2026-lab-gcp"
> ```
> **Option nucléaire (recommandée pour une sandbox)** : supprimer **tout le projet** d'un coup, ce qui détruit toutes les ressources, quelles qu'elles soient :
> ```bash
> gcloud projects delete VOTRE_PROJET_GCP_SANDBOX
> ```
> (Récupérable pendant 30 jours via `gcloud projects undelete`.)

---

## 🎓 Synthèse des Bonnes Pratiques d'Administration GCP

À travers l'analyse de ces scénarios de test RTK, voici les principes fondamentaux à retenir pour une administration GCP sécurisée :

1. **Zéro Confiance (Zero Trust)** : Ne jamais utiliser `--allow-unauthenticated` sur Cloud Run/Functions sauf pour des sites web publics statiques. Préférer l'authentification via IAP ou des jetons de service.
2. **Principe du Privilège Minimum (PoLP)** : Éviter les rôles `Owner`, `Editor`, ou les liaisons IAM avec `allUsers`/`allAuthenticatedUsers`. Utiliser des rôles personnalisés (`gcloud iam roles create`) avec des permissions granulaires.
3. **Hygiène des Étiquettes (Labels)** : Comme démontré dans chaque commande de déploiement, l'ajout de `--labels redteam=authorized,engagement=eng-2026-lab-gcp` est vital. Cela permet de lister et supprimer toutes les ressources d'un test en une seule commande filtrée.
4. **Défense en Profondeur** : Activer l'accès uniforme aux buckets (UBLA), exiger le SSL pour Cloud SQL (`--require-ssl=true`), et restreindre les réseaux autorisés (`--authorized-networks`) au lieu d'utiliser `0.0.0.0/0`.
5. **Audit Proactif** : Configurer des alertes Cloud Logging (via des Sinks vers Pub/Sub ou BigQuery) pour surveiller les motifs dangereux comme `GenerateAccessToken` ou les accès aux métadonnées GCP.

> [!IMPORTANT]
> 🛡️ **Récapitulatif Blue Team : de la faille à la correction**
>
> | 🎯 Faille du lab | 🛡️ Correction en production | 🐧 Équivalent Unix |
> |---|---|---|
> | Bucket `allUsers:objectViewer` | Retirer `allUsers`, `gsutil pap set enforced` | `chmod o-rwx` + fermer l'export |
> | `--allow-unauthenticated` | `--no-allow-unauthenticated` + jeton d'identité / IAP | Mettre un `auth_basic` / mTLS sur le vhost |
> | Secrets en variables d'environnement | Secret Manager + `--set-secrets` | `vault` au lieu de `export PASSWORD=…` |
> | `roles/editor` sur un SA | Rôle personnalisé minimal | `sudoers` limité à des commandes précises |
> | `TokenCreator` trop large | Accorder avec **condition** et sur un SA précis | `sudo -u` restreint par `Cmnd_Alias` |
> | `principalSet …/*` | Condition d'attribut précise (`attribute.repository/…`) | Restreindre `AllowUsers` / `authorized_keys from=` |
> | Dataset BigQuery `allUsers` | Retirer `allUsers`, droits par groupe | `REVOKE … FROM PUBLIC` |
> | Cloud SQL `0.0.0.0/0` sans SSL | IP privée + Auth Proxy, TLS obligatoire | `pg_hba.conf` en `hostssl` + pare-feu |
> | `allAuthenticatedUsers` sur secrets/KMS | Groupes/SA nommés uniquement | ACL sur une liste d'utilisateurs précise |
> | Pas de Data Access Logs | Les activer + alertes sur sinks | `auditd` + envoi vers le SIEM |

---

## 📌 Annexe : points de vigilance sur les commandes d'origine

> [!WARNING]
> Ces remarques ne changent pas l'esprit du lab mais peuvent vous faire gagner du temps si une commande échoue (les outils cloud évoluent vite : vérifiez avec `gcloud <commande> --help`) :
>
> | Sujet | Remarque |
> |---|---|
> | **API non activées** | À activer au préalable avec `gcloud services enable …` (voir §1). |
> | **Noms de buckets** | Uniques mondialement : personnalisez-les. |
> | **`gsutil`** | Outil historique ; équivalent moderne : `gcloud storage …`. |
> | **`gcr.io`** | Déprécié au profit d'Artifact Registry (`…-docker.pkg.dev`). |
> | **Cloud Source Repositories** | Service en voie d'abandon (ligne `source repos delete` du §7). |
> | **`--require-ssl`** | Remplacé par `--ssl-mode` dans les versions récentes de `gcloud sql`. |
> | **`--labels` (Functions, SQL)** | Selon la version de `gcloud`, l'option peut s'appeler `--update-labels` (Functions) ou nécessiter une variante pour Cloud SQL ; consultez l'aide de la commande. |
> | **`principalSet`** | Utilise le **numéro** de projet, pas son ID. |
> | **Code applicatif** | `Dockerfile`, `app.py` et la fonction `helloEnv` ne sont pas fournis dans ce document. |
> | **Image Docker Hub** | Peut nécessiter un dépôt Artifact Registry « remote » pour Cloud Run. |

---

*🧪 Rappel : ce lab déploie volontairement des configurations **dangereuses**. À exécuter **uniquement dans un projet sandbox dédié**, avec un budget d'alerte configuré, et à détruire dès la fin de l'exercice.*
