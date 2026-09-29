Pour faire passer le RTK au niveau **"Ultimate"**, voici les modules et capacités manquants, classés par priorité stratégique :

> **Mise à jour du 29 septembre 2026.** Le dépôt livré (v0.5.0) a depuis implémenté 10 des 20 vecteurs de la matrice, dont deux qui figuraient dans la liste « manquants » ci-dessous : **RTK-05** (`buckets.cors_traversal`) et **RTK-08** (`network.external_surface`). Ils sont marqués ✅ **Implémenté** ci-dessous et retirés du calcul d'effort restant ; le reste de l'analyse (priorités, efforts estimés) reste valable tel quel pour les vecteurs encore manquants. Le détail complet de la couverture actuelle (10/20) figure dans `rapport_technique_rtk.md`, §7.

---

## 🔴 Modules manquants de la matrice (couverture complète)

### **RTK-03 : Extraction de secrets via le LLM** *(Critique)*
- **Pourquoi** : C'est le vecteur #3 de la matrice, directement lié à l'architecture LLM+MCP. Sans lui, on ne teste pas si le modèle peut révéler ses propres secrets (clés d'outils MCP, prompt système contenant des tokens).
- **Implémentation** : Corpus de 30+ techniques (repeat text above, rôles alternés, encodage base64, DAN variants, reformulation bénigne).
- **Effort** : 3-4 jours (corpus + intégration au runner existant).

### **RTK-05 : CORS & traversée de préfixe buckets** *(Moyenne)* — ✅ **Implémenté**
- **Pourquoi** : Complète RTK-04. Un bucket accessible anonymement peut avoir une config CORS permettant à un site tiers de lire ses données, ou un service de tuiles peut permettre d'accéder à des objets hors préfixe.
- **Statut** : livré sous `rtk.modules.buckets.cors_traversal`.

### **RTK-08 : Cartographie surface externe** *(Haute)* — ✅ **Implémenté**
- **Pourquoi** : Détecter les endpoints oubliés (serveur MCP de dev exposé, API LLM sans auth). Indispensable avant de lancer les tests offensifs.
- **Statut** : livré sous `rtk.modules.network.external_surface`, conforme à l'implémentation envisagée : énumération de sous-domaines via `subfinder` (avec repli silencieux si le binaire est absent) puis fingerprinting HTTP par signatures MCP/LLM/WMS.

### **RTK-09 : Contournement WAF** *(Moyenne)*
- **Pourquoi** : Valider que les garde-fous réseau (AWS WAF, Cloud Armor) résistent aux techniques d'évasion connues.
- **Garde-fou** : Rate limiting codé en dur (max 10 req/min).
- **Effort** : 2 jours.

### **RTK-12 : Agentivité excessive** *(Critique)*
- **Pourquoi** : Tester si le modèle peut enchaîner des outils au-delà de ce qui est autorisé (ex: passer de "lire météo" à "écrire dans un bucket").
- **Implémentation** : Scénarios de chaînage dans le corpus, vérification via les logs du proxy MCP.
- **Effort** : 3 jours.

### **RTK-15 : DoS économique** *(Moyenne)*
- **Pourquoi** : Simuler des requêtes coûteuses (boucles d'outils, tokens max) pour valider les défenses de rate limiting et alerter sur les risques de facturation.
- **Effort** : 2 jours.

### **RTK-16 : Vérification signature artefacts** *(Haute)*
- **Pourquoi** : S'assurer que les images conteneur et modèles déployés sont signés (SLSA).
- **Implémentation** : Wrapper `cosign verify` + comparaison avec clés attendues.
- **Effort** : 2 jours.

### **RTK-17 : Dependency confusion** *(Moyenne, risque juridique)*
- **Pourquoi** : Détecter les paquets internes non enregistrés sur PyPI qui pourraient être spoofés.
- **Garde-fou** : Flag explicite `--i-have-written-authorization` + nom de canary non guessable.
- **Effort** : 3 jours (incluant validation juridique).

### **RTK-19 : Angles morts journalisation** *(Haute)*
- **Pourquoi** : Identifier les actions qui ne génèrent aucune trace exploitable (CloudTrail, logs MCP).
- **Implémentation** : Pour chaque finding `simulated_attack=True`, vérifier l'existence d'un log correspondant.
- **Effort** : 3 jours.

---

## 🟡 Modules "Ultimate" (au-delà de la matrice)

### **1. Instrumentation OpenTelemetry complète**
- **Pourquoi** : Permettre un MTTD **par composant** (délai détection côté LLM vs côté cloud vs côté SIEM).
- **Implémentation** : Trace ID propagé client LLM → proxy MCP → serveur MCP → action cloud. Span attributes : `mcp.tool.name`, `llm.model`, `llm.tokens.in/out`.
- **Effort** : 4 jours.

### **2. Techniques d'attaque avancées LLM**
- **Many-shot jailbreaking** : Exploiter la grande fenêtre de contexte pour noyer les instructions système.
- **Crescendo attack** : Escalade progressive sur plusieurs tours de conversation.
- **Skeleton Key** : Contournement des guardrails par reformulation bénigne.
- **Multimodal injection** : Injection via pixels/stéganographie dans les tuiles GIS (si le LLM ingère des images).
- **Effort** : 5 jours (corpus + générateurs).

### **3. Modules pour modèles fine-tunés** *(si le scope inclut le fine-tuning)*
- **Model inversion** : Reconstituer des données d'entraînement depuis les sorties.
- **Membership inference** : Déterminer si un échantillon a été utilisé pour l'entraînement.
- **Backdoor detection** : Détecter des déclencheurs cachés modifiant le comportement du modèle.
- **Model extraction** : Voler le modèle par requêtes massives.
- **Effort** : 6 jours (nécessite expertise ML).

### **4. Supply chain des modèles**
- **Pourquoi** : Vérifier la signature des **poids de modèles** (pas seulement des conteneurs).
- **Implémentation** : Sigstore/cosign sur les artefacts de modèles (Hugging Face, Model Zoo).
- **Effort** : 2 jours.

### **5. RGPD & Ré-identification GIS**
- **k-anonymat** : Vérifier que les jeux de données publiés ne permettent pas de ré-identifier un individu (seuil k=5).
- **Différential privacy** : Vérifier l'absence de fuite par recoupement sur les agrégats publiés.
- **Linkage attacks** : Croiser les données publiées avec des sources externes (OpenStreetMap, registres publics).
- **Effort** : 4 jours (nécessite expertise GIS/RGPD).

### **6. Double évaluation (LLM-as-judge)**
- **Pourquoi** : Le juge déterministe actuel rate les bypass subtils (ex: le modèle refuse explicitement mais exécute quand même l'action via un tool_call détourné).
- **Implémentation** : Re-évaluation par un LLM juge **sur les cas ambigus uniquement**, avec accord humain en cas de divergence.
- **Effort** : 3 jours.

### **7. Rotation effective des secrets (RTK-21)**
- **Pourquoi** : RTK-01 détecte les secrets exposés, mais ne vérifie pas que la rotation **effective** a lieu.
- **Implémentation** : Comparer `LastRotatedDate` (AWS) / versions (GCP) sur plusieurs semaines. Détecter les secrets dont la rotation est configurée mais jamais exécutée.
- **Effort** : 2 jours.

### **8. Dashboard de dérive des schémas MCP**
- **Pourquoi** : RTK-13 est un démon ponctuel. Il faut un dashboard temps réel montrant l'évolution des schémas d'outils sur la durée de la mission.
- **Implémentation** : Web UI (Streamlit ou Gradio) affichant les diffs de schémas, alertes sur changements.
- **Effort** : 4 jours.

### **9. Reporting avancé**
- **PDF professionnel** : Jinja2 + WeasyPrint pour un rapport client imprimable.
- **Graphes d'élévation IAM** : Export GraphML/JSON du graphe privesc (RTK-06).
- **Matrices croisées** : Vecteur × MTTD, Vecteur × Garde-fou, Vecteur × Sévérité.
- **Recommandations actionnables** : Génération automatique de tickets Jira/ServiceNow à partir des findings.
- **Effort** : 5 jours.

---

## 🟢 Améliorations transversales

### **1. Idempotence et CI/CD**
- **Pourquoi** : Le harnais doit être rejouable en CI sans effet de bord.
- **Implémentation** : Déduplication par hash `(case.id, target)` déjà en place, mais ajouter un mode `--dry-run` et un export des résultats en JUnit XML pour intégration CI.
- **Effort** : 2 jours.

### **2. Mode "Surveillance continue"**
- **Pourquoi** : Le RTK actuel est orienté "scan ponctuel". Il faut un mode démon pour surveiller en continu (tool poisoning, dérive de schémas, nouveaux buckets exposés).
- **Implémentation** : Démon léger (RTK-13 étendu) avec alertes Slack/PagerDuty.
- **Effort** : 4 jours.

### **3. Support multi-cloud étendu**
- **Pourquoi** : Actuellement AWS/GCP. Ajouter Azure (Blob Storage, Entra ID, Azure AI) pour couvrir 100% du marché cloud.
- **Effort** : 5 jours (abstraction cloud existante facilite l'ajout).

### **4. Intégration avec les SIEM**
- **Pourquoi** : Corréler automatiquement les findings avec les alertes Splunk/Sentinel/Chronicle pour calculer le MTTD réel.
- **Implémentation** : Connecteurs API pour les SIEM majeurs.
- **Effort** : 4 jours.

---

## 📊 Synthèse : Roadmap vers "Ultimate"

| Phase | Contenu | Durée | Priorité |
|-------|---------|-------|----------|
| **Phase 1** | Couverture complète des 20 vecteurs — restant : RTK-03, 09, 12, 15, 16, 17, 19 (RTK-05 et RTK-08 livrés) | ~2 semaines | 🔴 Critique |
| **Phase 2** | Techniques avancées LLM + OpenTelemetry + Double évaluation | 2 semaines | 🟡 Haute |
| **Phase 3** | Modules fine-tuning + Supply chain modèles + RGPD GIS | 2 semaines | 🟡 Haute (si scope) |
| **Phase 4** | Reporting avancé + Dashboard dérive + Surveillance continue | 2 semaines | 🟢 Moyenne |
| **Phase 5** | Multi-cloud (Azure) + Intégration SIEM | 2 semaines | 🟢 Moyenne |

**Total** : ~11 semaines pour un développeur senior, ~6 semaines à deux.

---

## 🎯 Recommandation immédiate (mise à jour)

RTK-08 (cartographie de surface), initialement en tête de liste, est désormais livré. Pour la suite du passage au niveau "Ultimate", je recommande de prioriser :

1. **RTK-03** (extraction secrets via LLM) — toujours critique, bloque le reporting complet sur le périmètre LLM+MCP
2. **RTK-12** (agentivité excessive) — cœur métier LLM+MCP, non traité
3. **RTK-19** (angles morts journalisation) — complète naturellement `audit.mttd_closed_loop`, déjà livré pour AWS/CloudTrail
4. **OpenTelemetry** — instrumente le MTTD fin
5. **Reporting avancé** — livrable client professionnel

Ces 5 chantiers représentent ~2 semaines de dev et couvrent l'essentiel de la valeur ajoutée "Ultimate" restante.

Souhaitez-vous que je génère l'implémentation complète de l'un de ces modules manquants ?
