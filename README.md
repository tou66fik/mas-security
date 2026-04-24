# 🛡️ MAS Security - Multi-Agent System for Cyber Defense
 Voici un fichier `README.md` professionnel, complet et prêt à être collé à la racine de votre projet. Il documente l'architecture, l'installation (avec les correctifs spécifiques Ubuntu/Python 3.12), le lancement multi-terminal et le dépannage.

```markdown
# 🛡️ MAS Security - Multi-Agent System for Cyber Defense

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![RabbitMQ](https://img.shields.io/badge/Broker-RabbitMQ-orange.svg)](https://www.rabbitmq.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Système multi-agents (MAS) événementiel et asynchrone conçu pour la **détection, la vérification et la réponse automatisée** aux menaces cyber en temps réel. Le système orchestre des agents spécialisés via RabbitMQ, enrichit les alertes avec le framework **MITRE ATT&CK**, intègre une **validation humaine**, et offre un dashboard de supervision temps réel.

## 📐 Architecture
```
[Agents Détection] ──▶ RabbitMQ (Topics) ──▶ [Agent AA/Enrichissement] ──▶ [Agent APROVE] ──▶ [Agent AR] ──▶ Actions/Logs
         │                      │                          │                          │                │
   ADI (Brute Force)            │                  MITRE ATT&CK Mapping        Slack/Timeout       iptables/WAF/EDR
   ASI (SQLi)                   │                  Risk Scoring & GeoIP        (Validation Humaine)
   ACSRf (CSRF)                 │                  STIX 2.1 Normalisation
   AMITM (Man-in-the-Middle)    │
   ACT (Trojan/C2)              ▼
                           Elasticsearch (Persistance)
```

## 🧩 Composants
| Agent | Rôle | Déclencheur |
|-------|------|-------------|
| `ADI` | Détection Brute Force | >5 échecs d'authentification |
| `ASI` | Détection Injection SQL | Patterns SQLi dans payloads HTTP |
| `ACSRf` | Détection CSRF | Tokens manquants/invalides |
| `AMITM` | Détection MITM | Certificats mismatch, anomalies ARP |
| `ACT` | Détection Cheval de Troie | Beacons C2, processus suspects |
| `AA` | Authentification & Corrélation | Enrichissement, scoring risque, mapping MITRE |
| `APROVE` | Validation Humaine | Slack/Webhook, timeout 30s, mode auto/sécurité |
| `AR` | Agent de Réponse | Blocage IP, journalisation, reporting |

## 🛠️ Prérequis
- **Python 3.12+**
- **Docker & Docker Compose** (pour RabbitMQ + Elasticsearch)
- **Git**
- **pip** (ou `python3 -m pip`)

## 📦 Installation & Démarrage

### 1. Cloner le projet
```bash
git clone <votre-repo>
cd mas-security
```

### 2. Environnement Virtuel (⚠️ Critique sur Ubuntu/Debian)
```bash
python3 -m venv venv
# Activation explicite pour éviter les bugs de PATH
source venv/bin/activate
export PATH="$PWD/venv/bin:$PATH"
```

### 3. Installer les dépendances
```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

### 4. Démarrer l'infrastructure (RabbitMQ + Elasticsearch)
```bash
docker compose up -d
# Attendre ~15s que les services soient prêts
docker exec mas_rabbitmq rabbitmq-diagnostics -q ping
```

### 5. Lancer le Système MAS
Ouvrez **3 terminaux** séparés (gardez le venv activé dans chacun) :

**Terminal 1 - Agents & Orchestrateur**
```bash
source venv/bin/activate
python3 main.py
```

**Terminal 2 - Simulateur d'Attaques**
```bash
source venv/bin/activate
python3 simulator.py
```

**Terminal 3 - Dashboard Streamlit**
```bash
source venv/bin/activate
python3 -m streamlit run dashboard.py --server.port 8501
```
👉 Ouvrez [http://localhost:8501](http://localhost:8501) dans votre navigateur.

## ⚙️ Configuration
- `config.py` : URL RabbitMQ (vhost encodé `%2F`), noms des queues, index ES.
- `config/prod/mitre_mapping.yaml` : Correspondance Menace → Technique MITRE ATT&CK.
- `agents/aapprove.py` : Ajoutez votre webhook Slack pour la validation humaine.
- `orchestrator_prod.py` : Seuil de confiance (`risk_score`), règles de blocage automatique.

## 🚀 Fonctionnalités Production
| Fonctionnalité | Description |
|----------------|-------------|
| 🔒 mTLS & RBAC | Authentification mutuelle via certificats OpenSSL + vhost dédié |
| 🤖 Validation Humaine | Agent `APROVE` avec timeout, mode `DRY_RUN` ou `AUTO_APPROVED` |
| 📊 MITRE ATT&CK | Enrichissement automatique des alertes (T1110, T1190, T1557...) |
| 📜 Export & Reporting | Script `kibana_exporter.py` → CSV/PDF conforme ISO27001/NIST |
| 🐇 Broker Robuste | `aio-pika` avec reconnect automatique, durable queues, persistance messages |

## 🐛 Dépannage (Troubleshooting)
| Symptôme | Solution |
|----------|----------|
| `externally-managed-environment` | Utiliser `python3 -m venv venv` + `source venv/bin/activate` |
| `Command 'python' not found` | Utiliser `python3` ou le chemin absolu `~/Desktop/mas-security/venv/bin/python3` |
| `ModuleNotFoundError: aio_pika` | `export PATH="$PWD/venv/bin:$PATH"` puis `pip install -r requirements.txt` |
| `TypeError: 'coroutine' object is not callable` | La méthode `_wrap` dans `base_agent.py` ne doit **pas** être `async`. Vérifiez le code fourni. |
| `Connection reset by peer` (RabbitMQ) | Vérifier `docker compose ps`, encoder le vhost `%2F` dans `config.py`, ajouter délai `sleep 15` |
| `streamlit: command not found` | Lancer avec `python3 -m streamlit run dashboard.py` |

## 📈 Génération de Rapports
```bash
# Export CSV + PDF des 7 derniers jours
python3 kibana_exporter.py --es http://localhost:9200 --index mas-alerts --days 7 --fmt both --output ./reports
```

## 🤝 Contribution & Licence
Projet académique/professionnel ouvert aux améliorations. Sous licence MIT.
```

### 💡 Conseils d'utilisation
1. **Copiez-collez** ce contenu dans un fichier `README.md` à la racine de `~/Desktop/mas-security/`
2. Remplacez `<votre-repo>` par l'URL de votre dépôt Git si vous en créez un
3. Le README inclut **tous les correctifs** que nous avons appliqués (PATH, venv, coroutine, vhost RabbitMQ, Python 3.12)

Votre projet est maintenant **documenté, reproductible et prêt pour une présentation ou un déploiement**. Si vous souhaitez que j'ajoute un fichier `LICENSE`, un `Makefile` pour automatiser les commandes, ou un guide d'intégration SIEM (Splunk/Sentinel), dites-le-moi. 🛡️📊✅
