# 🛡️ DDoS Detection System with AI & SDN

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![AI](https://img.shields.io/badge/AI-Random%20Forest-orange.svg)](https://scikit-learn.org/)
[![Network](https://img.shields.io/badge/Network-Real%20Time-red.svg)](https://scapy.net/)

Un système avancé de détection d'attaques DDoS utilisant l'Intelligence Artificielle et les concepts de réseaux SDN, avec interface web temps réel et capacités de mitigation automatique.

## 🎯 Objectifs du Projet

- ✅ **Détection automatique** des attaques DDoS via modèle d'IA (Random Forest)
- ✅ **Réduction des faux positifs** grâce à l'apprentissage automatique
- ✅ **Gestion centralisée** inspirée des réseaux SDN
- ✅ **Mitigation en temps réel** avec blocage automatique des IPs malveillantes
- ✅ **Interface web interactive** avec dashboard et visualisations
- ✅ **Déploiement sur réseau réel** avec capture de paquets

## 🏗️ Architecture

```
ddos_detection_project/
├── 🎛️ controllers/          # Contrôleurs SDN et logique de gestion
├── 🤖 models/               # Modèles d'IA et extraction de features
├── 🌐 network/              # Topologie réseau et générateur de trafic
├── 📊 data/                 # Données d'entraînement et logs
├── 🔧 utils/                # Utilitaires (logging, configuration)
├── 🌍 web_interface/        # Interface web Flask avec dashboard
├── 📱 main.py               # Version simulation
├── 🚀 main_real.py          # Version déploiement réseau réel
└── 🌐 network_analyzer.py   # Analyseur de trafic réseau réel
```

## ✨ Fonctionnalités Principales

### 🤖 Intelligence Artificielle
- **Modèle Random Forest** avec 100 arbres de décision
- **10 features extraites** du trafic réseau (débit, diversité IPs, flags TCP, etc.)
- **Entraînement automatique** sur 15,000 échantillons synthétiques
- **Évaluation de performance** avec métriques de précision/rappel

### 🌐 Analyse Réseau Temps Réel
- **Capture de paquets** via Scapy sur interfaces réseau réelles
- **Analyse de flux** avec fenêtre glissante de 30 secondes  
- **Détection multi-types** : attaques volumétriques, SYN flood, UDP flood
- **Métriques avancées** : entropie des ports, variance des tailles de paquets

### 🛡️ Mitigation Automatique
- **Blocage d'IPs** via iptables en temps réel
- **Limitation de débit** avec traffic control (tc)
- **Seuils configurables** pour déclenchement des alertes
- **Actions graduées** selon le niveau de menace

### 📱 Interface Web Interactive
- **Dashboard temps réel** avec statistiques live
- **Graphiques dynamiques** (Chart.js) : bande passante, paquets/sec, score de menace
- **Liste des IPs bloquées** avec détails d'attaque
- **Historique des incidents** avec timestamps
- **Contrôles administrateur** : déblocage, reset, configuration

## 🚀 Installation et Utilisation

### 📋 Prérequis

```bash
# Système Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip libpcap-dev

# Système CentOS/RHEL
sudo yum install python3 python3-pip libpcap-devel
```

### 💾 Installation

```bash
# Cloner le repository
git clone https://github.com/Derbyneon/ddos-detection-ai.git
cd ddos-detection-ai

# Installer les dépendances Python
pip3 install -r requirements.txt
```

### 🎮 Utilisation - Mode Simulation

```bash
# Lancer le système en mode simulation
python3 main.py
```

**Commandes disponibles :**
- `attack_low` - Simulation attaque légère (100 flux)
- `attack_medium` - Simulation attaque moyenne (500 flux)  
- `attack_high` - Simulation attaque intense (1,000 flux)
- `attack_critical` - Simulation attaque critique (2,000 flux)
- `normal` - Génération de trafic légitime
- `stats` - Affichage des statistiques détaillées
- `help` - Liste complète des commandes

**Interface Web :** http://localhost:5000

### 🌐 Utilisation - Mode Réseau Réel

```bash
# Lancer avec privilèges root (requis pour capture de paquets)
sudo python3 main_real.py

# Lister les interfaces réseau disponibles
python3 main_real.py --list-interfaces

# Spécifier une interface spécifique
sudo python3 main_real.py -i eth0
```

## 📊 Fonctionnalités du Dashboard

### 🎯 Métriques Principales
- **Flux réseau** : Total, actifs, paquets/seconde
- **Sécurité** : IPs bloquées, alertes générées, niveau de menace
- **Système** : CPU, mémoire, uptime, taux de détection

### 📈 Visualisations Temps Réel
- **Graphique multi-courbes** : Bande passante, débit de paquets, score de menace
- **Mise à jour automatique** toutes les 2-6 secondes
- **Historique** : Conservation des 50 derniers points de données

### 🚫 Gestion des Blocages
- **Liste interactive** des IPs bloquées avec détails
- **Déblocage individuel** ou en masse
- **Informations d'attaque** : type, confiance, timestamp

## 🧪 Features d'IA Extraites

| Feature | Description | Utilité |
|---------|-------------|---------|
| `packet_count` | Nombre total de paquets | Détection attaques volumétriques |
| `byte_count` | Volume de données | Identification pic de trafic |
| `packets_per_second` | Débit de paquets | Indicateur clé d'attaque |
| `unique_src_ips` | IPs sources uniques | Attaques distribuées |
| `syn_flag_ratio` | Proportion flags SYN | Détection SYN flood |
| `avg_packet_size` | Taille moyenne paquets | Petits paquets suspects |
| `port_scan_score` | Score activité de scan | Reconnaissance réseau |
| `flow_rate` | Débit nouveaux flux | Intensité de l'attaque |

## ⚙️ Configuration

### 🎛️ Paramètres ML (models/ml_model.py)
```python
# Configuration Random Forest
n_estimators = 100        # Nombre d'arbres
max_depth = 10           # Profondeur maximale
alert_threshold = 0.7    # Seuil de confiance pour alerte
```

### 🌐 Paramètres Réseau (network_analyzer.py)
```python
time_window = 30         # Fenêtre d'analyse (secondes)
analysis_interval = 5    # Fréquence d'analyse (secondes)  
alert_threshold = 0.7    # Seuil déclenchement alerte
```

## 📈 Performances

### 🎯 Métriques d'Évaluation
- **Précision d'entraînement** : 95-98%
- **Précision de test** : 92-96%
- **Temps de traitement** : < 100ms par batch
- **Détection attaques volumétriques** : > 99%
- **Taux de faux positifs** : < 5%

### 🚀 Capacités de Traitement
- **Paquets/seconde** : Jusqu'à 10,000 pps
- **Flux simultanés** : Plusieurs milliers
- **Mémoire requise** : ~200MB
- **Latence de détection** : 5-30 secondes

## 🛠️ Développement et Extension

### 📦 Dépendances Principales
```bash
scapy>=2.4.5          # Capture et analyse de paquets
scikit-learn>=1.0.0    # Machine Learning
flask>=2.0.0           # Interface web
pandas>=1.3.0          # Manipulation de données
numpy>=1.21.0          # Calculs numériques
psutil>=5.8.0          # Informations système
```

### 🔧 Personnalisation
- **Nouveaux types d'attaques** : Étendre `generate_attack_flows()`
- **Features personnalisées** : Modifier `FeatureExtractor`
- **Algorithmes ML** : Remplacer Random Forest dans `DDoSDetectionModel`
- **Actions de mitigation** : Enrichir `mitigate_attack()`

## 📚 Documentation Technique

### 🤖 Modèle d'IA
Le système utilise un **Random Forest Classifier** entraîné sur des données synthétiques représentant :
- **50% trafic normal** : Connexions HTTP/HTTPS classiques
- **50% attaques DDoS** : Volumétriques, SYN flood, UDP flood

### 🌐 Architecture SDN Simulée
- **Contrôleur centralisé** pour gestion des règles
- **Vision globale** du réseau et des menaces
- **Réaction rapide** via API de contrôle
- **Collecte de télémétrie** temps réel

## ⚠️ Limitations et Prérequis

### 🔒 Privilèges Requis
- **Mode réel** : Privilèges root pour capture de paquets et iptables
- **Simulation** : Aucun privilège spécial requis

### 🌐 Compatibilité Réseau
- **Linux** : Support complet (Ubuntu, CentOS, Debian)
- **Windows** : Mode simulation uniquement
- **macOS** : Support partiel (pas de mitigation automatique)

### 📊 Données d'Entraînement
- **Actuellement** : Données synthétiques générées
- **Recommandation** : Utiliser datasets publics (NSL-KDD, CICIDS) pour production

## 🤝 Contribution

Les contributions sont les bienvenues ! Merci de :

1. **Fork** le projet
2. **Créer** une branche pour votre feature (`git checkout -b feature/nouvelle-fonctionnalite`)
3. **Commiter** vos changements (`git commit -am 'Ajout nouvelle fonctionnalité'`)
4. **Push** sur la branche (`git push origin feature/nouvelle-fonctionnalite`)
5. **Créer** une Pull Request



## 👨‍💻 Auteur

**Derbyneon**
- GitHub: [@Derbyneon](https://github.com/Derbyneon)
- Email: jacobwilson20xy@gmail.com
- LinkedIn: [Jacob](https://www.linkedin.com/in/sewah-akouete-jacob-wilson/)

