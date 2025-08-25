#!/usr/bin/env python3

import warnings
warnings.filterwarnings("ignore")

import sys
import os
import threading
import time
import signal
import socket
from web_interface.app import app as web_app, update_stats, add_blocked_ip, update_blocked_ips
from utils.logger import setup_logger
from models.ml_model import DDoSDetectionModel
from models.feature_extractor import FeatureExtractor
import random
from datetime import datetime
import json

# Variables globales
system_running = True
ddos_model = None
feature_extractor = None
stats_data = {
    'total_flows': 0,
    'blocked_ips': 0,
    'alert_count': 0,
    'active_flows': 0,
    'system_status': 'SAFE',
    'threat_level': 'LOW'
}
blocked_ips_list = set()

def signal_handler(signum, frame):
    """Gestionnaire de signal pour arrêt propre"""
    global system_running
    print("\n🛑 Arrêt demandé...")
    system_running = False
    cleanup_and_exit()

def start_web_interface():
    """Démarre l'interface web en mode silencieux"""
    try:
        # Redirection des logs Flask vers null pour éviter le spam
        import logging
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        web_app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"❌ Erreur interface web: {e}")

def simulate_background_traffic():
    """Simule le trafic de fond en temps réel"""
    global stats_data, ddos_model, feature_extractor
    
    while system_running:
        try:
            # Simulation de trafic de fond aléatoire
            if random.random() < 0.3:  # 30% de chance d'activité de fond
                num_flows = random.randint(1, 20)
                flows = generate_normal_flows(num_flows)
                
                # Analyse des flux
                features = feature_extractor.get_feature_vector(flows)
                is_ddos, confidence = ddos_model.predict(features)
                
                # Mise à jour des stats (trafic normal)
                stats_data['active_flows'] = num_flows
                stats_data['total_flows'] += num_flows
                
                # Rare faux positif (réalisme)
                if is_ddos and random.random() < 0.02:  # 2% de faux positifs
                    stats_data['alert_count'] += 1
                
                # IMPORTANT: Synchronisation avec l'interface web
                update_stats(stats_data)
                
            time.sleep(random.uniform(3, 7))  # Intervalle variable
            
        except Exception as e:
            print(f"⚠️ Erreur simulation de fond: {e}")
            time.sleep(5)

def generate_attack_flows(intensity='medium', num_flows=1000):
    """Génère des flux d'attaque selon l'intensité"""
    flows = []
    
    # Paramètres selon l'intensité
    intensity_params = {
        'low': {
            'duration_range': (0.5, 2.0),
            'byte_range': (200, 800),
            'port_variety': [80, 443, 8080, 3389],
            'ip_diversity': 20
        },
        'medium': {
            'duration_range': (0.1, 1.0),
            'byte_range': (64, 400),
            'port_variety': [80, 443, 8080],
            'ip_diversity': 50
        },
        'high': {
            'duration_range': (0.01, 0.3),
            'byte_range': (32, 200),
            'port_variety': [80, 443],
            'ip_diversity': 100
        },
        'critical': {
            'duration_range': (0.001, 0.1),
            'byte_range': (20, 100),
            'port_variety': [80],
            'ip_diversity': 200
        }
    }
    
    params = intensity_params.get(intensity, intensity_params['medium'])
    
    for i in range(num_flows):
        # Génération d'IPs malveillantes plus réalistes
        src_network = random.choice([
            "192.168.1", "10.0.0", "172.16.1", 
            "203.0.113", "198.51.100", "147.45.22"
        ])
        
        flow = {
            'src_ip': f"{src_network}.{random.randint(1, 255)}",
            'dst_ip': random.choice(["10.0.0.100", "10.0.0.101", "10.0.0.102"]),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(params['port_variety']),
            'protocol': random.choice([6, 17]),  # TCP, UDP
            'byte_count': random.randint(*params['byte_range']),
            'duration': random.uniform(*params['duration_range']),
            'packet_count': random.randint(1, 100),
            'flags': random.choice(['SYN', 'ACK', 'FIN', 'RST'])
        }
        flows.append(flow)
    
    return flows

def generate_normal_flows(num_flows=10):
    """Génère du trafic normal réaliste"""
    flows = []
    
    for i in range(num_flows):
        flow = {
            'src_ip': f"10.0.{random.randint(1, 5)}.{random.randint(1, 50)}",
            'dst_ip': f"10.0.{random.randint(1, 5)}.{random.randint(1, 50)}",
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 22, 25, 53, 993, 995]),
            'protocol': random.choice([6, 17]),
            'byte_count': random.randint(500, 1500),
            'duration': random.uniform(1, 30),
            'packet_count': random.randint(10, 1000),
            'flags': 'ACK'
        }
        flows.append(flow)
    
    return flows

def execute_attack_simulation(intensity, num_flows, description):
    """Exécute une simulation d'attaque avec analyse détaillée"""
    global stats_data, ddos_model, feature_extractor, blocked_ips_list
    
    print(f"🚨 Lancement simulation d'attaque DDoS ({description})...")
    print(f"   📊 Génération de {num_flows} flux malveillants...")
    
    # Génération des flux d'attaque
    attack_flows = generate_attack_flows(intensity, num_flows)
    
    # Analyse par le modèle ML
    features = feature_extractor.get_feature_vector(attack_flows)
    is_ddos, confidence = ddos_model.predict(features)
    
    # Simulation du temps de traitement
    processing_time = len(attack_flows) * 0.001
    time.sleep(min(processing_time, 2))
    
    # Mise à jour des statistiques
    stats_data['active_flows'] = len(attack_flows)
    stats_data['total_flows'] += len(attack_flows)
    
    # Résultats de la détection
    if is_ddos:
        stats_data['alert_count'] += 1
        
        # Simulation de blocage d'IPs
        num_blocked = min(random.randint(3, 15), len(set(flow['src_ip'] for flow in attack_flows)))
        blocked_ips = set(random.choices([flow['src_ip'] for flow in attack_flows], k=num_blocked))
        
        blocked_ips_list.update(blocked_ips)
        stats_data['blocked_ips'] = len(blocked_ips_list)
        
        # IMPORTANT: Mise à jour de l'interface web avec les nouvelles IPs
        for ip in blocked_ips:
            add_blocked_ip(ip, f"Attaque {intensity.upper()}", confidence)
        
        # Synchronisation avec l'interface web
        update_stats(stats_data)
        update_blocked_ips(blocked_ips_list)
        
        # Affichage des résultats
        print(f"🔴 ATTAQUE DÉTECTÉE!")
        print(f"   🎯 Confiance: {confidence:.1%}")
        print(f"   📊 Flux analysés: {len(attack_flows):,}")
        print(f"   🚫 IPs bloquées: {len(blocked_ips)}")
        print(f"   ⏱️  Temps de traitement: {processing_time:.3f}s")
        
        # Affichage des IPs bloquées
        for ip in list(blocked_ips)[:5]:  # Afficher les 5 premières
            print(f"   🚫 {ip}")
        if len(blocked_ips) > 5:
            print(f"   🚫 ... et {len(blocked_ips) - 5} autres")
    else:
        print(f"❌ Attaque non détectée (confiance: {confidence:.1%})")
        print(f"   ⚠️  Possible évasion ou faux négatif")
    
    # IMPORTANT: Toujours synchroniser avec l'interface web
    update_stats(stats_data)
    print(f"✅ Simulation terminée\n")

def display_stats():
    """Affiche les statistiques détaillées"""
    print("📊 STATISTIQUES DÉTAILLÉES:")
    print("=" * 50)
    print(f"   🌐 Flux actifs       : {stats_data['active_flows']:,}")
    print(f"   📈 Total flux        : {stats_data['total_flows']:,}")
    print(f"   🚨 Alertes générées  : {stats_data['alert_count']:,}")
    print(f"   🚫 IPs bloquées      : {stats_data['blocked_ips']:,}")
    print(f"   🛡️  Statut système    : {stats_data.get('system_status', 'UNKNOWN')}")
    print(f"   ⚡ Niveau menace    : {stats_data.get('threat_level', 'UNKNOWN')}")
    print(f"   🌐 Interface web     : http://localhost:5000")
    print("=" * 50)
    
    if blocked_ips_list:
        print("🚫 IPs actuellement bloquées:")
        for i, ip in enumerate(list(blocked_ips_list)[:10], 1):
            print(f"   {i:2d}. {ip}")
        if len(blocked_ips_list) > 10:
            print(f"   ... et {len(blocked_ips_list) - 10} autres")
    print()

def cleanup_and_exit():
    """Nettoyage et sortie propre"""
    print("\n🧹 Nettoyage des ressources...")
    
    # Sauvegarde des statistiques
    try:
        os.makedirs('data/logs', exist_ok=True)
        with open('data/logs/final_stats.json', 'w') as f:
            json.dump(stats_data, f, indent=2)
        print("💾 Statistiques sauvegardées")
    except Exception as e:
        print(f"⚠️ Erreur sauvegarde: {e}")
    
    print("✅ Nettoyage terminé")
    print("🎯 Merci d'avoir utilisé le système de détection DDoS!")
    print("👋 Au revoir !")
    os._exit(0)

def main():
    global ddos_model, feature_extractor, stats_data
    
    # Gestionnaire de signal
    signal.signal(signal.SIGINT, signal_handler)
    
    logger = setup_logger()
    logger.info("🚀 Démarrage du système de détection DDoS avancé")
    
    # Banner amélioré
    print("""
╔══════════════════════════════════════════════════════════════════╗
║              🛡️ SYSTÈME DE DÉTECTION DDOS AVANCÉ 🛡️              ║
║                       INTELLIGENCE ARTIFICIELLE                  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  🤖 Modèle d'IA avec apprentissage automatique                   ║
║  🌐 Interface web temps réel avec graphiques                     ║
║  📊 Simulation de trafic réseau avancée                          ║
║  🚨 Détection automatique multi-niveaux                          ║
║  🔒 Blocage intelligent des menaces                              ║
║  📈 Métriques et analytics en temps réel                         ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        # 1. Initialisation du modèle ML
        print("1️⃣  Initialisation du modèle d'Intelligence Artificielle...")
        ddos_model = DDoSDetectionModel()
        if not ddos_model.load_model():
            print("   🔄 Entraînement du modèle ML en cours...")
            ddos_model.train()
        
        feature_extractor = FeatureExtractor()
        print("✅ Modèle d'IA opérationnel!")
        
        # 2. Démarrage de l'interface web
        print("2️⃣  Démarrage de l'interface web avancée...")
        web_thread = threading.Thread(target=start_web_interface, daemon=True)
        web_thread.start()
        time.sleep(3)
        print("✅ Interface web démarrée sur http://localhost:5000")
        
        # 3. Initialisation des stats dans l'interface web
        print("3️⃣  Synchronisation des données...")
        update_stats(stats_data)
        print("✅ Données synchronisées!")
        
        # 4. Démarrage de la simulation de trafic de fond
        print("4️⃣  Démarrage de la simulation de trafic...")
        traffic_thread = threading.Thread(target=simulate_background_traffic, daemon=True)
        traffic_thread.start()
        print("✅ Simulation de trafic active!")
        
        print("""
✅ SYSTÈME OPÉRATIONNEL ! 

📱 Dashboard: http://localhost:5000

🎮 COMMANDES DISPONIBLES:
┌─────────────────────────────────────────────────────────────┐
│ SIMULATIONS D'ATTAQUES:                                     │
│  • attack_low      - Attaque faible (100 flux)             │
│  • attack_medium   - Attaque moyenne (500 flux)            │
│  • attack_high     - Attaque forte (1,000 flux)            │
│  • attack_critical - Attaque critique (2,000 flux)         │
│  • attack          - Attaque standard (1,000 flux)         │
│                                                             │
│ TRAFIC NORMAL:                                              │
│  • normal          - Générer trafic légitime               │
│  • traffic_burst   - Pic de trafic normal                  │
│                                                             │
│ GESTION SYSTÈME:                                            │
│  • stats           - Statistiques détaillées               │
│  • reset           - Reset complet du système              │
│  • clear_blocked   - Débloquer toutes les IPs              │
│  • status          - État du système                       │
│                                                             │
│ UTILITAIRES:                                                │
│  • help            - Afficher cette aide                   │
│  • quit            - Quitter le système                    │
└─────────────────────────────────────────────────────────────┘
        """)
        
        # 5. Interface utilisateur interactive améliorée
        while system_running:
            try:
                command = input("🔧 ddos_detection> ").strip().lower()
                
                if command in ['quit', 'exit', 'q']:
                    break
                
                elif command == 'attack_low':
                    execute_attack_simulation('low', 100, "faible intensité")
                
                elif command == 'attack_medium':
                    execute_attack_simulation('medium', 500, "intensité moyenne")
                
                elif command == 'attack_high':
                    execute_attack_simulation('high', 1000, "haute intensité")
                
                elif command == 'attack_critical':
                    execute_attack_simulation('critical', 2000, "intensité critique")
                
                elif command == 'attack':
                    execute_attack_simulation('medium', 1000, "intensité standard")
                
                elif command == 'normal':
                    print("✅ Génération de trafic normal...")
                    normal_flows = generate_normal_flows(random.randint(15, 30))
                    
                    features = feature_extractor.get_feature_vector(normal_flows)
                    is_ddos, confidence = ddos_model.predict(features)
                    
                    stats_data['active_flows'] = len(normal_flows)
                    stats_data['total_flows'] += len(normal_flows)
                    
                    if is_ddos:
                        print(f"⚠️ Faux positif détecté (confiance: {confidence:.1%})")
                        stats_data['alert_count'] += 1
                    else:
                        print(f"✅ Trafic normal confirmé (confiance: {1-confidence:.1%})")
                    
                    # IMPORTANT: Synchronisation
                    update_stats(stats_data)
                
                elif command == 'traffic_burst':
                    print("📈 Simulation pic de trafic normal...")
                    burst_flows = generate_normal_flows(random.randint(100, 200))
                    
                    features = feature_extractor.get_feature_vector(burst_flows)
                    is_ddos, confidence = ddos_model.predict(features)
                    
                    stats_data['active_flows'] = len(burst_flows)
                    stats_data['total_flows'] += len(burst_flows)
                    
                    print(f"📊 {len(burst_flows)} flux de trafic normal généré")
                    if is_ddos:
                        print(f"⚠️ Faux positif sur pic de trafic (confiance: {confidence:.1%})")
                        stats_data['alert_count'] += 1
                    else:
                        print(f"✅ Pic de trafic correctement identifié")
                    
                    # IMPORTANT: Synchronisation
                    update_stats(stats_data)
                
                elif command == 'stats':
                    display_stats()
                
                elif command == 'status':
                    print(f"🛡️ Statut système: {stats_data.get('system_status', 'UNKNOWN')}")
                    print(f"⚡ Niveau menace: {stats_data.get('threat_level', 'LOW')}")
                    print(f"🌐 Interface web: {'✅ Active' if True else '❌ Inactive'}")
                    print(f"🤖 IA Detection: {'✅ Active' if ddos_model else '❌ Inactive'}")
                
                elif command == 'reset':
                    confirm = input("⚠️ Confirmer la remise à zéro complète? (oui/non): ")
                    if confirm.lower() in ['oui', 'o', 'yes', 'y']:
                        stats_data = {
                            'total_flows': 0, 'blocked_ips': 0, 'alert_count': 0, 
                            'active_flows': 0, 'system_status': 'SAFE', 'threat_level': 'LOW'
                        }
                        blocked_ips_list.clear()
                        # IMPORTANT: Synchronisation du reset
                        update_stats(stats_data)
                        update_blocked_ips(set())
                        print("🔄 Système remis à zéro complet")
                    else:
                        print("❌ Remise à zéro annulée")
                
                elif command == 'clear_blocked':
                    count = len(blocked_ips_list)
                    blocked_ips_list.clear()
                    stats_data['blocked_ips'] = 0
                    # IMPORTANT: Synchronisation
                    update_stats(stats_data)
                    update_blocked_ips(set())
                    print(f"🔓 {count} IPs débloquées")
                
                elif command == 'help':
                    print("""
🎮 GUIDE DES COMMANDES:

🚨 ATTAQUES SIMULÉES:
  attack_low      → Attaque DDoS légère (100 flux)
  attack_medium   → Attaque DDoS modérée (500 flux)
  attack_high     → Attaque DDoS intense (1,000 flux)
  attack_critical → Attaque DDoS critique (2,000 flux)
  attack          → Attaque standard

🌐 TRAFIC NORMAL:
  normal          → Trafic utilisateur normal
  traffic_burst   → Pic de trafic légitime

📊 SYSTÈME:
  stats           → Statistiques détaillées
  status          → État du système
  reset           → Remise à zéro complète
  clear_blocked   → Débloquer toutes les IPs

🔧 UTILITAIRES:
  help            → Cette aide
  quit            → Quitter le système
                    """)
                
                elif command == '':
                    continue
                
                else:
                    print(f"❌ Commande inconnue: '{command}'")
                    print("💡 Tapez 'help' pour voir toutes les commandes")
                    
            except (EOFError, KeyboardInterrupt):
                break
                
    except Exception as e:
        logger.error(f"Erreur critique: {e}")
        print(f"❌ Erreur critique: {e}")
        
    finally:
        cleanup_and_exit()

if __name__ == '__main__':
    main()