#!/usr/bin/env python3

"""
SYSTÈME DE DÉTECTION DDoS - DÉPLOIEMENT RÉSEAU RÉEL
Analyse du trafic réseau réel et détection via IA
"""

import warnings
warnings.filterwarnings("ignore")


import sys
import os
import threading
import time
import signal
import argparse
from network_analyzer import RealNetworkAnalyzer
from models.ml_model import DDoSDetectionModel
from utils.logger import setup_logger
import psutil

# Variables globales
system_running = True
network_analyzer = None

def signal_handler(signum, frame):
    """Gestionnaire de signal pour arrêt propre"""
    global system_running, network_analyzer
    print("\n🛑 Arrêt demandé...")
    system_running = False
    if network_analyzer:
        network_analyzer.stop_capture()
    cleanup_and_exit()

def get_default_interface():
    """Trouve l'interface réseau principale"""
    try:
        # Obtenir les statistiques réseau
        net_stats = psutil.net_io_counters(pernic=True)
        
        # Filtrer les interfaces actives (avec trafic)
        active_interfaces = []
        for interface, stats in net_stats.items():
            if stats.bytes_sent > 1000 and stats.bytes_recv > 1000:
                # Exclure les interfaces locales
                if not interface.startswith(('lo', 'docker', 'veth', 'br-')):
                    active_interfaces.append({
                        'name': interface,
                        'bytes_sent': stats.bytes_sent,
                        'bytes_recv': stats.bytes_recv
                    })
        
        if active_interfaces:
            # Prendre l'interface avec le plus de trafic
            best_interface = max(active_interfaces, 
                               key=lambda x: x['bytes_sent'] + x['bytes_recv'])
            return best_interface['name']
        else:
            return "any"
            
    except Exception as e:
        print(f"⚠️ Erreur détection interface: {e}")
        return "any"

def list_network_interfaces():
    """Liste les interfaces réseau disponibles"""
    print("🌐 INTERFACES RÉSEAU DISPONIBLES:")
    print("=" * 50)
    
    try:
        net_stats = psutil.net_io_counters(pernic=True)
        net_addrs = psutil.net_if_addrs()
        
        for interface in sorted(net_stats.keys()):
            stats = net_stats[interface]
            
            # Obtenir l'adresse IP si disponible
            ip_addr = "N/A"
            if interface in net_addrs:
                for addr in net_addrs[interface]:
                    if addr.family == 2:  # AF_INET (IPv4)
                        ip_addr = addr.address
                        break
            
            # Statut actif/inactif
            status = "🟢 ACTIF" if stats.bytes_recv > 1000 else "🔴 INACTIF"
            
            print(f"📡 {interface:15} | {ip_addr:15} | {status}")
            print(f"   📥 Reçu:    {stats.bytes_recv:>12,} bytes")
            print(f"   📤 Envoyé:  {stats.bytes_sent:>12,} bytes")
            print(f"   📊 Paquets: {stats.packets_recv:>8,} reçus, {stats.packets_sent:>8,} envoyés")
            print("-" * 50)
            
    except Exception as e:
        print(f"❌ Erreur: {e}")

def check_privileges():
    """Vérifie les privilèges root nécessaires"""
    if os.geteuid() != 0:
        print("⚠️  ATTENTION: Privilèges root non détectés")
        print("💡 Pour capture de paquets et mitigation automatique:")
        print("   sudo python3 main_real.py")
        print()
        response = input("Continuer en mode lecture seule? (o/n): ")
        if response.lower() not in ['o', 'oui', 'y', 'yes']:
            sys.exit(1)
        return False
    return True

def display_real_stats():
    """Affiche les statistiques du trafic réseau réel"""
    global network_analyzer
    
    if not network_analyzer:
        print("❌ Analyseur réseau non initialisé")
        return
    
    stats = network_analyzer.get_statistics()
    
    print("📊 STATISTIQUES RÉSEAU RÉEL:")
    print("=" * 60)
    print(f"   📦 Paquets capturés    : {stats['total_packets']:,}")
    print(f"   📊 Bytes analysés      : {stats['total_bytes']:,}")
    print(f"   🌊 Flux actifs         : {stats['active_flows']:,}")
    print(f"   ⚡ Paquets/seconde     : {stats['packets_per_second']:.1f}")
    print(f"   🚨 Alertes générées    : {stats['alerts_count']:,}")
    print(f"   🚫 IPs bloquées        : {stats['blocked_ips']:,}")
    print("=" * 60)
    
    # Alertes récentes
    if stats['recent_alerts']:
        print("🚨 ALERTES RÉCENTES:")
        for alert in stats['recent_alerts'][-5:]:
            timestamp = alert['timestamp'].split('T')[1][:8]
            print(f"   {timestamp} | {alert['type']} | Confiance: {alert['confidence']:.1%}")
    
    # IPs bloquées
    if network_analyzer.blocked_ips:
        print("🚫 IPs ACTUELLEMENT BLOQUÉES:")
        for ip in list(network_analyzer.blocked_ips)[:10]:
            print(f"   🔒 {ip}")
    
    print()

def test_attack_simulation():
    """Génère du trafic de test pour validation"""
    print("🧪 GÉNÉRATION DE TRAFIC DE TEST")
    print("⚠️  Ceci génère du trafic réseau pour tester la détection")
    
    import socket
    import random
    
    def generate_test_traffic():
        """Génère du trafic de test léger"""
        try:
            # Créer plusieurs connexions simultanées
            targets = ['google.com', 'github.com', 'stackoverflow.com']
            
            for _ in range(50):  # 50 connexions de test
                target = random.choice(targets)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((target, 80))
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                    sock.recv(100)
                    sock.close()
                except:
                    pass
                time.sleep(0.1)
                
        except Exception as e:
            print(f"Erreur génération trafic: {e}")
    
    # Lancer en thread pour ne pas bloquer
    test_thread = threading.Thread(target=generate_test_traffic, daemon=True)
    test_thread.start()
    
    print("✅ Trafic de test généré - Surveillez les statistiques")

def cleanup_and_exit():
    """Nettoyage et sortie propre"""
    global network_analyzer
    
    print("\n🧹 Nettoyage des ressources...")
    
    try:
        if network_analyzer:
            network_analyzer.stop_capture()
        
        print("✅ Nettoyage terminé")
        print("👋 Au revoir!")
        
    except Exception as e:
        print(f"⚠️ Erreur nettoyage: {e}")
    
    os._exit(0)

def main():
    global system_running, network_analyzer
    
    # Gestionnaire de signal
    signal.signal(signal.SIGINT, signal_handler)
    
    # Arguments ligne de commande
    parser = argparse.ArgumentParser(description='Système de détection DDoS sur réseau réel')
    parser.add_argument('-i', '--interface', type=str, default=None,
                       help='Interface réseau à monitorer (auto-détection par défaut)')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='Lister les interfaces disponibles')
    parser.add_argument('--no-ml', action='store_true',
                       help='Désactiver le modèle ML')
    
    args = parser.parse_args()
    
    # Lister les interfaces si demandé
    if args.list_interfaces:
        list_network_interfaces()
        return
    
    # Configuration logging
    logger = setup_logger()
    logger.info("🚀 Démarrage système détection DDoS - RÉSEAU RÉEL")
    
    # Banner
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║              🛡️ DÉTECTION DDoS - DÉPLOIEMENT RÉSEAU RÉEL 🛡️           ║
║                          ANALYSE TRAFIC EN TEMPS RÉEL                 ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  🌐 Capture de paquets réseau réels via Scapy                        ║
║  🤖 Détection par Intelligence Artificielle                         ║
║  🚫 Blocage automatique via iptables                                ║
║  ⚡ Limitation de débit via traffic control                          ║
║  📊 Analyse temps réel des flux réseau                               ║
║  🔒 Mitigation automatique des attaques                             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Vérification privilèges
    has_root = check_privileges()
    
    try:
        # Détection interface réseau
        if args.interface:
            interface = args.interface
        else:
            interface = get_default_interface()
            
        print(f"🌐 Interface sélectionnée: {interface}")
        
        # Initialisation du modèle ML
        ml_model = None
        if not args.no_ml:
            print("1️⃣  Initialisation du modèle d'IA...")
            ml_model = DDoSDetectionModel()
            if not ml_model.load_model():
                print("   🔄 Entraînement du modèle en cours...")
                ml_model.train()
            print("✅ Modèle d'IA opérationnel!")
        
        # Initialisation de l'analyseur réseau
        print("2️⃣  Initialisation de l'analyseur réseau...")
        network_analyzer = RealNetworkAnalyzer(interface=interface, ml_model=ml_model)
        print("✅ Analyseur réseau prêt!")
        
        # Démarrage de la capture en arrière-plan
        print("3️⃣  Démarrage de la capture réseau...")
        capture_thread = threading.Thread(target=network_analyzer.start_capture, daemon=True)
        capture_thread.start()
        
        # Attendre un peu pour que la capture démarre
        time.sleep(2)
        print("✅ Capture réseau active!")
        
        print(f"""
✅ SYSTÈME OPÉRATIONNEL - ANALYSE RÉSEAU RÉEL!

🌐 Interface: {interface}
🔍 Analyse ML: {'Activée' if ml_model else 'Désactivée'}  
🛡️  Mitigation: {'Activée' if has_root else 'Mode lecture seule'}

🎮 COMMANDES DISPONIBLES:
┌─────────────────────────────────────────────────────────────┐
│ ANALYSE RÉSEAU:                                             │
│  • stats           - Statistiques trafic en temps réel     │
│  • alerts          - Liste des alertes DDoS               │
│  • blocked         - IPs actuellement bloquées           │
│  • flows           - Flux réseau actifs                   │
│                                                             │
│ MITIGATION:                                                 │
│  • unblock <ip>    - Débloquer une IP                     │
│  • clear_blocks    - Supprimer tous les blocages          │
│  • limit_rate      - Appliquer limitation débit           │
│                                                             │
│ TESTS:                                                      │
│  • test_traffic    - Générer trafic de test               │
│  • simulate_attack - Simulation légère d'attaque          │
│                                                             │
│ SYSTÈME:                                                    │
│  • interfaces      - Lister interfaces réseau             │
│  • status          - État détaillé du système             │
│  • help            - Afficher cette aide                  │
│  • quit            - Quitter le système                   │
└─────────────────────────────────────────────────────────────┘
        """)
        
        # Interface utilisateur interactive
        while system_running:
            try:
                command = input("🔧 ddos_real> ").strip().lower()
                parts = command.split()
                cmd = parts[0] if parts else ""
                
                if cmd in ['quit', 'exit', 'q']:
                    break
                
                elif cmd == 'stats':
                    display_real_stats()
                
                elif cmd == 'alerts':
                    stats = network_analyzer.get_statistics()
                    if stats['recent_alerts']:
                        print("🚨 ALERTES DDoS DÉTECTÉES:")
                        print("=" * 60)
                        for i, alert in enumerate(stats['recent_alerts'], 1):
                            timestamp = alert['timestamp'].split('T')[1][:8]
                            print(f"{i:2d}. {timestamp} | {alert['type']} | "
                                  f"Confiance: {alert['confidence']:.1%} | "
                                  f"Sévérité: {alert['severity']}")
                        print()
                    else:
                        print("✅ Aucune alerte DDoS détectée")
                
                elif cmd == 'blocked':
                    if network_analyzer.blocked_ips:
                        print("🚫 IPs BLOQUÉES VIA IPTABLES:")
                        print("=" * 40)
                        for i, ip in enumerate(network_analyzer.blocked_ips, 1):
                            print(f"{i:2d}. {ip}")
                        print(f"\nTotal: {len(network_analyzer.blocked_ips)} IPs bloquées")
                    else:
                        print("✅ Aucune IP actuellement bloquée")
                
                elif cmd == 'flows':
                    print("🌊 FLUX RÉSEAU ACTIFS:")
                    print("=" * 80)
                    current_time = time.time()
                    active_count = 0
                    
                    for flow_key, stats in list(network_analyzer.flow_stats.items())[:20]:
                        if current_time - stats['last_seen'] < 30:  # Flux récent
                            active_count += 1
                            parts = flow_key.split(':')
                            src_ip = parts[0] if len(parts) > 0 else 'N/A'
                            dst_ip = parts[1] if len(parts) > 1 else 'N/A'
                            
                            print(f"{active_count:2d}. {src_ip:15} → {dst_ip:15} | "
                                  f"Paquets: {stats['packet_count']:>6,} | "
                                  f"Bytes: {stats['byte_count']:>8,}")
                    
                    if active_count == 0:
                        print("Aucun flux actif détecté")
                    else:
                        print(f"\n{active_count} flux actifs affichés (max 20)")
                
                elif cmd == 'unblock' and len(parts) > 1:
                    ip_to_unblock = parts[1]
                    if has_root:
                        if network_analyzer.unblock_ip(ip_to_unblock):
                            print(f"✅ IP {ip_to_unblock} débloquée")
                        else:
                            print(f"❌ Erreur déblocage {ip_to_unblock}")
                    else:
                        print("❌ Privilèges root requis pour débloquer")
                
                elif cmd == 'clear_blocks':
                    if has_root:
                        network_analyzer.clear_all_blocks()
                        print("✅ Tous les blocages supprimés")
                    else:
                        print("❌ Privilèges root requis")
                
                elif cmd == 'limit_rate':
                    if has_root:
                        network_analyzer._apply_rate_limiting()
                        print("✅ Limitation de débit appliquée")
                    else:
                        print("❌ Privilèges root requis")
                
                elif cmd == 'test_traffic':
                    test_attack_simulation()
                
                elif cmd == 'simulate_attack':
                    print("🧪 Simulation d'attaque légère...")
                    print("⚠️  Ceci génère du trafic réseau intensif temporairement")
                    
                    # Simulation simple d'attaque
                    import socket
                    
                    def fake_attack():
                        for _ in range(100):
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(0.1)
                                sock.connect_ex(('127.0.0.1', 22))  # Connexion SSH locale
                                sock.close()
                            except:
                                pass
                            time.sleep(0.01)
                    
                    attack_thread = threading.Thread(target=fake_attack, daemon=True)
                    attack_thread.start()
                    print("✅ Simulation lancée - Vérifiez les alertes avec 'alerts'")
                
                elif cmd == 'interfaces':
                    list_network_interfaces()
                
                elif cmd == 'status':
                    print("🛡️ ÉTAT SYSTÈME DÉTAILLÉ:")
                    print("=" * 50)
                    print(f"   📡 Interface réseau    : {interface}")
                    print(f"   🤖 Modèle ML          : {'✅ Actif' if ml_model else '❌ Désactivé'}")
                    print(f"   🔒 Privilèges root     : {'✅ Oui' if has_root else '❌ Non'}")
                    print(f"   🌊 Capture active      : {'✅ Oui' if network_analyzer.running else '❌ Non'}")
                    
                    # Statistiques système
                    try:
                        import psutil
                        cpu_percent = psutil.cpu_percent(interval=1)
                        memory = psutil.virtual_memory()
                        print(f"   💻 CPU Usage          : {cpu_percent:.1f}%")
                        print(f"   🧠 Memory Usage       : {memory.percent:.1f}%")
                    except:
                        pass
                
                elif cmd == 'help':
                    print("""
🎮 GUIDE DÉTAILLÉ DES COMMANDES:

📊 ANALYSE RÉSEAU:
  stats           → Statistiques complètes du trafic réseau
  alerts          → Liste détaillée des alertes DDoS
  blocked         → IPs actuellement bloquées par iptables  
  flows           → Flux réseau actifs avec détails

🛡️ MITIGATION:
  unblock <ip>    → Débloquer une IP spécifique
  clear_blocks    → Supprimer tous les blocages iptables
  limit_rate      → Appliquer limitation débit réseau

🧪 TESTS:
  test_traffic    → Générer trafic réseau de test
  simulate_attack → Simulation légère pour test détection

⚙️ SYSTÈME:
  interfaces      → Lister toutes les interfaces réseau
  status          → État complet du système
  help            → Cette aide détaillée
  quit            → Arrêt propre du système

💡 CONSEILS:
  • Lancez avec sudo pour mitigation complète
  • Utilisez 'stats' régulièrement pour monitoring
  • Les alertes sont stockées 24h maximum
  • Testez avec 'simulate_attack' pour valider
                    """)
                
                elif cmd == '':
                    continue
                
                else:
                    print(f"❌ Commande inconnue: '{command}'")
                    print("💡 Tapez 'help' pour voir toutes les commandes")
                    
            except (EOFError, KeyboardInterrupt):
                break
            except Exception as e:
                print(f"❌ Erreur commande: {e}")
                
    except Exception as e:
        logger.error(f"Erreur critique: {e}")
        print(f"❌ Erreur critique: {e}")
        
    finally:
        cleanup_and_exit()

if __name__ == '__main__':
    main()