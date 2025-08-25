#!/usr/bin/env python3

"""
SYSTÈME DE DÉTECTION DDoS DÉPLOYABLE SUR VRAI RÉSEAU
Capture et analyse le trafic réseau réel via interfaces réseau
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import time
import psutil
import subprocess
import socket
import struct
from collections import defaultdict, deque
import numpy as np
from datetime import datetime, timedelta
import logging
import json

class RealNetworkAnalyzer:
    def __init__(self, interface="any", ml_model=None):
        """
        Analyseur de réseau réel
        interface: interface réseau à monitorer ("eth0", "wlan0", "any")
        """
        self.interface = interface
        self.ml_model = ml_model
        self.running = False
        
        # Stockage des flux en temps réel
        self.active_flows = defaultdict(dict)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_seen': None,
            'syn_count': 0,
            'flags': []
        })
        
        # Fenêtre glissante pour analyse temporelle
        self.time_window = 30  # 30 secondes
        self.packet_timestamps = deque()
        self.flow_history = deque()
        
        # Statistiques globales
        self.total_packets = 0
        self.total_bytes = 0
        self.alerts = []
        self.blocked_ips = set()
        
        # Configuration
        self.alert_threshold = 0.7  # Seuil de confiance pour alerte
        self.analysis_interval = 5  # Analyse toutes les 5 secondes
        
        self.logger = logging.getLogger(__name__)
        
    def get_network_interfaces(self):
        """Obtient la liste des interfaces réseau disponibles"""
        try:
            import netifaces
            interfaces = netifaces.interfaces()
            active_interfaces = []
            
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    active_interfaces.append({
                        'name': iface,
                        'ip': addrs[netifaces.AF_INET][0]['addr']
                    })
            return active_interfaces
        except ImportError:
            # Fallback sans netifaces
            return [{'name': 'auto', 'ip': 'auto-detect'}]
    
    def packet_handler(self, packet):
        """
        Gestionnaire de paquets capturés en temps réel
        """
        try:
            current_time = time.time()
            self.total_packets += 1
            
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ip_layer.proto
                packet_size = len(packet)
                self.total_bytes += packet_size
                
                # Identifier le flux (5-tuple)
                flow_key = f"{src_ip}:{dst_ip}:{protocol}"
                
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    flow_key += f":{tcp_layer.sport}:{tcp_layer.dport}"
                    
                    # Analyser les flags TCP
                    flags = []
                    if tcp_layer.flags & 0x02:  # SYN
                        flags.append('SYN')
                        self.flow_stats[flow_key]['syn_count'] += 1
                    if tcp_layer.flags & 0x10:  # ACK
                        flags.append('ACK')
                    if tcp_layer.flags & 0x01:  # FIN
                        flags.append('FIN')
                    if tcp_layer.flags & 0x04:  # RST
                        flags.append('RST')
                        
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    flow_key += f":{udp_layer.sport}:{udp_layer.dport}"
                    flags = ['UDP']
                else:
                    flags = ['OTHER']
                
                # Mettre à jour les statistiques du flux
                flow_stat = self.flow_stats[flow_key]
                flow_stat['packet_count'] += 1
                flow_stat['byte_count'] += packet_size
                flow_stat['flags'].extend(flags)
                
                if flow_stat['start_time'] is None:
                    flow_stat['start_time'] = current_time
                flow_stat['last_seen'] = current_time
                
                # Ajouter à l'historique temporel
                self.packet_timestamps.append(current_time)
                
                # Nettoyer les anciennes entrées (fenêtre glissante)
                cutoff_time = current_time - self.time_window
                while self.packet_timestamps and self.packet_timestamps[0] < cutoff_time:
                    self.packet_timestamps.popleft()
                
        except Exception as e:
            self.logger.error(f"Erreur traitement paquet: {e}")
    
    def extract_network_features(self):
        """
        Extrait les features du trafic réseau réel capturé
        """
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        
        # Nettoyer les flux inactifs
        active_flows = {}
        for flow_key, stats in self.flow_stats.items():
            if stats['last_seen'] > cutoff_time:
                active_flows[flow_key] = stats
        
        if not active_flows:
            return self._get_empty_features()
        
        # Calculs des métriques
        features = {}
        
        # 1. Métriques de base
        total_packets = sum(f['packet_count'] for f in active_flows.values())
        total_bytes = sum(f['byte_count'] for f in active_flows.values())
        
        features['packet_count'] = total_packets
        features['byte_count'] = total_bytes
        
        # 2. Métriques temporelles  
        durations = []
        for stats in active_flows.values():
            if stats['start_time'] and stats['last_seen']:
                duration = max(stats['last_seen'] - stats['start_time'], 0.1)
                durations.append(duration)
        
        features['duration'] = np.mean(durations) if durations else 1.0
        
        # 3. Débit de paquets
        features['packets_per_second'] = len(self.packet_timestamps) / self.time_window
        
        # 4. Diversité des sources
        src_ips = set()
        dst_ports = set()
        for flow_key in active_flows.keys():
            parts = flow_key.split(':')
            if len(parts) >= 2:
                src_ips.add(parts[0])
            if len(parts) >= 5:
                dst_ports.add(parts[4])
        
        features['unique_src_ips'] = len(src_ips)
        features['unique_dst_ports'] = len(dst_ports)
        
        # 5. Analyse des flags
        total_flags = []
        syn_count = 0
        for stats in active_flows.values():
            total_flags.extend(stats['flags'])
            syn_count += stats['syn_count']
        
        features['syn_flag_ratio'] = syn_count / max(total_packets, 1)
        
        # 6. Taille moyenne des paquets
        features['avg_packet_size'] = total_bytes / max(total_packets, 1)
        
        # 7. Débit de flux
        features['flow_rate'] = len(active_flows) / self.time_window
        
        # 8. Score de scan de ports
        features['port_scan_score'] = self._calculate_port_scan_score(active_flows)
        
        return features
    
    def _calculate_port_scan_score(self, flows):
        """Calcule le score de scan de ports"""
        src_to_ports = defaultdict(set)
        
        for flow_key in flows.keys():
            parts = flow_key.split(':')
            if len(parts) >= 5:
                src_ip = parts[0]
                dst_port = parts[4]
                src_to_ports[src_ip].add(dst_port)
        
        scan_scores = []
        for src_ip, ports in src_to_ports.items():
            if len(ports) > 3:  # Plus de 3 ports = suspect
                scan_scores.append(min(len(ports) / 20.0, 1.0))
        
        return np.mean(scan_scores) if scan_scores else 0.0
    
    def _get_empty_features(self):
        """Features par défaut"""
        return {
            'packet_count': 0, 'byte_count': 0, 'duration': 1.0,
            'packets_per_second': 0, 'unique_src_ips': 0,
            'unique_dst_ports': 0, 'syn_flag_ratio': 0,
            'avg_packet_size': 0, 'flow_rate': 0, 'port_scan_score': 0
        }
    
    def analyze_traffic(self):
        """
        Analyse périodique du trafic avec le modèle ML
        """
        while self.running:
            try:
                # Extraire les features du trafic réel
                features = self.extract_network_features()
                
                # Prédiction avec le modèle ML
                if self.ml_model:
                    is_attack, confidence = self.ml_model.predict(features)
                    
                    if is_attack and confidence > self.alert_threshold:
                        # ALERTE DDoS détectée !
                        alert = {
                            'timestamp': datetime.now().isoformat(),
                            'confidence': confidence,
                            'features': features,
                            'type': 'DDoS_DETECTED',
                            'severity': 'HIGH' if confidence > 0.9 else 'MEDIUM'
                        }
                        self.alerts.append(alert)
                        
                        # Actions de mitigation
                        self.mitigate_attack(features)
                        
                        print(f"🚨 ALERTE DDoS - Confiance: {confidence:.1%}")
                        print(f"   📊 Paquets/sec: {features['packets_per_second']:.0f}")
                        print(f"   🌐 Sources uniques: {features['unique_src_ips']}")
                        print(f"   🎯 Ports ciblés: {features['unique_dst_ports']}")
                
                # Nettoyage des anciens alertes
                cutoff_time = datetime.now() - timedelta(hours=24)
                self.alerts = [a for a in self.alerts if 
                              datetime.fromisoformat(a['timestamp']) > cutoff_time]
                
                time.sleep(self.analysis_interval)
                
            except Exception as e:
                self.logger.error(f"Erreur analyse: {e}")
                time.sleep(5)
    
    def mitigate_attack(self, features):
        """
        Actions de mitigation en cas d'attaque détectée
        """
        try:
            # 1. Identifier les IPs suspectes
            suspicious_ips = self._identify_suspicious_ips()
            
            # 2. Bloquer via iptables (nécessite sudo)
            for ip in suspicious_ips[:10]:  # Limiter à 10 IPs
                if ip not in self.blocked_ips:
                    self._block_ip_iptables(ip)
                    self.blocked_ips.add(ip)
                    print(f"🚫 IP {ip} bloquée via iptables")
            
            # 3. Limiter la bande passante (tc - traffic control)
            self._apply_rate_limiting()
            
        except Exception as e:
            self.logger.error(f"Erreur mitigation: {e}")
    
    def _identify_suspicious_ips(self):
        """Identifie les IPs les plus actives (potentiellement malveillantes)"""
        ip_activity = defaultdict(int)
        
        for flow_key, stats in self.flow_stats.items():
            src_ip = flow_key.split(':')[0]
            # Score basé sur l'activité et les patterns suspects
            score = stats['packet_count'] * (1 + stats['syn_count'] / max(stats['packet_count'], 1))
            ip_activity[src_ip] += score
        
        # Retourner les IPs les plus actives
        sorted_ips = sorted(ip_activity.items(), key=lambda x: x[1], reverse=True)
        return [ip for ip, score in sorted_ips if score > 100]  # Seuil arbitraire
    
    def _block_ip_iptables(self, ip):
        """Bloque une IP via iptables (nécessite privileges root)"""
        try:
            # Commande iptables pour bloquer l'IP
            cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            
            # Ajouter aussi en OUTPUT pour être sûr
            cmd_out = f"sudo iptables -A OUTPUT -d {ip} -j DROP"
            subprocess.run(cmd_out, shell=True, check=True, capture_output=True)
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Erreur iptables pour {ip}: {e}")
        except Exception as e:
            self.logger.error(f"Erreur blocage {ip}: {e}")
    
    def _apply_rate_limiting(self):
        """Applique une limitation de débit via tc (traffic control)"""
        try:
            interface = self.interface if self.interface != "any" else "eth0"
            
            # Limiter le débit entrant à 50Mbps pendant l'attaque
            cmd = f"sudo tc qdisc add dev {interface} root handle 1: htb default 12"
            subprocess.run(cmd, shell=True, capture_output=True)
            
            cmd2 = f"sudo tc class add dev {interface} parent 1: classid 1:12 htb rate 50mbit"
            subprocess.run(cmd2, shell=True, capture_output=True)
            
            print("⚡ Limitation de débit appliquée (50Mbps)")
            
        except Exception as e:
            self.logger.error(f"Erreur rate limiting: {e}")
    
    def start_capture(self):
        """
        Démarre la capture de paquets en temps réel
        """
        print(f"🌐 Démarrage capture sur interface: {self.interface}")
        print("🔍 Analyse du trafic réseau en temps réel...")
        print("⚠️  ATTENTION: Nécessite privilèges root pour capture et mitigation")
        
        self.running = True
        
        # Thread d'analyse
        analysis_thread = threading.Thread(target=self.analyze_traffic, daemon=True)
        analysis_thread.start()
        
        try:
            # Démarrer la capture Scapy
            scapy.sniff(
                iface=self.interface if self.interface != "any" else None,
                prn=self.packet_handler,
                store=0,  # Ne pas stocker les paquets en mémoire
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print("❌ ERREUR: Privilèges root requis pour capture de paquets")
            print("💡 Essayez: sudo python3 main_real.py")
        except Exception as e:
            print(f"❌ Erreur capture: {e}")
    
    def stop_capture(self):
        """Arrête la capture"""
        self.running = False
        print("🛑 Arrêt de la capture réseau")
    
    def get_statistics(self):
        """Retourne les statistiques actuelles"""
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'active_flows': len(self.flow_stats),
            'alerts_count': len(self.alerts),
            'blocked_ips': len(self.blocked_ips),
            'packets_per_second': len(self.packet_timestamps) / self.time_window,
            'recent_alerts': self.alerts[-10:] if self.alerts else []
        }
    
    def unblock_ip(self, ip):
        """Débloque une IP via iptables"""
        try:
            cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            
            cmd_out = f"sudo iptables -D OUTPUT -d {ip} -j DROP"
            subprocess.run(cmd_out, shell=True, check=True, capture_output=True)
            
            self.blocked_ips.discard(ip)
            print(f"🔓 IP {ip} débloquée")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur déblocage {ip}: {e}")
            return False
    
    def clear_all_blocks(self):
        """Supprime tous les blocages iptables"""
        try:
            # Flush des règles INPUT et OUTPUT
            subprocess.run("sudo iptables -F INPUT", shell=True, check=True)
            subprocess.run("sudo iptables -F OUTPUT", shell=True, check=True)
            
            self.blocked_ips.clear()
            print("🔓 Tous les blocages supprimés")
            
        except Exception as e:
            self.logger.error(f"Erreur suppression blocages: {e}")