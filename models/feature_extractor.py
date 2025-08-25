#!/usr/bin/env python3

import numpy as np
from collections import Counter, defaultdict

class FeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'packet_count', 'byte_count', 'duration', 'packets_per_second',
            'unique_src_ips', 'unique_dst_ports', 'syn_flag_ratio',
            'avg_packet_size', 'flow_rate', 'port_scan_score'
        ]
    
    def get_feature_vector(self, flows):
        """
        Extrait des caractéristiques RÉELLES pour l'IA
        """
        if not flows:
            return self._get_empty_features()
        
        # Calculs des métriques réelles
        features = {}
        
        # 1. Métriques de base
        features['packet_count'] = sum(flow.get('packet_count', 1) for flow in flows)
        features['byte_count'] = sum(flow.get('byte_count', 0) for flow in flows)
        
        # 2. Métriques temporelles
        durations = [flow.get('duration', 1) for flow in flows]
        features['duration'] = np.mean(durations)
        
        # 3. Débit de paquets
        if features['duration'] > 0:
            features['packets_per_second'] = features['packet_count'] / features['duration']
        else:
            features['packets_per_second'] = features['packet_count']
        
        # 4. Diversité des sources
        src_ips = [flow.get('src_ip', '0.0.0.0') for flow in flows]
        features['unique_src_ips'] = len(set(src_ips))
        
        # 5. Diversité des ports de destination
        dst_ports = [flow.get('dst_port', 80) for flow in flows]
        features['unique_dst_ports'] = len(set(dst_ports))
        
        # 6. Ratio de flags SYN (indicateur d'attaque SYN flood)
        syn_count = sum(1 for flow in flows if flow.get('flags', '') == 'SYN')
        features['syn_flag_ratio'] = syn_count / len(flows) if flows else 0
        
        # 7. Taille moyenne des paquets
        if features['packet_count'] > 0:
            features['avg_packet_size'] = features['byte_count'] / features['packet_count']
        else:
            features['avg_packet_size'] = 0
        
        # 8. Débit de flux
        if features['duration'] > 0:
            features['flow_rate'] = len(flows) / features['duration']
        else:
            features['flow_rate'] = len(flows)
        
        # 9. Score de scan de ports (heuristique)
        features['port_scan_score'] = self._calculate_port_scan_score(flows)
        
        return features
    
    def _calculate_port_scan_score(self, flows):
        """
        Calcule un score indiquant une possible activité de scan de ports
        """
        if not flows:
            return 0
        
        # Analyser les patterns de ports
        src_to_ports = defaultdict(set)
        for flow in flows:
            src_ip = flow.get('src_ip', '0.0.0.0')
            dst_port = flow.get('dst_port', 80)
            src_to_ports[src_ip].add(dst_port)
        
        # Score basé sur le nombre de ports différents par IP source
        scan_indicators = []
        for src_ip, ports in src_to_ports.items():
            if len(ports) > 5:  # Plus de 5 ports différents = suspect
                scan_indicators.append(len(ports) / 10.0)  # Normaliser
        
        return np.mean(scan_indicators) if scan_indicators else 0
    
    def _get_empty_features(self):
        """
        Features par défaut quand pas de flux
        """
        return {name: 0.0 for name in self.feature_names}
    
    def extract_advanced_features(self, flows):
        """
        Extraction de features avancées pour analyse plus poussée
        """
        base_features = self.get_feature_vector(flows)
        
        if not flows:
            return base_features
        
        # Features avancées
        advanced = {}
        
        # 1. Entropie des ports sources
        src_ports = [flow.get('src_port', 0) for flow in flows]
        advanced['src_port_entropy'] = self._calculate_entropy(src_ports)
        
        # 2. Entropie des IPs sources
        src_ips = [flow.get('src_ip', '0.0.0.0') for flow in flows]
        advanced['src_ip_entropy'] = self._calculate_entropy(src_ips)
        
        # 3. Variance de la taille des paquets
        packet_sizes = [flow.get('byte_count', 0) / max(flow.get('packet_count', 1), 1) 
                       for flow in flows]
        advanced['packet_size_variance'] = np.var(packet_sizes)
        
        # 4. Ratio de connexions courtes
        short_connections = sum(1 for flow in flows if flow.get('duration', 1) < 1.0)
        advanced['short_connection_ratio'] = short_connections / len(flows)
        
        # 5. Distribution des protocoles
        protocols = [flow.get('protocol', 6) for flow in flows]
        protocol_counter = Counter(protocols)
        advanced['protocol_diversity'] = len(protocol_counter)
        
        # Fusionner avec les features de base
        base_features.update(advanced)
        
        return base_features
    
    def _calculate_entropy(self, values):
        """
        Calcule l'entropie d'une liste de valeurs
        """
        if not values:
            return 0
        
        counter = Counter(values)
        total = len(values)
        
        entropy = 0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    def get_feature_importance_explanation(self):
        """
        Explication des features pour compréhension
        """
        explanations = {
            'packet_count': 'Nombre total de paquets - Les attaques DDoS génèrent beaucoup de paquets',
            'byte_count': 'Volume total de données - Attaques volumétriques',
            'duration': 'Durée moyenne des flux - Attaques courtes vs trafic normal long',
            'packets_per_second': 'Débit de paquets - Indicateur clé d\'attaque',
            'unique_src_ips': 'Nombre d\'IPs sources uniques - Attaques distribuées',
            'unique_dst_ports': 'Diversité des ports ciblés - Scan vs attaque ciblée',
            'syn_flag_ratio': 'Proportion de flags SYN - Détection SYN flood',
            'avg_packet_size': 'Taille moyenne des paquets - Petits paquets = suspect',
            'flow_rate': 'Débit de nouveaux flux - Indicateur d\'intensité',
            'port_scan_score': 'Score de scan de ports - Activité de reconnaissance'
        }
        return explanations