from flask import Flask, render_template, jsonify
import json
import time
import threading
import random
from datetime import datetime, timedelta

app = Flask(__name__)

# Désactiver les logs Flask pour un terminal plus propre
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Variables globales pour stocker les données
stats_data = {
    'total_flows': 0,
    'blocked_ips': 0,
    'alert_count': 0,
    'active_flows': 0,
    'system_status': 'SAFE',
    'threat_level': 'LOW',
    'uptime': 0
}

blocked_ips_data = {}  # Dictionnaire avec plus d'infos
attack_history = []
network_metrics = {
    'bandwidth_usage': [],
    'packet_rate': [],
    'connection_count': [],
    'threat_score': [],
    'timestamps': []
}

system_start_time = time.time()

def update_stats(new_stats):
    """Met à jour les statistiques depuis le contrôleur"""
    global stats_data
    stats_data.update(new_stats)
    stats_data['uptime'] = int(time.time() - system_start_time)
    
    # Calcul du niveau de menace
    if stats_data['alert_count'] > 10:
        stats_data['threat_level'] = 'CRITICAL'
        stats_data['system_status'] = 'UNDER_ATTACK'
    elif stats_data['alert_count'] > 5:
        stats_data['threat_level'] = 'HIGH'
        stats_data['system_status'] = 'MONITORING'
    elif stats_data['alert_count'] > 0:
        stats_data['threat_level'] = 'MEDIUM'
        stats_data['system_status'] = 'ALERT'
    else:
        stats_data['threat_level'] = 'LOW'
        stats_data['system_status'] = 'SAFE'

def add_blocked_ip(ip, attack_type="DDoS", confidence=0.0):
    """Ajoute une IP à la liste des bloquées avec plus de détails"""
    global blocked_ips_data, attack_history
    
    blocked_ips_data[ip] = {
        'ip': ip,
        'blocked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'attack_type': attack_type,
        'confidence': confidence,
        'threat_score': min(int(confidence * 100), 100),
        'packets_blocked': random.randint(1000, 50000)
    }
    
    # Ajouter à l'historique
    attack_info = {
        'ip': ip,
        'type': attack_type,
        'confidence': confidence,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'severity': 'HIGH' if confidence > 0.8 else 'MEDIUM' if confidence > 0.6 else 'LOW',
        'packets': random.randint(1000, 50000)
    }
    attack_history.append(attack_info)
    
    # Garder seulement les 100 dernières attaques
    if len(attack_history) > 100:
        attack_history.pop(0)

def update_blocked_ips(ips_set):
    """Met à jour la liste des IPs bloquées depuis le main"""
    global blocked_ips_data
    
    # Supprimer les IPs qui ne sont plus bloquées
    current_ips = set(blocked_ips_data.keys())
    ips_to_remove = current_ips - ips_set
    for ip in ips_to_remove:
        if ip in blocked_ips_data:
            del blocked_ips_data[ip]
    
    # Ajouter les nouvelles IPs
    for ip in ips_set:
        if ip not in blocked_ips_data:
            add_blocked_ip(ip, "DDoS", random.uniform(0.7, 0.95))

def remove_blocked_ip(ip):
    """Retire une IP de la liste des bloquées"""
    global blocked_ips_data
    if ip in blocked_ips_data:
        del blocked_ips_data[ip]
        return True
    return False

def update_network_metrics():
    """Met à jour les métriques réseau pour les graphiques"""
    global network_metrics
    
    current_time = datetime.now()
    
    # Ajouter de nouvelles données
    network_metrics['timestamps'].append(current_time.strftime('%H:%M:%S'))
    
    # Métriques plus réalistes basées sur l'état du système
    base_bandwidth = 30
    base_packets = 500
    base_connections = 200
    
    # Ajustement selon le niveau de menace
    threat_multiplier = 1
    if stats_data.get('threat_level') == 'CRITICAL':
        threat_multiplier = 3
    elif stats_data.get('threat_level') == 'HIGH':
        threat_multiplier = 2.5
    elif stats_data.get('threat_level') == 'MEDIUM':
        threat_multiplier = 1.8
    
    network_metrics['bandwidth_usage'].append(
        min(int(base_bandwidth * threat_multiplier + random.randint(-10, 20)), 100)
    )
    network_metrics['packet_rate'].append(
        int(base_packets * threat_multiplier + random.randint(-100, 300))
    )
    network_metrics['connection_count'].append(
        int(base_connections * threat_multiplier + random.randint(-50, 100))
    )
    
    # Calcul du score de menace basé sur l'activité récente
    threat_score = 0
    if len(attack_history) > 0:
        recent_attacks = [a for a in attack_history if 
                         datetime.strptime(a['timestamp'], '%Y-%m-%d %H:%M:%S') > 
                         current_time - timedelta(minutes=10)]
        threat_score = min(len(recent_attacks) * 20, 100)
    
    # Ajout de variabilité
    threat_score += random.randint(-5, 15)
    threat_score = max(0, min(100, threat_score))
    
    network_metrics['threat_score'].append(threat_score)
    
    # Garder seulement les 50 derniers points
    for key in network_metrics:
        if len(network_metrics[key]) > 50:
            network_metrics[key].pop(0)

# Thread pour mettre à jour les métriques en temps réel
def metrics_updater():
    while True:
        update_network_metrics()
        time.sleep(3)  # Mise à jour plus fréquente

metrics_thread = threading.Thread(target=metrics_updater, daemon=True)
metrics_thread.start()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    global stats_data, blocked_ips_data
    stats_copy = stats_data.copy()
    stats_copy['blocked_ips'] = len(blocked_ips_data)
    return jsonify(stats_copy)

@app.route('/api/blocked_ips')
def get_blocked_ips():
    return jsonify(list(blocked_ips_data.values()))

@app.route('/api/attack_history')
def get_attack_history():
    return jsonify(attack_history[-20:])  # Les 20 dernières attaques

@app.route('/api/network_metrics')
def get_network_metrics():
    return jsonify(network_metrics)

@app.route('/api/unblock/<ip>')
def unblock_ip(ip):
    if remove_blocked_ip(ip):
        return jsonify({'success': True, 'message': f'IP {ip} débloquée avec succès'})
    return jsonify({'success': False, 'message': f'IP {ip} non trouvée dans la liste'})

@app.route('/api/clear_history')
def clear_history():
    global attack_history
    attack_history.clear()
    return jsonify({'success': True, 'message': 'Historique effacé'})

@app.route('/api/system_info')
def get_system_info():
    uptime_seconds = stats_data.get('uptime', 0)
    uptime_hours = uptime_seconds // 3600
    uptime_minutes = (uptime_seconds % 3600) // 60
    
    return jsonify({
        'uptime': uptime_seconds,
        'uptime_formatted': f"{uptime_hours:02d}h {uptime_minutes:02d}m",
        'system_status': stats_data.get('system_status', 'UNKNOWN'),
        'threat_level': stats_data.get('threat_level', 'UNKNOWN'),
        'active_connections': stats_data.get('active_flows', 0),
        'cpu_usage': random.randint(15, 85),
        'memory_usage': random.randint(35, 75),
        'detection_rate': 99.2 + random.uniform(-0.5, 0.5),
        'total_processed': stats_data.get('total_flows', 0),
        'blocked_count': len(blocked_ips_data),
        'alert_count': stats_data.get('alert_count', 0)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)