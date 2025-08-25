import logging
import os
from datetime import datetime
import json

def setup_logger():
    """Configuration du système de logging avancé"""
    # Créer le dossier de logs s'il n'existe pas
    if not os.path.exists('data/logs'):
        os.makedirs('data/logs', exist_ok=True)
    
    # Configuration du logger principal
    logger = logging.getLogger('ddos_detection')
    logger.setLevel(logging.INFO)
    
    # Éviter les doublons de handlers
    if logger.handlers:
        logger.handlers.clear()
    
    # Handler pour fichier avec rotation
    file_handler = logging.FileHandler(
        f'data/logs/ddos_detection_{datetime.now().strftime("%Y%m%d")}.log',
        encoding='utf-8'
    )
    file_handler.setLevel(logging.INFO)
    
    # Handler pour console (seulement erreurs)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    
    # Format des logs
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def log_attack_detection(ip, confidence, attack_type, blocked=True):
    """Log spécialisé pour les détections d'attaque"""
    logger = logging.getLogger('ddos_detection')
    
    log_data = {
        'timestamp': datetime.now().isoformat(),
        'event_type': 'ATTACK_DETECTION',
        'ip': ip,
        'confidence': confidence,
        'attack_type': attack_type,
        'blocked': blocked,
        'severity': 'HIGH' if confidence > 0.8 else 'MEDIUM' if confidence > 0.6 else 'LOW'
    }
    
    logger.info(f"ATTACK DETECTED: {json.dumps(log_data)}")
    
    # Log dans fichier séparé pour les attaques
    with open('data/logs/attacks.jsonl', 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_data) + '\\n')

def log_system_event(event_type, details):
    """Log pour les événements système"""
    logger = logging.getLogger('ddos_detection')
    
    log_data = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'details': details
    }
    
    logger.info(f"SYSTEM EVENT: {json.dumps(log_data)}")