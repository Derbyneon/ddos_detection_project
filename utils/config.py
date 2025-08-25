# Configuration générale du projet
import os

class Config:
    # Paramètres réseau
    CONTROLLER_IP = '127.0.0.1'
    CONTROLLER_PORT = 6633
    WEB_PORT = 5000
    
    # Paramètres de détection
    FLOW_TIMEOUT = 10
    MONITORING_INTERVAL = 1
    DDOS_THRESHOLD = 1000  # paquets par seconde
    
    # Paramètres ML
    TRAINING_DATA_PATH = 'data/training_data/'
    MODEL_PATH = 'models/trained_model.pkl'
    FEATURE_WINDOW = 10
    
    # Logging
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'data/logs/ddos_detection.log'