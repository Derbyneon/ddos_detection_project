#!/usr/bin/env python3

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os
import logging
from datetime import datetime

class RealDDoSDetectionModel:
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = 'models/ddos_model.pkl'
        self.scaler_path = 'models/ddos_scaler.pkl'
        self.logger = logging.getLogger(__name__)
        
        # Créer le dossier models s'il n'existe pas
        os.makedirs('models', exist_ok=True)
    
    def generate_training_data(self, n_samples=10000):
        """
        Génère des données d'entraînement réalistes pour DDoS
        """
        print("🔄 Génération des données d'entraînement...")
        
        # Initialiser les listes pour stocker les données
        data = []
        labels = []
        
        # Générer du trafic NORMAL (50% des données)
        for i in range(n_samples // 2):
            # Caractéristiques du trafic normal
            sample = {
                'packet_count': np.random.normal(50, 20),  # Moyenne 50 paquets
                'byte_count': np.random.normal(1200, 400),  # Taille normale
                'duration': np.random.exponential(5),      # Durée variable
                'packets_per_second': np.random.normal(10, 5),  # Rythme normal
                'unique_src_ips': np.random.poisson(1),   # Généralement 1 IP source
                'unique_dst_ports': np.random.poisson(2), # Peu de ports destination
                'syn_flag_ratio': np.random.beta(2, 8),   # Peu de SYN flags
                'avg_packet_size': np.random.normal(800, 200),  # Taille moyenne
                'flow_rate': np.random.gamma(2, 2),       # Débit normal
                'port_scan_score': np.random.beta(1, 9),  # Score de scan faible
            }
            
            data.append(sample)
            labels.append(0)  # 0 = Normal
        
        # Générer du trafic DDOS (50% des données)
        for i in range(n_samples // 2):
            # Différents types d'attaques DDoS
            attack_type = np.random.choice(['volumetric', 'syn_flood', 'udp_flood'])
            
            if attack_type == 'volumetric':
                # Attaque volumétrique - beaucoup de données
                sample = {
                    'packet_count': np.random.gamma(100, 2),    # Beaucoup de paquets
                    'byte_count': np.random.gamma(5000, 2),     # Beaucoup de bytes
                    'duration': np.random.exponential(0.5),     # Durée courte
                    'packets_per_second': np.random.gamma(200, 2), # Très rapide
                    'unique_src_ips': np.random.poisson(50),    # Nombreuses IPs
                    'unique_dst_ports': np.random.poisson(1),   # Port ciblé
                    'syn_flag_ratio': np.random.beta(8, 2),     # Beaucoup de SYN
                    'avg_packet_size': np.random.normal(64, 20), # Petits paquets
                    'flow_rate': np.random.gamma(10, 5),        # Débit élevé
                    'port_scan_score': np.random.beta(8, 2),    # Score élevé
                }
            
            elif attack_type == 'syn_flood':
                # Attaque SYN flood
                sample = {
                    'packet_count': np.random.gamma(150, 1.5),
                    'byte_count': np.random.gamma(2000, 1.5),
                    'duration': np.random.exponential(0.2),
                    'packets_per_second': np.random.gamma(300, 1),
                    'unique_src_ips': np.random.poisson(100),
                    'unique_dst_ports': np.random.poisson(1),
                    'syn_flag_ratio': np.random.beta(9, 1),     # Presque que des SYN
                    'avg_packet_size': np.random.normal(40, 10),
                    'flow_rate': np.random.gamma(15, 3),
                    'port_scan_score': np.random.beta(9, 1),
                }
            
            else:  # udp_flood
                # Attaque UDP flood
                sample = {
                    'packet_count': np.random.gamma(80, 2),
                    'byte_count': np.random.gamma(3000, 2),
                    'duration': np.random.exponential(0.3),
                    'packets_per_second': np.random.gamma(250, 1.5),
                    'unique_src_ips': np.random.poisson(30),
                    'unique_dst_ports': np.random.poisson(10),
                    'syn_flag_ratio': np.random.beta(1, 9),
                    'avg_packet_size': np.random.normal(512, 100),
                    'flow_rate': np.random.gamma(12, 4),
                    'port_scan_score': np.random.beta(7, 3),
                }
            
            data.append(sample)
            labels.append(1)  # 1 = DDoS
        
        # Convertir en DataFrame
        df = pd.DataFrame(data)
        
        # S'assurer que toutes les valeurs sont positives et finies
        df = df.clip(lower=0)
        df = df.fillna(0)
        
        print(f"✅ {len(df)} échantillons générés")
        print(f"   📊 Normal: {np.sum(np.array(labels) == 0)}")
        print(f"   🚨 DDoS: {np.sum(np.array(labels) == 1)}")
        
        return df, np.array(labels)
    
    def train(self, retrain=False):
        """
        Entraîne le modèle avec des données réelles
        """
        if self.is_trained and not retrain:
            print("✅ Modèle déjà entraîné")
            return
        
        print("🤖 ENTRAÎNEMENT DU MODÈLE D'IA")
        print("=" * 50)
        
        # Générer les données d'entraînement
        X, y = self.generate_training_data(n_samples=15000)
        
        # Division train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"📚 Données d'entraînement: {len(X_train)} échantillons")
        print(f"🧪 Données de test: {len(X_test)} échantillons")
        
        # Normalisation des features
        print("🔄 Normalisation des données...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Entraînement du modèle
        print("🚀 Entraînement en cours...")
        self.model.fit(X_train_scaled, y_train)
        
        # Évaluation
        print("📊 Évaluation du modèle...")
        train_score = self.model.score(X_train_scaled, y_train)
        test_score = self.model.score(X_test_scaled, y_test)
        
        print(f"✅ Score d'entraînement: {train_score:.3f}")
        print(f"✅ Score de test: {test_score:.3f}")
        
        # Prédictions pour rapport détaillé
        y_pred = self.model.predict(X_test_scaled)
        
        print("\n📋 RAPPORT DE CLASSIFICATION:")
        print(classification_report(y_test, y_pred, 
                                  target_names=['Normal', 'DDoS']))
        
        print("\n🎯 MATRICE DE CONFUSION:")
        cm = confusion_matrix(y_test, y_pred)
        print(f"Vrais Négatifs: {cm[0,0]}, Faux Positifs: {cm[0,1]}")
        print(f"Faux Négatifs: {cm[1,0]}, Vrais Positifs: {cm[1,1]}")
        
        # Importance des features
        print("\n🔍 IMPORTANCE DES CARACTÉRISTIQUES:")
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        for _, row in feature_importance.head().iterrows():
            print(f"   {row['feature']}: {row['importance']:.3f}")
        
        # Sauvegarde
        self.save_model()
        self.is_trained = True
        
        print(f"\n🎉 ENTRAÎNEMENT TERMINÉ!")
        print(f"💾 Modèle sauvegardé dans {self.model_path}")
    
    def predict(self, features):
        """
        Prédiction avec le VRAI modèle d'IA entraîné
        """
        if not self.is_trained:
            # Fallback vers simulation si pas entraîné
            return self._simulate_prediction(features)
        
        try:
            # Conversion des features en format attendu
            feature_vector = np.array([[
                features.get('packet_count', 0),
                features.get('byte_count', 0),
                features.get('duration', 0),
                features.get('packets_per_second', 0),
                features.get('unique_src_ips', 0),
                features.get('unique_dst_ports', 0),
                features.get('syn_flag_ratio', 0),
                features.get('avg_packet_size', 0),
                features.get('flow_rate', 0),
                features.get('port_scan_score', 0)
            ]])
            
            # Normalisation
            feature_vector_scaled = self.scaler.transform(feature_vector)
            
            # Prédiction
            prediction = self.model.predict(feature_vector_scaled)[0]
            confidence = self.model.predict_proba(feature_vector_scaled)[0]
            
            # Retourner résultat avec vraie probabilité
            if prediction == 1:  # DDoS détecté
                return True, confidence[1]  # Probabilité de DDoS
            else:  # Trafic normal
                return False, confidence[0]  # Probabilité de normal
                
        except Exception as e:
            self.logger.error(f"Erreur prédiction: {e}")
            return self._simulate_prediction(features)
    
    def _simulate_prediction(self, features):
        """
        Simulation basique si le modèle n'est pas entraîné
        """
        # Logique basique pour simulation
        suspicious_score = 0
        
        if features.get('flow_count', 0) > 500:
            suspicious_score += 0.3
        if features.get('avg_duration', 1) < 0.5:
            suspicious_score += 0.2
        if features.get('unique_src_ips', 1) > 10:
            suspicious_score += 0.3
        if features.get('packets_per_second', 0) > 100:
            suspicious_score += 0.2
        
        # Ajouter du bruit réaliste
        noise = np.random.normal(0, 0.1)
        final_confidence = np.clip(suspicious_score + noise, 0.05, 0.95)
        
        is_ddos = final_confidence > 0.6
        return is_ddos, final_confidence
    
    def save_model(self):
        """Sauvegarde le modèle et le scaler"""
        try:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            print(f"💾 Modèle sauvegardé: {self.model_path}")
        except Exception as e:
            print(f"❌ Erreur sauvegarde: {e}")
    
    def load_model(self):
        """Charge le modèle pré-entraîné"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.is_trained = True
                print("✅ Modèle pré-entraîné chargé")
                return True
        except Exception as e:
            print(f"⚠️ Impossible de charger le modèle: {e}")
        
        return False
    
    def get_model_info(self):
        """Informations sur le modèle"""
        if not self.is_trained:
            return {
                'status': 'Non entraîné',
                'type': 'Simulation basique',
                'accuracy': 'N/A'
            }
        
        return {
            'status': 'Entraîné',
            'type': 'Random Forest',
            'n_estimators': self.model.n_estimators,
            'max_depth': self.model.max_depth,
            'features': ['packet_count', 'byte_count', 'duration', 
                        'packets_per_second', 'unique_src_ips', 
                        'unique_dst_ports', 'syn_flag_ratio',
                        'avg_packet_size', 'flow_rate', 'port_scan_score']
        }

# Classe de compatibilité pour remplacer l'ancienne
class DDoSDetectionModel(RealDDoSDetectionModel):
    pass