import threading
import time
import subprocess
import random
import os
import signal

class TrafficGenerator:
    def __init__(self, net):
        self.net = net
        self.running = False
        self.threads = []
        self.attack_processes = []
        
    def generate_normal_traffic(self):
        """Génère du trafic normal simple"""
        if not self.net:
            return
            
        while self.running:
            try:
                # Ping simple entre hôtes
                h1 = self.net.get('h1')
                h2 = self.net.get('h2')
                server = self.net.get('server')
                
                if h1 and server:
                    h1.cmd('ping -c 1 10.0.0.100 > /dev/null 2>&1 &')
                if h2 and server:
                    h2.cmd('ping -c 1 10.0.0.100 > /dev/null 2>&1 &')
                
                time.sleep(2)
                
            except Exception as e:
                print(f"Erreur trafic normal: {e}")
                break
    
    def generate_simple_ddos(self, target_ip='10.0.0.100'):
        """Génère une attaque DDoS simple"""
        print(f"🚨 Démarrage attaque DDoS simple vers {target_ip}")
        
        try:
            attacker = self.net.get('attacker1')
            if attacker:
                # Attaque ping flood simple
                cmd = f'ping -f {target_ip} > /dev/null 2>&1 &'
                attacker.cmd(cmd)
                
                # Attaque avec netcat si disponible
                cmd2 = f'timeout 30 bash -c "while true; do echo test | nc {target_ip} 80 2>/dev/null; done" &'
                attacker.cmd(cmd2)
                
                print("Attaque DDoS démarrée")
                return True
                
        except Exception as e:
            print(f"Erreur lors de l'attaque: {e}")
            return False
    
    def start_traffic_generation(self):
        """Démarre la génération de trafic"""
        self.running = True
        
        # Thread pour le trafic normal
        normal_thread = threading.Thread(target=self.generate_normal_traffic)
        normal_thread.daemon = True
        normal_thread.start()
        self.threads.append(normal_thread)
        
        print("✅ Génération de trafic normal démarrée")
    
    def simulate_attack(self):
        """Simule une attaque simple"""
        if not self.running:
            self.start_traffic_generation()
        
        return self.generate_simple_ddos()
    
    def stop_all_attacks(self):
        """Arrête toutes les attaques"""
        try:
            # Tuer tous les processus d'attaque
            if self.net:
                attacker = self.net.get('attacker1')
                if attacker:
                    attacker.cmd('pkill -f ping')
                    attacker.cmd('pkill -f nc')
            print("🛑 Attaques arrêtées")
        except Exception as e:
            print(f"Erreur arrêt attaques: {e}")
    
    def stop_traffic_generation(self):
        """Arrête la génération de trafic"""
        self.running = False
        self.stop_all_attacks()