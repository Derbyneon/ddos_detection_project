from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
import time
import sys

class DDoSTopology:
    def __init__(self):
        self.net = None
        
    def create_simple_topology(self):
        """Crée une topologie simple pour éviter les blocages"""
        print("Création d'une topologie réseau simple...")
        setLogLevel('warning')  # Réduire les logs
        
        try:
            # Création du réseau avec contrôleur distant
            self.net = Mininet(
                controller=RemoteController,
                switch=OVSSwitch,
                autoSetMacs=True,
                cleanup=True
            )
            
            # Ajout du contrôleur
            c0 = self.net.addController('c0', ip='127.0.0.1', port=6633)
            
            # Ajout d'un switch simple
            s1 = self.net.addSwitch('s1')
            
            # Ajout de quelques hôtes
            h1 = self.net.addHost('h1', ip='10.0.0.1/24')
            h2 = self.net.addHost('h2', ip='10.0.0.2/24')
            server = self.net.addHost('server', ip='10.0.0.100/24')
            
            # Hôtes attaquants
            attacker1 = self.net.addHost('attacker1', ip='192.168.1.10/24')
            
            # Connexions simples
            self.net.addLink(h1, s1)
            self.net.addLink(h2, s1)
            self.net.addLink(server, s1)
            self.net.addLink(attacker1, s1)
            
            print("Topologie créée avec succès")
            return self.net
            
        except Exception as e:
            print(f"Erreur lors de la création de la topologie: {e}")
            return None
    
    def start_network(self):
        """Démarre le réseau"""
        if self.net:
            try:
                print("Démarrage du réseau...")
                self.net.start()
                
                # Test de connectivité de base
                print("Test de connectivité...")
                result = self.net.pingAll()
                
                print("Réseau démarré avec succès!")
                return True
            except Exception as e:
                print(f"Erreur lors du démarrage: {e}")
                return False
        return False
    
    def stop_network(self):
        """Arrête le réseau"""
        if self.net:
            try:
                print("Arrêt du réseau...")
                self.net.stop()
                print("Réseau arrêté")
            except Exception as e:
                print(f"Erreur lors de l'arrêt: {e}")
    
    def run_cli(self):
        """Lance l'interface en ligne de commande Mininet"""
        if self.net:
            CLI(self.net)