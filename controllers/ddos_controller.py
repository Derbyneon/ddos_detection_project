from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub
import time
from collections import defaultdict
from models.ml_model import DDoSDetectionModel
from models.feature_extractor import FeatureExtractor
from utils.logger import setup_logger
from utils.config import Config

class DDoSDetectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(DDoSDetectionController, self).__init__(*args, **kwargs)
        self.logger = setup_logger()
        self.mac_to_port = {}
        self.flow_stats = defaultdict(list)
        self.ml_model = DDoSDetectionModel()
        self.feature_extractor = FeatureExtractor()
        
        # Chargement ou entraînement du modèle
        if not self.ml_model.load_model():
            self.logger.info("Entraînement du modèle ML...")
            self.ml_model.train()
            
        # Démarrage du monitoring
        self.monitoring_thread = hub.spawn(self._monitor_flows)
        
        self.blocked_ips = set()
        self.alert_count = 0
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Gestionnaire de connexion des switches"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Installation d'une règle par défaut pour envoyer au contrôleur
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info(f"Switch {datapath.id} connecté")
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Ajoute une règle de flux"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  priority=priority, match=match,
                                  instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Gestionnaire des paquets entrants"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Ignorer les paquets de diffusion
        if eth.ethertype == 0x88cc:  # LLDP packet
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        self.mac_to_port.setdefault(dpid, {})
        
        # Apprentissage de l'adresse MAC
        self.mac_to_port[dpid][src] = in_port
        
        # Analyse du paquet pour la détection DDoS
        self._analyze_packet(pkt, src, dst, in_port, datapath)
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            
        actions = [parser.OFPActionOutput(out_port)]
        
        # Installation d'une règle si ce n'est pas du flooding
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            # Vérification si l'IP source est bloquée
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt and ip_pkt.src in self.blocked_ips:
                self.logger.warning(f"Paquet bloqué de l'IP {ip_pkt.src}")
                return
                
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
                
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def _analyze_packet(self, pkt, src_mac, dst_mac, in_port, datapath):
        """Analyse un paquet pour la détection DDoS"""
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return
            
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        # Collecte des statistiques
        flow_key = f"{ip_pkt.src}-{ip_pkt.dst}"
        flow_info = {
            'timestamp': time.time(),
            'src_ip': ip_pkt.src,
            'dst_ip': ip_pkt.dst,
            'src_port': tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else 0),
            'dst_port': tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else 0),
            'protocol': ip_pkt.proto,
            'byte_count': len(pkt.data),
            'duration': 1.0,
            'switch_id': datapath.id,
            'in_port': in_port
        }
        
        self.flow_stats[flow_key].append(flow_info)
    
    def _monitor_flows(self):
        """Thread de monitoring des flux"""
        while True:
            hub.sleep(Config.MONITORING_INTERVAL)
            
            if not self.flow_stats:
                continue
                
            # Analyse des flux collectés
            current_time = time.time()
            flows_to_analyze = []
            
            for flow_key, flow_list in list(self.flow_stats.items()):
                # Nettoyer les anciens flux
                recent_flows = [f for f in flow_list 
                              if current_time - f['timestamp'] < Config.FLOW_TIMEOUT]
                
                if recent_flows:
                    self.flow_stats[flow_key] = recent_flows
                    flows_to_analyze.extend(recent_flows)
                else:
                    del self.flow_stats[flow_key]
            
            if flows_to_analyze:
                self._detect_ddos(flows_to_analyze)
    
    def _detect_ddos(self, flows):
        """Détecte les attaques DDoS"""
        # Regroupement par IP source
        ip_flows = defaultdict(list)
        for flow in flows:
            ip_flows[flow['src_ip']].extend([flow])
        
        for src_ip, src_flows in ip_flows.items():
            if src_ip in self.blocked_ips:
                continue
                
            # Extraction des caractéristiques
            features = self.feature_extractor.get_feature_vector(src_flows)
            
            # Détection ML
            is_ddos, confidence = self.ml_model.predict(features)
            
            # Vérification basée sur des seuils
            packets_per_sec = len(src_flows) / Config.FLOW_TIMEOUT
            threshold_exceeded = packets_per_sec > Config.DDOS_THRESHOLD
            
            if is_ddos or threshold_exceeded:
                self._handle_ddos_detection(src_ip, src_flows, confidence, features)
    
    def _handle_ddos_detection(self, src_ip, flows, confidence, features):
        """Gère la détection d'une attaque DDoS"""
        self.alert_count += 1
        
        self.logger.warning(
            f"ALERTE DDoS #{self.alert_count}: IP source {src_ip}, "
            f"Confiance: {confidence:.2f}, "
            f"Paquets: {features[0]}, "
            f"Débit: {features[3]:.2f} pps"
        )
        
        # Blocage de l'IP malveillante
        self._block_ip(src_ip, flows)
    
    def _block_ip(self, src_ip, flows):
        """Bloque une IP malveillante"""
        self.blocked_ips.add(src_ip)
        
        # Installation de règles de blocage sur tous les switches concernés
        switches = set(flow['switch_id'] for flow in flows)
        
        for switch_id in switches:
            # Ici vous ajouteriez le code pour installer des règles de blocage
            # sur le switch spécifique
            self.logger.info(f"IP {src_ip} bloquée sur le switch {switch_id}")
    
    def get_statistics(self):
        """Retourne les statistiques actuelles"""
        return {
            'total_flows': len(self.flow_stats),
            'blocked_ips': len(self.blocked_ips),
            'alert_count': self.alert_count,
            'active_flows': sum(len(flows) for flows in self.flow_stats.values())
        }