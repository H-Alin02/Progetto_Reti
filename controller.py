import ipaddress
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4

class L3Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Controller, self).__init__(*args, **kwargs)
        self.logger.info("Avvio Controller L3 Statico")

        # Inizializza la tabella MAC per S1
        self.s1_mac_to_port = {}

        # -- Tabella ARP Statica    
        # {IP : MAC}
        self.arp_table = {
            # Hosts
            "10.0.0.2" : "00:00:00:00:00:01",
            "10.0.0.3" : "00:00:00:00:00:02",
            "11.0.0.2" : "00:00:00:00:00:03",
            "192.168.1.2" : "00:00:00:00:00:04",
            "10.8.1.2" : "00:00:00:00:00:05",

            # Gateway S1
            "10.0.0.1": "00:10:00:00:01:01",
            "200.0.0.1": "00:10:00:00:01:02",

            # Gateway S2
            "192.168.1.1": "00:10:00:00:02:01", 
            "200.0.0.2": "00:10:00:00:02:02",
            "170.0.0.1": "00:10:00:00:02:03", 

            # Gateway S3
            "10.8.1.1": "00:10:00:00:03:01",
            "170.0.0.2": "00:10:00:00:03:02", 
            "180.1.2.1": "00:10:00:00:03:03",

            # Gateway S4
            "11.0.0.1": "00:10:00:00:04:01",
            "180.1.2.2": "00:10:00:00:04:02"
        }

        # -- Mappa interfacce/porte
        # {DPID : {IP/Subnet : Porta}}
        self.switch_ports = {
            1 : {
                "10.0.0.1/24": [1,2],
                "200.0.0.1/30" : 3 
            },
            2 : {
                "192.168.1.1/24" : 1,
                "200.0.0.2/30": 2,
                "170.0.0.1/30": 3
            },
            3 : {
                "10.8.1.1/24": 1,
                "170.0.0.2/30": 2,
                "180.1.2.1/30": 3
            },
            4 : {
                "11.0.0.1/24": 1,
                "180.1.2.2/30": 2
            }
        }

        # Mappa interfacce a MAC (per trovare il MAC sorgente del router)
        self.interface_to_mac = {
            1: {  # S1
                "10.0.0.1/24": "00:10:00:00:01:01",
                "200.0.0.1/30": "00:10:00:00:01:02"
            },
            2: {  # S2
                "192.168.1.1/24": "00:10:00:00:02:01",
                "200.0.0.2/30": "00:10:00:00:02:02",
                "170.0.0.1/30": "00:10:00:00:02:03"
            },
            3: {  # S3
                "10.8.1.1/24": "00:10:00:00:03:01",
                "170.0.0.2/30": "00:10:00:00:03:02",
                "180.1.2.1/30": "00:10:00:00:03:03"
            },
            4: {  # S4
                "11.0.0.1/24": "00:10:00:00:04:01",
                "180.1.2.2/30": "00:10:00:00:04:02"
            }
        }

        # -- Tabella di routing statico
        # {DPID : {Rete Destinazione : IP Next-Hop}}
        self.routing_table = {
            1 : {
                "10.0.0.0/24" : "direct",
                "200.0.0.0/30": "direct",  # Link diretto a S2
                "192.168.1.0/24" : "200.0.0.2",
                "170.0.0.0/30": "200.0.0.2",  # Via S2
                "10.8.1.0/24": "200.0.0.2",
                "180.1.2.0/30": "200.0.0.2",  # Via S2
                "11.0.0.0/24": "200.0.0.2"
            },
            2 : {
                "192.168.1.0/24": "direct",
                "200.0.0.0/30": "direct",  # Link diretto a S1
                "170.0.0.0/30": "direct",  # Link diretto a S3
                "10.0.0.0/24" : "200.0.0.1",
                "10.8.1.0/24": "170.0.0.2",
                "180.1.2.0/30": "170.0.0.2",  # Via S3
                "11.0.0.0/24": "170.0.0.2"
            },
            3 : {
                "10.8.1.0/24": "direct",
                "170.0.0.0/30": "direct",  # Link diretto a S2
                "180.1.2.0/30": "direct",  # Link diretto a S4
                "11.0.0.0/24": "180.1.2.2",
                "192.168.1.0/24": "170.0.0.1",
                "200.0.0.0/30": "170.0.0.1",  # Via S2
                "10.0.0.0/24": "170.0.0.1"
            }, 
            4 : {
                "11.0.0.0/24": "direct",
                "180.1.2.0/30": "direct",  # Link diretto a S3
                "10.8.1.0/24": "180.1.2.1",
                "170.0.0.0/30": "180.1.2.1",  # Via S3
                "192.168.1.0/24": "180.1.2.1",
                "200.0.0.0/30": "180.1.2.1",  # Via S3
                "10.0.0.0/24": "180.1.2.1"
            }
        }

    # Funzione helper per aggiungere flow rule
    def add_flow(self, datapath, priority, match, actions, idle_timeout=60):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, 
                                priority=priority, 
                                match=match, 
                                idle_timeout=idle_timeout, 
                                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.logger.info(f"Switch DPID {datapath.id} connesso")
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, idle_timeout=0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Gestione ARP per tutti gli switch
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(msg, datapath, in_port, eth, arp_pkt)
            return

        # Per pacchetti IP, controlla sempre se è traffico L3
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            # Per S1: controlla se il traffico è locale (10.0.0.0/24) o deve essere instradato
            if dpid == 1 and in_port in [1, 2]:
                dst_ip = ipv4_pkt.dst
                # Se destinazione è nella subnet locale, usa L2
                try:
                    local_network = ipaddress.ip_network("10.0.0.0/24", strict=False)
                    if ipaddress.ip_address(dst_ip) in local_network:
                        # Traffico locale su S1, usa L2 switching
                        self._handle_l2_switch(msg, datapath, in_port, eth)
                        return
                except ValueError:
                    pass
            
            # Altrimenti usa routing L3
            self._handle_ipv4(msg, datapath, in_port, eth, ipv4_pkt)

    def _handle_arp(self, msg, datapath, port, eth, arp_pkt):
        dpid = datapath.id
        
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return

        if arp_pkt.dst_ip not in self.arp_table:
            self.logger.info(f"ARP: DPID {dpid} - IP dest {arp_pkt.dst_ip} sconosciuto")
            return
            
        self.logger.info(f"ARP: DPID {dpid} - Rispondo a {arp_pkt.src_ip} per {arp_pkt.dst_ip}")
        
        reply_src_mac = self.arp_table[arp_pkt.dst_ip]

        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                                        dst=eth.src,
                                        src=reply_src_mac))
        p.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                               src_mac=reply_src_mac,
                               src_ip=arp_pkt.dst_ip,
                               dst_mac=arp_pkt.src_mac,
                               dst_ip=arp_pkt.src_ip))
        p.serialize()

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=p.data)
        datapath.send_msg(out)

    def _handle_l2_switch(self, msg, datapath, in_port, eth):
        """ Gestisce il traffico L2 per s1 (DPID 1) sulle porte 1 e 2 - SOLO per traffico locale """
        
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        src_mac = eth.src
        dst_mac = eth.dst

        # Apprendimento MAC
        self.s1_mac_to_port[src_mac] = in_port
        self.logger.info(f"L2_SWITCH (s1): Appreso {src_mac} su porta {in_port}")

        # Determina porta di uscita
        if dst_mac in self.s1_mac_to_port:
            out_port = self.s1_mac_to_port[dst_mac]
            # Controlla che sia una porta L2 (1 o 2)
            if out_port in [1, 2]:
                actions = [parser.OFPActionOutput(out_port)]
                
                # Installa flow rule per traffico locale L2
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="10.0.0.0/24")
                self.add_flow(datapath, 50, match, actions, idle_timeout=60)
                self.logger.info(f"L2_SWITCH (s1): Installata regola L2 per {dst_mac} -> porta {out_port}")
            else:
                self.logger.warning(f"L2_SWITCH (s1): MAC {dst_mac} è su porta L3 ({out_port}), non dovrebbe accadere")
                return
        else:
            # Flood solo sulle porte L2 (1 e 2), escludendo la porta di ingresso
            flood_ports = [p for p in [1, 2] if p != in_port]
            actions = [parser.OFPActionOutput(p) for p in flood_ports]
            self.logger.info(f"L2_SWITCH (s1): Flood su porte {flood_ports}")

        # Invia il pacchetto
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def _find_interface_for_ip(self, dpid, ip_addr):
        """Trova l'interfaccia (subnet e MAC) che contiene un dato IP"""
        for iface_prefix, port in self.switch_ports.get(dpid, {}).items():
            try:
                network = ipaddress.ip_network(iface_prefix, strict=False)
                if ipaddress.ip_address(ip_addr) in network:
                    mac = self.interface_to_mac.get(dpid, {}).get(iface_prefix)
                    return iface_prefix, port, mac
            except ValueError:
                continue
        return None, None, None

    def _handle_ipv4(self, msg, datapath, in_port, eth, ipv4_pkt):
        """ Gestisce il routing L3 per tutti i pacchetti IP """
        
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dst_ip = ipv4_pkt.dst
        src_ip = ipv4_pkt.src
        
        self.logger.info(f"L3_ROUTER (DPID {dpid}): Pacchetto da {src_ip} a {dst_ip}, porta in {in_port}")

        # Trova la rotta (Longest Prefix Match)
        router_routes = self.routing_table.get(dpid)
        if not router_routes:
            self.logger.warning(f"L3_ROUTER: DPID {dpid} non ha una tabella di routing!")
            return

        best_route = None
        longest_prefix = -1
        
        for prefix_str, next_hop_ip in router_routes.items():
            try:
                network = ipaddress.ip_network(prefix_str, strict=False)
                if ipaddress.ip_address(dst_ip) in network:
                    if network.prefixlen > longest_prefix:
                        longest_prefix = network.prefixlen
                        best_route = (prefix_str, next_hop_ip)
            except ValueError:
                continue

        if not best_route:
            self.logger.warning(f"L3_ROUTER (DPID {dpid}): Nessuna rotta trovata per {dst_ip}")
            return

        route_prefix, next_hop_ip = best_route
        
        # Se la rotta è "direct", il next-hop è l'IP di destinazione stesso
        if next_hop_ip == "direct":
            next_hop_ip = dst_ip
            
        self.logger.info(f"L3_ROUTER (DPID {dpid}): Rotta per {dst_ip} è {route_prefix} via {next_hop_ip}")

        # Trova MAC di destinazione (next-hop)
        dst_mac = self.arp_table.get(next_hop_ip)
        if not dst_mac:
            self.logger.warning(f"L3_ROUTER (DPID {dpid}): Manca MAC per next-hop {next_hop_ip}")
            return
        
        # Trova l'interfaccia di uscita che contiene il next-hop
        out_iface, out_port, src_mac = self._find_interface_for_ip(dpid, next_hop_ip)
        
        if not out_port or not src_mac:
            self.logger.error(f"L3_ROUTER (DPID {dpid}): Impossibile trovare interfaccia per {next_hop_ip}")
            return
        
        # Gestione speciale per S1: se out_port è una lista, usa il MAC learning per traffico locale
        if isinstance(out_port, list):
            # Questo succede solo per la subnet 10.0.0.0/24 su S1
            # Se stiamo instradando VERSO questa subnet, usa il MAC learning
            if dst_mac in self.s1_mac_to_port and self.s1_mac_to_port[dst_mac] in out_port:
                out_port = self.s1_mac_to_port[dst_mac]
                self.logger.info(f"L3_ROUTER (S1): Uso MAC learning per destinazione finale -> porta {out_port}")
            else:
                # Se il MAC non è stato ancora appreso, usa la prima porta disponibile
                # (in pratica flood, ma il pacchetto verrà gestito)
                self.logger.warning(f"L3_ROUTER (S1): MAC {dst_mac} non appreso, uso porta {out_port[0]}")
                out_port = out_port[0]
        
        self.logger.info(f"L3_ROUTER (DPID {dpid}): Inoltro a {dst_ip} via porta {out_port}, src_mac={src_mac}, dst_mac={dst_mac}")

        # Costruisci azioni e flow rule
        actions = [
            parser.OFPActionDecNwTtl(),  # Decrementa TTL
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                               ipv4_dst=dst_ip)
        
        # Priorità più alta per le route L3 (150) rispetto a L2 (50)
        priority = 150
        
        # Installa la regola
        self.add_flow(datapath, priority, match, actions, idle_timeout=60)
        self.logger.info(f"L3_ROUTER (DPID {dpid}): Installata flow rule per {dst_ip}")

        # Invia il pacchetto corrente
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)