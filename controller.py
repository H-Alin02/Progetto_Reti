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
        
        # Tabella per il learning MAC su S1 (L2)
        self.s1_mac_to_port = {}

        # Tabella ARP statica - associa IP a MAC
        self.arp_table = {
            # Hosts
            "10.0.0.2": "00:00:00:00:00:01",  # H1
            "10.0.0.3": "00:00:00:00:00:02",  # H2  
            "11.0.0.2": "00:00:00:00:00:03",  # H3
            "192.168.1.2": "00:00:00:00:00:04",  # H4
            "10.8.1.2": "00:00:00:00:00:05",  # H5

            # Gateway dei router
            "10.0.0.1": "00:10:00:00:01:01",  # S1
            "200.0.0.1": "00:10:00:00:01:02",  # S1
            "192.168.1.1": "00:10:00:00:02:01",  # S2
            "200.0.0.2": "00:10:00:00:02:02",  # S2
            "170.0.0.1": "00:10:00:00:02:03",  # S2
            "10.8.1.1": "00:10:00:00:03:01",  # S3
            "170.0.0.2": "00:10:00:00:03:02",  # S3
            "180.1.2.1": "00:10:00:00:03:03",  # S3
            "11.0.0.1": "00:10:00:00:04:01",  # S4
            "180.1.2.2": "00:10:00:00:04:02"  # S4
        }

        # Mappa delle interfacce dei router
        self.switch_ports = {
            1: {"10.0.0.1/24": [1,2], "200.0.0.1/30": 3},
            2: {"192.168.1.1/24": 1, "200.0.0.2/30": 2, "170.0.0.1/30": 3},
            3: {"10.8.1.1/24": 1, "170.0.0.2/30": 2, "180.1.2.1/30": 3},
            4: {"11.0.0.1/24": 1, "180.1.2.2/30": 2}
        }

        # Tabella di routing statica
        self.routing_table = {
            1: {
            "10.0.0.0/24": "direct",
            "192.168.1.0/24": "200.0.0.2",
            "10.8.1.0/24": "200.0.0.2",
            "11.0.0.0/24": "200.0.0.2"
            },
            2: {
            "192.168.1.0/24": "direct",
            "10.0.0.0/24": "200.0.0.1",
            "10.8.1.0/24": "170.0.0.2",
            "11.0.0.0/24": "170.0.0.2"
            },
            3: {
            "10.8.1.0/24": "direct",
            "11.0.0.0/24": "180.1.2.2",
            "192.168.1.0/24": "170.0.0.1",
            "10.0.0.0/24": "170.0.0.1"
            },
            4: {
            "11.0.0.0/24": "direct",
            "10.8.1.0/24": "180.1.2.1",
            "192.168.1.0/24": "180.1.2.1",
            "10.0.0.0/24": "180.1.2.1"
            }
        }

    def add_flow(self, datapath, priority, match, actions, idle_timeout=60):
        """Installa una flow rule sullo switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, 
            idle_timeout=idle_timeout, instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        """Handler per quando uno switch si connette - installa regola di default"""
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        
        # Regola di default: invia tutto al controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions, idle_timeout=0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handler principale per tutti i pacchetti che arrivano al controller"""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Gestione richieste ARP
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(msg, datapath, in_port, eth, arp_pkt)
            return

        # Gestione pacchetti IP
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            # Su S1, controlla se il traffico è locale (L2) o deve essere instradato (L3)
            if datapath.id == 1 and in_port in [1, 2]:
                dst_ip = ipv4_pkt.dst
                local_network = ipaddress.ip_network("10.0.0.0/24", strict=False)
                if ipaddress.ip_address(dst_ip) in local_network:
                    # Traffico locale su S1 - usa switching L2
                    self._handle_l2_switch(msg, datapath, in_port, eth)
                    return
            
            # Altrimenti usa routing L3
            self._handle_ipv4(msg, datapath, in_port, eth, ipv4_pkt)

    def _handle_arp(self, msg, datapath, port, eth, arp_pkt):
        """Gestisce le richieste ARP rispondendo con il MAC appropriato"""
        if arp_pkt.opcode != arp.ARP_REQUEST or arp_pkt.dst_ip not in self.arp_table:
            return

        # Prepara la risposta ARP
        reply_src_mac = self.arp_table[arp_pkt.dst_ip]
        
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(
            ethertype=eth.ethertype, dst=eth.src, src=reply_src_mac
        ))
        p.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY, src_mac=reply_src_mac, src_ip=arp_pkt.dst_ip,
            dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip
        ))
        p.serialize()

        # Invia la risposta
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=p.data
        )
        datapath.send_msg(out)

    def _handle_l2_switch(self, msg, datapath, in_port, eth):
        """Gestisce il traffico L2 su S1 tra H1 e H2"""
        parser = datapath.ofproto_parser
        src_mac = eth.src
        dst_mac = eth.dst

        # Learning: memorizza quale MAC è su quale porta
        self.s1_mac_to_port[src_mac] = in_port

        # Se conosciamo la porta di destinazione, invia lì
        if dst_mac in self.s1_mac_to_port:
            out_port = self.s1_mac_to_port[dst_mac]
            if out_port in [1, 2]:  # Solo porte L2
                actions = [parser.OFPActionOutput(out_port)]
                # Installa regola per evitare futuri PacketIn
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
                self.add_flow(datapath, 50, match, actions, idle_timeout=60)
        else:
            # Se non conosciamo la destinazione, flood sulle porte L2
            flood_ports = [p for p in [1, 2] if p != in_port]
            actions = [parser.OFPActionOutput(p) for p in flood_ports]

        # Invia il pacchetto
        data = msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

    def _find_interface_for_next_hop(self, dpid, next_hop_ip):
        """Trova l'interfaccia (porta e MAC) per raggiungere un next-hop"""
        for subnet, port in self.switch_ports.get(dpid, {}).items():
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                if ipaddress.ip_address(next_hop_ip) in network:
                    # Estrai l'IP del gateway da questa interfaccia
                    gateway_ip = str(list(network.hosts())[0])
                    mac = self.arp_table.get(gateway_ip)
                    return port, mac
            except ValueError:
                continue
        return None, None

    def _handle_ipv4(self, msg, datapath, in_port, eth, ipv4_pkt):
        """Gestisce il routing L3 per pacchetti IP"""
        dpid = datapath.id
        parser = datapath.ofproto_parser
        dst_ip = ipv4_pkt.dst

        # Cerca una rotta per la destinazione
        router_routes = self.routing_table.get(dpid, {})
        best_route = None
        for prefix, next_hop in router_routes.items():
            try:
                network = ipaddress.ip_network(prefix, strict=False)
                if ipaddress.ip_address(dst_ip) in network:
                    best_route = (prefix, next_hop)
                    break 
            except ValueError:
                continue

        if not best_route:
            self.logger.info(f"Switch {dpid}: Nessuna rotta trovata per {dst_ip}")
            return

        next_hop_ip = best_route[1]
        # Se la rotta è diretta, il next-hop è l'IP di destinazione
        if next_hop_ip == "direct":
            next_hop_ip = dst_ip

        # Trova il MAC del next-hop
        dst_mac = self.arp_table.get(next_hop_ip)
        if not dst_mac:
            return

        # Trova porta e MAC sorgente per inviare al next-hop
        out_port, src_mac = self._find_interface_for_next_hop(dpid, next_hop_ip)
        if not out_port or not src_mac:
            return

        # Gestione speciale per S1: se out_port è una lista (porte L2)
        if isinstance(out_port, list):
            if dst_mac in self.s1_mac_to_port and self.s1_mac_to_port[dst_mac] in out_port:
                out_port = self.s1_mac_to_port[dst_mac] # Usa MAC learning
            else:
                out_port = out_port[0] # Altrimenti usa la prima porta

        # Azioni: decrementa TTL, cambia MAC, invia alla porta
        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        # Installa regola per futuri pacchetti
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
        self.add_flow(datapath, 150, match, actions, idle_timeout=60)

        # Invia il pacchetto corrente
        data = msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)