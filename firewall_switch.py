from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from firewall import Firewall

RULES_FILE = "firewall_rules.txt"


class FirewallSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FirewallSwitch, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}

        # Create firewall
        self.firewall = Firewall()
        self.firewall.read_rules_from_file(RULES_FILE)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Add firewall rules
        self.add_firewall_rules(datapath, parser)

        parser.OFPMatch()
        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst, table_id=0)
        datapath.send_msg(mod)
        # self.add_flow(datapath, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, table_id=1)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    def add_firewall_rules(self, datapath, parser):
        ofproto = datapath.ofproto

        for rule in self.firewall.rules:
            if rule['pro_type'] == 'IP':
                firewall_match = parser.OFPMatch(
                    ipv4_src=rule['ip_src'], ipv4_dst=rule['ip_dst'], eth_type=2048)
            elif rule['pro_type'] == 'TCP':
                if rule['port_src'] > 0:
                    firewall_match = parser.OFPMatch(
                        tcp_src=rule['port_src'], eth_type=2048, ip_proto=6)
                else:
                    firewall_match = parser.OFPMatch(
                        tcp_dst=rule['port_dst'], eth_type=2048, ip_proto=6)
            elif rule['pro_type'] == 'UDP':
                firewall_match = parser.OFPMatch(
                    udp_src=rule['port_src'], udp_dst=rule['port_dst'])
            else:
                print("No protocol known")
                continue

            if rule['perm'] == "permit":
                # Send to next table
                inst = [parser.OFPInstructionGotoTable(1)]
            else:
                # Drop
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                     [])]

            mod = parser.OFPFlowMod(datapath=datapath, priority=2,
                                    match=firewall_match, instructions=inst,
                                    table_id=0)
            datapath.send_msg(mod)
