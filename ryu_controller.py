"""
ryu_controller.py — Ryu SDN Controller
=========================================
Bridges the IDS logic with the actual Mininet network via OpenFlow.

What it does:
  1. Listens for switch connections (OpenFlow)
  2. Implements MAC learning + packet forwarding
  3. Exposes REST API so routing.py can push DROP/FORWARD rules

Run BEFORE Mininet:
    ryu-manager ryu_controller.py --observe-links

REST API endpoints:
    POST /ids/block/<ip>   → install DROP rule for that IP on switch 1
    GET  /ids/status       → return controller state (switches, blocked IPs)

Install Ryu:
    pip install ryu eventlet==0.30.2
"""

import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.app.wsgi import ControllerBase, WSGIApplication, route, Response


class SelfHealingController(app_manager.RyuApp):
    """
    Ryu application: MAC learning switch + IDS REST API.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS    = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SelfHealingController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}    # { dpid: { mac: port } }
        self.datapaths   = {}    # { dpid: datapath }
        self.blocked_ips = set()

        kwargs['wsgi'].register(IDSRestAPI, {'controller': self})
        self.logger.info('SelfHealingController started. REST API ready.')

    # ── OpenFlow event handlers ───────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_connected(self, ev):
        """Install table-miss rule when a switch connects."""
        dp      = ev.msg.datapath
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser

        self.datapaths[dp.id] = dp

        # Table-miss: send unknown packets to controller
        self._add_flow(dp, priority=0,
                       match=parser.OFPMatch(),
                       actions=[parser.OFPActionOutput(
                           ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
                       )])
        self.logger.info(f'Switch {dp.id} connected.')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        """MAC learning + forwarding for unknown packets."""
        msg     = ev.msg
        dp      = msg.datapath
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt     = packet.Packet(msg.data)
        eth     = pkt.get_protocols(ethernet.ethernet)[0]
        dpid    = dp.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # Drop packets from blocked IPs
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt and ip_pkt.src in self.blocked_ips:
            self.logger.info(f'Dropping packet from blocked IP: {ip_pkt.src}')
            return

        # Forward or flood
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            self._add_flow(dp, priority=1,
                           match=parser.OFPMatch(in_port=in_port, eth_dst=eth.dst),
                           actions=actions)

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        ))

    # ── Helper ────────────────────────────────────────────────────────────────

    def _add_flow(self, dp, priority, match, actions, idle_timeout=0):
        """Install a flow entry on a switch."""
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=[parser.OFPInstructionActions(
                dp.ofproto.OFPIT_APPLY_ACTIONS, actions
            )],
            idle_timeout=idle_timeout,
        ))

    # ── IDS control methods (called via REST API) ─────────────────────────────

    def block_ip(self, dpid, src_ip):
        """Install a DROP rule for src_ip on switch dpid."""
        if dpid not in self.datapaths:
            self.logger.warning(f'Switch {dpid} not connected.')
            return False

        dp     = self.datapaths[dpid]
        parser = dp.ofproto_parser
        self._add_flow(dp, priority=200,
                       match=parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip),
                       actions=[])
        self.blocked_ips.add(src_ip)
        self.logger.info(f'DROP rule installed for {src_ip} on switch {dpid}')
        return True


# ── REST API ──────────────────────────────────────────────────────────────────

class IDSRestAPI(ControllerBase):
    """REST endpoints called by routing.py."""

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.controller = data['controller']

    @route('ids', '/ids/block/{ip}', methods=['POST'])
    def block_ip_api(self, req, ip, **kwargs):
        """POST /ids/block/10.0.0.3 → block IP on switch 1"""
        success = self.controller.block_ip(dpid=1, src_ip=ip)
        body = json.dumps({'blocked': ip, 'success': success})
        return Response(content_type='application/json', body=body)

    @route('ids', '/ids/status', methods=['GET'])
    def status_api(self, req, **kwargs):
        """GET /ids/status → controller state"""
        body = json.dumps({
            'connected_switches': list(self.controller.datapaths.keys()),
            'blocked_ips':        list(self.controller.blocked_ips),
            'mac_table':          {str(d): t for d, t in self.controller.mac_to_port.items()},
        })
        return Response(content_type='application/json', body=body)
