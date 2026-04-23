"""
features.py — Flow-Level Feature Extraction
============================================
Buffers raw packets per source IP, then computes 13 flow-level
statistics over a sliding time window (FLOW_WINDOW seconds).

These features are fed into the ML models in detector.py.
"""

import time
import numpy as np
from collections import defaultdict
from config import FLOW_WINDOW, FLOW_MAX_AGE_SEC

# ── Flow buffer: { src_ip: [packet_dict, ...] } ───────────────────────────────
flow_buffer = defaultdict(list)

# ── Ordered feature columns (must match model training order) ─────────────────
FEATURE_COLUMNS = [
    'packet_count', 'byte_count', 'avg_pkt_size', 'std_pkt_size',
    'packet_rate', 'byte_rate', 'unique_dst_ports', 'unique_dst_ips',
    'syn_count', 'rst_count', 'proto_tcp_ratio', 'proto_udp_ratio',
    'avg_inter_arrival',
]


def extract_packet_data(packet):
    """
    Pull raw fields from a Scapy packet.
    Returns a dict, or None if not an IP packet.
    """
    from scapy.all import IP, TCP, UDP

    if not packet.haslayer(IP):
        return None

    ip = packet[IP]
    data = {
        'timestamp': time.time(),
        'src_ip':    ip.src,
        'dst_ip':    ip.dst,
        'length':    len(packet),
        'proto':     ip.proto,   # 6=TCP, 17=UDP, 1=ICMP
        'src_port':  0,
        'dst_port':  0,
        'syn_flag':  0,
        'rst_flag':  0,
        'fin_flag':  0,
        'ack_flag':  0,
    }

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        data['src_port'] = tcp.sport
        data['dst_port'] = tcp.dport
        data['syn_flag'] = 1 if tcp.flags & 0x02 else 0
        data['rst_flag'] = 1 if tcp.flags & 0x04 else 0
        data['fin_flag'] = 1 if tcp.flags & 0x01 else 0
        data['ack_flag'] = 1 if tcp.flags & 0x10 else 0
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        data['src_port'] = udp.sport
        data['dst_port'] = udp.dport

    return data


def add_to_flow_buffer(packet_data):
    """Append a packet dict to the buffer for its source IP."""
    if packet_data:
        flow_buffer[packet_data['src_ip']].append(packet_data)


def compute_flow_features(src_ip):
    """
    Compute flow statistics for src_ip from buffered packets.
    Returns a feature dict, or None if fewer than 2 packets in window.
    """
    now     = time.time()
    packets = [p for p in flow_buffer.get(src_ip, [])
               if now - p['timestamp'] <= FLOW_WINDOW]
    flow_buffer[src_ip] = packets   # trim stale packets

    if len(packets) < 2:
        return None

    lengths      = [p['length'] for p in packets]
    timestamps   = sorted(p['timestamp'] for p in packets)
    inter_arr    = [(timestamps[i+1] - timestamps[i]) * 1000
                    for i in range(len(timestamps) - 1)]
    duration     = max(timestamps) - min(timestamps)
    duration     = max(duration, 0.001)
    tcp_pkts     = [p for p in packets if p['proto'] == 6]
    udp_pkts     = [p for p in packets if p['proto'] == 17]
    n            = len(packets)

    return {
        'src_ip':            src_ip,
        'packet_count':      n,
        'byte_count':        sum(lengths),
        'avg_pkt_size':      np.mean(lengths),
        'std_pkt_size':      np.std(lengths),
        'packet_rate':       n / duration,
        'byte_rate':         sum(lengths) / duration,
        'unique_dst_ports':  len(set(p['dst_port'] for p in packets)),
        'unique_dst_ips':    len(set(p['dst_ip']   for p in packets)),
        'syn_count':         sum(p['syn_flag'] for p in packets),
        'rst_count':         sum(p['rst_flag'] for p in packets),
        'proto_tcp_ratio':   len(tcp_pkts) / n,
        'proto_udp_ratio':   len(udp_pkts) / n,
        'avg_inter_arrival': np.mean(inter_arr) if inter_arr else 0,
    }


def features_to_vector(feature_dict):
    """Convert feature dict → ordered list for ML input."""
    return [feature_dict.get(col, 0) for col in FEATURE_COLUMNS]


def clear_old_flows(max_age_seconds=None):
    """Remove packets older than max_age_seconds from all flow buffers."""
    max_age = max_age_seconds or FLOW_MAX_AGE_SEC
    now     = time.time()
    for ip in list(flow_buffer.keys()):
        flow_buffer[ip] = [p for p in flow_buffer[ip]
                           if now - p['timestamp'] <= max_age]
        if not flow_buffer[ip]:
            del flow_buffer[ip]
