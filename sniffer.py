"""
sniffer.py — Live Packet Capture with Flow Buffering
======================================================
Captures packets using Scapy, groups them by source IP into flows,
and triggers the detection callback every FLOW_WINDOW seconds.

Usage (standalone test):
    sudo python3 sniffer.py
    sudo python3 sniffer.py --iface eth0
    sudo python3 sniffer.py --iface any        ← captures ALL interfaces

In Mininet (best approach):
    sudo python3 main.py --iface any
    sudo python3 main.py --iface s1-eth1
"""

import time
import threading
import argparse
from collections import defaultdict
from scapy.all import sniff, IP

from config import FLOW_WINDOW, FLOW_CLEANUP_SEC, FLOW_MAX_AGE_SEC
from features import (
    extract_packet_data, add_to_flow_buffer,
    compute_flow_features, features_to_vector, clear_old_flows,
    flow_buffer,
)

# ── Callback registered by main.py ────────────────────────────────────────────
# Set via:  sniffer.on_flow_ready = my_handler_function
on_flow_ready = None

# ── Track last processing time per source IP ──────────────────────────────────
_last_processed = defaultdict(float)

# ── Packet counter for debug ──────────────────────────────────────────────────
_pkt_count = 0
_pkt_debug_interval = 10   # print a line every N packets


def _process_flow(src_ip):
    """Compute features for src_ip and fire the callback."""
    features = compute_flow_features(src_ip)
    if features is None:
        print(f'[Flow] {src_ip} — not enough packets yet (need >= 2 in window)')
        return

    print(f'[Flow] Features ready for {src_ip} | '
          f'pkts={features["packet_count"]} | '
          f'rate={features["packet_rate"]:.1f}/s | '
          f'syn={features["syn_count"]} | '
          f'ports={features["unique_dst_ports"]}')

    feature_vector = features_to_vector(features)

    if on_flow_ready is not None:
        try:
            on_flow_ready(features, feature_vector)
        except Exception as e:
            print(f'[Sniffer] Callback error: {e}')


def _packet_handler(packet):
    """Called for every captured packet by Scapy."""
    global _pkt_count

    if not packet.haslayer(IP):
        return

    pkt_data = extract_packet_data(packet)
    if pkt_data is None:
        return

    add_to_flow_buffer(pkt_data)

    _pkt_count += 1
    src_ip = pkt_data['src_ip']

    # Debug: print first 5 packets and every 10th
    if _pkt_count <= 5 or _pkt_count % _pkt_debug_interval == 0:
        print(f'[Packet] #{_pkt_count} {packet.summary()}')

    now = time.time()
    if now - _last_processed[src_ip] >= FLOW_WINDOW:
        _last_processed[src_ip] = now
        print(f'[Flow] Processing flow for {src_ip} | '
              f'buffer size: {len(flow_buffer.get(src_ip, []))}')
        _process_flow(src_ip)


def _cleanup_loop():
    """Background thread: remove stale flows periodically."""
    while True:
        time.sleep(FLOW_CLEANUP_SEC)
        clear_old_flows(FLOW_MAX_AGE_SEC)


def _detect_best_iface():
    """
    Auto-detect best interface.
    In WSL2 without Mininet: use 'eth0' so attacker.py L3 packets are captured.
    With Mininet: prefer s1-eth interfaces.
    """
    try:
        import subprocess
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        lines  = result.stdout

        # Prefer Mininet switch interfaces if they exist
        mininet_ifaces = []
        for line in lines.splitlines():
            if ':' not in line:
                continue
            name = line.split(':')[1].strip().split('@')[0]
            for prefix in ('s1-eth', 's2-eth', 's3-eth'):
                if name.startswith(prefix):
                    mininet_ifaces.append(name)
                    break

        if mininet_ifaces:
            for preferred in ('s1-eth2', 's1-eth1'):
                if preferred in mininet_ifaces:
                    return preferred
            return mininet_ifaces[0]

        # No Mininet — WSL2 direct mode: use eth0
        for line in lines.splitlines():
            if ':' not in line:
                continue
            name = line.split(':')[1].strip().split('@')[0]
            if name in ('eth0', 'ens33', 'ens3', 'enp0s3'):
                return name

        return 'eth0'
    except Exception:
        pass
    return 'eth0'


def start_sniffing(iface=None, bpf_filter='ip'):
    """
    Start packet capture (blocking call).

    Args:
        iface      : Interface name. None = auto-detect.
                     Use 'any' to capture all interfaces (best for Mininet).
        bpf_filter : BPF filter string (default: IPv4 only)
    """
    threading.Thread(target=_cleanup_loop, daemon=True).start()

    if iface is None:
        iface = _detect_best_iface()
        print(f'[Sniffer] Auto-detected interface: {iface}')

    # Strip @ifN suffix that Linux adds (e.g. s1-eth1@if2 → s1-eth1)
    iface = iface.split('@')[0]

    # 'any' is a special Scapy keyword — pass None to sniff all
    sniff_iface = None if iface == 'any' else iface

    print(f'[Sniffer] Capturing on "{iface}" | window={FLOW_WINDOW}s | filter={bpf_filter}')
    print('[Sniffer] Waiting for packets... (run pingall or attacker.py to generate traffic)')
    print('[Sniffer] Press Ctrl+C to stop.\n')

    try:
        sniff(iface=sniff_iface, filter=bpf_filter, prn=_packet_handler, store=0)
    except KeyboardInterrupt:
        print('\n[Sniffer] Stopped.')
    except PermissionError:
        print('[Sniffer] ERROR: Permission denied. Run with sudo.')
    except Exception as e:
        print(f'[Sniffer] Error: {e}')


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', default=None)
    args = parser.parse_args()

    def _test_callback(features, fv):
        print(f"[Flow] src={features['src_ip']} | "
              f"pkts={features['packet_count']} | "
              f"rate={features['packet_rate']:.1f}/s | "
              f"syn={features['syn_count']} | "
              f"ports={features['unique_dst_ports']}")

    on_flow_ready = _test_callback
    start_sniffing(iface=args.iface)
