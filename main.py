"""
main.py — System Entry Point
==============================
Starts all components in the correct order and wires them together.

Run:
    sudo python3 main.py                  # Full system
    sudo python3 main.py --no-ryu         # Simulation mode (no Ryu needed)
    sudo python3 main.py --no-dash        # Skip dashboard
    sudo python3 main.py --iface eth0     # Specific network interface

Startup sequence:
    1. Load ML models
    2. Build network graph + restore previous state
    3. Start dashboard (background thread)
    4. Start periodic stats printer (background thread)
    5. Register detection callback → start packet sniffer (blocking)

Detection callback (runs every FLOW_WINDOW seconds per source IP):
    sniffer → features → detector → action:
        BLOCK   → block IP + push DROP rule to Ryu + reroute
        REROUTE → penalize switch + recompute path
        LOG     → log only, keep monitoring
    → update dashboard → save routing state
"""

import sys
import os
import time
import signal
import argparse
import threading

import sniffer
import logger
import dashboard as dash_module

try:
    import dashboard_visual as visual_module
    VISUAL_AVAILABLE = True
except ImportError as e:
    print(f'[Main] Visual dashboard unavailable: {e}')
    print('[Main] Install with: pip install dash-cytoscape')
    VISUAL_AVAILABLE = False
    visual_module = None

from config import CONFIDENCE_LEARN, SAFE_IPS, SENDER_HOST, RECEIVER_HOST
from model    import load_models, adaptive_update, FEATURE_COLUMNS
from detector import detect, learn_new_signature, reload_models
from routing  import (
    create_random_network, load_routing_state, save_routing_state,
    get_safe_path,
    handle_attack, penalize_node, reward_node,
    blocked_ips, attack_counts,
)

# ── Global state ──────────────────────────────────────────────────────────────
G            = None
current_path = []

# Adaptive learning buffer — retrain model every _ADAPTIVE_BATCH confirmed attacks
_adaptive_X     = []
_adaptive_y     = []
_ADAPTIVE_BATCH = 50
_LABEL_MAP      = {'DoS / DDoS': 1, 'Port Scan / Probe': 2, 'Brute Force': 3}


# ── Detection callback ────────────────────────────────────────────────────────

def on_flow_detected(features, feature_vector):
    """
    Called by sniffer.py every FLOW_WINDOW seconds per source IP.
    This is the core decision loop of the entire system.
    """
    global current_path

    src_ip = features.get('src_ip', 'unknown')

    # Skip already-blocked IPs and known safe IPs (sender + receiver)
    if src_ip in blocked_ips:
        return
    if src_ip in SAFE_IPS:
        return

    # Run hybrid detection (signature → ML → anomaly)
    result = detect(features, feature_vector)
    if result is None:
        return

    logger.log_detection(result)

    if not result['is_attack']:
        # Reward all switch nodes that are on the current active path
        import config
        for node in current_path:
            if node.startswith('s'):
                reward_node(G, node)
        # Keep dashboard path current even during normal traffic
        current_path, _ = get_safe_path(G, SENDER_HOST, RECEIVER_HOST)
        dash_module.update_state(
            G=G,
            active_path=current_path,
            blocked_ips=blocked_ips,
            attack_counts=attack_counts,
        )
        visual_module.update_visual_state(
            active_path=current_path,
            blocked_ips=blocked_ips,
            stats=logger.stats,
        ) if VISUAL_AVAILABLE else None
        return

    # ── Attack confirmed ──────────────────────────────────────────────────────
    action      = result['action']
    confidence  = result['confidence']
    attack_type = result['attack_type']

    print(f"\n{'='*60}")
    print(f"  ATTACK DETECTED")
    print(f"  Type:       {attack_type}")
    print(f"  Source:     {src_ip}")
    print(f"  Confidence: {confidence:.1f}%")
    print(f"  Method:     {result['method']}")
    print(f"  Action:     {action}")
    print(f"{'='*60}\n")

    old_path = current_path.copy()

    if action == 'BLOCK':
        logger.log_block(src_ip, reason=f'{attack_type} ({confidence:.1f}%)')
        new_path = handle_attack(G, src_ip, attack_type, confidence)
        if new_path and new_path != old_path:
            current_path = new_path
            logger.log_reroute(old_path, new_path, reason=f'After blocking {src_ip}')

    elif action == 'REROUTE':
        import config
        attacker_switch = config.IP_TO_SWITCH.get(src_ip)
        if attacker_switch:
            penalize_node(G, attacker_switch, penalty=5.0)
        new_path, _ = get_safe_path(G, SENDER_HOST, RECEIVER_HOST)
        if new_path and new_path != old_path:
            current_path = new_path
            logger.log_reroute(old_path, new_path, reason=f'Avoiding {src_ip} ({attack_type})')

    elif action == 'LOG':
        logger.log_system(f'Low-confidence: {attack_type} from {src_ip} ({confidence:.1f}%)')

    # Auto-learn signature if high confidence and not already a signature match
    if confidence >= CONFIDENCE_LEARN and result['method'] != 'signature':
        learn_new_signature(features, attack_type)

    # Adaptive learning — buffer confirmed attack samples, retrain every batch
    label_int = _LABEL_MAP.get(attack_type)
    if label_int is not None and feature_vector:
        _adaptive_X.append(feature_vector)
        _adaptive_y.append(label_int)
        if len(_adaptive_X) >= _ADAPTIVE_BATCH:
            adaptive_update(_adaptive_X.copy(), _adaptive_y.copy())
            reload_models()   # detector picks up the newly saved model
            _adaptive_X.clear()
            _adaptive_y.clear()

    # Push updated state to both dashboards
    dash_module.update_state(
        G=G,
        active_path=current_path,
        blocked_ips=blocked_ips,
        attack_counts=attack_counts,
        event=result,
    )
    if VISUAL_AVAILABLE:
        visual_module.update_visual_state(
            active_path=current_path,
            blocked_ips=blocked_ips,
            event=result,
            stats=logger.stats,
        )

    # Persist routing state to disk
    save_routing_state(G)


# ── Background threads ────────────────────────────────────────────────────────

def _stats_loop():
    """Print session stats every 60 seconds."""
    while True:
        time.sleep(60)
        logger.print_stats()


def _graceful_exit(signum, frame):
    """Handle Ctrl+C: print stats, save state, exit cleanly."""
    print('\n[Main] Shutting down...')
    logger.print_stats()
    if G is not None:
        save_routing_state(G)
    logger.log_system('System stopped by user.')
    sys.exit(0)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    global G, current_path

    parser = argparse.ArgumentParser(description='AI Self-Healing Network IDS')
    parser.add_argument('--iface',   default=None,         help='Network interface to sniff')
    parser.add_argument('--no-ryu',  action='store_true',  help='Disable Ryu (simulation mode)')
    parser.add_argument('--no-dash', action='store_true',  help='Disable web dashboard')
    parser.add_argument('--fresh',   action='store_true',  help='Clear previous routing state (unblock all IPs)')
    parser.add_argument('--visual',  action='store_true',  help='Start enhanced visual dashboard on port 8051')
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _graceful_exit)

    print('\n' + '=' * 60)
    print('   AI SELF-HEALING NETWORK — INTRUSION DETECTION SYSTEM')
    print('=' * 60 + '\n')

    if args.no_ryu:
        print('[Main] Ryu disabled — running in simulation mode.\n')

    # Step 1 — Load ML models
    logger.log_system('Loading ML models...')
    load_models()   # warms up detector.py's lazy-loaded models
    logger.log_system('Models ready.')

    # Step 2 — Build random network graph (new topology every run)
    G = create_random_network()
    if args.fresh:
        print('[Main] --fresh: starting with clean routing state.')
        if os.path.exists('routing_state.json'):
            os.remove('routing_state.json')
    else:
        G = load_routing_state(G)
    current_path, _ = get_safe_path(G, SENDER_HOST, RECEIVER_HOST)
    print(f'[Main] Initial path: {" → ".join(current_path)}')

    # Step 3 — Start dashboard(s)
    if not args.no_dash:
        dash_module.init_state(G, current_path)
        threading.Thread(
            target=lambda: dash_module.run_dashboard(debug=False),
            daemon=True,
        ).start()
        print('[Main] Dashboard → http://127.0.0.1:8050')

    if args.visual:
        if not VISUAL_AVAILABLE:
            print('[Main] Cannot start visual dashboard — run: pip install dash-cytoscape')
        else:
            threading.Thread(
                target=lambda: visual_module.run_visual_dashboard(debug=False),
                daemon=True,
            ).start()
            print('[Main] Visual Dashboard → http://127.0.0.1:8051')

    # Step 4 — Start stats thread
    threading.Thread(target=_stats_loop, daemon=True).start()

    # Step 5 — Start sniffer (blocking)
    sniffer.on_flow_ready = on_flow_detected
    logger.log_system('System started. Monitoring network...')
    print('\n[Main] Listening for traffic. Run attacker.py on any attacker host to test.\n')
    sniffer.start_sniffing(iface=args.iface)


if __name__ == '__main__':
    main()
