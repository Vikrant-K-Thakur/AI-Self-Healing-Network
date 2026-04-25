"""
config.py — Central Configuration
===================================
All constants, paths, and settings in one place.
Every other module imports from here — no hardcoded values anywhere else.

Random topology is generated fresh every run by routing.py and saved to
topology_state.json so topo.py (Mininet) can read the same graph.
"""

import os

# ── Project root (folder this file lives in) ──────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR   = os.path.join(BASE_DIR, 'models')
LOGS_DIR     = os.path.join(BASE_DIR, 'logs')
DATA_DIR     = os.path.join(BASE_DIR, 'data')

# ── ML model file paths ────────────────────────────────────────────────────────
MODEL_PATH   = os.path.join(MODELS_DIR, 'saved_model.pkl')
SCALER_PATH  = os.path.join(MODELS_DIR, 'saved_scaler.pkl')
ANOMALY_PATH = os.path.join(MODELS_DIR, 'saved_anomaly.pkl')
ENCODER_PATH = os.path.join(MODELS_DIR, 'saved_encoder.pkl')

# ── Dataset file paths ─────────────────────────────────────────────────────────
TRAIN_FILE   = os.path.join(DATA_DIR, 'KDDTrain+.txt')
TEST_FILE    = os.path.join(DATA_DIR, 'KDDTest+.txt')

# ── Log file paths ─────────────────────────────────────────────────────────────
EVENTS_LOG   = os.path.join(LOGS_DIR, 'events.log')
ALERTS_LOG   = os.path.join(LOGS_DIR, 'alerts.log')

# ── State persistence ──────────────────────────────────────────────────────────
ROUTING_STATE_FILE      = os.path.join(BASE_DIR, 'routing_state.json')
LEARNED_SIGNATURES_FILE = os.path.join(BASE_DIR, 'learned_signatures.json')
TOPOLOGY_STATE_FILE     = os.path.join(BASE_DIR, 'topology_state.json')
FORCED_ATTACK_FILE      = os.path.join(BASE_DIR, 'forced_attack_state.json')

# ── Random topology parameters ─────────────────────────────────────────────────
NUM_SWITCHES_MIN      = 4   # minimum switches
NUM_SWITCHES_MAX      = 8   # maximum switches
NUM_ATTACKERS_MIN     = 2   # minimum attacker hosts
NUM_ATTACKERS_MAX     = 4   # maximum attacker hosts
NUM_NORMAL_HOSTS_MIN  = 1   # extra normal observer hosts (besides h1/h2)
NUM_NORMAL_HOSTS_MAX  = 3   # extra normal observer hosts (besides h1/h2)

# Fixed sender / receiver host names and IPs
SENDER_HOST   = 'h1'
RECEIVER_HOST = 'h2'
SENDER_IP     = '10.0.0.1'
RECEIVER_IP   = '10.0.0.2'

# IPs that should never be treated as attackers (sender + receiver)
SAFE_IPS = {SENDER_IP, RECEIVER_IP}

# Attacker IPs start from 10.0.0.3 upward — populated dynamically by routing.py
# These are read back from topology_state.json by other modules
HOST_IPS     = {'h1': SENDER_IP, 'h2': RECEIVER_IP}   # extended at runtime
IP_TO_SWITCH  = {}   # populated at runtime by create_random_network()
DPID          = {}   # populated at runtime by create_random_network()

# ── Ryu SDN Controller ─────────────────────────────────────────────────────────
RYU_HOST          = '127.0.0.1'
RYU_REST_PORT     = 8080
RYU_OPENFLOW_PORT = 6653
RYU_BASE_URL      = f'http://{RYU_HOST}:{RYU_REST_PORT}'

# ── Sniffer / Flow analysis ────────────────────────────────────────────────────
FLOW_WINDOW      = 2.0    # seconds per flow analysis window
FLOW_CLEANUP_SEC = 30     # how often to clean stale flows
FLOW_MAX_AGE_SEC = 60     # max age of packets in buffer

# ── Detection thresholds ───────────────────────────────────────────────────────
CONFIDENCE_BLOCK   = 80   # >= this → BLOCK
CONFIDENCE_REROUTE = 50   # >= this → REROUTE
CONFIDENCE_LEARN   = 85   # >= this → learn new signature

# ── Routing weights ────────────────────────────────────────────────────────────
EDGE_WEIGHT_DEFAULT = 1.0
EDGE_PENALTY        = 10.0
EDGE_REWARD         = 0.5
EDGE_WEIGHT_MIN     = 1.0

# ── Dashboard ──────────────────────────────────────────────────────────────────
DASHBOARD_HOST = '0.0.0.0'
DASHBOARD_PORT = 8050

# ── Ensure all directories exist ──────────────────────────────────────────────
for _d in [MODELS_DIR, LOGS_DIR, DATA_DIR]:
    os.makedirs(_d, exist_ok=True)
