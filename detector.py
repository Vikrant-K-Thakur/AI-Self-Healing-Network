"""
detector.py — Hybrid Intrusion Detection Engine
=================================================
Three detection methods run in priority order:

  1. Signature Engine  — instant pattern matching (fastest)
  2. ML Classifier     — Random Forest on NSL-KDD features
  3. Anomaly Detector  — IsolationForest for unknown/zero-day attacks

Decision based on confidence score:
  >= CONFIDENCE_BLOCK   (80%) → BLOCK
  >= CONFIDENCE_REROUTE (50%) → REROUTE
  <  CONFIDENCE_REROUTE       → LOG
"""

import time
import json
import os

from config import (
    CONFIDENCE_BLOCK, CONFIDENCE_REROUTE,
    LEARNED_SIGNATURES_FILE,
)
from model import LABEL_NAMES, load_models

# ── Lazy-loaded model references ──────────────────────────────────────────────
_rf_model  = None
_scaler    = None
_iso_model = None

# ── Override LABEL_NAMES to match new 4-class model ──────────────────────────
LABEL_NAMES = {
    0: 'Normal',
    1: 'DoS / DDoS',
    2: 'Port Scan / Probe',
    3: 'Brute Force',
}

# ── Built-in attack signatures ────────────────────────────────────────────────
# Each signature: { feature_name: check_function }
# A signature matches if >= 75% of its checks pass.
# Thresholds tuned for Mininet (~20-30 pkt/s, not real-world 500+ pkt/s)
SIGNATURES = {
    'syn_flood': {
        'syn_count':   lambda v: v > 15,
        'packet_rate': lambda v: v > 10,
    },
    'port_scan': {
        'unique_dst_ports': lambda v: v > 8,
        'packet_rate':      lambda v: v > 8,
    },
    'brute_force': {
        'unique_dst_ports': lambda v: v == 1,
        'packet_count':     lambda v: v > 25,
        'avg_pkt_size':     lambda v: v < 200,
    },
    'icmp_flood': {
        'proto_tcp_ratio': lambda v: v < 0.1,
        'packet_rate':     lambda v: v > 10,
        'byte_rate':       lambda v: v > 2000,
    },
}


def _load_models_once():
    global _rf_model, _scaler, _iso_model
    if _rf_model is None:
        _rf_model, _scaler, _iso_model = load_models()


def reload_models():
    """Force reload models from disk (called after adaptive_update)."""
    global _rf_model, _scaler, _iso_model
    _rf_model, _scaler, _iso_model = load_models()
    print('[Detector] Models reloaded after adaptive update.')


# ── Detection methods ─────────────────────────────────────────────────────────

def check_signatures(features):
    """
    Match features against built-in + learned signatures.
    Returns (sig_name, confidence) or (None, 0).
    """
    for sig_name, checks in SIGNATURES.items():
        matched = sum(
            1 for feat, fn in checks.items()
            if feat in features and fn(features[feat])
        )
        ratio = matched / len(checks)
        if ratio >= 0.75:
            return sig_name, ratio * 100

    # Check learned signatures saved by learn_new_signature()
    if os.path.exists(LEARNED_SIGNATURES_FILE):
        with open(LEARNED_SIGNATURES_FILE, 'r') as f:
            learned = json.load(f)
        for sig_name, thresholds in learned.items():
            matched = sum(
                1 for feat, thresh in thresholds.items()
                if feat in features and features[feat] > thresh
            )
            if matched == len(thresholds):
                return sig_name, 85.0

    return None, 0


def check_ml(feature_vector):
    """
    Random Forest classification.
    Returns (label_int, label_name, confidence_pct).
    """
    _load_models_once()
    try:
        expected = _rf_model.n_features_in_
        if len(feature_vector) != expected:
            print(f'[Detector] ML skipped: got {len(feature_vector)} features, '
                  f'model expects {expected}. Retrain with: python3 model.py')
            return 0, 'Normal', 0.0
        import numpy as np
        scaled     = _scaler.transform(np.array([feature_vector]))
        prediction = _rf_model.predict(scaled)[0]
        probs      = _rf_model.predict_proba(scaled)[0]
        confidence = max(probs) * 100
        return prediction, LABEL_NAMES.get(prediction, 'Unknown'), confidence
    except Exception as e:
        print(f'[Detector] ML error: {e}')
        return 0, 'Normal', 0.0


def check_anomaly(feature_vector):
    """
    IsolationForest anomaly detection.
    Returns (is_anomaly: bool, confidence_pct: float).
    """
    _load_models_once()
    try:
        import numpy as np
        scaled     = _scaler.transform(np.array([feature_vector]))
        prediction = _iso_model.predict(scaled)[0]
        score      = _iso_model.decision_function(scaled)[0]
        confidence = max(0, min(100, (-score + 0.5) * 100))
        return prediction == -1, confidence
    except Exception as e:
        print(f'[Detector] Anomaly error: {e}')
        return False, 0


def _decide_action(confidence):
    """Map confidence score to response action."""
    if confidence >= CONFIDENCE_BLOCK:
        return 'BLOCK'
    elif confidence >= CONFIDENCE_REROUTE:
        return 'REROUTE'
    return 'LOG'


# ── Main detection entry point ────────────────────────────────────────────────

def detect(features, feature_vector):
    """
    Run all three detection methods in priority order.

    Args:
        features       : dict from compute_flow_features()
        feature_vector : list from features_to_vector()

    Returns:
        dict with keys: is_attack, attack_type, confidence,
                        method, action, src_ip, timestamp
    """
    if not features or feature_vector is None:
        return None

    src_ip = features.get('src_ip', 'unknown')
    result = {
        'is_attack':   False,
        'attack_type': 'Normal',
        'confidence':  0.0,
        'method':      'none',
        'action':      'ALLOW',
        'src_ip':      src_ip,
        'timestamp':   time.strftime('%Y-%m-%d %H:%M:%S'),
    }

    # Method 1 — Signature (fastest, runs first)
    sig_name, sig_conf = check_signatures(features)
    if sig_conf >= 75:
        result.update({
            'is_attack':   True,
            'attack_type': sig_name,
            'confidence':  sig_conf,
            'method':      'signature',
            'action':      _decide_action(sig_conf),
        })
        return result

    # Method 2 — ML Classifier
    ml_label, ml_name, ml_conf = check_ml(feature_vector)
    if ml_label != 0 and ml_conf >= CONFIDENCE_REROUTE:
        result.update({
            'is_attack':   True,
            'attack_type': ml_name,
            'confidence':  ml_conf,
            'method':      'ml_classifier',
            'action':      _decide_action(ml_conf),
        })
        return result

    # Method 3 — Anomaly Detection (catches unknown attacks)
    is_anomaly, anom_conf = check_anomaly(feature_vector)
    if is_anomaly and anom_conf >= 60:
        result.update({
            'is_attack':   True,
            'attack_type': 'Unknown Anomaly',
            'confidence':  anom_conf,
            'method':      'anomaly_detection',
            'action':      _decide_action(anom_conf),
        })
        return result

    # No attack — return normal result with ML confidence
    result['confidence'] = ml_conf
    return result


def learn_new_signature(features, attack_name):
    """
    Extract and save a new signature pattern from a confirmed attack.
    Called automatically when confidence >= CONFIDENCE_LEARN.
    """
    thresholds = {
        'packet_rate':      100,
        'syn_count':        50,
        'unique_dst_ports': 15,
        'byte_rate':        10000,
    }
    sig = {
        feat: features[feat] * 0.7   # 70% of observed value as threshold
        for feat, thresh in thresholds.items()
        if feat in features and features[feat] > thresh
    }
    if not sig:
        return

    learned = {}
    if os.path.exists(LEARNED_SIGNATURES_FILE):
        with open(LEARNED_SIGNATURES_FILE, 'r') as f:
            learned = json.load(f)

    learned[attack_name] = sig
    with open(LEARNED_SIGNATURES_FILE, 'w') as f:
        json.dump(learned, f, indent=2)

    print(f'[Detector] New signature learned: {attack_name}')
