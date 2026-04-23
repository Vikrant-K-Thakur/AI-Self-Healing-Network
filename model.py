"""
model.py — ML Model Training on Live Flow Features
====================================================
Trains two models on the same 13 features that sniffer.py extracts:
  1. RandomForestClassifier  — classifies: Normal / DoS / PortScan / BruteForce
  2. IsolationForest         — detects unknown/zero-day anomalies

Run once to train and save:
    python3 model.py

Features (must match features.py FEATURE_COLUMNS exactly):
    packet_count, byte_count, avg_pkt_size, std_pkt_size,
    packet_rate, byte_rate, unique_dst_ports, unique_dst_ips,
    syn_count, rst_count, proto_tcp_ratio, proto_udp_ratio,
    avg_inter_arrival

Attack labels:
    0 = Normal
    1 = DoS / DDoS
    2 = Port Scan / Probe
    3 = Brute Force
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from config import MODEL_PATH, SCALER_PATH, ANOMALY_PATH, ENCODER_PATH, MODELS_DIR

# ── Must match features.py FEATURE_COLUMNS exactly ───────────────────────────
FEATURE_COLUMNS = [
    'packet_count', 'byte_count', 'avg_pkt_size', 'std_pkt_size',
    'packet_rate', 'byte_rate', 'unique_dst_ports', 'unique_dst_ips',
    'syn_count', 'rst_count', 'proto_tcp_ratio', 'proto_udp_ratio',
    'avg_inter_arrival',
]

LABEL_NAMES = {
    0: 'Normal',
    1: 'DoS / DDoS',
    2: 'Port Scan / Probe',
    3: 'Brute Force',
}


def _generate_synthetic_data(n_per_class=3000, noise=0.15):
    """
    Generate synthetic flow samples that match real Mininet traffic patterns.
    Each class is defined by realistic feature ranges based on attack behavior.
    """
    rng = np.random.default_rng(42)

    def _jitter(base, scale, size):
        return np.abs(base + rng.normal(0, scale * base + 0.01, size))

    n = n_per_class
    rows = []

    # ── Label 0: Normal traffic ───────────────────────────────────────────────
    for _ in range(n):
        pc  = rng.integers(2, 30)
        pkt = rng.uniform(100, 900)
        rows.append([
            pc,                          # packet_count
            pc * pkt,                    # byte_count
            pkt,                         # avg_pkt_size
            rng.uniform(10, 150),        # std_pkt_size
            rng.uniform(0.5, 15),        # packet_rate
            pc * pkt * rng.uniform(0.5, 1.5),  # byte_rate
            rng.integers(1, 5),          # unique_dst_ports
            1,                           # unique_dst_ips
            rng.integers(0, 3),          # syn_count
            rng.integers(0, 2),          # rst_count
            rng.uniform(0.5, 1.0),       # proto_tcp_ratio
            rng.uniform(0.0, 0.3),       # proto_udp_ratio
            rng.uniform(50, 500),        # avg_inter_arrival (ms)
            0,
        ])

    # ── Label 1: DoS / SYN Flood ──────────────────────────────────────────────
    for _ in range(n):
        pc  = rng.integers(300, 3000)
        pkt = rng.uniform(40, 80)        # small SYN packets
        rows.append([
            pc,
            pc * pkt,
            pkt,
            rng.uniform(0, 15),          # very uniform sizes
            rng.uniform(200, 2000),      # very high packet_rate
            pc * pkt * rng.uniform(0.8, 1.2),
            rng.integers(1, 3),          # few ports (flood one port)
            1,
            int(pc * rng.uniform(0.85, 1.0)),  # almost all SYN
            rng.integers(0, 5),
            rng.uniform(0.9, 1.0),       # all TCP
            rng.uniform(0.0, 0.05),
            rng.uniform(0.1, 5),         # very low inter-arrival
            1,
        ])

    # ── Label 2: Port Scan ────────────────────────────────────────────────────
    for _ in range(n):
        ports = rng.integers(25, 500)
        rows.append([
            ports,
            ports * rng.uniform(40, 70),
            rng.uniform(40, 70),
            rng.uniform(0, 20),
            rng.uniform(20, 200),
            ports * rng.uniform(40, 70) * rng.uniform(0.8, 1.2),
            ports,                       # unique_dst_ports ≈ packet_count
            1,
            int(ports * rng.uniform(0.8, 1.0)),
            rng.integers(0, 10),
            rng.uniform(0.9, 1.0),
            rng.uniform(0.0, 0.05),
            rng.uniform(5, 50),
            2,
        ])

    # ── Label 3: Brute Force ──────────────────────────────────────────────────
    for _ in range(n):
        pc  = rng.integers(100, 800)
        pkt = rng.uniform(40, 120)       # small auth packets
        rows.append([
            pc,
            pc * pkt,
            pkt,
            rng.uniform(0, 30),
            rng.uniform(10, 100),
            pc * pkt * rng.uniform(0.8, 1.2),
            1,                           # always same port (e.g. 22)
            1,
            int(pc * rng.uniform(0.7, 1.0)),
            rng.integers(0, 20),
            rng.uniform(0.9, 1.0),
            rng.uniform(0.0, 0.05),
            rng.uniform(5, 80),
            3,
        ])

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ['label'])

    # Add small gaussian noise to all numeric features
    for col in FEATURE_COLUMNS:
        df[col] = df[col] + rng.normal(0, noise * df[col].std() + 0.001, len(df))
        df[col] = df[col].clip(lower=0)

    return df[FEATURE_COLUMNS], df['label'].astype(int)


def train_and_save():
    """Generate synthetic data, train models, save to disk."""
    print('\n=== Generating synthetic flow dataset ===')
    X, y = _generate_synthetic_data(n_per_class=3000)
    print(f'Total samples: {len(X)}')
    print(f'Label distribution:\n{y.value_counts().sort_index()}')
    print(f'Features ({len(FEATURE_COLUMNS)}): {FEATURE_COLUMNS}')

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print('\n=== Scaling features ===')
    scaler         = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    print('\n=== Training Random Forest ===')
    rf_model = RandomForestClassifier(
        n_estimators=150, max_depth=20, min_samples_split=5,
        random_state=42, n_jobs=-1, class_weight='balanced',
        warm_start=False,
    )
    rf_model.fit(X_train_scaled, y_train)

    y_pred   = rf_model.predict(X_test_scaled)
    accuracy = (y_pred == y_test.values).mean()
    print(classification_report(
        y_test, y_pred,
        target_names=[LABEL_NAMES[i] for i in sorted(LABEL_NAMES)],
    ))
    print(f'Overall Accuracy: {accuracy * 100:.2f}%')
    print(f'Model expects {rf_model.n_features_in_} features ✓')

    print('\n=== Training IsolationForest (anomaly detector) ===')
    X_normal  = X_train_scaled[y_train == 0]
    iso_model = IsolationForest(
        n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1,
    )
    iso_model.fit(X_normal)
    print(f'Trained on {len(X_normal)} normal samples.')

    print('\n=== Saving models ===')
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(rf_model,       MODEL_PATH)
    joblib.dump(scaler,         SCALER_PATH)
    joblib.dump(iso_model,      ANOMALY_PATH)
    joblib.dump(FEATURE_COLUMNS, ENCODER_PATH)  # save feature order
    print(f'  Saved to {MODELS_DIR}/')
    print('=== Training complete! ===\n')

    return rf_model, scaler, iso_model


def load_models():
    """Load saved models from disk. Retrains if not found or feature count mismatch."""
    required = [MODEL_PATH, SCALER_PATH, ANOMALY_PATH]
    if not all(os.path.exists(p) for p in required):
        print('[Model] Saved models not found — training now...')
        return train_and_save()

    rf_model  = joblib.load(MODEL_PATH)
    scaler    = joblib.load(SCALER_PATH)
    iso_model = joblib.load(ANOMALY_PATH)

    # Verify feature count matches live features
    expected = len(FEATURE_COLUMNS)
    if hasattr(rf_model, 'n_features_in_') and rf_model.n_features_in_ != expected:
        print(f'[Model] Feature mismatch: model={rf_model.n_features_in_}, '
              f'live={expected} — retraining...')
        return train_and_save()

    print(f'[Model] Models loaded. Features: {rf_model.n_features_in_} ✓')
    return rf_model, scaler, iso_model


def adaptive_update(new_features_list, new_labels_list):
    """
    Incrementally retrain model with new confirmed attack samples.
    new_features_list: list of feature vectors (each length 13)
    new_labels_list:   list of int labels
    """
    if not new_features_list:
        return

    adaptive_path = os.path.join(MODELS_DIR, 'adaptive_data.pkl')

    new_X = pd.DataFrame(new_features_list, columns=FEATURE_COLUMNS)
    new_y = pd.Series(new_labels_list)

    if os.path.exists(adaptive_path):
        old       = joblib.load(adaptive_path)
        combined_X = pd.concat([old['X'], new_X], ignore_index=True)
        combined_y = pd.concat([old['y'], new_y], ignore_index=True)
    else:
        combined_X, combined_y = new_X, new_y

    joblib.dump({'X': combined_X, 'y': combined_y}, adaptive_path)

    rf_model = joblib.load(MODEL_PATH)
    scaler   = joblib.load(SCALER_PATH)

    rf_model.n_estimators += 10
    rf_model.warm_start    = True
    rf_model.fit(scaler.transform(combined_X.fillna(0)), combined_y)
    joblib.dump(rf_model, MODEL_PATH)
    print(f'[Model] Adaptive update: +{len(new_X)} samples, '
          f'model now has {rf_model.n_estimators} trees.')


if __name__ == '__main__':
    train_and_save()
