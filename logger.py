"""
logger.py — Structured Event Logging
======================================
Writes all IDS events to:
  - Console  (formatted, human-readable)
  - logs/events.log  (JSON, one event per line — machine-readable)
  - logs/alerts.log  (attack alerts only, human-readable)
"""

import os
import json
import time
import logging
from datetime import datetime

from config import EVENTS_LOG, ALERTS_LOG, LOGS_DIR

# ── Ensure logs directory exists ──────────────────────────────────────────────
os.makedirs(LOGS_DIR, exist_ok=True)

# ── Console logger setup ──────────────────────────────────────────────────────
_logger = logging.getLogger('IDS')
_logger.setLevel(logging.DEBUG)
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'
    ))
    _logger.addHandler(_h)

# ── Session statistics ────────────────────────────────────────────────────────
stats = {
    'total_flows':      0,
    'attacks_detected': 0,
    'ips_blocked':      0,
    'reroutes':         0,
    'start_time':       time.time(),
}


# ── Core log writer ───────────────────────────────────────────────────────────

def _write_event(event_type, data):
    """Append a JSON event to events.log."""
    entry = {'timestamp': datetime.now().isoformat(), 'event_type': event_type, **data}
    with open(EVENTS_LOG, 'a') as f:
        f.write(json.dumps(entry) + '\n')
    return entry


# ── Public logging functions ──────────────────────────────────────────────────

def log_detection(result):
    """Log a detection result (attack or normal)."""
    if result is None:
        return

    stats['total_flows'] += 1

    if not result.get('is_attack'):
        return

    stats['attacks_detected'] += 1

    attack_type = result.get('attack_type', 'Unknown')
    confidence  = result.get('confidence', 0)
    src_ip      = result.get('src_ip', '?')
    action      = result.get('action', '?')
    method      = result.get('method', '?')

    _logger.warning(
        f'ATTACK | {attack_type} | {src_ip} | '
        f'confidence={confidence:.1f}% | method={method} | action={action}'
    )

    with open(ALERTS_LOG, 'a') as f:
        f.write(
            f'[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] '
            f'⚠ {attack_type} from {src_ip} | '
            f'Confidence: {confidence:.1f}% | Method: {method} | Action: {action}\n'
        )

    _write_event('DETECTION', result)


def log_block(ip_address, reason=''):
    """Log an IP block action."""
    stats['ips_blocked'] += 1
    _logger.warning(f'BLOCKED | {ip_address} | {reason}')
    _write_event('BLOCK', {'ip': ip_address, 'reason': reason})


def log_reroute(old_path, new_path, reason=''):
    """Log a path reroute event."""
    stats['reroutes'] += 1
    old_str = ' → '.join(old_path) if old_path else 'N/A'
    new_str = ' → '.join(new_path) if new_path else 'N/A'
    _logger.info(f'REROUTE | {old_str} → {new_str} | {reason}')
    _write_event('REROUTE', {'old_path': old_path, 'new_path': new_path, 'reason': reason})


def log_system(message):
    """Log a system-level message."""
    _logger.info(f'SYSTEM | {message}')
    _write_event('SYSTEM', {'message': message})


def print_stats():
    """Print session statistics to console."""
    uptime = time.time() - stats['start_time']
    print('\n' + '=' * 50)
    print('  SESSION STATISTICS')
    print('=' * 50)
    print(f"  Uptime:           {uptime / 60:.1f} minutes")
    print(f"  Flows analyzed:   {stats['total_flows']}")
    print(f"  Attacks detected: {stats['attacks_detected']}")
    print(f"  IPs blocked:      {stats['ips_blocked']}")
    print(f"  Path reroutes:    {stats['reroutes']}")
    print('=' * 50 + '\n')


def get_recent_alerts(n=20):
    """Return the last n lines from alerts.log."""
    if not os.path.exists(ALERTS_LOG):
        return []
    with open(ALERTS_LOG, 'r') as f:
        return f.readlines()[-n:]


def get_event_history(event_type=None, limit=50):
    """Return recent events from events.log, optionally filtered by type."""
    if not os.path.exists(EVENTS_LOG):
        return []
    events = []
    with open(EVENTS_LOG, 'r') as f:
        for line in f:
            try:
                ev = json.loads(line.strip())
                if event_type is None or ev.get('event_type') == event_type:
                    events.append(ev)
            except json.JSONDecodeError:
                continue
    return events[-limit:]
