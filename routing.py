"""
routing.py — Self-Healing Network Routing
==========================================
Manages the logical network graph (NetworkX) and pushes
real OpenFlow rules to Mininet switches via Ryu REST API.

Self-healing flow:
  Attack detected → penalize switch → Dijkstra finds new safe path
                  → push DROP + new flow rules to Ryu

RL-inspired weight system:
  Attack on node  → edge weights increase (penalty)
  No attack       → edge weights slowly decrease (reward)
  Dijkstra always picks the minimum-weight (safest) path.
"""

import json
import os
import requests
import networkx as nx

from config import (
    RYU_BASE_URL,
    EDGE_WEIGHT_DEFAULT, EDGE_PENALTY, EDGE_REWARD, EDGE_WEIGHT_MIN,
    ROUTING_STATE_FILE,
)

# ── Ryu REST endpoints ────────────────────────────────────────────────────────
_FLOW_ADD_URL = RYU_BASE_URL + '/stats/flowentry/add'

# ── Runtime state ─────────────────────────────────────────────────────────────
blocked_ips   = set()
attack_counts = {}


# ── Graph construction ────────────────────────────────────────────────────────

def create_random_network():
    """
    Generate a fully random topology every run.

    Every run produces:
      - Random switches          (NUM_SWITCHES_MIN .. NUM_SWITCHES_MAX)
      - Random attacker hosts    (NUM_ATTACKERS_MIN .. NUM_ATTACKERS_MAX)
      - Random extra normal hosts(NUM_NORMAL_HOSTS_MIN .. NUM_NORMAL_HOSTS_MAX)
      - Random initial edge weights (1.0 .. 3.0) so Dijkstra picks a
        different initial best-path each run
      - True random mesh: Prufer-sequence spanning tree guarantees full
        connectivity, then n//2 extra edges guarantee multiple paths
      - Attackers placed on random INTERMEDIATE switches only
      - Normal observer hosts placed on random switches
      - At least 2 node-disjoint paths h1 → h2 guaranteed
      - Full topology saved to topology_state.json for topo.py

    Updates config.HOST_IPS, config.IP_TO_SWITCH, config.DPID,
    config.SAFE_IPS in-place so all other modules see the new topology.
    """
    import random
    import config
    from config import (
        NUM_SWITCHES_MIN, NUM_SWITCHES_MAX,
        NUM_ATTACKERS_MIN, NUM_ATTACKERS_MAX,
        NUM_NORMAL_HOSTS_MIN, NUM_NORMAL_HOSTS_MAX,
        SENDER_IP, RECEIVER_IP, TOPOLOGY_STATE_FILE,
    )

    rng = random.Random()   # unseeded → different every run

    # ── 1. Decide counts ───────────────────────────────────────────────────
    n_sw   = rng.randint(NUM_SWITCHES_MIN, NUM_SWITCHES_MAX)
    n_atk  = rng.randint(NUM_ATTACKERS_MIN, NUM_ATTACKERS_MAX)
    n_norm = rng.randint(NUM_NORMAL_HOSTS_MIN, NUM_NORMAL_HOSTS_MAX)

    switch_names = [f's{i}' for i in range(1, n_sw + 1)]

    # h1 always attaches to s1, h2 always attaches to last switch
    src_sw = switch_names[0]
    dst_sw = switch_names[-1]

    # ── 2. Build random spanning tree via Prufer sequence ──────────────────
    # A Prufer sequence of length n-2 uniquely encodes a random labeled tree
    # on n nodes — this gives a truly random spanning tree (not just a chain)
    sw_edges = set()
    if n_sw == 2:
        sw_edges.add((switch_names[0], switch_names[1]))
    else:
        prufer = [rng.choice(switch_names) for _ in range(n_sw - 2)]
        degree = {s: 1 for s in switch_names}
        for node in prufer:
            degree[node] += 1
        prufer_copy = prufer[:]
        for node in prufer_copy:
            # Find lowest-index leaf (degree == 1)
            leaf = next(s for s in switch_names if degree[s] == 1)
            edge = tuple(sorted([leaf, node]))
            sw_edges.add(edge)
            degree[leaf]  -= 1
            degree[node]  -= 1
        # Last edge: connect the two remaining nodes with degree >= 1
        remaining = [s for s in switch_names if degree[s] >= 1]
        if len(remaining) >= 2:
            sw_edges.add(tuple(sorted([remaining[0], remaining[1]])))

    # ── 3. Add extra random edges for redundancy (multiple paths) ─────────
    extra    = max(2, n_sw // 2)
    attempts = 0
    while extra > 0 and attempts < 200:
        u = rng.choice(switch_names)
        v = rng.choice(switch_names)
        edge = tuple(sorted([u, v]))
        if u != v and edge not in sw_edges:
            sw_edges.add(edge)
            extra -= 1
        attempts += 1
    sw_edges = list(sw_edges)

    # ── 4. Assign random initial edge weights (1.0 – 3.0) ────────────────
    # Different weights each run → Dijkstra picks a different initial path
    edge_weights = {}
    for e in sw_edges:
        edge_weights[e] = round(rng.uniform(1.0, 3.0), 2)
    # Host↔switch edges always weight 1.0
    host_edge_weight = 1.0

    # ── 5. Assign attacker hosts to intermediate switches ─────────────────
    mid_switches = [s for s in switch_names if s not in (src_sw, dst_sw)]
    if not mid_switches:
        mid_switches = switch_names

    attacker_hosts       = {}   # {hname: ip}
    attacker_ip_to_sw    = {}   # {ip: switch}
    for i in range(n_atk):
        hname = f'h{i + 3}'
        ip    = f'10.0.0.{i + 3}'
        sw    = rng.choice(mid_switches)
        attacker_hosts[hname]  = ip
        attacker_ip_to_sw[ip]  = sw

    # ── 6. Assign extra normal observer hosts ───────────────────────────
    # IPs in 10.0.1.x range so they never clash with attackers
    normal_hosts       = {}   # {hname: ip}
    normal_ip_to_sw    = {}   # {ip: switch}
    base_norm_idx      = n_atk + 3   # h-name index after attackers
    for i in range(n_norm):
        hname = f'h{base_norm_idx + i}'
        ip    = f'10.0.1.{i + 1}'
        sw    = rng.choice(switch_names)
        normal_hosts[hname]  = ip
        normal_ip_to_sw[ip]  = sw

    # ── 7. Update config dicts in-place ─────────────────────────────────
    config.HOST_IPS = {
        'h1': SENDER_IP,
        'h2': RECEIVER_IP,
        **attacker_hosts,
        **normal_hosts,
    }
    config.IP_TO_SWITCH = {
        SENDER_IP:   src_sw,
        RECEIVER_IP: dst_sw,
        **attacker_ip_to_sw,
        **normal_ip_to_sw,
    }
    config.DPID     = {sw: idx + 1 for idx, sw in enumerate(switch_names)}
    config.SAFE_IPS = (
        {SENDER_IP, RECEIVER_IP}
        | set(normal_hosts.values())   # normal observer hosts are never attackers
    )

    # ── 8. Build NetworkX graph ──────────────────────────────────────────
    all_hosts = (
        ['h1', 'h2']
        + list(attacker_hosts.keys())
        + list(normal_hosts.keys())
    )
    G = nx.Graph()
    G.add_nodes_from(all_hosts + switch_names)

    # h1 ↔ src_sw,  h2 ↔ dst_sw
    G.add_edge('h1', src_sw, weight=host_edge_weight)
    G.add_edge('h2', dst_sw, weight=host_edge_weight)

    # attacker hosts ↔ their switches
    for hname, ip in attacker_hosts.items():
        G.add_edge(hname, attacker_ip_to_sw[ip], weight=host_edge_weight)

    # normal observer hosts ↔ their switches
    for hname, ip in normal_hosts.items():
        G.add_edge(hname, normal_ip_to_sw[ip], weight=host_edge_weight)

    # switch ↔ switch edges with random weights
    for e in sw_edges:
        G.add_edge(e[0], e[1], weight=edge_weights[e])

    # ── 9. Guarantee ≥2 node-disjoint paths h1 → h2 ─────────────────────
    try:
        n_paths = len(list(nx.node_disjoint_paths(G, 'h1', 'h2')))
    except nx.NetworkXError:
        n_paths = 0
    if n_paths < 2:
        backup_w = round(rng.uniform(1.0, 3.0), 2)
        G.add_edge(src_sw, dst_sw, weight=backup_w)
        sw_edges.append((src_sw, dst_sw))
        edge_weights[(src_sw, dst_sw)] = backup_w
        print(f'[Routing] Added backup edge {src_sw}↔{dst_sw} '
              f'(w={backup_w}) to guarantee 2 paths.')

    # ── 10. Print ASCII topology summary ───────────────────────────────
    initial_path, initial_cost = _dijkstra_raw(G, 'h1', 'h2')
    path_str = ' → '.join(initial_path) if initial_path else 'N/A'

    print('\n' + '='*62)
    print('  RANDOM TOPOLOGY GENERATED')
    print('='*62)
    print(f'  Switches ({n_sw})  : {" ".join(switch_names)}')
    print(f'  Src switch      : {src_sw}   Dst switch: {dst_sw}')
    print(f'  Attackers ({n_atk})  : '
          + '  '.join(f'{h}({ip})→{attacker_ip_to_sw[ip]}'
                      for h, ip in attacker_hosts.items()))
    print(f'  Normal hosts({n_norm}): '
          + '  '.join(f'{h}({ip})→{normal_ip_to_sw[ip]}'
                      for h, ip in normal_hosts.items()))
    print(f'  SW edges        : '
          + '  '.join(f'{e[0]}-{e[1]}(w={edge_weights[e]})' for e in sw_edges))
    print(f'  Initial path    : {path_str}  (cost: {initial_cost:.2f})')
    print('='*62 + '\n')

    # ── 11. Save to topology_state.json ────────────────────────────────
    state = {
        'switches':       switch_names,
        'src_sw':         src_sw,
        'dst_sw':         dst_sw,
        'host_ips':       config.HOST_IPS,
        'ip_to_switch':   dict(config.IP_TO_SWITCH),
        'sw_edges':       [list(e) for e in sw_edges],
        'edge_weights':   {f'{e[0]}-{e[1]}': w for e, w in edge_weights.items()},
        'attacker_hosts': attacker_hosts,
        'normal_hosts':   normal_hosts,
        'safe_ips':       list(config.SAFE_IPS),
    }
    with open(TOPOLOGY_STATE_FILE, 'w', newline='\n') as f:
        json.dump(state, f, indent=2)
    print(f'[Routing] Topology saved → topology_state.json')

    return G


def _dijkstra_raw(G, source, target):
    """Simple Dijkstra without blocked-IP filtering — used only at startup."""
    try:
        path = nx.shortest_path(G, source, target, weight='weight')
        cost = nx.shortest_path_length(G, source, target, weight='weight')
        return path, cost
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None, float('inf')


# ── Weight management (RL-inspired) ──────────────────────────────────────────

def penalize_node(G, node_name, penalty=None):
    """
    Increase edge weights on all edges touching node_name.
    Called when an attack is detected on that node.
    """
    if node_name not in G.nodes:
        return G

    p = EDGE_PENALTY if penalty is None else penalty
    attack_counts[node_name] = attack_counts.get(node_name, 0) + 1
    total = p * attack_counts[node_name]

    for nb in G.neighbors(node_name):
        old = G[node_name][nb]['weight']
        G[node_name][nb]['weight'] = old + total
        print(f'[Routing] Edge {node_name}↔{nb}: {old:.1f} → {old + total:.1f}')

    return G


def reward_node(G, node_name, reward=None):
    """
    Slowly decrease edge weights on safe nodes (no attack).
    Weight never drops below EDGE_WEIGHT_MIN.
    """
    if node_name not in G.nodes:
        return G

    r = EDGE_REWARD if reward is None else reward
    for nb in G.neighbors(node_name):
        old = G[node_name][nb]['weight']
        G[node_name][nb]['weight'] = max(EDGE_WEIGHT_MIN, old - r)

    return G


# ── Path computation ──────────────────────────────────────────────────────────

def get_safe_path(G, source='h1', target='h2'):
    """
    Dijkstra's algorithm on the weighted graph.
    Blocked IPs' switches are temporarily removed before computing.
    Returns (path_list, cost) or (None, inf).
    """
    import config
    G_temp = G.copy()
    for ip in blocked_ips:
        sw = config.IP_TO_SWITCH.get(ip)
        if sw and sw in G_temp.nodes:
            G_temp.remove_node(sw)

    try:
        path = nx.shortest_path(G_temp, source, target, weight='weight')
        cost = nx.shortest_path_length(G_temp, source, target, weight='weight')
        return path, cost
    except (nx.NetworkXNoPath, nx.NodeNotFound) as e:
        print(f'[Routing] No path available: {e}')
        return None, float('inf')


# ── IP blocking ───────────────────────────────────────────────────────────────

def _iptables_block(ip_address):
    """Drop all traffic from ip_address using iptables (Linux/Mininet only)."""
    try:
        # Check if rule already exists before adding
        ret = os.system(f'sudo iptables -C INPUT -s {ip_address} -j DROP 2>/dev/null')
        if ret != 0:
            os.system(f'sudo iptables -A INPUT -s {ip_address} -j DROP')
            print(f'[Routing] iptables DROP rule added for {ip_address}')
    except Exception as e:
        print(f'[Routing] iptables error: {e}')


def block_ip(ip_address):
    """Block IP: in-memory set + Ryu (if available) + iptables fallback."""
    blocked_ips.add(ip_address)
    print(f'[Routing] Blocked (in-memory): {ip_address}')
    _iptables_block(ip_address)


def unblock_ip(ip_address):
    """Remove IP from block list and remove iptables rule."""
    blocked_ips.discard(ip_address)
    try:
        os.system(f'sudo iptables -D INPUT -s {ip_address} -j DROP 2>/dev/null')
    except Exception:
        pass
    print(f'[Routing] Unblocked: {ip_address}')


# ── Ryu OpenFlow rule pushing ─────────────────────────────────────────────────

def _push_to_ryu(rule):
    """POST a flow rule dict to Ryu REST API. Returns True on success."""
    try:
        r = requests.post(_FLOW_ADD_URL, json=rule, timeout=3)
        return r.status_code == 200
    except requests.exceptions.ConnectionError:
        print('[Routing] Ryu not reachable — rule not pushed.')
        return False


def drop_ip_rule_ryu(dpid, src_ip, priority=200):
    """Push a DROP rule for src_ip on switch dpid."""
    rule = {
        'dpid': dpid, 'priority': priority,
        'match': {'dl_type': 0x0800, 'nw_src': src_ip},
        'actions': [],   # empty = DROP
    }
    ok = _push_to_ryu(rule)
    if ok:
        print(f'[Routing] DROP rule pushed: {src_ip} on switch {dpid}')
    return ok


def push_flow_rule_ryu(dpid, src_ip, dst_ip, out_port, priority=100):
    """Push a forwarding rule to a switch via Ryu."""
    rule = {
        'dpid': dpid, 'priority': priority,
        'match': {'dl_type': 0x0800, 'nw_src': src_ip, 'nw_dst': dst_ip},
        'actions': [{'type': 'OUTPUT', 'port': out_port}],
    }
    ok = _push_to_ryu(rule)
    if ok:
        print(f'[Routing] Flow rule pushed: {src_ip}→{dst_ip} via port {out_port}')
    return ok


# ── Full attack response ──────────────────────────────────────────────────────

def handle_attack(G, attacker_ip, attack_type, confidence):
    """
    Complete response to a confirmed attack:
      1. Block attacker IP
      2. Penalize the attacker's connected switch edges
      3. Recompute safe path (Dijkstra)
      4. Push DROP rule to Ryu
    Returns the new path list.
    """
    import config
    print(f'\n[Routing] Responding to {attack_type} from {attacker_ip} '
          f'(confidence: {confidence:.1f}%)')

    block_ip(attacker_ip)

    # Find which switch the attacker connects to (fully generic — no hardcoded IPs)
    attacker_switch = config.IP_TO_SWITCH.get(attacker_ip)

    # Find the attacker's host node name from HOST_IPS
    attacker_node = next(
        (h for h, ip in config.HOST_IPS.items() if ip == attacker_ip), None
    )

    if attacker_node and attacker_switch and G.has_edge(attacker_node, attacker_switch):
        # Penalize only the direct host↔switch edge
        old = G[attacker_node][attacker_switch]['weight']
        G[attacker_node][attacker_switch]['weight'] = old + EDGE_PENALTY
        print(f'[Routing] Edge {attacker_node}↔{attacker_switch}: '
              f'{old:.1f} → {old + EDGE_PENALTY:.1f}')
    elif attacker_switch:
        penalize_node(G, attacker_switch)

    new_path, cost = get_safe_path(G, 'h1', 'h2')
    if new_path:
        print(f'[Routing] New safe path: {" → ".join(new_path)} (cost: {cost:.1f})')
        # Push DROP rule to the switch the attacker is connected to
        sw_dpid = config.DPID.get(attacker_switch, 1) if attacker_switch else 1
        drop_ip_rule_ryu(sw_dpid, attacker_ip)
    else:
        print('[Routing] WARNING: No alternate path found!')

    return new_path


# ── Network status (for dashboard) ───────────────────────────────────────────

def get_network_status(G):
    """Return current graph state as a dict."""
    path, cost = get_safe_path(G)
    return {
        'nodes':         list(G.nodes()),
        'edges':         [{'src': u, 'dst': v, 'weight': round(G[u][v]['weight'], 2)}
                          for u, v in G.edges()],
        'blocked_ips':   list(blocked_ips),
        'active_path':   path,
        'path_cost':     round(cost, 2) if cost != float('inf') else 'N/A',
        'attack_counts': dict(attack_counts),
    }


# ── State persistence ─────────────────────────────────────────────────────────

def save_routing_state(G):
    """Save edge weights, blocked IPs, and attack counts to disk."""
    state = {
        'edge_weights':  {f'{u}-{v}': G[u][v]['weight'] for u, v in G.edges()},
        'blocked_ips':   list(blocked_ips),
        'attack_counts': attack_counts,
    }
    with open(ROUTING_STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)


def load_routing_state(G):
    """Restore edge weights, blocked IPs, and attack counts from disk."""
    if not os.path.exists(ROUTING_STATE_FILE):
        return G

    with open(ROUTING_STATE_FILE, 'r') as f:
        state = json.load(f)

    for key, weight in state.get('edge_weights', {}).items():
        # key format: "nodeA-nodeB" — split on first dash only
        parts = key.split('-', 1)
        if len(parts) == 2:
            u, v = parts
            if G.has_edge(u, v):
                G[u][v]['weight'] = weight

    for ip in state.get('blocked_ips', []):
        blocked_ips.add(ip)

    attack_counts.update(state.get('attack_counts', {}))
    print('[Routing] Previous state restored from disk.')
    return G
