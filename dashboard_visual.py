"""
dashboard_visual.py — Visual Network Simulation Dashboard
===========================================================
Real-time animated network topology at http://127.0.0.1:8051

Shows:
  - Network nodes with icons (laptop / server / attacker / switch)
  - Animated packet dots moving along the active path
  - Attack detection: h3 + affected switch turn red
  - Path reroute animation: blue = new safe path
  - Live alert feed + session stats

Run standalone:
    python3 dashboard_visual.py

Started automatically by main.py when --visual flag is passed:
    sudo python3 main.py --no-ryu --fresh --visual
"""

import time
import threading

try:
    import dash
    from dash import dcc, html
    from dash.dependencies import Input, Output
    import dash_cytoscape as cyto
    try:
        cyto.load_extra_layouts()
    except Exception:
        pass   # extra layouts optional
    DASH_AVAILABLE = True
except ImportError as e:
    DASH_AVAILABLE = False
    print(f'[Visual] Import error: {e}')
    print('[Visual] Install: pip install dash dash-cytoscape plotly')

from config import DASHBOARD_PORT, ALERTS_LOG
import os

# ── Shared state (written by main.py via update_visual_state()) ───────────────
_vstate = {
    'active_path':   ['h1', 's1', 's2', 'h2'],
    'blocked_ips':   set(),
    'blocked_switches': set(),
    'attack_type':   None,
    'attack_src':    None,
    'confidence':    0,
    'method':        None,
    'is_attacking':  False,
    'flows':         0,
    'attacks':       0,
    'blocked_count': 0,
    'reroutes':      0,
    'packet_pos':    0,   # 0-3 index along active_path for dot animation
}

_vstate_lock = threading.Lock()


def update_visual_state(active_path, blocked_ips, blocked_switches=None, event=None, stats=None):
    """Called from main.py after every detection event."""
    with _vstate_lock:
        _vstate['active_path'] = active_path or ['h1', 's1', 's2', 'h2']
        _vstate['blocked_ips'] = blocked_ips or set()
        _vstate['blocked_switches'] = blocked_switches or set()
        if event:
            _vstate['is_attacking']  = event.get('is_attack', False)
            _vstate['attack_type']   = event.get('attack_type')
            _vstate['attack_src']    = event.get('src_ip')
            _vstate['confidence']    = event.get('confidence', 0)
            _vstate['method']        = event.get('method')
        if stats:
            _vstate['flows']         = stats.get('total_flows', 0)
            _vstate['attacks']       = stats.get('attacks_detected', 0)
            _vstate['blocked_count'] = stats.get('ips_blocked', 0)
            _vstate['reroutes']      = stats.get('reroutes', 0)


# ── Dynamic node positions loaded from topology_state.json ───────────────────
import json as _json
import math as _math

_TOPO_FILE_V = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'topology_state.json')


def _load_visual_topology():
    """Load topology_state.json and compute positions + edges dynamically."""
    if not os.path.exists(_TOPO_FILE_V):
        # fallback defaults
        positions = {
            'h1': {'x': 50,  'y': 200}, 's1': {'x': 250, 'y': 200},
            's2': {'x': 450, 'y': 200}, 'h2': {'x': 650, 'y': 200},
            's3': {'x': 350, 'y': 380}, 'h3': {'x': 50,  'y': 380},
        }
        edges = [('h1','s1'),('s1','s2'),('s2','h2'),('s1','s3'),('s3','h2'),('h3','s1')]
        labels = {n: n for n in positions}
        return positions, edges, labels

    with open(_TOPO_FILE_V, 'r') as f:
        topo = _json.load(f)

    switches  = topo.get('switches', [])
    host_ips  = topo.get('host_ips', {})
    sw_edges  = [tuple(e) for e in topo.get('sw_edges', [])]
    ip_to_sw  = topo.get('ip_to_switch', {})

    attackers = [h for h, ip in host_ips.items()
                 if h not in ('h1', 'h2') and ip.startswith('10.0.0.')]
    normals   = [h for h, ip in host_ips.items()
                 if h not in ('h1', 'h2') and ip.startswith('10.0.1.')]

    positions = {}
    positions['h1'] = {'x': 50,  'y': 200}
    positions['h2'] = {'x': 750, 'y': 200}

    # Switches: spread horizontally, split into 2 rows if > 4
    n_sw = len(switches)
    if n_sw <= 4:
        rows = [switches]
    else:
        mid = _math.ceil(n_sw / 2)
        rows = [switches[:mid], switches[mid:]]
    row_ys = [200, 380] if len(rows) == 2 else [200]
    for ri, row in enumerate(rows):
        y = row_ys[ri]
        xs = 180
        xe = 620
        step = (xe - xs) / max(len(row) - 1, 1) if len(row) > 1 else 0
        for ji, sw in enumerate(row):
            x = xs + ji * step if len(row) > 1 else (xs + xe) // 2
            positions[sw] = {'x': int(x), 'y': y}

    # Attackers: bottom-left
    for i, h in enumerate(sorted(attackers)):
        positions[h] = {'x': 50, 'y': 380 + i * 80}

    # Normal observers: bottom-right
    for i, h in enumerate(sorted(normals)):
        positions[h] = {'x': 750, 'y': 380 + i * 80}

    # Edges: host↔switch + switch↔switch
    edges = []
    for h, ip in host_ips.items():
        sw = ip_to_sw.get(ip)
        if sw and h in positions and sw in positions:
            edges.append((h, sw))
    for e in sw_edges:
        u, v = e[0], e[1]
        if (u, v) not in edges and (v, u) not in edges:
            edges.append((u, v))

    # Labels
    labels = {}
    labels['h1'] = '💻 h1\n(User)'
    labels['h2'] = '🖥️ h2\n(Server)'
    for h in attackers:
        labels[h] = f'💀 {h}\n(Attacker)'
    for h in normals:
        labels[h] = f'💻 {h}\n(Observer)'
    for sw in switches:
        labels[sw] = f'🔲 {sw}'

    return positions, edges, labels


_NODE_POSITIONS, _EDGES, _NODE_LABELS = _load_visual_topology()


def _build_elements(active_path, blocked_ips, blocked_switches, is_attacking, attack_src, packet_pos):
    """Build Cytoscape elements list with current state colors."""
    # Reload topology each call so it reflects the current run
    node_positions, edges, node_labels = _load_visual_topology()

    elements = []
    blocked_ips = blocked_ips or set()
    blocked_switches = blocked_switches or set()
    active_path = active_path or []

    # IP → node name map (built from live HOST_IPS)
    from config import HOST_IPS as _HOST_IPS
    ip_to_node = {ip: h for h, ip in _HOST_IPS.items()}
    blocked_nodes = {ip_to_node.get(ip, ip) for ip in blocked_ips} | set(blocked_switches)

    # ── Nodes ─────────────────────────────────────────────────────────────────
    for node, pos in node_positions.items():
        if node in blocked_nodes:
            color = '#e53935'
            border = '#b71c1c'
            shape  = 'octagon'
        elif node == attack_src or (is_attacking and node in blocked_nodes):
            color = '#ff7043'
            border = '#e53935'
            shape  = 'octagon'
        elif node in active_path:
            color = '#43a047'
            border = '#1b5e20'
            shape  = 'ellipse' if node.startswith('h') else 'rectangle'
        elif node.startswith('s'):
            color = '#78909c'
            border = '#455a64'
            shape  = 'rectangle'
        else:
            color = '#1e88e5'
            border = '#0d47a1'
            shape  = 'ellipse'

        elements.append({
            'data': {
                'id':    node,
                'label': node_labels.get(node, node),
            },
            'position': pos,
            'classes': node,
            'style': {
                'background-color': color,
                'border-color':     border,
                'border-width':     3,
                'shape':            shape,
                'width':            70,
                'height':           70,
                'font-size':        11,
                'color':            'white',
                'text-wrap':        'wrap',
                'text-valign':      'center',
                'text-halign':      'center',
                'font-weight':      'bold',
            }
        })

    # ── Edges ─────────────────────────────────────────────────────────────────
    active_edges = set()
    for i in range(len(active_path) - 1):
        a, b = active_path[i], active_path[i + 1]
        active_edges.add((a, b))
        active_edges.add((b, a))

    for u, v in edges:
        on_path  = (u, v) in active_edges
        is_block = u in blocked_nodes or v in blocked_nodes

        if is_block:
            color = '#e53935'; width = 2; style = 'dashed'
        elif on_path:
            color = '#00e676'; width = 5; style = 'solid'
        else:
            color = '#546e7a'; width = 2; style = 'solid'

        elements.append({
            'data': {'source': u, 'target': v, 'id': f'{u}-{v}'},
            'style': {
                'line-color':         color,
                'width':              width,
                'line-style':         style,
                'target-arrow-color': color,
                'target-arrow-shape': 'triangle',
                'curve-style':        'bezier',
            }
        })

    # ── Animated packet dot along active path ─────────────────────────────────
    if len(active_path) >= 2 and not blocked_nodes:
        idx = packet_pos % (len(active_path) - 1)
        src = active_path[idx]
        dst = active_path[idx + 1]
        if src in node_positions and dst in node_positions:
            sx, sy = node_positions[src]['x'], node_positions[src]['y']
            dx, dy = node_positions[dst]['x'], node_positions[dst]['y']
            elements.append({
                'data': {'id': 'packet_dot', 'label': '●'},
                'position': {'x': (sx + dx) / 2, 'y': (sy + dy) / 2},
                'style': {
                    'background-color': '#ffeb3b',
                    'width':  18, 'height': 18,
                    'shape':  'ellipse',
                    'color':  '#ffeb3b',
                    'font-size': 10,
                    'border-width': 0,
                    'z-index': 999,
                }
            })

    return elements


# ── Dash app ──────────────────────────────────────────────────────────────────

def _create_app():
    app = dash.Dash(__name__, title='AI Self-Healing Network — Visual')

    app.layout = html.Div(
        style={
            'backgroundColor': '#0a0a1a',
            'minHeight': '100vh',
            'padding': '16px',
            'fontFamily': 'monospace',
        },
        children=[
            # Title
            html.H2(
                '🛡️ AI Self-Healing Network — Live Simulation',
                style={'color': '#00e5ff', 'textAlign': 'center', 'margin': '0 0 12px 0'}
            ),

            # Stats row
            html.Div(
                style={'display': 'flex', 'gap': '10px', 'marginBottom': '12px'},
                children=[
                    html.Div(id='v-flows',   style=_stat_card('#00e5ff')),
                    html.Div(id='v-attacks', style=_stat_card('#ef5350')),
                    html.Div(id='v-blocked', style=_stat_card('#ff7043')),
                    html.Div(id='v-reroutes',style=_stat_card('#66bb6a')),
                ]
            ),

            # Attack alert banner
            html.Div(id='v-alert-banner', style={'marginBottom': '10px'}),

            # Main layout: graph left, alerts right
            html.Div(
                style={'display': 'flex', 'gap': '12px'},
                children=[
                    # Network graph
                    html.Div(
                        style={
                            'flex': 2,
                            'background': '#0d1117',
                            'borderRadius': '10px',
                            'border': '1px solid #1e3a5f',
                            'padding': '10px',
                        },
                        children=[
                            html.P(
                                '🟢 Green = Active Path  |  🔴 Red = Blocked  |  🟡 Yellow = Packet  |  ⬜ Gray = Idle',
                                style={'color': '#607d8b', 'fontSize': '11px', 'margin': '0 0 8px 0'}
                            ),
                            cyto.Cytoscape(
                                id='cyto-graph',
                                layout={'name': 'preset'},
                                style={'width': '100%', 'height': '420px'},
                                elements=[],
                                userZoomingEnabled=False,
                                userPanningEnabled=False,
                                stylesheet=[
                                    {
                                        'selector': 'node',
                                        'style': {
                                            'label': 'data(label)',
                                            'text-wrap': 'wrap',
                                            'text-valign': 'center',
                                            'text-halign': 'center',
                                            'color': 'white',
                                            'font-size': '11px',
                                            'font-weight': 'bold',
                                        }
                                    },
                                    {
                                        'selector': 'edge',
                                        'style': {
                                            'curve-style': 'bezier',
                                            'target-arrow-shape': 'triangle',
                                        }
                                    }
                                ],
                            ),
                            # Path display
                            html.Div(id='v-path-display', style={
                                'color': '#00e676', 'fontSize': '13px',
                                'textAlign': 'center', 'marginTop': '8px',
                                'fontWeight': 'bold',
                            }),
                        ]
                    ),

                    # Right panel: detection info + alerts
                    html.Div(
                        style={'flex': 1, 'display': 'flex', 'flexDirection': 'column', 'gap': '10px'},
                        children=[
                            # Detection info box
                            html.Div(
                                id='v-detection-box',
                                style={
                                    'background': '#0d1117',
                                    'borderRadius': '10px',
                                    'border': '1px solid #1e3a5f',
                                    'padding': '14px',
                                    'minHeight': '140px',
                                }
                            ),
                            # Recent alerts
                            html.Div(
                                style={
                                    'background': '#0d1117',
                                    'borderRadius': '10px',
                                    'border': '1px solid #1e3a5f',
                                    'padding': '14px',
                                    'flex': 1,
                                },
                                children=[
                                    html.P('📋 Recent Alerts', style={
                                        'color': '#ef5350', 'margin': '0 0 8px 0',
                                        'fontWeight': 'bold', 'fontSize': '13px'
                                    }),
                                    html.Div(id='v-alerts', style={
                                        'fontSize': '11px', 'color': '#b0bec5',
                                        'overflowY': 'auto', 'maxHeight': '240px',
                                    }),
                                ]
                            ),
                        ]
                    ),
                ]
            ),
            dcc.Interval(id='v-refresh', interval=500, n_intervals=0),
        ]
    )

    @app.callback(
        [
            Output('cyto-graph',      'elements'),
            Output('v-alert-banner',  'children'),
            Output('v-detection-box', 'children'),
            Output('v-path-display',  'children'),
            Output('v-alerts',        'children'),
            Output('v-flows',         'children'),
            Output('v-attacks',       'children'),
            Output('v-blocked',       'children'),
            Output('v-reroutes',      'children'),
        ],
        [Input('v-refresh', 'n_intervals')]
    )
    def _refresh(n):
        with _vstate_lock:
            state = dict(_vstate)
            # Advance packet dot position each tick
            _vstate['packet_pos'] = (state['packet_pos'] + 1) % max(1, len(state['active_path']) - 1)

        elements = _build_elements(
            state['active_path'],
            state['blocked_ips'],
            state.get('blocked_switches', set()),
            state['is_attacking'],
            state['attack_src'],
            state['packet_pos'],
        )

        # Alert banner
        if state['is_attacking'] and state['attack_src']:
            banner = html.Div(
                f"🚨 ATTACK DETECTED — {state['attack_type']} from {state['attack_src']} "
                f"| Confidence: {state['confidence']:.1f}% | Method: {state['method']}",
                style={
                    'background': '#b71c1c', 'color': 'white',
                    'padding': '10px 16px', 'borderRadius': '8px',
                    'fontWeight': 'bold', 'fontSize': '13px',
                    'textAlign': 'center', 'animation': 'pulse 1s infinite',
                }
            )
        else:
            banner = html.Div(
                '✅ Network Normal — Monitoring Traffic',
                style={
                    'background': '#1b5e20', 'color': '#a5d6a7',
                    'padding': '8px 16px', 'borderRadius': '8px',
                    'fontSize': '12px', 'textAlign': 'center',
                }
            )

        # Detection info box
        if state['is_attacking']:
            det_box = html.Div([
                html.P('🔴 ATTACK IN PROGRESS', style={'color': '#ef5350', 'fontWeight': 'bold', 'margin': '0 0 8px 0'}),
                _info_row('Type',       state['attack_type'] or '—'),
                _info_row('Source IP',  state['attack_src']  or '—'),
                _info_row('Confidence', f"{state['confidence']:.1f}%"),
                _info_row('Method',     state['method']      or '—'),
                _info_row('Blocked IPs', str(len(state['blocked_ips']))),
            ])
        else:
            det_box = html.Div([
                html.P('🟢 System Status: NORMAL', style={'color': '#66bb6a', 'fontWeight': 'bold', 'margin': '0 0 8px 0'}),
                _info_row('Monitoring', 'Active'),
                _info_row('Interface',  's1-eth2'),
                _info_row('Window',     '2.0s'),
                _info_row('Detection',  'Signature + ML + Anomaly'),
            ])

        # Active path display
        path_str = ' → '.join(state['active_path']) if state['active_path'] else 'Computing...'
        path_display = f'Active Path: {path_str}'

        # Recent alerts from file
        alerts = []
        if os.path.exists(ALERTS_LOG):
            with open(ALERTS_LOG, 'r') as f:
                lines = f.readlines()[-12:]
            for line in reversed(lines):
                color = '#ef5350' if '⚠' in line else '#b0bec5'
                alerts.append(html.P(
                    line.strip(),
                    style={'margin': '2px 0', 'color': color,
                           'borderBottom': '1px solid #1e3a5f', 'paddingBottom': '2px'}
                ))
        if not alerts:
            alerts = [html.P('No alerts yet.', style={'color': '#546e7a'})]

        def _stat(val, label, color):
            return html.Div([
                html.H3(str(val), style={'margin': 0, 'color': color}),
                html.P(label, style={'margin': 0, 'fontSize': '11px', 'color': '#90a4ae'}),
            ], style={'textAlign': 'center'})

        return (
            elements,
            banner,
            det_box,
            path_display,
            alerts,
            _stat(state['flows'],         'Flows Analyzed',   '#00e5ff'),
            _stat(state['attacks'],        'Attacks Detected', '#ef5350'),
            _stat(state['blocked_count'],  'IPs Blocked',      '#ff7043'),
            _stat(state['reroutes'],       'Path Reroutes',    '#66bb6a'),
        )

    return app


def _stat_card(color):
    return {
        'flex': 1, 'background': '#0d1117', 'padding': '12px',
        'borderRadius': '8px', 'border': f'1px solid {color}33',
        'textAlign': 'center',
    }


def _info_row(label, value):
    return html.Div([
        html.Span(f'{label}: ', style={'color': '#607d8b', 'fontSize': '12px'}),
        html.Span(str(value),   style={'color': '#e0e0e0', 'fontSize': '12px', 'fontWeight': 'bold'}),
    ], style={'marginBottom': '4px'})


def run_visual_dashboard(host='0.0.0.0', port=8051, debug=False):
    """Start the visual dashboard server."""
    if not DASH_AVAILABLE:
        print('[Visual] Install with: pip install dash dash-cytoscape')
        return
    app = _create_app()
    print(f'[Visual] Starting at http://127.0.0.1:{port}')
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_visual_dashboard(debug=True)
