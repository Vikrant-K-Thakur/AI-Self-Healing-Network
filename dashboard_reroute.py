"""
Advanced reroute dashboard that guarantees packets never traverse blocked switches.
Runs on http://127.0.0.1:8053
"""

import math

import networkx as nx

from config import DASHBOARD_HOST, SENDER_HOST, RECEIVER_HOST

try:
    import dash
    from dash import dcc, html
    from dash.dependencies import Input, Output
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False

_state = {
    'G': None,
    'active_path': [],
    'blocked_ips': set(),
    'blocked_switches': set(),
    'event': None,
    'tick': 0,
}


def init_state(G, active_path):
    _state['G'] = G
    _state['active_path'] = active_path or []


def update_state(G, active_path, blocked_ips, blocked_switches=None, event=None):
    _state['G'] = G
    _state['active_path'] = active_path or []
    _state['blocked_ips'] = blocked_ips or set()
    _state['blocked_switches'] = blocked_switches or set()
    _state['event'] = event


def _compute_safe_path():
    G = _state['G']
    if G is None:
        return []

    G_temp = G.copy()

    # Hard remove blocked switches so route and packet can never pass through them.
    for sw in _state['blocked_switches']:
        if sw in G_temp.nodes:
            G_temp.remove_node(sw)

    try:
        return nx.shortest_path(G_temp, SENDER_HOST, RECEIVER_HOST, weight='weight')
    except Exception:
        return []


def _compute_positions(G):
    pos = {}
    if G is None:
        return pos

    # Hosts on far left and far right - more compact
    pos['h1'] = (120, 280)
    pos['h2'] = (1080, 280)

    switches = sorted([n for n in G.nodes() if n.startswith('s')])
    attackers = sorted([n for n in G.nodes() if n.startswith('h') and n not in ('h1', 'h2')])

    # Distribute switches in 2 rows - more compact spacing
    n_sw = len(switches)
    if n_sw <= 3:
        rows = [switches]
        row_ys = [280]
    else:
        mid = math.ceil(n_sw / 2)
        rows = [switches[:mid], switches[mid:]]
        row_ys = [180, 380]
    
    for ridx, row in enumerate(rows):
        if not row:
            continue
        # Tighter horizontal space for switches
        xs, xe = 380, 820
        if len(row) == 1:
            x_positions = [(xs + xe) / 2]
        else:
            step = (xe - xs) / (len(row) - 1)
            x_positions = [xs + i * step for i in range(len(row))]
        
        for i, sw in enumerate(row):
            pos[sw] = (int(x_positions[i]), row_ys[ridx])

    # Attacker hosts on the right side - more compact
    for i, h in enumerate(attackers):
        pos[h] = (1080, 450 + i * 60)

    return pos


def _build_svg(tick):
    G = _state['G']
    if G is None:
        return '<svg width="100%" viewBox="0 0 1200 750"><text x="600" y="375" text-anchor="middle" fill="#8b949e" font-size="16">Waiting for topology...</text></svg>', []

    safe_path = _compute_safe_path()
    pos = _compute_positions(G)

    active_edges = set()
    for i in range(len(safe_path) - 1):
        a, b = safe_path[i], safe_path[i + 1]
        active_edges.add((a, b))
        active_edges.add((b, a))

    blocked_switches = set(_state['blocked_switches'])

    p = []
    
    # Defs and styles
    p.append('<defs>'
             '<style>'
             'body{background:#0d1117}'
             '@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}'
             '@keyframes glow{0%,100%{filter:drop-shadow(0 0 3px #42a5f5)}50%{filter:drop-shadow(0 0 8px #42a5f5)}}'
             '.pulse{animation:pulse .8s ease-in-out infinite}'
             '.glow{animation:glow 1.5s ease-in-out infinite}'
             '</style>'
             '</defs>')

    # Legend with better spacing - smaller
    p.append('<g transform="translate(40, 25)">')
    p.append('<circle cx="0" cy="0" r="5" fill="#4caf50"/><text x="10" y="4" fill="#c9d1d9" font-size="12" font-family="system-ui">Safe route</text>')
    p.append('<circle cx="110" cy="0" r="5" fill="#ef5350"/><text x="120" y="4" fill="#c9d1d9" font-size="12" font-family="system-ui">Blocked switch</text>')
    p.append('<circle cx="250" cy="0" r="5" fill="#42a5f5"/><text x="260" y="4" fill="#c9d1d9" font-size="12" font-family="system-ui">Packet</text>')
    p.append('</g>')

    # Draw edges
    for u, v in G.edges():
        if u not in pos or v not in pos:
            continue
        x1, y1 = pos[u]
        x2, y2 = pos[v]
        on_path = (u, v) in active_edges
        blocked_edge = u in blocked_switches or v in blocked_switches

        if blocked_edge:
            color, width, dash = '#ef5350', 2.5, '8 5'
        elif on_path:
            color, width, dash = '#42a5f5', 4, ''
        else:
            color, width, dash = '#30363d', 2, '6 4'

        dashed = f' stroke-dasharray="{dash}"' if dash else ''
        p.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="{color}" stroke-width="{width}"{dashed} '
            f'stroke-linecap="round" opacity="0.95"/>'
        )

    # Draw nodes
    for n, (x, y) in pos.items():
        is_switch = n.startswith('s')
        is_blocked = n in blocked_switches
        on_path = n in safe_path

        if is_blocked:
            fill, stroke, text, glow_class = '#fbe9e7', '#ef5350', '#d32f2f', ' class="pulse"'
        elif on_path:
            fill, stroke, text, glow_class = '#e3f2fd', '#42a5f5', '#1976d2', ' class="glow"'
        elif is_switch:
            fill, stroke, text, glow_class = '#1c2128', '#30363d', '#8b949e', ''
        else:
            fill, stroke, text, glow_class = '#e8f5e9', '#66bb6a', '#2e7d32', ''

        if is_switch:
            # Switch: smaller rounded rectangle with inner detail
            p.append(f'<rect x="{x-35}" y="{y-26}" width="70" height="52" rx="10" fill="{fill}" stroke="{stroke}" stroke-width="2.5"{glow_class}/>')
            p.append(f'<rect x="{x-28}" y="{y-18}" width="56" height="36" rx="5" fill="{stroke}" opacity="0.3"/>')
            # Port indicators
            for i in range(4):
                px = x - 20 + i * 13
                p.append(f'<circle cx="{px}" cy="{y+16}" r="2.5" fill="{stroke}" opacity="0.6"/>')
        else:
            # Host: smaller rounded rectangle with icon-like appearance
            p.append(f'<rect x="{x-40}" y="{y-30}" width="80" height="60" rx="12" fill="{fill}" stroke="{stroke}" stroke-width="2.5"{glow_class}/>')
            # Inner screen
            p.append(f'<rect x="{x-30}" y="{y-20}" width="60" height="36" rx="5" fill="{stroke}" opacity="0.25"/>')
            # Screen highlight
            p.append(f'<rect x="{x-28}" y="{y-18}" width="56" height="16" rx="3" fill="white" opacity="0.15"/>')

        # Label - smaller font
        font_weight = 'bold' if on_path else 'normal'
        p.append(f'<text x="{x}" y="{y+45}" text-anchor="middle" fill="{text}" font-size="15" font-weight="{font_weight}" font-family="system-ui, monospace">{n}</text>')

    # Animated packet - smaller
    if len(safe_path) >= 2:
        seg = tick % (len(safe_path) - 1)
        progress = 0.5  # Middle of segment
        u, v = safe_path[seg], safe_path[seg + 1]
        if u in pos and v in pos:
            x1, y1 = pos[u]
            x2, y2 = pos[v]
            px = int(x1 + (x2 - x1) * progress)
            py = int(y1 + (y2 - y1) * progress)
            # Glowing packet
            p.append(f'<circle cx="{px}" cy="{py}" r="8" fill="#42a5f5" opacity="0.3"/>')
            p.append(f'<circle cx="{px}" cy="{py}" r="6" fill="#42a5f5" class="glow"/>')

    # Status messages at bottom - smaller font
    if blocked_switches:
        sw = ', '.join(sorted(blocked_switches))
        p.append(f'<text x="600" y="720" text-anchor="middle" fill="#ef5350" font-size="13" font-family="system-ui">⚠ Blocked: {sw} — Traffic automatically rerouted</text>')

    if not safe_path:
        p.append('<text x="600" y="700" text-anchor="middle" fill="#ef5350" font-size="14" font-weight="bold" font-family="system-ui">❌ No safe path available</text>')

    return '<svg width="100%" viewBox="0 0 1200 750" style="background:#0d1117">' + ''.join(p) + '</svg>', safe_path


def _create_app():
    app = dash.Dash(__name__, title='Advanced Reroute Simulator')

    app.layout = html.Div(
        style={'background': '#0d1117', 'minHeight': '100vh', 'padding': '24px', 'color': '#e6edf3', 'fontFamily': 'system-ui, -apple-system, sans-serif'},
        children=[
            html.Div(style={'maxWidth': '1400px', 'margin': '0 auto'}, children=[
                html.H1(' Advanced Reroute Simulator', style={'margin': '0 0 8px 0', 'fontSize': '28px', 'fontWeight': '600', 'color': '#58a6ff'}),
                html.P('Packets are always recomputed on safe path and never traverse blocked switches.', 
                       style={'color': '#8b949e', 'marginBottom': '20px', 'fontSize': '15px'}),
                
                # Stats row
                html.Div(id='stats-row', style={'display': 'flex', 'gap': '12px', 'marginBottom': '16px'}, children=[
                    html.Div(id='stat-flows', style={'flex': 1, 'background': '#161b22', 'padding': '16px', 'borderRadius': '8px', 'border': '1px solid #30363d', 'textAlign': 'center'}),
                    html.Div(id='stat-attacks', style={'flex': 1, 'background': '#161b22', 'padding': '16px', 'borderRadius': '8px', 'border': '1px solid #30363d', 'textAlign': 'center'}),
                    html.Div(id='stat-blocked', style={'flex': 1, 'background': '#161b22', 'padding': '16px', 'borderRadius': '8px', 'border': '1px solid #30363d', 'textAlign': 'center'}),
                    html.Div(id='stat-reroutes', style={'flex': 1, 'background': '#161b22', 'padding': '16px', 'borderRadius': '8px', 'border': '1px solid #30363d', 'textAlign': 'center'}),
                ]),
                
                # Alert banner
                html.Div(id='alert-banner', style={'marginBottom': '16px'}),
                
                html.Div(id='path-label', style={'marginBottom': '16px', 'fontSize': '16px', 'color': '#42a5f5', 'fontWeight': '500', 'padding': '12px 16px', 'background': '#161b22', 'borderRadius': '8px', 'border': '1px solid #30363d'}),
                html.Div(style={'background': '#161b22', 'border': '1px solid #30363d', 'borderRadius': '12px', 'padding': '16px', 'minHeight': '800px', 'overflow': 'hidden'}, children=[
                    html.Div(id='svg-container', style={'width': '100%', 'height': '100%'})
                ]),
            ]),
            dcc.Store(id='svg-store', data=''),
            dcc.Store(id='stats-store', data={}),
            dcc.Interval(id='tick', interval=800, n_intervals=0),
        ],
    )

    # Clientside callback to inject SVG directly into DOM
    app.clientside_callback(
        '''
        function(svg_html) {
            var el = document.getElementById('svg-container');
            if (el && svg_html) { 
                el.innerHTML = svg_html;
                el.style.overflow = 'hidden';
            }
            return window.dash_clientside.no_update;
        }
        ''',
        Output('svg-container', 'children'),
        Input('svg-store', 'data'),
    )

    @app.callback(
        [Output('svg-store', 'data'), Output('path-label', 'children'), 
         Output('stats-store', 'data'), Output('alert-banner', 'children'),
         Output('stat-flows', 'children'), Output('stat-attacks', 'children'),
         Output('stat-blocked', 'children'), Output('stat-reroutes', 'children')],
        [Input('tick', 'n_intervals')],
    )
    def _refresh(tick):
        from logger import stats as lstats
        
        svg, safe_path = _build_svg(tick)
        path_txt = ' → '.join(safe_path) if safe_path else 'No safe path'
        
        # Get current stats
        flows = lstats.get('total_flows', 0)
        attacks = lstats.get('attacks_detected', 0)
        blocked = lstats.get('ips_blocked', 0)
        reroutes = lstats.get('reroutes', 0)
        
        # Check if there's an active attack
        blocked_switches = _state.get('blocked_switches', set())
        event = _state.get('event')
        is_attacking = event and event.get('is_attack') and event.get('action') in ('BLOCK', 'REROUTE')
        
        # Alert banner
        if is_attacking and event:
            attack_type = event.get('attack_type', 'Unknown')
            src_ip = event.get('src_ip', '?')
            confidence = event.get('confidence', 0)
            method = event.get('method', '?')
            banner = html.Div(
                f"🚨 ATTACK DETECTED — {attack_type} from {src_ip} | Confidence: {confidence:.1f}% | Method: {method}",
                style={
                    'background': '#b71c1c', 'color': 'white',
                    'padding': '12px 16px', 'borderRadius': '8px',
                    'fontWeight': '600', 'fontSize': '14px',
                    'textAlign': 'center', 'border': '1px solid #d32f2f'
                }
            )
        elif blocked_switches:
            banner = html.Div(
                f"✅ Traffic Rerouted — Blocked switches: {', '.join(sorted(blocked_switches))}",
                style={
                    'background': '#1b5e20', 'color': '#a5d6a7',
                    'padding': '10px 16px', 'borderRadius': '8px',
                    'fontSize': '13px', 'textAlign': 'center', 'border': '1px solid #2e7d32'
                }
            )
        else:
            banner = html.Div(
                '✅ Network Normal — Monitoring Traffic',
                style={
                    'background': '#1b5e20', 'color': '#a5d6a7',
                    'padding': '10px 16px', 'borderRadius': '8px',
                    'fontSize': '13px', 'textAlign': 'center', 'border': '1px solid #2e7d32'
                }
            )
        
        # Stat cards
        def _stat_card(value, label, color):
            return html.Div([
                html.Div(str(value), style={'fontSize': '28px', 'fontWeight': '700', 'color': color, 'marginBottom': '4px'}),
                html.Div(label, style={'fontSize': '12px', 'color': '#8b949e', 'textTransform': 'uppercase', 'letterSpacing': '0.5px'}),
            ])
        
        stat_flows_card = _stat_card(flows, 'Flows Analyzed', '#00e5ff')
        stat_attacks_card = _stat_card(attacks, 'Attacks Detected', '#ef5350')
        stat_blocked_card = _stat_card(blocked, 'IPs Blocked', '#ff7043')
        stat_reroutes_card = _stat_card(reroutes, 'Path Reroutes', '#66bb6a')
        
        stats_data = {'flows': flows, 'attacks': attacks, 'blocked': blocked, 'reroutes': reroutes}
        
        return svg, f' Active safe path: {path_txt}', stats_data, banner, stat_flows_card, stat_attacks_card, stat_blocked_card, stat_reroutes_card

    return app


def run_dashboard(host=None, port=8053, debug=False):
    if not DASH_AVAILABLE:
        print('[Reroute Dashboard] Install with: pip install dash')
        return
    app = _create_app()
    h = host or DASHBOARD_HOST
    print(f'[Reroute Dashboard] Starting at http://127.0.0.1:{port}')
    app.run(host=h, port=port, debug=debug)


if __name__ == '__main__':
    run_dashboard(debug=True)
