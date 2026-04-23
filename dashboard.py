"""
dashboard.py — Live Web Dashboard
===================================
Dash 4 compatible. Uses a clientside callback to inject raw SVG
into the topology container (dangerouslySetInnerHTML was removed in Dash 4).
"""

import os
import math
import json

from config import DASHBOARD_HOST, DASHBOARD_PORT, HOST_IPS, IP_TO_SWITCH

try:
    import dash
    from dash import dcc, html, clientside_callback, ClientsideFunction
    from dash.dependencies import Input, Output
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False

# ── Shared state ──────────────────────────────────────────────────────────────
_state = {
    'G':             None,
    'active_path':   [],
    'blocked_ips':   set(),
    'attack_counts': {},
    'recent_events': [],
    'last_event':    None,
}


def init_state(G, active_path):
    _state['G']           = G
    _state['active_path'] = active_path or []


def update_state(G, active_path, blocked_ips, attack_counts, event=None):
    _state['G']             = G
    _state['active_path']   = active_path   or []
    _state['blocked_ips']   = blocked_ips   or set()
    _state['attack_counts'] = attack_counts or {}
    if event:
        _state['recent_events'].append(event)
        _state['recent_events'] = _state['recent_events'][-50:]
        if event.get('is_attack'):
            _state['last_event'] = event


# ── Node layout ───────────────────────────────────────────────────────────────

def _is_attacker(node_name):
    ip = HOST_IPS.get(node_name, '')
    return ip.startswith('10.0.0.') and node_name not in ('h1', 'h2')


def _compute_positions(G):
    if G is None:
        return {}
    pos = {}
    pos['h1'] = (70, 140)
    pos['h2'] = (610, 140)

    switches  = sorted([n for n in G.nodes() if n.startswith('s')])
    attackers = sorted([n for n in G.nodes()
                        if n.startswith('h') and n not in ('h1', 'h2')
                        and _is_attacker(n)])
    normals   = sorted([n for n in G.nodes()
                        if n.startswith('h') and n not in ('h1', 'h2')
                        and not _is_attacker(n)])

    n_sw = len(switches)
    if n_sw > 0:
        rows = [switches] if n_sw <= 4 else [switches[:math.ceil(n_sw/2)], switches[math.ceil(n_sw/2):]]
        row_ys = [130, 230] if len(rows) == 2 else [140]
        for ri, row in enumerate(rows):
            y = row_ys[ri]
            xs, xe = 160, 520
            for j, sw in enumerate(row):
                x = xs + j * (xe - xs) / max(len(row) - 1, 1) if len(row) > 1 else (xs + xe) // 2
                pos[sw] = (int(x), y)

    for i, h in enumerate(attackers):
        pos[h] = (70, 240 + i * 65)
    for i, h in enumerate(normals):
        pos[h] = (610, 240 + i * 65)

    return pos


# ── SVG builder ───────────────────────────────────────────────────────────────

def _build_svg(tick):
    G           = _state['G']
    active_path = _state['active_path'] or []
    blocked_ips = _state['blocked_ips'] or set()
    last_event  = _state['last_event']

    is_blocked   = bool(blocked_ips)
    is_attacking = bool(last_event and last_event.get('is_attack')
                        and last_event.get('action') in ('BLOCK', 'REROUTE'))

    pos = _compute_positions(G)
    if not pos:
        return '<svg width="100%" viewBox="0 0 680 320"><text x="340" y="160" text-anchor="middle" fill="#8b949e" font-size="13" font-family="monospace">Waiting for topology...</text></svg>'

    blocked_switches = {IP_TO_SWITCH.get(ip, '') for ip in blocked_ips}
    active_edges = set()
    for i in range(len(active_path) - 1):
        active_edges.add((active_path[i], active_path[i+1]))
        active_edges.add((active_path[i+1], active_path[i]))

    p = []

    # defs + animations
    p.append('<defs>'
             '<marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">'
             '<path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>'
             '</marker>'
             '<style>'
             '@keyframes pulse-red{0%,100%{opacity:1}50%{opacity:.4}}'
             '@keyframes shake{0%,100%{transform:translate(0,0)}25%{transform:translate(-3px,0)}75%{transform:translate(3px,0)}}'
             '.shake{animation:shake .25s ease-in-out infinite}'
             '.pulse{animation:pulse-red .7s ease-in-out infinite}'
             '</style>'
             '</defs>')

    # legend
    p.append('<circle cx="44" cy="16" r="5" fill="#639922" opacity="0.8"/>'
             '<text x="53" y="20" font-size="10" fill="#8b949e" font-family="monospace">Active path</text>'
             '<circle cx="130" cy="16" r="5" fill="#E24B4A" opacity="0.8"/>'
             '<text x="139" y="20" font-size="10" fill="#8b949e" font-family="monospace">Attacker/blocked</text>'
             '<circle cx="240" cy="16" r="5" fill="#EF9F27" opacity="0.8"/>'
             '<text x="249" y="20" font-size="10" fill="#8b949e" font-family="monospace">Packet</text>'
             '<circle cx="300" cy="16" r="5" fill="#378ADD" opacity="0.8"/>'
             '<text x="309" y="20" font-size="10" fill="#8b949e" font-family="monospace">Rerouted</text>')

    # edges
    if G:
        for u, v in G.edges():
            if u not in pos or v not in pos:
                continue
            x1, y1 = pos[u]
            x2, y2 = pos[v]
            on_path  = (u, v) in active_edges
            blk_edge = u in blocked_switches or v in blocked_switches
            atk_edge = _is_attacker(u) or _is_attacker(v)

            if blk_edge:
                color, width, dash, marker = '#E24B4A', '1.5', '3 4', ''
            elif on_path and is_blocked:
                color, width, dash, marker = '#378ADD', '3', '', 'marker-end="url(#arr)"'
            elif on_path:
                color, width, dash, marker = '#639922', '2.5', '', 'marker-end="url(#arr)"'
            elif atk_edge and is_attacking:
                color, width, dash, marker = '#E24B4A', '2', '', ''
            else:
                color, width, dash, marker = '#30363d', '1.5', '4 3', ''

            da = f'stroke-dasharray="{dash}"' if dash else ''
            p.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                     f'stroke="{color}" stroke-width="{width}" {da} {marker} '
                     f'stroke-linecap="round" opacity="0.9"/>')

    # attack packets
    if is_attacking and last_event:
        src_ip   = last_event.get('src_ip', '')
        atk_node = next((h for h, ip in HOST_IPS.items() if ip == src_ip), None)
        atk_sw   = IP_TO_SWITCH.get(src_ip, '')
        if atk_node and atk_sw and atk_node in pos and atk_sw in pos:
            ax1, ay1 = pos[atk_node]
            ax2, ay2 = pos[atk_sw]
            for offset in (0.0, 0.45):
                t  = (tick * 0.25 + offset) % 1.0
                px = int(ax1 + (ax2 - ax1) * t)
                py = int(ay1 + (ay2 - ay1) * t)
                p.append(f'<circle cx="{px}" cy="{py}" r="5" fill="#E24B4A" opacity="0.9"/>')

    # normal/rerouted packet along active path
    if len(active_path) >= 2:
        coords = [pos[n] for n in active_path if n in pos]
        if len(coords) >= 2:
            n_segs  = len(coords) - 1
            seg     = (tick // 5) % n_segs
            prog    = (tick % 5) / 5.0
            x1, y1  = coords[seg]
            x2, y2  = coords[seg + 1]
            px = int(x1 + (x2 - x1) * prog)
            py = int(y1 + (y2 - y1) * prog)
            color = '#378ADD' if is_blocked else '#EF9F27'
            p.append(f'<circle cx="{px}" cy="{py}" r="6" fill="{color}" opacity="0.95"/>')

    # nodes
    for node, (nx, ny) in pos.items():
        is_blk  = node in blocked_ips or node in blocked_switches
        on_path = node in active_path
        is_sw   = node.startswith('s')
        is_atk  = _is_attacker(node)

        shake = ''
        if is_sw and is_attacking and not is_blocked and last_event:
            if node == IP_TO_SWITCH.get(last_event.get('src_ip', ''), ''):
                shake = ' class="shake"'

        if is_sw:
            _sw(p, node, nx, ny, on_path, is_blk, shake)
        elif node == 'h1':
            _host(p, node, nx, ny, 'user', True, False)
        elif node == 'h2':
            _host(p, node, nx, ny, 'server', True, False)
        elif is_atk:
            _host(p, node, nx, ny, 'attacker', False, is_blk,
                  attacker=True, dim=not (is_attacking or is_blk))
        else:
            _host(p, node, nx, ny, 'observer', on_path, False)

    # alert banner
    if is_attacking and not is_blocked and last_event:
        src  = last_event.get('src_ip', '?')
        atyp = last_event.get('attack_type', '?')
        conf = last_event.get('confidence', 0)
        msg  = f'Attack: {atyp} from {src} — {conf:.1f}% confidence — blocking...'
        svg_h = _svg_height(pos)
        by = svg_h - 30
        p.append(f'<g class="pulse">'
                 f'<rect x="20" y="{by}" width="640" height="22" rx="4" fill="#FCEBEB" stroke="#E24B4A" stroke-width="0.5"/>'
                 f'<text x="340" y="{by+15}" text-anchor="middle" font-size="11" fill="#791F1F" font-family="monospace">{msg}</text>'
                 f'</g>')

    h = _svg_height(pos)
    return f'<svg width="100%" viewBox="0 0 680 {h}" style="display:block">' + ''.join(p) + '</svg>'


def _svg_height(pos):
    if not pos:
        return 320
    return max(320, max(y for _, y in pos.values()) + 90)


def _sw(p, node, nx, ny, on_path, blocked, shake=''):
    if blocked:
        fill, stroke, tf = '#FCEBEB', '#E24B4A', '#791F1F'
    elif on_path:
        fill, stroke, tf = '#E6F1FB', '#378ADD', '#0C447C'
    else:
        fill, stroke, tf = '#1c2128', '#30363d', '#8b949e'
    p.append(f'<g{shake}>'
             f'<rect x="{nx-35}" y="{ny-26}" width="70" height="52" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
             f'<rect x="{nx-27}" y="{ny-18}" width="54" height="26" rx="3" fill="{stroke}" opacity="0.5"/>')
    for i, xo in enumerate([-23, -15, -7, 1, 9, 17]):
        h = 12 if i % 2 == 0 else 16
        p.append(f'<line x1="{nx+xo}" y1="{ny-h//2}" x2="{nx+xo}" y2="{ny+h//2}" stroke="white" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>')
    p.append(f'<text x="{nx}" y="{ny+37}" text-anchor="middle" font-size="11" font-weight="500" fill="{tf}" font-family="monospace">{node}</text>'
             f'</g>')


def _host(p, node, nx, ny, sublabel, on_path, blocked, attacker=False, dim=False):
    if blocked or (attacker and not dim):
        fill, stroke, tf, stf = '#FCEBEB', '#E24B4A', '#791F1F', '#A32D2D'
    elif on_path:
        fill, stroke, tf, stf = '#EAF3DE', '#639922', '#27500A', '#3B6D11'
    else:
        fill, stroke, tf, stf = '#1c2128', '#30363d', '#8b949e', '#6e7681'

    op = '0.15' if dim else '1'
    p.append(f'<g opacity="{op}">'
             f'<rect x="{nx-35}" y="{ny-30}" width="70" height="60" rx="10" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
             f'<rect x="{nx-21}" y="{ny-21}" width="42" height="28" rx="3" fill="{stroke}" opacity="0.6"/>'
             f'<rect x="{nx-17}" y="{ny-17}" width="34" height="20" rx="2" fill="{fill}" opacity="0.9"/>')
    if attacker and not dim:
        p.append(f'<text x="{nx-14}" y="{ny-3}" font-size="16" fill="{stroke}" font-family="monospace">!</text>')
    p.append(f'<text x="{nx}" y="{ny+39}" text-anchor="middle" font-size="11" font-weight="500" fill="{tf}" font-family="monospace">{node}</text>'
             f'<text x="{nx}" y="{ny+51}" text-anchor="middle" font-size="9" fill="{stf}" font-family="monospace">{sublabel}</text>')
    if blocked:
        d = 8
        p.append(f'<line x1="{nx-d}" y1="{ny-d}" x2="{nx+d}" y2="{ny+d}" stroke="#E24B4A" stroke-width="3" stroke-linecap="round"/>'
                 f'<line x1="{nx+d}" y1="{ny-d}" x2="{nx-d}" y2="{ny+d}" stroke="#E24B4A" stroke-width="3" stroke-linecap="round"/>')
    p.append('</g>')


# ── Phase / status helpers ────────────────────────────────────────────────────

def _phase_info():
    blocked_ips = _state['blocked_ips'] or set()
    last_event  = _state['last_event']
    is_blocked   = bool(blocked_ips)
    is_attacking = bool(last_event and last_event.get('is_attack')
                        and last_event.get('action') in ('BLOCK', 'REROUTE'))
    if is_blocked:   return 'Rerouted',    '#378ADD'
    if is_attacking: return 'Under attack', '#E24B4A'
    return 'Normal', '#639922'


def _status_text():
    active_path = _state['active_path'] or []
    blocked_ips = _state['blocked_ips'] or set()
    last_event  = _state['last_event']
    path_str    = ' → '.join(active_path) if active_path else '...'
    if bool(blocked_ips):
        return f'Rerouted — traffic flowing via: {path_str}'
    if bool(last_event and last_event.get('is_attack')
            and last_event.get('action') in ('BLOCK', 'REROUTE')):
        src  = last_event.get('src_ip', '?')
        atyp = last_event.get('attack_type', '?')
        conf = last_event.get('confidence', 0)
        return f'Attack detected — {atyp} from {src} ({conf:.1f}%) — blocking...'
    return f'Normal operation — packets flowing {path_str}'


# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = '''
body { background:#0d1117; color:#e6edf3;
       font-family:ui-monospace,SFMono-Regular,monospace; margin:0; padding:0; }
* { box-sizing:border-box; }
'''

_CARD = {'background':'#161b22','borderRadius':'8px',
         'padding':'10px 12px','border':'0.5px solid #30363d'}


# ── App ───────────────────────────────────────────────────────────────────────

def _create_app():
    app = dash.Dash(__name__, title='Network Topology Simulator')

    app.index_string = (
        '<!DOCTYPE html><html><head>'
        '{%metas%}<title>{%title%}</title>{%favicon%}{%css%}'
        '<style>' + _CSS + '</style>'
        '</head><body>'
        '{%app_entry%}'
        '<footer>{%config%}{%scripts%}{%renderer%}</footer>'
        '</body></html>'
    )

    app.layout = html.Div([

        # hidden store carries SVG string to clientside callback
        dcc.Store(id='svg-store', data=''),

        html.Div(style={'padding':'24px 28px'}, children=[

            # header
            html.Div(style={'display':'flex','alignItems':'center',
                            'justifyContent':'space-between','marginBottom':'12px'},
                     children=[html.Div([
                html.Div('Network Topology Simulator',
                         style={'fontSize':'15px','fontWeight':'500','color':'#e6edf3'}),
                html.Div(id='status-label',
                         style={'fontSize':'12px','color':'#8b949e','marginTop':'2px'}),
            ])]),

            # stats row
            html.Div(style={'display':'flex','gap':'8px','marginBottom':'12px'}, children=[
                html.Div(id='stat-phase',   style={**_CARD,'flex':1}),
                html.Div(id='stat-path',    style={**_CARD,'flex':2}),
                html.Div(id='stat-packets', style={**_CARD,'flex':1}),
            ]),

            # SVG container — innerHTML set by clientside callback
            html.Div(style={'background':'#161b22','borderRadius':'10px',
                            'border':'0.5px solid #30363d','padding':'8px'},
                     children=[html.Div(id='svg-container')]),

            # event log
            html.Div(style={'marginTop':'10px','background':'#161b22',
                            'borderRadius':'8px','border':'0.5px solid #30363d',
                            'padding':'10px 12px','maxHeight':'130px','overflowY':'auto'},
                     children=[
                html.Div('Event log',
                         style={'fontSize':'11px','color':'#8b949e',
                                'marginBottom':'4px','fontWeight':'500'}),
                html.Div(id='log-entries'),
            ]),
        ]),

        dcc.Interval(id='anim-tick', interval=800,  n_intervals=0),
        dcc.Interval(id='data-tick', interval=3000, n_intervals=0),
    ])

    # clientside callback — sets innerHTML directly, bypassing Dash's escaping
    app.clientside_callback(
        '''
        function(svg_html) {
            var el = document.getElementById('svg-container');
            if (el && svg_html) { el.innerHTML = svg_html; }
            return window.dash_clientside.no_update;
        }
        ''',
        Output('svg-container', 'children'),
        Input('svg-store', 'data'),
    )

    # server callback — builds SVG + stats, pushes to store
    @app.callback(
        [Output('svg-store',    'data'),
         Output('status-label', 'children'),
         Output('stat-phase',   'children'),
         Output('stat-path',    'children'),
         Output('stat-packets', 'children')],
        Input('anim-tick', 'n_intervals'),
    )
    def _anim(tick):
        from logger import stats as lstats

        phase, phase_color = _phase_info()
        active_path = _state['active_path'] or []
        path_str    = ' → '.join(active_path) if active_path else '...'
        path_color  = {'Rerouted':'#378ADD','Under attack':'#E24B4A'}.get(phase,'#639922')

        phase_div = html.Div([
            html.Div('Phase',  style={'fontSize':'11px','color':'#8b949e'}),
            html.Div(phase,    style={'fontSize':'14px','fontWeight':'500','color':phase_color}),
        ])
        path_div = html.Div([
            html.Div('Active path', style={'fontSize':'11px','color':'#8b949e'}),
            html.Div(path_str,      style={'fontSize':'13px','fontWeight':'500','color':path_color}),
        ])
        packets_div = html.Div([
            html.Div('Packets sent', style={'fontSize':'11px','color':'#8b949e'}),
            html.Div(str(lstats.get('total_flows', 0)),
                     style={'fontSize':'14px','fontWeight':'500','color':'#e6edf3'}),
        ])

        return _build_svg(tick), _status_text(), phase_div, path_div, packets_div

    # log callback
    @app.callback(
        Output('log-entries', 'children'),
        Input('data-tick', 'n_intervals'),
    )
    def _log(_):
        from logger import get_recent_alerts
        alerts = get_recent_alerts(12)

        def _c(line):
            lo = line.lower()
            if 'block'   in lo: return '#E24B4A'
            if 'reroute' in lo: return '#378ADD'
            if '⚠'       in line: return '#EF9F27'
            return '#8b949e'

        return [html.Div(a.strip(), style={
            'fontSize':'11px','padding':'2px 0',
            'borderBottom':'0.5px solid #30363d','color':_c(a),
        }) for a in reversed(alerts)]

    return app


def run_dashboard(host=None, port=None, debug=False):
    if not DASH_AVAILABLE:
        print('[Dashboard] Install with: pip install dash')
        return
    app = _create_app()
    h = host or DASHBOARD_HOST
    p = port or DASHBOARD_PORT
    print(f'[Dashboard] Starting at http://127.0.0.1:{p}')
    app.run(host=h, port=p, debug=debug)


if __name__ == '__main__':
    run_dashboard(debug=True)
