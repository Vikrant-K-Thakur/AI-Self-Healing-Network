import dash
from dash import html, dcc, Input, Output, State
import json
import os
import subprocess
import threading

from config import FORCED_ATTACK_FILE, TOPOLOGY_STATE_FILE

app = dash.Dash(__name__, title="Attacker Control Panel")


def _load_switch_options():
    if not os.path.exists(TOPOLOGY_STATE_FILE):
        return [{'label': 's1', 'value': 's1'}]
    try:
        with open(TOPOLOGY_STATE_FILE, 'r') as f:
            topo = json.load(f)
        switches = topo.get('switches', [])
        if switches:
            return [{'label': sw, 'value': sw} for sw in switches]
    except Exception:
        pass
    return [{'label': 's1', 'value': 's1'}]

app.layout = html.Div(style={'fontFamily': 'Arial, sans-serif', 'padding': '20px', 'maxWidth': '600px', 'margin': '0 auto'}, children=[
    html.H1("👹 Attack Control Panel", style={'color': '#d32f2f', 'textAlign': 'center'}),
    html.Hr(),
    html.Div([
        html.Label("Target IP (Main IDS Host IP):"),
        dcc.Input(id='target-ip', type='text', value='172.25.55.232', style={'width': '100%', 'marginBottom': '15px', 'padding': '8px', 'fontSize': '16px'}),
        
        html.Label("Attacker (Source) IP:"),
        dcc.Input(id='src-ip', type='text', value='10.0.0.3', style={'width': '100%', 'marginBottom': '20px', 'padding': '8px', 'fontSize': '16px'}),

        html.Label("Attack / Block Switch:"),
        dcc.Dropdown(
            id='target-switch',
            options=_load_switch_options(),
            value=_load_switch_options()[0]['value'],
            clearable=False,
            style={'width': '100%', 'marginBottom': '20px', 'color': '#111'}
        ),
        
        html.H3("Select Attack to Launch:"),
        html.Button('🚀 Launch DDoS (SYN Flood)', id='btn-ddos', n_clicks=0, style={'width': '100%', 'padding': '12px', 'marginBottom': '10px', 'backgroundColor': '#ff9800', 'color': 'white', 'border': 'none', 'cursor': 'pointer', 'fontSize': '16px', 'borderRadius': '4px'}),
        html.Button('🔍 Launch Port Scan', id='btn-portscan', n_clicks=0, style={'width': '100%', 'padding': '12px', 'marginBottom': '10px', 'backgroundColor': '#2196f3', 'color': 'white', 'border': 'none', 'cursor': 'pointer', 'fontSize': '16px', 'borderRadius': '4px'}),
        html.Button('🔑 Launch Brute Force', id='btn-brute', n_clicks=0, style={'width': '100%', 'padding': '12px', 'marginBottom': '10px', 'backgroundColor': '#9c27b0', 'color': 'white', 'border': 'none', 'cursor': 'pointer', 'fontSize': '16px', 'borderRadius': '4px'}),
        html.Button('🔥 Launch Mixed Attack', id='btn-mixed', n_clicks=0, style={'width': '100%', 'padding': '12px', 'marginBottom': '20px', 'backgroundColor': '#f44336', 'color': 'white', 'border': 'none', 'cursor': 'pointer', 'fontSize': '16px', 'fontWeight': 'bold', 'borderRadius': '4px'}),
        
        html.Hr(),
        html.Div(id='output-status', style={'padding': '15px', 'backgroundColor': '#e8f5e9', 'border': '1px solid #c8e6c9', 'minHeight': '50px', 'borderRadius': '4px'})
    ]),
    dcc.Interval(id='switch-refresh', interval=2000, n_intervals=0)
])

def run_attack_bg(attack_type, target_ip, src_ip, target_switch):
    try:
        with open(FORCED_ATTACK_FILE, 'w') as f:
            json.dump({'switch': target_switch, 'src_ip': src_ip, 'attack': attack_type}, f)
    except Exception as e:
        print(f"Failed to write forced attack state: {e}")

    # Run the attacker script using the local venv python
    cmd = ['venv/bin/python', 'attacker.py', '--attack', attack_type, '--target', target_ip, '--src', src_ip]
    try:
        subprocess.Popen(cmd)
    except Exception as e:
        print(f"Failed to run attack: {e}")


@app.callback(
    [Output('target-switch', 'options'), Output('target-switch', 'value')],
    [Input('switch-refresh', 'n_intervals')],
    [State('target-switch', 'value')]
)
def refresh_switch_options(_, current_value):
    options = _load_switch_options()
    option_values = [opt['value'] for opt in options]
    if current_value not in option_values:
        current_value = option_values[0] if option_values else None
    return options, current_value

@app.callback(
    Output('output-status', 'children'),
    [Input('btn-ddos', 'n_clicks'),
     Input('btn-portscan', 'n_clicks'),
     Input('btn-brute', 'n_clicks'),
     Input('btn-mixed', 'n_clicks')],
    [State('target-ip', 'value'),
     State('src-ip', 'value'),
     State('target-switch', 'value')]
)
def trigger_attack(btn_ddos, btn_portscan, btn_brute, btn_mixed, target_ip, src_ip, target_switch):
    ctx = dash.callback_context
    if not ctx.triggered:
        return html.Div("Ready. Select an attack above to begin.", style={'color': '#555'})
    
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    attack_map = {
        'btn-ddos': 'ddos',
        'btn-portscan': 'portscan',
        'btn-brute': 'brute',
        'btn-mixed': 'mixed'
    }
    
    attack_type = attack_map.get(button_id)
        
    if attack_type:
        # Launch attack in background thread so the UI remains responsive
        threading.Thread(target=run_attack_bg, args=(attack_type, target_ip, src_ip, target_switch)).start()
        
        return html.Div([
            html.Strong("✅ Command Sent! "), 
            html.Span(f"Executing "),
            html.Strong(f"{attack_type.upper()} ", style={'color': '#d32f2f'}),
            html.Span(f"attack from {src_ip} to {target_ip} targeting {target_switch}."),
            html.Br(), html.Br(),
            html.Small("Switch to your main dashboard (Port 8050) to watch the network defend itself, block the selected switch, and reroute!", style={'fontStyle': 'italic'})
        ], style={'color': '#2e7d32'})
        
    return html.Div("Ready. Select an attack to begin.", style={'color': '#555'})

if __name__ == '__main__':
    # Running on port 8052 to avoid conflict with main dashboard (8050) and visual dashboard (8051)
    print("Starting Attack Dashboard on port 8052...")
    app.run(host='0.0.0.0', port=8052, debug=False)
