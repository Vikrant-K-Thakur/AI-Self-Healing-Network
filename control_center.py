import dash
from dash import html, dcc, Input, Output, State
import json
import subprocess
import os
import threading
import queue

from config import FORCED_ATTACK_FILE, TOPOLOGY_STATE_FILE

app = dash.Dash(__name__, title="Unified Command Center")

# Queues for capturing output
output_queue = queue.Queue()
processes = {}

def enqueue_output(out, queue_name):
    for line in iter(out.readline, b''):
        output_queue.put(f"[{queue_name}] {line.decode('utf-8').strip()}")
    out.close()


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

app.layout = html.Div(style={'fontFamily': 'Arial, sans-serif', 'padding': '20px', 'backgroundColor': '#1e1e1e', 'color': '#d4d4d4', 'minHeight': '100vh'}, children=[
    html.H1("Unified Terminal & Command Center", style={'textAlign': 'center', 'color': '#4CAF50'}),
    
    html.Div([
        html.A("Open Advanced Reroute Dashboard (Port 8053)", href="http://127.0.0.1:8053", target="_blank", style={'margin': '10px', 'padding': '10px 20px', 'backgroundColor': '#2e7d32', 'color': 'white', 'textDecoration': 'none', 'borderRadius': '5px', 'display': 'inline-block'})
    ], style={'textAlign': 'center', 'marginBottom': '20px'}),

    html.Div([
        html.Div([
            html.H3("Main System (IDS / Server)"),
            html.Button("Start Main System", id="btn-start-main", n_clicks=0, style={'marginRight': '10px', 'padding': '10px', 'backgroundColor': '#4CAF50', 'color': 'white', 'border': 'none', 'cursor': 'pointer', 'borderRadius': '5px'}),
            html.Button("Stop Main System", id="btn-stop-main", n_clicks=0, style={'marginRight': '10px', 'padding': '10px', 'backgroundColor': '#f44336', 'color': 'white', 'border': 'none', 'cursor': 'pointer', 'borderRadius': '5px'}),
            html.Button("Clear Terminal", id="btn-clear-terminal", n_clicks=0, style={'padding': '10px', 'backgroundColor': '#607d8b', 'color': 'white', 'border': 'none', 'cursor': 'pointer', 'borderRadius': '5px'}),
            html.Div(id="main-status", style={'marginTop': '10px', 'color': '#ffeb3b'})
        ], style={'padding': '20px', 'backgroundColor': '#252526', 'borderRadius': '8px', 'marginBottom': '20px'}),

        html.Div([
            html.H3("Attack Simulation"),
            html.Label("Attack / Block Switch:"),
            dcc.Dropdown(
                id='attack-switch',
                options=_load_switch_options(),
                value=_load_switch_options()[0]['value'],
                clearable=False,
                style={'color': 'black', 'marginBottom': '10px'}
            ),
            dcc.Dropdown(
                id='attack-type',
                options=[
                    {'label': 'Mixed Attack', 'value': 'mixed'},
                    {'label': 'Port Scan', 'value': 'portscan'},
                    {'label': 'Brute Force', 'value': 'brute'},
                    {'label': 'DDoS (SYN Flood)', 'value': 'ddos'}
                ],
                value='mixed',
                style={'color': 'black', 'marginBottom': '10px'}
            ),
            html.Button("Launch Attack", id="btn-start-attack", n_clicks=0, style={'marginRight': '10px', 'padding': '10px', 'backgroundColor': '#ff9800', 'color': 'white', 'border': 'none', 'cursor': 'pointer', 'borderRadius': '5px'}),
            html.Button("Stop Attack", id="btn-stop-attack", n_clicks=0, style={'padding': '10px', 'backgroundColor': '#f44336', 'color': 'white', 'border': 'none', 'cursor': 'pointer', 'borderRadius': '5px'}),
            html.Div(id="attack-status", style={'marginTop': '10px', 'color': '#ffeb3b'})
        ], style={'padding': '20px', 'backgroundColor': '#252526', 'borderRadius': '8px'}),
        dcc.Interval(id='attack-switch-refresh', interval=2000, n_intervals=0)
    ], style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '20px'}),

    html.Div([
        html.H3("Terminal Output", style={'marginTop': '20px'}),
        html.Div(id="terminal-output", style={
            'backgroundColor': '#000', 'color': '#0f0', 'height': '400px', 'overflowY': 'scroll', 
            'padding': '10px', 'fontFamily': 'monospace', 'whiteSpace': 'pre-wrap', 'border': '1px solid #333'
        }),
        dcc.Interval(id='interval-log', interval=1000, n_intervals=0)
    ])
])

output_logs = []

@app.callback(
    Output("main-status", "children"),
    Input("btn-start-main", "n_clicks"),
    Input("btn-stop-main", "n_clicks"),
    Input("btn-clear-terminal", "n_clicks"),
    prevent_initial_call=True
)
def manage_main(start_clicks, stop_clicks, clear_clicks):
    ctx = dash.callback_context
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    global processes, output_logs
    
    if button_id == "btn-clear-terminal":
        output_logs.clear()
        return "Terminal cleared."
    
    if button_id == "btn-start-main":
        if "main" in processes and processes["main"].poll() is None:
            return "Main System is already running."
        # Running via sudo requires virtual environment and explicit path to site-packages
        venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "bin", "python")
        site_packages = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "lib", "python3.12", "site-packages")
        
        env = os.environ.copy()
        env["PYTHONPATH"] = site_packages + (":" + env["PYTHONPATH"] if "PYTHONPATH" in env else "")
        
        python_cmd = venv_python if os.path.exists(venv_python) else "python3"
        cmd = ["sudo", "-E", python_cmd, "main.py", "--no-ryu", "--fresh", "--iface", "eth0", "--visual"]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=os.path.dirname(os.path.abspath(__file__)), env=env)
        processes["main"] = p
        t = threading.Thread(target=enqueue_output, args=(p.stdout, "MAIN"), daemon=True)
        t.start()
        return "Started Main System (PID: {}).".format(p.pid)
        
    elif button_id == "btn-stop-main":
        if "main" in processes and processes["main"].poll() is None:
            # Need sudo to kill sudo process
            subprocess.run(["sudo", "pkill", "-f", "main.py"])
            output_logs.clear()  # Clear terminal when stopping
            return "Main System stopped. Terminal cleared."
        output_logs.clear()  # Clear terminal even if not running
        return "Main System is not running. Terminal cleared."

@app.callback(
    Output("attack-status", "children"),
    Input("btn-start-attack", "n_clicks"),
    Input("btn-stop-attack", "n_clicks"),
    State("attack-type", "value"),
    State("attack-switch", "value"),
    prevent_initial_call=True
)
def manage_attack(start_clicks, stop_clicks, attack_type, attack_switch):
    ctx = dash.callback_context
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    global processes
    if button_id == "btn-start-attack":
        # Check if venv python path exists, fallback to standard python3
        venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "bin", "python")
        site_packages = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "lib", "python3.12", "site-packages")
        
        env = os.environ.copy()
        env["PYTHONPATH"] = site_packages + (":" + env["PYTHONPATH"] if "PYTHONPATH" in env else "")
        
        python_cmd = venv_python if os.path.exists(venv_python) else "python3"
        try:
            with open(FORCED_ATTACK_FILE, "w") as f:
                json.dump({"switch": attack_switch, "attack": attack_type}, f)
        except Exception as e:
            output_queue.put(f"[ATTACK] Failed to persist forced attack switch: {e}")
        cmd = ["sudo", "-E", python_cmd, "attacker.py", "--attack", attack_type, "--target", "127.0.0.1", "--src", "10.0.0.3"]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=os.path.dirname(os.path.abspath(__file__)), env=env)
        processes["attack"] = p
        t = threading.Thread(target=enqueue_output, args=(p.stdout, "ATTACK"), daemon=True)
        t.start()
        return f"Launched {attack_type} attack targeting {attack_switch} (PID: {p.pid})."
        
    elif button_id == "btn-stop-attack":
        if "attack" in processes and processes["attack"].poll() is None:
            subprocess.run(["sudo", "pkill", "-f", "attacker.py"])
            return "Attack stopped."
        # Cleanup any lingering attacker processes just in case
        subprocess.run(["sudo", "pkill", "-f", "attacker.py"])
        return "Attack stopped forcefully."

@app.callback(
    Output("terminal-output", "children"),
    Input("interval-log", "n_intervals"),
)
def update_logs(n):
    # Fetch all new lines from queue
    while not output_queue.empty():
        try:
            line = output_queue.get_nowait()
            output_logs.append(line)
        except queue.Empty:
            break
            
    # Keep last 1000 lines
    if len(output_logs) > 1000:
        del output_logs[:len(output_logs)-1000]
        
    return "\n".join(output_logs)


@app.callback(
    [Output("attack-switch", "options"), Output("attack-switch", "value")],
    Input("attack-switch-refresh", "n_intervals"),
    State("attack-switch", "value"),
    prevent_initial_call=False
)
def refresh_attack_switch_options(_, current_value):
    options = _load_switch_options()
    option_values = [opt["value"] for opt in options]
    if current_value not in option_values:
        current_value = option_values[0] if option_values else None
    return options, current_value

if __name__ == '__main__':
    # Run on an unused port, like 8060
    app.run(host='0.0.0.0', port=8060, debug=False)
