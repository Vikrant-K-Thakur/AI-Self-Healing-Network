"""
topo.py — Mininet Network Topology (Dynamic)
=============================================
Reads topology_state.json written by routing.py at startup.
Uses UserSwitch (userspace switching) which works in WSL2.

Run AFTER main.py has generated topology_state.json:

  Terminal 1:  sudo python3 main.py --no-ryu --fresh
  Terminal 2:  sudo mn --custom topo.py --topo mytopo --controller=none
"""

import json
import os

from mininet.topo   import Topo
from mininet.net    import Mininet
from mininet.node   import OVSSwitch, Controller, UserSwitch
from mininet.cli    import CLI
from mininet.log    import setLogLevel

try:
    _TOPO_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'topology_state.json')
except NameError:
    _TOPO_FILE = os.path.join(os.getcwd(), 'topology_state.json')


def _load_topology():
    if not os.path.exists(_TOPO_FILE):
        raise FileNotFoundError(
            f'\n[topo.py] topology_state.json not found.\n'
            'Run "sudo python3 main.py --fresh" first.'
        )
    with open(_TOPO_FILE, 'r', newline='') as f:
        raw = f.read().replace('\r', '')
    return json.loads(raw)


def _clean(val):
    return val.strip().replace('\r', '') if isinstance(val, str) else val


class MyTopo(Topo):
    def build(self):
        state        = _load_topology()
        switches     = [_clean(s) for s in state['switches']]
        host_ips     = {_clean(k): _clean(v) for k, v in state['host_ips'].items()}
        ip_to_switch = {_clean(k): _clean(v) for k, v in state['ip_to_switch'].items()}
        sw_edges     = [[_clean(e[0]), _clean(e[1])] for e in state['sw_edges']]

        for sw in switches:
            self.addSwitch(sw)

        for hname, ip in host_ips.items():
            self.addHost(hname, ip=f'{ip}/24')
            sw = ip_to_switch[ip]
            self.addLink(hname, sw)

        added = set()
        for edge in sw_edges:
            u, v = edge[0], edge[1]
            pair = tuple(sorted([u, v]))
            if pair not in added:
                added.add(pair)
                self.addLink(u, v)


def _setup_hosts(net):
    """
    WSL2 fix: all hosts share root namespace.
    We set up direct veth routes between every pair of hosts.
    """
    # Build ip -> interface name mapping
    ip_intf = {}
    for h in net.hosts:
        ip   = _clean(h.IP())
        intf = h.defaultIntf()
        if ip and intf:
            ip_intf[ip] = intf.name

    # Static ARP on every host for every other host
    ip_mac = {_clean(h.IP()): h.MAC() for h in net.hosts if h.IP() and h.MAC()}
    for h in net.hosts:
        my_ip = _clean(h.IP())
        for ip, mac in ip_mac.items():
            if ip != my_ip:
                h.cmd(f'arp -s {ip} {mac}')

    # Since all hosts are in root namespace in WSL2,
    # add host routes directly via their veth interfaces
    import subprocess
    for h in net.hosts:
        my_ip   = _clean(h.IP())
        my_intf = h.defaultIntf()
        if not my_intf:
            continue
        for ip, intf_name in ip_intf.items():
            if ip != my_ip:
                # Add direct host route via the destination's own interface
                h.cmd(f'ip route replace {ip}/32 dev {my_intf.name} 2>/dev/null')

    # Enable IP forwarding everywhere
    os.system('sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1')
    for sw in net.switches:
        sw.cmd('sysctl -w net.ipv4.ip_forward=1 2>/dev/null')
        for intf in sw.intfList():
            if intf.name and intf.name != 'lo':
                sw.cmd(f'sysctl -w net.ipv4.conf.{intf.name}.proxy_arp=1 2>/dev/null')

    print(f'[topo] Setup complete: {len(net.hosts)} hosts, '
          f'{len(ip_mac)} ARP entries, IP forwarding enabled on switches')


# Monkey-patch Mininet.start to run setup automatically after --custom startup
try:
    from mininet.net import Mininet as _MN
    _orig_start = _MN.start

    def _patched_start(self):
        _orig_start(self)
        try:
            _setup_hosts(self)
        except Exception as e:
            print(f'[topo] Setup warning: {e}')

    _MN.start = _patched_start
except Exception:
    pass


topos = {'mytopo': (lambda: MyTopo())}


def run_network():
    setLogLevel('info')
    state = _load_topology()

    net = Mininet(
        topo=MyTopo(),
        switch=OVSSwitch,
        controller=None,
        waitConnected=False,
    )
    net.start()
    _setup_hosts(net)

    host_ips       = {_clean(k): _clean(v) for k, v in state['host_ips'].items()}
    attacker_hosts = state.get('attacker_hosts', {})
    normal_hosts   = state.get('normal_hosts', {})
    receiver_ip    = _clean(host_ips.get('h2', '10.0.0.2'))

    print('\n' + '='*60)
    print('  RANDOM NETWORK STARTED')
    print('='*60)
    print('Hosts:   ', [h.name for h in net.hosts])
    print('Switches:', [s.name for s in net.switches])
    print()
    print('Test: mininet> h1 ping h2')
    print()
    print('Attack commands:')
    for hname, ip in attacker_hosts.items():
        print(f'  mininet> {hname} python3 attacker.py '
              f'--attack mixed --target {receiver_ip} --src {_clean(ip)}')
    print('='*60 + '\n')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    run_network()
