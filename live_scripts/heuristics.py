# heuristics.py
"""
Heuristic detectors for MQTT brute-force, SSH brute-force (sparta), and TCP/UDP scans.
Input: meta_rows produced by extractor.extract_biflow_29
"""

import time

def detect_mqtt_bruteforce(meta_rows, broker_ip=None, broker_port=1883, connect_threshold=20, msg_threshold=40):
    alerts = []
    for m in meta_rows:
        # filter by broker if provided
        if broker_ip:
            if not ((m.get('dst') == broker_ip and int(m.get('dport',0)) == broker_port) or
                    (m.get('src') == broker_ip and int(m.get('sport',0)) == broker_port)):
                continue
        total_connects = int(m.get('f_mqtt_connects', 0)) + int(m.get('b_mqtt_connects', 0))
        total_msgs = int(m.get('f_mqtt_msgs', 0)) + int(m.get('b_mqtt_msgs', 0))
        if total_connects >= connect_threshold or total_msgs >= msg_threshold:
            alerts.append({
                'type': 'mqtt_bruteforce',
                'flow': {'src': m.get('src'), 'dst': m.get('dst'), 'sport': m.get('sport'), 'dport': m.get('dport')},
                'connects': total_connects,
                'msgs': total_msgs,
                'time': time.time()
            })
    return alerts


def detect_ssh_bruteforce(meta_rows, ssh_pkt_threshold=100, ssh_syn_threshold=50):
    alerts = []
    for m in meta_rows:
        total_ssh_pkts = int(m.get('f_ssh_pkts', 0)) + int(m.get('b_ssh_pkts', 0))
        total_ssh_syn = int(m.get('f_ssh_syn', 0)) + int(m.get('b_ssh_syn', 0))
        # consider flows touching port 22
        if int(m.get('sport', 0)) == 22 or int(m.get('dport', 0)) == 22 or total_ssh_pkts > 0:
            if total_ssh_pkts >= ssh_pkt_threshold or total_ssh_syn >= ssh_syn_threshold:
                alerts.append({
                    'type': 'sparta',
                    'flow': {'src': m.get('src'), 'dst': m.get('dst'), 'sport': m.get('sport'), 'dport': m.get('dport')},
                    'ssh_pkts': total_ssh_pkts,
                    'ssh_syn': total_ssh_syn,
                    'time': time.time()
                })
    return alerts


def detect_tcp_udp_scans(meta_rows, tcp_port_threshold=15, udp_port_threshold=12):
    alerts = []
    for m in meta_rows:
        f_ports = set(m.get('f_ports_set', set()))
        b_ports = set(m.get('b_ports_set', set()))
        # TCP scans (Scan A): many distinct dst ports (forward or backward)
        if len(f_ports) >= tcp_port_threshold:
            alerts.append({'type': 'scan_A', 'flow': {'src': m.get('src'), 'dst': m.get('dst')}, 'unique_ports': len(f_ports), 'direction': 'fwd', 'time': time.time()})
        if len(b_ports) >= tcp_port_threshold:
            alerts.append({'type': 'scan_A', 'flow': {'src': m.get('dst'), 'dst': m.get('src')}, 'unique_ports': len(b_ports), 'direction': 'bwd', 'time': time.time()})
        # UDP scans (sU) — approximate: if proto==17 mark UDP candidate
        if int(m.get('proto', 0)) == 17:
            if len(f_ports) >= udp_port_threshold:
                alerts.append({'type': 'scan_sU', 'flow': {'src': m.get('src'), 'dst': m.get('dst')}, 'unique_ports': len(f_ports), 'direction': 'fwd', 'time': time.time()})
            if len(b_ports) >= udp_port_threshold:
                alerts.append({'type': 'scan_sU', 'flow': {'src': m.get('dst'), 'dst': m.get('src')}, 'unique_ports': len(b_ports), 'direction': 'bwd', 'time': time.time()})
    return alerts
