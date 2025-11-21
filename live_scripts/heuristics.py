# heuristics.py (Hybrid heuristics: TCP + MQTT-layer)
"""
Heuristic detectors for:
- MQTT brute-force (hybrid TCP+MQTT)
- SSH brute-force (sparta)
- TCP aggressive scan (scan_A)
- UDP scan (scan_sU)
"""

import time

def detect_mqtt_bruteforce(meta_rows, broker_ip=None, broker_port=1883,
                           connect_threshold=6, connack_ratio_threshold=0.25, msg_threshold=10):
    """
    Hybrid detection:
      - many CONNECT attempts (>= connect_threshold)
      - low CONNACK response rate (connacks / connects <= connack_ratio_threshold)
      - few publish messages (bruteforce won't publish)
    """
    alerts = []
    for m in meta_rows:
        # Only flows touching broker:port (forward or backward)
        if broker_ip:
            if not ((m.get('dst') == broker_ip and int(m.get('dport',0)) == broker_port) or
                    (m.get('src') == broker_ip and int(m.get('sport',0)) == broker_port)):
                continue

        f_connects = int(m.get('f_mqtt_connects', 0))
        b_connects = int(m.get('b_mqtt_connects', 0))
        total_connects = f_connects + b_connects

        f_connacks = int(m.get('f_mqtt_connacks', 0))
        b_connacks = int(m.get('b_mqtt_connacks', 0))
        total_connacks = f_connacks + b_connacks

        f_msgs = int(m.get('f_mqtt_msgs', 0))
        b_msgs = int(m.get('b_mqtt_msgs', 0))
        total_msgs = f_msgs + b_msgs

        if total_connects < connect_threshold:
            continue

        # connack ratio safety: if there are many connacks relative to connects, it's likely normal
        connack_ratio = (total_connacks / total_connects) if total_connects > 0 else 0.0

        # Heuristic conditions for brute-force
        #  - many connects AND low connack rate OR many connects with very few publishes
        if (total_connects >= connect_threshold and connack_ratio <= connack_ratio_threshold) or \
           (total_connects >= (connect_threshold * 2) and total_msgs <= msg_threshold):
            alerts.append({
                'type': 'mqtt_bruteforce',
                'flow': {
                    'src': m.get('src'),
                    'dst': m.get('dst'),
                    'sport': m.get('sport'),
                    'dport': m.get('dport'),
                },
                'connects': total_connects,
                'connacks': total_connacks,
                'msgs': total_msgs,
                'time': time.time(),
            })
    return alerts

def detect_ssh_bruteforce(meta_rows,
                          attacker_ip=None,
                          ssh_pkt_threshold=200,
                          ssh_syn_threshold=150):
    alerts = []
    for m in meta_rows:
        try:
            if int(m.get('dport', 0)) != 22:
                continue
        except:
            continue
        if attacker_ip:
            if m.get('src') != attacker_ip:
                continue
        total_ssh_pkts = int(m.get('f_ssh_pkts', 0)) + int(m.get('b_ssh_pkts', 0))
        total_ssh_syn  = int(m.get('f_ssh_syn', 0))  + int(m.get('b_ssh_syn', 0))
        if total_ssh_pkts >= ssh_pkt_threshold or total_ssh_syn >= ssh_syn_threshold:
            alerts.append({
                'type': 'sparta',
                'flow': {
                    'src': m.get('src'),
                    'dst': m.get('dst'),
                    'sport': m.get('sport'),
                    'dport': m.get('dport'),
                },
                'ssh_pkts': total_ssh_pkts,
                'ssh_syn': total_ssh_syn,
                'time': time.time(),
            })
    return alerts

def detect_tcp_udp_scans(meta_rows,
                         tcp_port_threshold=10,
                         udp_port_threshold=8):
    alerts = []
    for m in meta_rows:
        f_ports = set(m.get('f_ports_set', []) if m.get('f_ports_set') is not None else [])
        b_ports = set(m.get('b_ports_set', []) if m.get('b_ports_set') is not None else [])
        try:
            proto = int(m.get('proto', 0))
        except:
            proto = 0

        # TCP Aggressive Scan (Scan A)
        if proto == 6 and len(f_ports) >= tcp_port_threshold:
            alerts.append({
                'type': 'scan_A',
                'flow': {'src': m.get('src'), 'dst': m.get('dst')},
                'unique_ports': len(f_ports),
                'direction': 'fwd',
                'time': time.time(),
            })

        if proto == 6 and len(b_ports) >= tcp_port_threshold:
            alerts.append({
                'type': 'scan_A',
                'flow': {'src': m.get('dst'), 'dst': m.get('src')},
                'unique_ports': len(b_ports),
                'direction': 'bwd',
                'time': time.time(),
            })

        # UDP Scan (Scan sU) - require at least 3 UDP packets and port cardinality
        udp_pkts = int(m.get("fwd_num_pkts", 0)) + int(m.get("bwd_num_pkts", 0))
        if proto == 17 and udp_pkts >= 3:
            if len(f_ports) >= udp_port_threshold:
                alerts.append({
                    'type': 'scan_sU',
                    'flow': {'src': m.get('src'), 'dst': m.get('dst')},
                    'unique_ports': len(f_ports),
                    'direction': 'fwd',
                    'time': time.time(),
                })
            if len(b_ports) >= udp_port_threshold:
                alerts.append({
                    'type': 'scan_sU',
                    'flow': {'src': m.get('dst'), 'dst': m.get('src')},
                    'unique_ports': len(b_ports),
                    'direction': 'bwd',
                    'time': time.time(),
                })

    return alerts
