# heuristics.py (Corrected Version)
"""
Heuristic detectors for:
- MQTT brute-force
- SSH brute-force (sparta)
- TCP aggressive scan (scan_A)
- UDP scan (scan_sU)

These heuristics are cleaned so they DO NOT trigger sparta for every attack.
"""

import time

# --------------------------------------------------------------------
# MQTT BRUTEFORCE
# --------------------------------------------------------------------
def detect_mqtt_bruteforce(meta_rows, broker_ip=None, broker_port=1883,
                           connect_threshold=10, msg_threshold=20):
    alerts = []
    for m in meta_rows:

        if broker_ip:
            # Only consider MQTT traffic targeting broker:1883
            if not ((m.get('dst') == broker_ip and int(m.get('dport',0)) == broker_port) or
                    (m.get('src') == broker_ip and int(m.get('sport',0)) == broker_port)):
                continue

        total_connects = int(m.get('f_mqtt_connects', 0)) + int(m.get('b_mqtt_connects', 0))
        total_msgs     = int(m.get('f_mqtt_msgs', 0))     + int(m.get('b_mqtt_msgs', 0))

        # meaningful thresholds
        if total_connects >= connect_threshold or total_msgs >= msg_threshold:
            alerts.append({
                'type': 'mqtt_bruteforce',
                'flow': {
                    'src': m.get('src'),
                    'dst': m.get('dst'),
                    'sport': m.get('sport'),
                    'dport': m.get('dport'),
                },
                'connects': total_connects,
                'msgs': total_msgs,
                'time': time.time(),
            })

    return alerts


# --------------------------------------------------------------------
# SSH BRUTEFORCE (SPARTA)
# --------------------------------------------------------------------
def detect_ssh_bruteforce(meta_rows,
                          attacker_ip=None,
                          ssh_pkt_threshold=200,    # increased thresholds
                          ssh_syn_threshold=150):   # prevents false positives
    alerts = []
    for m in meta_rows:

        # Only flows TARGETING port 22 on broker
        try:
            if int(m.get('dport', 0)) != 22:
                continue
        except:
            continue

        # If attacker IP specified, ONLY accept attacker → broker flows
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


# --------------------------------------------------------------------
# SCAN DETECTION (TCP + UDP)
# --------------------------------------------------------------------
def detect_tcp_udp_scans(meta_rows,
                         tcp_port_threshold=10,
                         udp_port_threshold=8):
    alerts = []

    for m in meta_rows:
        # ensure we can treat ports as sequences
        f_ports = set(m.get('f_ports_set', []) if m.get('f_ports_set') is not None else [])
        b_ports = set(m.get('b_ports_set', []) if m.get('b_ports_set') is not None else [])
        
        try:
            proto = int(m.get('proto', 0))
        except:
            proto = 0

        # ---- TCP Aggressive Scan (Scan A)
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

        # ---- UDP Scan (Scan sU)
        try:
            proto = int(m.get('proto', 0))
        except:
            proto = 0
            
        # Require at least 3 UDP packets to ensure true activity
        udp_pkts = m.get("fwd_num_pkts", 0) + m.get("bwd_num_pkts", 0)  

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
