# extractor.py (aligned with combined_feature_names.json)
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
try:
    from scapy.contrib.mqtt import MQTT
    _MQTT_OK = True
except Exception:
    _MQTT_OK = False

import numpy as np
from pathlib import Path
import json, os

def safe_stats(arr):
    if arr is None:
        return 0.0, 0.0, 0.0, 0.0

    # Handle NumPy arrays and lists safely
    try:
        if len(arr) == 0:
            return 0.0, 0.0, 0.0, 0.0
    except Exception:
        return 0.0, 0.0, 0.0, 0.0

    a = np.array(arr, dtype=float)

    return (
        float(a.mean()),
        float(a.std(ddof=0)),
        float(a.min()),
        float(a.max()),
    )


def _load_allowed_ips():
    try:
        base = Path(__file__).resolve().parent.parent
        cfg = base / "configs" / "network_config.json"
        if cfg.exists():
            j = json.loads(cfg.read_text(encoding="utf-8"))
            allowed = set()
            for k in ("broker_ip","attacker_ip","client1_ip","client2_ip"):
                if j.get(k):
                    allowed.add(str(j[k]))
            return allowed
    except Exception:
        pass
    return set()

ALLOWED_IPS = _load_allowed_ips()  # empty => no filtering

def _ip_ok(src,dst):
    if not ALLOWED_IPS:
        return True
    return (str(src) in ALLOWED_IPS) or (str(dst) in ALLOWED_IPS)

def extract_biflow_29(pcap_path):
    """
    Return (biflow_feature_rows, biflow_meta_rows)
    Feature names use fwd_/bwd_ prefixes matching combined_feature_names.json
    """
    try:
        pkts = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"[WARN] rdpcap failed: {e}")
        return [], []

    def key(src,dst,sport,dport,proto):
        return (str(src), str(dst), int(sport), int(dport), int(proto))

    flows = {}
    for p in pkts:
        if not p.haslayer(IP):
            continue
        ip = p[IP]
        if not _ip_ok(ip.src, ip.dst):
            continue

        proto = 0
        sport = 0; dport = 0
        is_tcp = False
        flags = 0
        if p.haslayer(TCP):
            proto = 6
            sport = int(p[TCP].sport)
            dport = int(p[TCP].dport)
            is_tcp = True
            flags = int(p[TCP].flags)
        elif p.haslayer(UDP):
            proto = 17
            sport = int(p[UDP].sport)
            dport = int(p[UDP].dport)
        else:
            continue

        k = key(ip.src, ip.dst, sport, dport, proto)
        t = float(p.time)
        size = len(p)

        if k not in flows:
            flows[k] = {
                "times": [], "sizes": [], "psh":0, "rst":0, "urg":0,
                "src": str(ip.src), "dst": str(ip.dst), "sport": sport, "dport": dport, "proto": proto,
                "ports_set": set(), "mqtt_connects":0, "mqtt_msgs":0, "ssh_syn":0, "ssh_pkts":0
            }

        f = flows[k]
        f["times"].append(t)
        f["sizes"].append(size)
        f["ports_set"].add(int(dport) if dport else 0)
        if is_tcp:
            if flags & 0x08: f["psh"] += 1
            if flags & 0x04: f["rst"] += 1
            if flags & 0x20: f["urg"] += 1
            if flags & 0x02: f["ssh_syn"] += 1
            if sport == 22 or dport == 22: f["ssh_pkts"] += 1

        if _MQTT_OK:
            try:
                if p.haslayer(MQTT):
                    m = p[MQTT]
                    mtype = getattr(m,"type",None) or getattr(m,"msgtype",None)
                    f["mqtt_msgs"] += 1
                    if mtype is not None and int(mtype) == 1:
                        f["mqtt_connects"] += 1
            except Exception:
                pass

    # Now pair flows into biflows (fwd/bwd)
    processed = set()
    biflow_feats = []
    biflow_meta = []

    keys = list(flows.keys())
    for k in keys:
        if k in processed:
            continue
        src,dst,sport,dport,proto = k
        f = flows[k]
        rev = (dst, src, dport, sport, proto)
        b = flows.get(rev)

        # compute forward stats
        f_times = sorted(f["times"])
        f_sizes = np.array(f["sizes"], dtype=float) if f["sizes"] else np.array([])
        f_mean_iat, f_std_iat, f_min_iat, f_max_iat = safe_compute_iat_stats(f_times)
        f_mean_len, f_std_len, f_min_len, f_max_len = safe_stats(f_sizes)
        f_num_pkts = int(f_sizes.size)
        f_num_bytes = int(f_sizes.sum()) if f_sizes.size>0 else 0
        f_psh = int(f["psh"]); f_rst = int(f["rst"]); f_urg = int(f["urg"])

        # backward defaults mirror forward if absent
        if b is not None:
            b_times = sorted(b["times"])
            b_sizes = np.array(b["sizes"], dtype=float) if b["sizes"] else np.array([])
            b_mean_iat, b_std_iat, b_min_iat, b_max_iat = safe_compute_iat_stats(b_times)
            b_mean_len, b_std_len, b_min_len, b_max_len = safe_stats(b_sizes)
            b_num_pkts = int(b_sizes.size)
            b_num_bytes = int(b_sizes.sum()) if b_sizes.size>0 else 0
            b_psh = int(b["psh"]); b_rst = int(b["rst"]); b_urg = int(b["urg"])
            f_ports_set = set(f["ports_set"])
            b_ports_set = set(b["ports_set"])
            f_mqtt_connects = int(f["mqtt_connects"]); b_mqtt_connects = int(b["mqtt_connects"])
            f_mqtt_msgs = int(f["mqtt_msgs"]); b_mqtt_msgs = int(b["mqtt_msgs"])
            f_ssh_syn = int(f["ssh_syn"]); b_ssh_syn = int(b["ssh_syn"])
            f_ssh_pkts = int(f["ssh_pkts"]); b_ssh_pkts = int(b["ssh_pkts"])
        else:
            b_mean_iat, b_std_iat, b_min_iat, b_max_iat = f_mean_iat, f_std_iat, f_min_iat, f_max_iat
            b_mean_len, b_std_len, b_min_len, b_max_len = f_mean_len, f_std_len, f_min_len, f_max_len
            b_num_pkts = f_num_pkts
            b_num_bytes = f_num_bytes
            b_psh, b_rst, b_urg = f_psh, f_rst, f_urg
            f_ports_set = set(f["ports_set"])
            b_ports_set = set()
            f_mqtt_connects = int(f["mqtt_connects"]); b_mqtt_connects = 0
            f_mqtt_msgs = int(f["mqtt_msgs"]); b_mqtt_msgs = 0
            f_ssh_syn = int(f["ssh_syn"]); b_ssh_syn = 0
            f_ssh_pkts = int(f["ssh_pkts"]); b_ssh_pkts = 0

        feat = {
            # header fields
            "prt_src": int(sport),
            "prt_dst": int(dport),
            "proto": int(proto),

            # counts
            "fwd_num_pkts": f_num_pkts,
            "bwd_num_pkts": b_num_pkts,

            # iat
            "fwd_mean_iat": float(f_mean_iat),
            "bwd_mean_iat": float(b_mean_iat),
            "fwd_std_iat": float(f_std_iat),
            "bwd_std_iat": float(b_std_iat),
            "fwd_min_iat": float(f_min_iat),
            "bwd_min_iat": float(b_min_iat),
            "fwd_max_iat": float(f_max_iat),
            "bwd_max_iat": float(b_max_iat),

            # pkt lengths stats
            "fwd_mean_pkt_len": float(f_mean_len),
            "bwd_mean_pkt_len": float(b_mean_len),
            "fwd_std_pkt_len": float(f_std_len),
            "bwd_std_pkt_len": float(b_std_len),
            "fwd_min_pkt_len": float(f_min_len),
            "bwd_min_pkt_len": float(b_min_len),
            "fwd_max_pkt_len": float(f_max_len),
            "bwd_max_pkt_len": float(b_max_len),

            # bytes
            "fwd_num_bytes": int(f_num_bytes),
            "bwd_num_bytes": int(b_num_bytes),

            # flags
            "fwd_num_psh_flags": int(f_psh),
            "bwd_num_psh_flags": int(b_psh),
            "fwd_num_rst_flags": int(f_rst),
            "bwd_num_rst_flags": int(b_rst),
            "fwd_num_urg_flags": int(f_urg),
            "bwd_num_urg_flags": int(b_urg),

            # placeholder attack flag (models expect this column)
            "is_attack": 0
        }

        meta = {
            "src": str(src),
            "dst": str(dst),
            "sport": int(sport),
            "dport": int(dport),
            "proto": int(proto),
            "f_ports_set": f_ports_set,
            "b_ports_set": b_ports_set,
            "f_mqtt_connects": f_mqtt_connects,
            "b_mqtt_connects": b_mqtt_connects,
            "f_mqtt_msgs": f_mqtt_msgs,
            "b_mqtt_msgs": b_mqtt_msgs,
            "f_ssh_syn": f_ssh_syn,
            "b_ssh_syn": b_ssh_syn,
            "f_ssh_pkts": f_ssh_pkts,
            "b_ssh_pkts": b_ssh_pkts
        }

        # append and mark processed
        biflow_feats.append(feat)
        biflow_meta.append(meta)
        processed.add(k)
        processed.add(rev)

    return biflow_feats, biflow_meta

# helper to compute iat stats safely
def safe_compute_iat_stats(times_sorted):
    if not times_sorted or len(times_sorted) < 2:
        return 0.0, 0.0, 0.0, 0.0
    iats = np.diff(np.array(times_sorted, dtype=float))
    return (
        float(iats.mean()),
        float(iats.std(ddof=0)),
        float(iats.min()),
        float(iats.max()),
    )



def biflow_to_uniflow_rows(biflow_rows, biflow_meta, uniflow_feature_names):
    """
    Convert a biflow row into two uniflow-style rows with feature names exactly matching:
    uniflow_random_forest.feature_names
    """
    u_rows = []
    u_meta = []
    for feat, meta in zip(biflow_rows, biflow_meta):
        # forward
        row_f = {
            "prt_src": feat.get("prt_src", 0),
            "prt_dst": feat.get("prt_dst", 0),
            "proto": feat.get("proto", 0),
            "num_pkts": feat.get("fwd_num_pkts", 0),
            "mean_iat": feat.get("fwd_mean_iat", 0.0),
            "std_iat": feat.get("fwd_std_iat", 0.0),
            "min_iat": feat.get("fwd_min_iat", 0.0),
            "max_iat": feat.get("fwd_max_iat", 0.0),
            "mean_pkt_len": feat.get("fwd_mean_pkt_len", 0.0),
            "num_bytes": feat.get("fwd_num_bytes", 0),
            "num_psh_flags": feat.get("fwd_num_psh_flags", 0),
            "num_rst_flags": feat.get("fwd_num_rst_flags", 0),
            "num_urg_flags": feat.get("fwd_num_urg_flags", 0),
            "std_pkt_len": feat.get("fwd_std_pkt_len", 0.0),
            "min_pkt_len": feat.get("fwd_min_pkt_len", 0.0),
            "max_pkt_len": feat.get("fwd_max_pkt_len", 0.0),
            "is_attack": 0
        }
        u_rows.append({k: row_f.get(k, 0) for k in uniflow_feature_names})
        u_meta.append({"src": meta["src"], "dst": meta["dst"], "sport": meta["sport"], "dport": meta["dport"], "proto": meta["proto"]})

        # backward
        row_b = {
            "prt_src": feat.get("prt_dst", 0),
            "prt_dst": feat.get("prt_src", 0),
            "proto": feat.get("proto", 0),
            "num_pkts": feat.get("bwd_num_pkts", 0),
            "mean_iat": feat.get("bwd_mean_iat", 0.0),
            "std_iat": feat.get("bwd_std_iat", 0.0),
            "min_iat": feat.get("bwd_min_iat", 0.0),
            "max_iat": feat.get("bwd_max_iat", 0.0),
            "mean_pkt_len": feat.get("bwd_mean_pkt_len", 0.0),
            "num_bytes": feat.get("bwd_num_bytes", 0),
            "num_psh_flags": feat.get("bwd_num_psh_flags", 0),
            "num_rst_flags": feat.get("bwd_num_rst_flags", 0),
            "num_urg_flags": feat.get("bwd_num_urg_flags", 0),
            "std_pkt_len": feat.get("bwd_std_pkt_len", 0.0),
            "min_pkt_len": feat.get("bwd_min_pkt_len", 0.0),
            "max_pkt_len": feat.get("bwd_max_pkt_len", 0.0),
            "is_attack": 0
        }
        u_rows.append({k: row_b.get(k, 0) for k in uniflow_feature_names})
        u_meta.append({"src": meta["dst"], "dst": meta["src"], "sport": meta["dport"], "dport": meta["sport"], "proto": meta["proto"]})
    return u_rows, u_meta

def extract_packet_level(pcap_path, packet_feature_names, broker_ip=None, broker_port=1883):
    """
    Return (packet_feature_rows, packet_meta_rows) where rows use the exact names:
    packet_decision_tree.feature_names
    """
    try:
        pkts = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"[WARN] rdpcap failed (packet): {e}")
        return [], []

    rows = []; metas = []
    for p in pkts:
        if not p.haslayer(IP):
            continue
        ip = p[IP]
        if not _ip_ok(ip.src, ip.dst):
            continue

        proto = 0; sport = 0; dport = 0
        if p.haslayer(TCP):
            proto = 6; sport = int(p[TCP].sport); dport = int(p[TCP].dport)
            flags = int(p[TCP].flags)
        elif p.haslayer(UDP):
            proto = 17; sport = int(p[UDP].sport); dport = int(p[UDP].dport)
            flags = 0
        else:
            continue

        # Base fields we can compute
        pkt_len = len(p)
        ttl = getattr(ip, "ttl", 0)
        ip_len = getattr(ip, "len", pkt_len)

        # TCP flags expanded
        tcp_flag_res = 0
        tcp_flag_ns = 0
        tcp_flag_cwr = 1 if (hasattr(p, 'TCP') and (int(p[TCP].flags) & 0x80)) else 0
        tcp_flag_ecn = 1 if (hasattr(p, 'TCP') and (int(p[TCP].flags) & 0x40)) else 0
        tcp_flag_urg = 1 if (hasattr(p, 'TCP') and (int(p[TCP].flags) & 0x20)) else 0
        tcp_flag_ack = 1 if (hasattr(p, 'TCP') and (int(p[TCP].flags) & 0x10)) else 0
        tcp_flag_push = 1 if (hasattr(p, 'TCP') and (int(p[TCP].flags) & 0x08)) else 0
        tcp_flag_reset = 1 if (hasattr(p, 'TCP') and (int(p[TCP].flags) & 0x04)) else 0
        tcp_flag_syn = 1 if (hasattr(p, 'TCP') and (int(p[TCP].flags) & 0x02)) else 0
        tcp_flag_fin = 1 if (hasattr(p, 'TCP') and (int(p[TCP].flags) & 0x01)) else 0

        # MQTT fields (best-effort)
        mqtt_messagetype = 0
        mqtt_messagelength = 0
        mqtt_flag_uname = 0
        mqtt_flag_passwd = 0
        mqtt_flag_retain = 0
        mqtt_flag_qos = 0
        mqtt_flag_willflag = 0
        mqtt_flag_clean = 0
        mqtt_flag_reserved = 0

        if _MQTT_OK:
            try:
                if p.haslayer(MQTT):
                    m = p[MQTT]
                    mqtt_messagelength = getattr(m,"length",0) or 0
                    mqtt_messagetype = getattr(m,"type",None) or getattr(m,"msgtype",0)
                    # best-effort flags from attributes if present
                    mqtt_flag_uname = int(getattr(m,"username",False) is not False)
                    mqtt_flag_passwd = int(getattr(m,"password",False) is not False)
                    # other flags may not be available via scapy layer; keep as 0 by default
            except Exception:
                pass

        # assemble row using requested feature names
        row = {}
        for fn in packet_feature_names:
            # map expected names to computed values
            if fn == "ttl":
                row[fn] = ttl
            elif fn == "ip_len":
                row[fn] = ip_len
            elif fn == "ip_flag_df":
                row[fn] = 0
            elif fn == "ip_flag_mf":
                row[fn] = 0
            elif fn == "ip_flag_rb":
                row[fn] = 0
            elif fn == "src_port":
                row[fn] = sport
            elif fn == "dst_port":
                row[fn] = dport
            elif fn == "tcp_flag_res":
                row[fn] = tcp_flag_res
            elif fn == "tcp_flag_ns":
                row[fn] = tcp_flag_ns
            elif fn == "tcp_flag_cwr":
                row[fn] = tcp_flag_cwr
            elif fn == "tcp_flag_ecn":
                row[fn] = tcp_flag_ecn
            elif fn == "tcp_flag_urg":
                row[fn] = tcp_flag_urg
            elif fn == "tcp_flag_ack":
                row[fn] = tcp_flag_ack
            elif fn == "tcp_flag_push":
                row[fn] = tcp_flag_push
            elif fn == "tcp_flag_reset":
                row[fn] = tcp_flag_reset
            elif fn == "tcp_flag_syn":
                row[fn] = tcp_flag_syn
            elif fn == "tcp_flag_fin":
                row[fn] = tcp_flag_fin
            elif fn == "mqtt_messagetype":
                row[fn] = mqtt_messagetype
            elif fn == "mqtt_messagelength":
                row[fn] = mqtt_messagelength
            elif fn == "mqtt_flag_uname":
                row[fn] = mqtt_flag_uname
            elif fn == "mqtt_flag_passwd":
                row[fn] = mqtt_flag_passwd
            elif fn == "mqtt_flag_retain":
                row[fn] = mqtt_flag_retain
            elif fn == "mqtt_flag_qos":
                row[fn] = mqtt_flag_qos
            elif fn == "mqtt_flag_willflag":
                row[fn] = mqtt_flag_willflag
            elif fn == "mqtt_flag_clean":
                row[fn] = mqtt_flag_clean
            elif fn == "mqtt_flag_reserved":
                row[fn] = mqtt_flag_reserved
            elif fn == "is_attack":
                row[fn] = 0
            else:
                # unknown expected feature — default to zero
                row[fn] = 0
        rows.append(row)
        metas.append({"src": str(ip.src), "dst": str(ip.dst), "sport": sport, "dport": dport, "proto": proto})
    return rows, metas
