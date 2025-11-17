# extractor.py (patched)
"""
Biflow and packet extractors.

- extract_biflow_29(pcap_path) -> (feature_rows, meta_rows)
  feature_rows: list of dicts matching the biflow model's expected features
  meta_rows: list of dicts with src/dst/sport/dport/proto and heuristic metadata
- extract_packet_level(pcap_path, packet_feature_names, ...) -> (rows, metas)
- biflow_to_uniflow_rows(feature_rows, meta_rows, uniflow_feature_names)
"""

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.contrib.mqtt import MQTT

import numpy as np
from collections import defaultdict
from pathlib import Path
import json
import os

def safe_stats_from_array(arr):
    if arr is None or len(arr) == 0:
        return 0.0, 0.0, 0.0, 0.0
    a = np.array(arr, dtype=float)
    return float(np.mean(a)), float(np.std(a, ddof=0)), float(np.min(a)), float(np.max(a))


# Load allowed IPs (broker + attacker) from configs/network_config.json if available.
def _load_allowed_ips():
    try:
        here = Path(__file__).resolve().parent.parent
        conf_path = here / "configs" / "network_config.json"
        if conf_path.exists():
            cfg = json.loads(conf_path.read_text(encoding="utf-8"))
            allowed = set()
            for k in ("broker_ip", "attacker_ip"):
                v = cfg.get(k)
                if v:
                    allowed.add(str(v))
            # also include client ips if present (optional)
            for k in ("client1_ip", "client2_ip"):
                v = cfg.get(k)
                if v:
                    allowed.add(str(v))
            return allowed
    except Exception:
        pass
    return set()

ALLOWED_IPS = _load_allowed_ips()  # empty set means "no filter"

def _ip_allowed(src, dst):
    if not ALLOWED_IPS:
        return True
    return (str(src) in ALLOWED_IPS) or (str(dst) in ALLOWED_IPS)


def extract_biflow_29(pcap_path):
    """
    Build biflow feature_rows (same fields your model expects) and meta_rows
    containing extra metadata used by heuristic detectors.

    Important: this function intentionally *does not* add new features to
    feature_rows (so it keeps model feature set unchanged). The heuristic
    metadata is returned in meta_rows.
    """
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"[WARN] Failed to read pcap {pcap_path}: {e}")
        return [], []

    def make_key(src, dst, sport, dport, proto):
        return (str(src), str(dst), int(sport), int(dport), int(proto))

    uniflows = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]

        # Defensive filtering: only handle packets involving allowed IPs (if configured)
        if not _ip_allowed(ip.src, ip.dst):
            continue

        proto = None
        sport = 0
        dport = 0
        is_tcp = False
        tcp_flags = 0

        if pkt.haslayer(TCP):
            proto = 6
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            is_tcp = True
            tcp_flags = int(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            proto = 17
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        else:
            continue

        key = make_key(ip.src, ip.dst, sport, dport, proto)
        t = float(pkt.time)
        size = len(pkt)

        if key not in uniflows:
            uniflows[key] = {
                "first_seen": t,
                "times": [],
                "sizes": [],
                "psh": 0,
                "rst": 0,
                "urg": 0,
                "proto": proto,
                "sport": sport,
                "dport": dport,
                "src": str(ip.src),
                "dst": str(ip.dst),
                "ports_set": set(),
                # heuristic metadata:
                "mqtt_connects": 0,
                "mqtt_msgs": 0,
                "ssh_syn": 0,
                "ssh_pkts": 0,
            }

        u = uniflows[key]
        u["times"].append(t)
        u["sizes"].append(size)
        try:
            u["ports_set"].add(int(dport))
        except Exception:
            pass

        if is_tcp:
            # PSH=0x08, RST=0x04, URG=0x20, SYN=0x02
            if tcp_flags & 0x08:
                u["psh"] += 1
            if tcp_flags & 0x04:
                u["rst"] += 1
            if tcp_flags & 0x20:
                u["urg"] += 1
            if tcp_flags & 0x02:
                u["ssh_syn"] += 1
            if sport == 22 or dport == 22:
                u["ssh_pkts"] += 1

        # MQTT detection via Scapy MQTT layer (we assume it's installed)
        try:
            if pkt.haslayer(MQTT):
                m = pkt[MQTT]
                mtype = getattr(m, "type", None) or getattr(m, "msgtype", None)
                u["mqtt_msgs"] += 1
                try:
                    if mtype is not None and int(mtype) == 1:
                        u["mqtt_connects"] += 1
                except Exception:
                    pass
        except Exception:
            pass

    # Pair into biflows
    processed = set()
    feature_rows = []
    meta_rows = []
    keys_list = list(uniflows.keys())

    for key in keys_list:
        if key in processed:
            continue

        src, dst, sport, dport, proto = key
        u = uniflows[key]
        rev_key = make_key(dst, src, dport, sport, proto)

        # UDP
        if proto == 17:
            f = u
            f_times_sorted = sorted(f["times"])
            f_sizes = np.array(f["sizes"], dtype=float) if f["sizes"] else np.array([], dtype=float)
            if len(f_times_sorted) > 1:
                f_iats = np.diff(np.array(f_times_sorted))
            else:
                f_iats = np.array([], dtype=float)

            f_mean_iat, f_std_iat, f_min_iat, f_max_iat = safe_stats_from_array(f_iats)
            f_mean_len, f_std_len, f_min_len, f_max_len = safe_stats_from_array(f_sizes)
            f_num_pkts = int(f_sizes.size)
            f_num_bytes = int(f_sizes.sum()) if f_sizes.size > 0 else 0

            feat = {
                "prt_src": int(f.get("sport", sport)),
                "prt_dst": int(f.get("dport", dport)),
                "proto": int(proto),

                "fwd_num_pkts": f_num_pkts,
                "bwd_num_pkts": f_num_pkts,

                "fwd_mean_iat": float(f_mean_iat),
                "bwd_mean_iat": float(f_mean_iat),
                "fwd_std_iat": float(f_std_iat),
                "bwd_std_iat": float(f_std_iat),
                "fwd_min_iat": float(f_min_iat),
                "bwd_min_iat": float(f_min_iat),
                "fwd_max_iat": float(f_max_iat),
                "bwd_max_iat": float(f_max_iat),

                "fwd_mean_pkt_len": float(f_mean_len),
                "bwd_mean_pkt_len": float(f_mean_len),
                "fwd_std_pkt_len": float(f_std_len),
                "bwd_std_pkt_len": float(f_std_len),
                "fwd_min_pkt_len": float(f_min_len),
                "bwd_min_pkt_len": float(f_min_len),
                "fwd_max_pkt_len": float(f_max_len),
                "bwd_max_pkt_len": float(f_max_len),

                "fwd_num_bytes": f_num_bytes,
                "bwd_num_bytes": f_num_bytes,

                "fwd_num_psh_flags": int(f.get("psh", 0)),
                "bwd_num_psh_flags": int(f.get("psh", 0)),
                "fwd_num_rst_flags": int(f.get("rst", 0)),
                "bwd_num_rst_flags": int(f.get("rst", 0)),
                "fwd_num_urg_flags": int(f.get("urg", 0)),
                "bwd_num_urg_flags": int(f.get("urg", 0)),
            }

            meta_rows.append({
                "src": f.get("src", src),
                "dst": f.get("dst", dst),
                "sport": int(f.get("sport", sport)),
                "dport": int(f.get("dport", dport)),
                "proto": int(proto),
                # heuristic extras (forward only)
                "f_ports_set": set(f.get("ports_set", set())),
                "b_ports_set": set(),
                "f_mqtt_connects": int(f.get("mqtt_connects", 0)),
                "b_mqtt_connects": 0,
                "f_mqtt_msgs": int(f.get("mqtt_msgs", 0)),
                "b_mqtt_msgs": 0,
                "f_ssh_syn": int(f.get("ssh_syn", 0)),
                "b_ssh_syn": 0,
                "f_ssh_pkts": int(f.get("ssh_pkts", 0)),
                "b_ssh_pkts": 0
            })
            feature_rows.append(feat)
            processed.add(key)
            continue

        # TCP handling (pair or single)
        if rev_key in uniflows and rev_key not in processed:
            u_rev = uniflows[rev_key]
            first_a = u.get("first_seen", min(u["times"]) if u["times"] else float("inf"))
            first_b = u_rev.get("first_seen", min(u_rev["times"]) if u_rev["times"] else float("inf"))
            if first_a <= first_b:
                f_uniflow = u
                b_uniflow = u_rev
                f_key = key
                b_key = rev_key
            else:
                f_uniflow = u_rev
                b_uniflow = u
                f_key = rev_key
                b_key = key
        else:
            f_uniflow = u
            b_uniflow = None
            f_key = key
            b_key = None

        # Forward stats
        f_times_sorted = sorted(f_uniflow["times"]) if f_uniflow["times"] else []
        f_sizes = np.array(f_uniflow["sizes"], dtype=float) if f_uniflow["sizes"] else np.array([], dtype=float)
        if len(f_times_sorted) > 1:
            f_iats = np.diff(np.array(f_times_sorted))
        else:
            f_iats = np.array([], dtype=float)
        f_mean_iat, f_std_iat, f_min_iat, f_max_iat = safe_stats_from_array(f_iats)
        f_mean_len, f_std_len, f_min_len, f_max_len = safe_stats_from_array(f_sizes)
        f_num_pkts = int(f_sizes.size)
        f_num_bytes = int(f_sizes.sum()) if f_sizes.size > 0 else 0
        f_psh = int(f_uniflow.get("psh", 0))
        f_rst = int(f_uniflow.get("rst", 0))
        f_urg = int(f_uniflow.get("urg", 0))

        # Backward stats
        if b_uniflow is not None:
            b_times_sorted = sorted(b_uniflow["times"]) if b_uniflow["times"] else []
            b_sizes = np.array(b_uniflow["sizes"], dtype=float) if b_uniflow["sizes"] else np.array([], dtype=float)
            if len(b_times_sorted) > 1:
                b_iats = np.diff(np.array(b_times_sorted))
            else:
                b_iats = np.array([], dtype=float)
            b_mean_iat, b_std_iat, b_min_iat, b_max_iat = safe_stats_from_array(b_iats)
            b_mean_len, b_std_len, b_min_len, b_max_len = safe_stats_from_array(b_sizes)
            b_num_pkts = int(b_sizes.size)
            b_num_bytes = int(b_sizes.sum()) if b_sizes.size > 0 else 0
            b_psh = int(b_uniflow.get("psh", 0))
            b_rst = int(b_uniflow.get("rst", 0))
            b_urg = int(b_uniflow.get("urg", 0))
        else:
            b_mean_iat, b_std_iat, b_min_iat, b_max_iat = f_mean_iat, f_std_iat, f_min_iat, f_max_iat
            b_mean_len, b_std_len, b_min_len, b_max_len = f_mean_len, f_std_len, f_min_len, f_max_len
            b_num_pkts = f_num_pkts
            b_num_bytes = f_num_bytes
            b_psh, b_rst, b_urg = f_psh, f_rst, f_urg

        prt_src = int(f_uniflow.get("sport", sport))
        prt_dst = int(f_uniflow.get("dport", dport))
        proto_val = int(f_uniflow.get("proto", proto))

        feat = {
            "prt_src": prt_src,
            "prt_dst": prt_dst,
            "proto": proto_val,

            "fwd_num_pkts": f_num_pkts,
            "bwd_num_pkts": b_num_pkts,

            "fwd_mean_iat": float(f_mean_iat),
            "bwd_mean_iat": float(b_mean_iat),
            "fwd_std_iat": float(f_std_iat),
            "bwd_std_iat": float(b_std_iat),
            "fwd_min_iat": float(f_min_iat),
            "bwd_min_iat": float(b_min_iat),
            "fwd_max_iat": float(f_max_iat),
            "bwd_max_iat": float(b_max_iat),

            "fwd_mean_pkt_len": float(f_mean_len),
            "bwd_mean_pkt_len": float(b_mean_len),
            "fwd_std_pkt_len": float(f_std_len),
            "bwd_std_pkt_len": float(b_std_len),
            "fwd_min_pkt_len": float(f_min_len),
            "bwd_min_pkt_len": float(b_min_len),
            "fwd_max_pkt_len": float(f_max_len),
            "bwd_max_pkt_len": float(b_max_len),

            "fwd_num_bytes": f_num_bytes,
            "bwd_num_bytes": b_num_bytes,

            "fwd_num_psh_flags": f_psh,
            "bwd_num_psh_flags": b_psh,
            "fwd_num_rst_flags": f_rst,
            "bwd_num_rst_flags": b_rst,
            "fwd_num_urg_flags": f_urg,
            "bwd_num_urg_flags": b_urg,
        }

        meta_rows.append({
            "src": f_uniflow.get("src", src),
            "dst": f_uniflow.get("dst", dst),
            "sport": prt_src,
            "dport": prt_dst,
            "proto": proto_val,
            "f_ports_set": set(f_uniflow.get("ports_set", set())),
            "b_ports_set": set(b_uniflow.get("ports_set", set())) if b_uniflow is not None else set(f_uniflow.get("ports_set", set())),
            "f_mqtt_connects": int(f_uniflow.get("mqtt_connects", 0)),
            "b_mqtt_connects": int(b_uniflow.get("mqtt_connects", 0)) if b_uniflow is not None else int(f_uniflow.get("mqtt_connects", 0)),
            "f_mqtt_msgs": int(f_uniflow.get("mqtt_msgs", 0)),
            "b_mqtt_msgs": int(b_uniflow.get("mqtt_msgs", 0)) if b_uniflow is not None else int(f_uniflow.get("mqtt_msgs", 0)),
            "f_ssh_syn": int(f_uniflow.get("ssh_syn", 0)),
            "b_ssh_syn": int(b_uniflow.get("ssh_syn", 0)) if b_uniflow is not None else int(f_uniflow.get("ssh_syn", 0)),
            "f_ssh_pkts": int(f_uniflow.get("ssh_pkts", 0)),
            "b_ssh_pkts": int(b_uniflow.get("ssh_pkts", 0)) if b_uniflow is not None else int(f_uniflow.get("ssh_pkts", 0)),
        })

        feature_rows.append(feat)
        processed.add(f_key)
        if b_key is not None:
            processed.add(b_key)

    return feature_rows, meta_rows


def biflow_to_uniflow_rows(feature_rows, meta_rows, uniflow_feature_names):
    """
    Convert biflow features -> uniflow rows (forward + backward) mapping fields used by uniflow model.
    """
    u_rows = []
    u_meta = []
    for feat, meta in zip(feature_rows, meta_rows):
        row_f = {}
        mapping_f = {
            "prt_src": "prt_src", "prt_dst": "prt_dst", "proto": "proto",
            "num_pkts": "fwd_num_pkts", "mean_iat": "fwd_mean_iat", "std_iat": "fwd_std_iat",
            "min_iat": "fwd_min_iat", "max_iat": "fwd_max_iat",
            "mean_pkt_len": "fwd_mean_pkt_len", "std_pkt_len": "fwd_std_pkt_len",
            "min_pkt_len": "fwd_min_pkt_len", "max_pkt_len": "fwd_max_pkt_len",
            "num_bytes": "fwd_num_bytes",
            "num_psh_flags": "fwd_num_psh_flags", "num_rst_flags": "fwd_num_rst_flags", "num_urg_flags": "fwd_num_urg_flags"
        }
        for fn in uniflow_feature_names:
            if fn in mapping_f:
                row_f[fn] = feat.get(mapping_f[fn], 0)
            else:
                row_f[fn] = feat.get(fn, 0)
        u_rows.append(row_f)
        u_meta.append({"src": meta["src"], "dst": meta["dst"], "sport": meta["sport"], "dport": meta["dport"], "proto": meta["proto"]})

        # backward
        row_b = {}
        mapping_b = {
            "prt_src": "prt_dst", "prt_dst": "prt_src", "proto": "proto",
            "num_pkts": "bwd_num_pkts", "mean_iat": "bwd_mean_iat", "std_iat": "bwd_std_iat",
            "min_iat": "bwd_min_iat", "max_iat": "bwd_max_iat",
            "mean_pkt_len": "bwd_mean_pkt_len", "std_pkt_len": "bwd_std_pkt_len",
            "min_pkt_len": "bwd_min_pkt_len", "max_pkt_len": "bwd_max_pkt_len",
            "num_bytes": "bwd_num_bytes",
            "num_psh_flags": "bwd_num_psh_flags", "num_rst_flags": "bwd_num_rst_flags", "num_urg_flags": "bwd_num_urg_flags"
        }
        for fn in uniflow_feature_names:
            if fn in mapping_b:
                row_b[fn] = feat.get(mapping_b[fn], 0)
            else:
                row_b[fn] = feat.get(fn, 0)
        u_rows.append(row_b)
        u_meta.append({"src": meta["dst"], "dst": meta["src"], "sport": meta["dport"], "dport": meta["sport"], "proto": meta["proto"]})
    return u_rows, u_meta


def extract_packet_level(pcap_path, packet_feature_names, broker_ip=None, broker_port=1883):
    """
    Best-effort packet feature extractor (keeps your existing pipeline intact).
    """
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"[WARN] Failed to read pcap for packet-level {pcap_path}: {e}")
        return [], []

    rows = []
    metas = []
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]

        # Defensive IP filter
        if not _ip_allowed(ip.src, ip.dst):
            continue

        proto = None
        sport = dport = 0
        tcp_flags = 0
        if pkt.haslayer(TCP):
            proto = 6
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            tcp_flags = int(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            proto = 17
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        else:
            continue

        base = {
            "src": ip.src, "dst": ip.dst, "sport": sport, "dport": dport, "proto": proto,
            "pkt_len": len(pkt),
            "has_payload": 1 if pkt.haslayer(Raw) else 0,
            "tcp_flags": tcp_flags,
            "ttl": getattr(ip, "ttl", 0),
            "ip_len": getattr(ip, "len", len(pkt))
        }

        row = {}
        for fn in packet_feature_names:
            if fn in base:
                row[fn] = base[fn]
            else:
                if fn in ("packet_len", "pkt_len"):
                    row[fn] = base["pkt_len"]
                elif fn == "src_ip":
                    row[fn] = base["src"]
                elif fn == "dst_ip":
                    row[fn] = base["dst"]
                elif fn == "sport":
                    row[fn] = base["sport"]
                elif fn == "dport":
                    row[fn] = base["dport"]
                elif fn == "proto":
                    row[fn] = base["proto"]
                else:
                    row[fn] = 0
        rows.append(row)
        metas.append({"src": base["src"], "dst": base["dst"], "sport": sport, "dport": dport, "proto": proto})
    return rows, metas
