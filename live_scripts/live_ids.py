#!/usr/bin/env python3
"""
Unified live_ids.py that supports three models (packet, uniflow, biflow) defined
by models_config.json. Logs alerts to logs/YYYY-MM-DD/ids_alerts.log.

This version preserves your model feature names exactly but fixes flow
construction logic (canonical direction, UDP duplication, strict timestamp
ordering, correct IAT/mean/std/min/max, TCP flag counting) to match the
original MQTT-IoT-IDS2020 extraction semantics.
"""

from pathlib import Path
import argparse
import time
import json
import signal
import sys
import joblib
import numpy as np
import pandas as pd
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

RUNNING = True
def handle_signal(sig, frame):
    global RUNNING
    print(f"\n[INFO] Received signal {sig}. Shutting down...")
    RUNNING = False

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# -------------------------
# Utility: safe stats
# -------------------------
def safe_stats_from_array(arr):
    if arr is None or len(arr) == 0:
        return 0.0, 0.0, 0.0, 0.0
    a = np.array(arr, dtype=float)
    return float(np.mean(a)), float(np.std(a, ddof=0)), float(np.min(a)), float(np.max(a))

# -------------------------
# Biflow extractor (corrected & paper-faithful)
# -------------------------
def extract_biflow_29(pcap_path):
    """
    Returns (feature_rows, meta_rows).
    feature_rows: list of dicts matching biflow features (without is_attack)
    meta_rows: list of meta dicts with src,dst,sport,dport,proto

    Algorithm:
      - Build uniflows keyed by (src, dst, sport, dport, proto) preserving packet order
      - Each uniflow stores list of packet times, sizes and TCP flag counts
      - Pair uniflows into biflows: if reverse uniflow exists, choose canonical forward
        as the uniflow with the earlier first-packet timestamp
      - For UDP, treat as unidirectional and duplicate forward stats into backward
    """
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"[WARN] Failed to read pcap {pcap_path}: {e}")
        return [], []

    # Build uniflows
    # key -> { first_seen: float, times: [], sizes: [], psh: int, rst: int, urg: int, proto:int, sport:int, dport:int, src:str, dst:str }
    uniflows = {}

    def make_key(src, dst, sport, dport, proto):
        return (str(src), str(dst), int(sport), int(dport), int(proto))

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]

        proto = None
        sport = None
        dport = None
        is_tcp = False
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
            tcp_flags = 0
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
                "dst": str(ip.dst)
            }
        u = uniflows[key]
        u["times"].append(t)
        u["sizes"].append(size)
        if is_tcp:
            # flags bits: PSH=0x08, RST=0x04, URG=0x20
            if tcp_flags & 0x08:
                u["psh"] += 1
            if tcp_flags & 0x04:
                u["rst"] += 1
            if tcp_flags & 0x20:
                u["urg"] += 1

    # Pair uniflows into biflows
    processed = set()
    feature_rows = []
    meta_rows = []

    # We'll iterate through keys deterministically
    keys_list = list(uniflows.keys())

    for key in keys_list:
        if key in processed:
            continue

        src, dst, sport, dport, proto = key
        u = uniflows[key]
        rev_key = make_key(dst, src, dport, sport, proto)

        if proto == 17:
            # UDP: treat as a unidirectional flow, duplicate forward into backward
            # Choose canonical forward = this uniflow
            f = u
            # compute forward stats
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
                "proto": int(proto)
            })
            feature_rows.append(feat)
            processed.add(key)
            # don't mark reverse (it may not exist) so processed only forward
            continue

        # Non-UDP (TCP)
        if rev_key in uniflows and rev_key not in processed:
            u_rev = uniflows[rev_key]

            # choose canonical forward based on earliest first_seen (smaller first packet time)
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
            # No reverse uniflow found — treat this as forward-only (duplicate to backward)
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

        # Backward stats (may be None -> duplicate forward)
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

        # Choose ports/proto for metadata from the forward uniflow (canonical)
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

        # meta: use canonical forward direction (src/dst ports from forward)
        meta_rows.append({
            "src": f_uniflow.get("src", src),
            "dst": f_uniflow.get("dst", dst),
            "sport": prt_src,
            "dport": prt_dst,
            "proto": proto_val
        })
        feature_rows.append(feat)

        # mark processed both directions if reverse existed
        processed.add(f_key)
        if b_key is not None:
            processed.add(b_key)

    return feature_rows, meta_rows

# -------------------------
# Convert biflow -> uniflow rows
# -------------------------
def biflow_to_uniflow_rows(feature_rows, meta_rows, uniflow_feature_names):
    """
    For each biflow produce up to two uniflow rows (forward and backward) mapping fields
    based on common uniflow names used in training (best-effort).
    """
    u_rows = []
    u_meta = []
    for feat, meta in zip(feature_rows, meta_rows):
        # forward direction
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

        # backward direction (swap src/dst and use bwd_ fields)
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
        # reverse meta for backward
        u_rows.append(row_b)
        u_meta.append({"src": meta["dst"], "dst": meta["src"], "sport": meta["dport"], "dport": meta["sport"], "proto": meta["proto"]})

    return u_rows, u_meta

# -------------------------
# Packet-level feature extraction (best-effort)
# -------------------------
def extract_packet_level(pcap_path, packet_feature_names, broker_ip=None, broker_port=1883):
    """
    Best-effort packet-level feature extractor:
    - For each packet produce a dict with keys in packet_feature_names.
    - If names are not found they are set to 0.
    This is intentionally permissive so we can run the DT packet model if its feature list exists.
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

        # map requested feature names to available computed base values (best-effort)
        row = {}
        for fn in packet_feature_names:
            if fn in base:
                row[fn] = base[fn]
            else:
                # some common alt names:
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

# -------------------------
# Flow filters (same as yours)
# -------------------------
def is_relevant_broker_flow(meta, broker_ip, broker_port):
    try:
        src = meta["src"]
        dst = meta["dst"]
        sport = int(meta["sport"])
        dport = int(meta["dport"])
    except:
        return False
    if (dst == broker_ip and dport == broker_port) or (src == broker_ip and sport == broker_port):
        return True
    return False

def is_broadcast_or_system_flow(meta):
    dst = meta.get("dst", "")
    proto = meta.get("proto", None)
    sport = int(meta.get("sport", 0))
    dport = int(meta.get("dport", 0))
    if isinstance(dst, str) and (dst.startswith("224.") or dst == "255.255.255.255"):
        return True
    if proto == 17 and {sport, dport} == {67, 68}:
        return True
    if proto == 17 and dport in (5355, 1900, 137, 138):
        return True
    return False

# -------------------------
# Main
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Real-time IDS unified (packet/uniflow/biflow)")
    parser.add_argument("--pcap-dir", required=True)
    parser.add_argument("--models-config", default="../configs/models_config.json",
                    help="Path to models_config.json (default: ../configs/models_config.json)")
    parser.add_argument("--out-log", default="ids_alerts.log")
    parser.add_argument("--csv-out", default="ids_summary.csv")
    parser.add_argument("--broker-ip", default=None)
    parser.add_argument("--broker-port", type=int, default=1883)
    parser.add_argument("--broker-only", action="store_true")
    parser.add_argument("--prob-threshold", type=float, default=0.75)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    args = parser.parse_args()

    # ---------------------------------------------------------------------
    # 1. Load models_config.json (absolute resolution of model/meta paths)
    # ---------------------------------------------------------------------
    models_cfg_path = Path(args.models_config).resolve()

    if not models_cfg_path.exists():
        print(f"[ERROR] models_config.json not found at {models_cfg_path}")
        sys.exit(1)

    with open(models_cfg_path, "r") as f:
        models_cfg = json.load(f)

    # Resolve paths relative to PROJECT ROOT, not configs/
    project_root = models_cfg_path.parent.parent

    active_models = {}

    for key in ("packet", "uniflow", "biflow"):
        entry = models_cfg.get(key)
        if not entry or not entry.get("enabled", False):
            print(f"[INFO] Model '{key}' disabled or not configured.")
            continue

        # Convert to absolute paths
        model_path = (project_root / entry["model_path"]).resolve()
        meta_path  = (project_root / entry["meta_path"]).resolve()

        if not model_path.exists():
            print(f"[WARN] Model file for '{key}' NOT FOUND: {model_path}")
            continue
        if not meta_path.exists():
            print(f"[WARN] Metadata for '{key}' NOT FOUND: {meta_path}")
            continue

        # Load model + metadata
        try:
            mdl = joblib.load(model_path)
            meta_json = json.load(open(meta_path, "r"))
            feature_names = meta_json.get("feature_names", [])

            active_models[key] = {
                "model": mdl,
                "feature_names": feature_names,
                "meta_json": meta_json
            }

            print(f"[OK] Loaded '{key}' model")
        except Exception as e:
            print(f"[ERROR] Failed to load model '{key}': {e}")

    if not active_models:
        print("[FATAL] No models successfully loaded. Exiting.")
        sys.exit(1)

    # ---------------------------------------------------------------------
    # 2. CSV Summary Initialization
    # ---------------------------------------------------------------------
    if not Path(args.csv_out).exists():
        with open(args.csv_out, "w") as f:
            f.write("time,pcap,status,attack_count\n")

    # ---------------------------------------------------------------------
    # 3. Daily Log Directory
    # ---------------------------------------------------------------------
    today = time.strftime("%Y-%m-%d")
    log_dir = Path("logs") / today
    log_dir.mkdir(parents=True, exist_ok=True)

    alert_log_path = log_dir / "ids_alerts.log"
    logf = open(alert_log_path, "a")
    print(f"[INFO] Logging alerts to: {alert_log_path}")

    # ---------------------------------------------------------------------
    # 4. Main IDS loop
    # ---------------------------------------------------------------------
    pcap_dir = Path(args.pcap_dir)
    seen = set()

    global RUNNING
    while RUNNING:
        for p in sorted(pcap_dir.glob("*.pcap")):
            if p.name in seen:
                continue

            print(f"[INFO] Processing {p.name}...")
            biflow_feats, biflow_meta = extract_biflow_29(p)

            if not biflow_feats:
                seen.add(p.name)
                continue

            attack_count = 0
            per_pcap_alerts = []

            # ================================================================
            # BIFLOW MODEL
            # ================================================================
            if "biflow" in active_models:
                bm = active_models["biflow"]

                df_b = pd.DataFrame(biflow_feats)
                df_b["is_attack"] = 0.0
                df_b = df_b.reindex(columns=bm["feature_names"], fill_value=0).astype(float)

                mask = np.ones(len(df_b), dtype=bool)
                if args.broker_only and args.broker_ip:
                    mask = [is_relevant_broker_flow(m, args.broker_ip, args.broker_port) for m in biflow_meta]

                mask_sys = [is_broadcast_or_system_flow(m) for m in biflow_meta]
                final_mask = [a and not b for a, b in zip(mask, mask_sys)]

                if any(final_mask):
                    df_sel = df_b.loc[final_mask]
                    meta_sel = [m for m, k in zip(biflow_meta, final_mask) if k]

                    preds = bm["model"].predict(df_sel)
                    probs = bm["model"].predict_proba(df_sel)

                    for i, lbl in enumerate(preds):
                        prob = float(max(probs[i]))
                        if lbl != "normal" and prob >= args.prob_threshold:
                            attack_count += 1

                            entry = {
                                "time": time.time(),
                                "pcap": p.name,
                                "model": "biflow",
                                "flow": meta_sel[i],
                                "predicted_label": str(lbl),
                                "prob": prob
                            }

                            print("[ALERT]", entry)
                            logf.write(json.dumps(entry) + "\n")

            # ================================================================
            # UNIFLOW MODEL (derived from biflow)
            # ================================================================
            if "uniflow" in active_models:
                um = active_models["uniflow"]

                u_rows, u_meta = biflow_to_uniflow_rows(
                    biflow_feats, biflow_meta, um["feature_names"]
                )

                if u_rows:
                    df_u = pd.DataFrame(u_rows)
                    df_u["is_attack"] = 0.0
                    df_u = df_u.reindex(columns=um["feature_names"], fill_value=0).astype(float)

                    mask = np.ones(len(df_u), dtype=bool)
                    if args.broker_only and args.broker_ip:
                        mask = [is_relevant_broker_flow(m, args.broker_ip, args.broker_port) for m in u_meta]

                    mask_sys = [is_broadcast_or_system_flow(m) for m in u_meta]
                    final_mask = [a and not b for a, b in zip(mask, mask_sys)]

                    if any(final_mask):
                        df_sel = df_u.loc[final_mask]
                        meta_sel = [m for m, k in zip(u_meta, final_mask) if k]

                        preds = um["model"].predict(df_sel)
                        probs = um["model"].predict_proba(df_sel)

                        for i, lbl in enumerate(preds):
                            prob = float(max(probs[i]))
                            if lbl != "normal" and prob >= args.prob_threshold:
                                attack_count += 1

                                entry = {
                                    "time": time.time(),
                                    "pcap": p.name,
                                    "model": "uniflow",
                                    "flow": meta_sel[i],
                                    "predicted_label": str(lbl),
                                    "prob": prob
                                }

                                print("[ALERT]", entry)
                                logf.write(json.dumps(entry) + "\n")

            # ================================================================
            # PACKET MODEL
            # ================================================================
            if "packet" in active_models:
                pm = active_models["packet"]
                pkt_rows, pkt_meta = extract_packet_level(
                    p, pm["feature_names"], broker_ip=args.broker_ip, broker_port=args.broker_port
                )

                if pkt_rows:
                    df_p = pd.DataFrame(pkt_rows)
                    df_p = df_p.reindex(columns=pm["feature_names"], fill_value=0).astype(float)

                    mask = np.ones(len(df_p), dtype=bool)
                    if args.broker_only and args.broker_ip:
                        mask = [is_relevant_broker_flow(m, args.broker_ip, args.broker_port) for m in pkt_meta]

                    mask_sys = [is_broadcast_or_system_flow(m) for m in pkt_meta]
                    final_mask = [a and not b for a, b in zip(mask, mask_sys)]

                    if any(final_mask):
                        df_sel = df_p.loc[final_mask]
                        meta_sel = [m for m, k in zip(pkt_meta, final_mask) if k]

                        preds = pm["model"].predict(df_sel)
                        probs = (
                            pm["model"].predict_proba(df_sel)
                            if hasattr(pm["model"], "predict_proba")
                            else None
                        )

                        for i, lbl in enumerate(preds):
                            prob = float(max(probs[i])) if probs is not None else 1.0
                            if lbl != "normal" and prob >= args.prob_threshold:
                                attack_count += 1

                                entry = {
                                    "time": time.time(),
                                    "pcap": p.name,
                                    "model": "packet",
                                    "flow": meta_sel[i],
                                    "predicted_label": str(lbl),
                                    "prob": prob
                                }

                                print("[ALERT]", entry)
                                logf.write(json.dumps(entry) + "\n")

            # ================================================================
            # Write summary
            # ================================================================
            with open(args.csv_out, "a") as f:
                status = "ATTACK" if attack_count > 0 else "NO_ATTACK"
                f.write(f"{time.time()},{p.name},{status},{attack_count}\n")

            seen.add(p.name)

        time.sleep(args.poll_interval)

    logf.close()
    print("[INFO] IDS stopped.")


if __name__ == "__main__":
    main()
