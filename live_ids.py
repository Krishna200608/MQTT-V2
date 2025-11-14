#!/usr/bin/env python3
"""
Unified live_ids.py that supports three models (packet, uniflow, biflow) defined
by models_config.json. Logs alerts to logs/YYYY-MM-DD/ids_alerts.log.

Drop models_config.json and network_config.json into repo root.
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
from scapy.all import rdpcap, IP, TCP, UDP, Raw

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
# Biflow extractor (your logic)
# -------------------------
def extract_biflow_29(pcap_path):
    """
    Returns (feature_rows, meta_rows).
    feature_rows: list of dicts matching biflow features (without is_attack)
    meta_rows: list of meta dicts with src,dst,sport,dport,proto
    """
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"[WARN] Failed to read pcap {pcap_path}: {e}")
        return [], []

    flow_map = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]

        proto = None
        sport = dport = None

        if pkt.haslayer(TCP):
            proto = 6
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flags = pkt[TCP].flags
        elif pkt.haslayer(UDP):
            proto = 17
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            flags = 0
        else:
            continue

        key_fwd = (ip.src, ip.dst, sport, dport, proto)
        key_bwd = (ip.dst, ip.src, dport, sport, proto)

        if key_fwd in flow_map:
            flow = flow_map[key_fwd]
            direction = "fwd"
        elif key_bwd in flow_map:
            flow = flow_map[key_bwd]
            direction = "bwd"
        else:
            flow = {
                "src": ip.src, "dst": ip.dst, "sport": sport, "dport": dport, "proto": proto,
                "fwd_sizes": [], "bwd_sizes": [],
                "fwd_times": [], "bwd_times": [],
                "fwd_psh": 0, "bwd_psh": 0,
                "fwd_rst": 0, "bwd_rst": 0,
                "fwd_urg": 0, "bwd_urg": 0,
            }
            flow_map[key_fwd] = flow
            direction = "fwd"

        size = len(pkt)
        t = float(pkt.time)

        if direction == "fwd":
            flow["fwd_sizes"].append(size)
            flow["fwd_times"].append(t)
            if pkt.haslayer(TCP):
                if flags & 0x08: flow["fwd_psh"] += 1
                if flags & 0x04: flow["fwd_rst"] += 1
                if flags & 0x20: flow["fwd_urg"] += 1
        else:
            flow["bwd_sizes"].append(size)
            flow["bwd_times"].append(t)
            if pkt.haslayer(TCP):
                if flags & 0x08: flow["bwd_psh"] += 1
                if flags & 0x04: flow["bwd_rst"] += 1
                if flags & 0x20: flow["bwd_urg"] += 1

    feature_rows = []
    meta_rows = []

    for canonical_key, f in flow_map.items():
        fs = np.array(f["fwd_sizes"], dtype=float) if f["fwd_sizes"] else np.array([], dtype=float)
        bs = np.array(f["bwd_sizes"], dtype=float) if f["bwd_sizes"] else np.array([], dtype=float)
        ft = np.sort(np.array(f["fwd_times"], dtype=float)) if f["fwd_times"] else np.array([], dtype=float)
        bt = np.sort(np.array(f["bwd_times"], dtype=float)) if f["bwd_times"] else np.array([], dtype=float)

        fiats = np.diff(ft) if ft.size > 1 else np.array([], dtype=float)
        biats = np.diff(bt) if bt.size > 1 else np.array([], dtype=float)

        f_mean_iat, f_std_iat, f_min_iat, f_max_iat = safe_stats_from_array(fiats)
        b_mean_iat, b_std_iat, b_min_iat, b_max_iat = safe_stats_from_array(biats)

        f_mean_len, f_std_len, f_min_len, f_max_len = safe_stats_from_array(fs)
        b_mean_len, b_std_len, b_min_len, b_max_len = safe_stats_from_array(bs)

        f_num_pkts = int(fs.size)
        b_num_pkts = int(bs.size)

        f_num_bytes = int(fs.sum()) if fs.size > 0 else 0
        b_num_bytes = int(bs.sum()) if bs.size > 0 else 0

        feat = {
            "prt_src": int(f["sport"]) if f.get("sport") is not None else int(canonical_key[2]),
            "prt_dst": int(f["dport"]) if f.get("dport") is not None else int(canonical_key[3]),
            "proto": int(f["proto"]) if f.get("proto") is not None else int(canonical_key[4]),

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

            "fwd_num_psh_flags": int(f.get("fwd_psh", 0)),
            "bwd_num_psh_flags": int(f.get("bwd_psh", 0)),
            "fwd_num_rst_flags": int(f.get("fwd_rst", 0)),
            "bwd_num_rst_flags": int(f.get("bwd_rst", 0)),
            "fwd_num_urg_flags": int(f.get("fwd_urg", 0)),
            "bwd_num_urg_flags": int(f.get("bwd_urg", 0)),
        }

        meta_rows.append({
            "src": f.get("src", canonical_key[0]),
            "dst": f.get("dst", canonical_key[1]),
            "sport": int(f.get("sport", canonical_key[2])),
            "dport": int(f.get("dport", canonical_key[3])),
            "proto": int(f.get("proto", canonical_key[4]))
        })

        feature_rows.append(feat)

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
        # best-effort mapping (common uniflow names)
        # Example uniflow feature names (train metadata may vary) handled generically:
        # prt_src, prt_dst, proto, num_pkts, mean_iat, std_iat, min_iat, max_iat,
        # mean_pkt_len, num_bytes, num_psh_flags, num_rst_flags, num_urg_flags, std_pkt_len, min_pkt_len, max_pkt_len, is_attack
        # Map using fwd_* and bwd_* fields
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
                # copy prt_src/prt_dst/proto from feat if requested
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
    This is intentionally permissive so we can run DT packet model if its feature list exists.
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
            "tcp_flags": tcp_flags
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
    parser.add_argument("--models-config", default="models_config.json", help="Path to models_config.json")
    parser.add_argument("--out-log", default="ids_alerts.log")
    parser.add_argument("--csv-out", default="ids_summary.csv")
    parser.add_argument("--broker-ip", default=None)
    parser.add_argument("--broker-port", type=int, default=1883)
    parser.add_argument("--broker-only", action="store_true")
    parser.add_argument("--prob-threshold", type=float, default=0.75)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    args = parser.parse_args()

    # load models config
    models_cfg_path = Path(args.models_config)
    if not models_cfg_path.exists():
        print(f"[WARN] models_config.json not found at {models_cfg_path}. Exiting.")
        sys.exit(1)
    models_cfg = json.load(open(models_cfg_path))

    # Attempt to load models and metadata
    active_models = {}
    for key in ("packet", "uniflow", "biflow"):
        entry = models_cfg.get(key)
        if not entry or not entry.get("enabled", False):
            print(f"[INFO] model '{key}' disabled or not configured.")
            continue
        model_path = Path(entry["model_path"])
        meta_path = Path(entry["meta_path"])
        if not model_path.exists():
            print(f"[WARN] model file for '{key}' not found: {model_path}. Skipping.")
            continue
        if not meta_path.exists():
            print(f"[WARN] metadata for '{key}' not found: {meta_path}. Skipping '{key}'.")
            continue
        try:
            mdl = joblib.load(str(model_path))
            meta_json = json.load(open(str(meta_path)))
            feature_names = meta_json.get("feature_names", [])
            active_models[key] = {"model": mdl, "feature_names": feature_names, "meta_json": meta_json}
            print(f"[OK] Loaded '{key}' model from {model_path}")
        except Exception as e:
            print(f"[WARN] Failed to load {key} model/meta: {e}")

    if not active_models:
        print("[ERROR] No models loaded. Check models_config.json and paths.")
        sys.exit(1)

    # CSV summary header
    if not Path(args.csv_out).exists():
        with open(args.csv_out, "w") as f:
            f.write("time,pcap,status,attack_count\n")

    # dynamic daily log folder
    today = time.strftime("%Y-%m-%d")
    log_dir = Path("logs") / today
    log_dir.mkdir(parents=True, exist_ok=True)
    alert_log_path = log_dir / "ids_alerts.log"
    logf = open(alert_log_path, "a")
    print(f"[INFO] Logging alerts to: {alert_log_path}")

    pcap_dir = Path(args.pcap_dir)
    seen = set()

    global RUNNING
    while RUNNING:
        for p in sorted(pcap_dir.glob("*.pcap")):
            if p.name in seen:
                continue
            print(f"[INFO] Processing {p.name}...")
            # core biflow extraction
            biflow_feats, biflow_meta = extract_biflow_29(p)
            if not biflow_feats:
                seen.add(p.name)
                continue

            attack_count = 0
            per_pcap_alerts = []

            # ----------------------
            # BIFLOW predictions
            # ----------------------
            if "biflow" in active_models:
                bm = active_models["biflow"]
                df_b = pd.DataFrame(biflow_feats)
                df_b["is_attack"] = 0.0
                # reindex to expected order
                df_b = df_b.reindex(columns=bm["feature_names"], fill_value=0).astype(float)
                # broker-only filter
                mask = np.ones(len(df_b), dtype=bool)
                if args.broker_only and args.broker_ip:
                    mask = [is_relevant_broker_flow(m, args.broker_ip, args.broker_port) for m in biflow_meta]
                    if not any(mask):
                        print("[DEBUG] No broker flows for biflow in this pcap.")
                        pass
                mask_sys = [is_broadcast_or_system_flow(m) for m in biflow_meta]
                final_mask = [r and not s for r, s in zip(mask, mask_sys)]
                if any(final_mask):
                    df_sel = df_b.loc[final_mask]
                    meta_sel = [m for m, k in zip(biflow_meta, final_mask) if k]
                    preds = bm["model"].predict(df_sel)
                    probs = bm["model"].predict_proba(df_sel)
                    for i, lbl in enumerate(preds):
                        prob = float(max(probs[i]))
                        label_str = str(lbl)
                        if label_str != "normal" and prob >= args.prob_threshold:
                            attack_count += 1
                            entry = {
                                "time": time.time(),
                                "pcap": p.name,
                                "model": "biflow",
                                "flow": meta_sel[i],
                                "predicted_label": label_str,
                                "prob": prob
                            }
                            print("[ALERT]", entry)
                            logf.write(json.dumps(entry) + "\n")
                            per_pcap_alerts.append(entry)

            # ----------------------
            # UNIFLOW predictions (derived from biflow)
            # ----------------------
            if "uniflow" in active_models:
                um = active_models["uniflow"]
                # create uniflow rows (2 per biflow)
                u_rows, u_meta = biflow_to_uniflow_rows(biflow_feats, biflow_meta, um["feature_names"])
                if u_rows:
                    df_u = pd.DataFrame(u_rows)
                    df_u["is_attack"] = 0.0
                    df_u = df_u.reindex(columns=um["feature_names"], fill_value=0).astype(float)
                    # apply broker-only if requested
                    mask = np.ones(len(df_u), dtype=bool)
                    if args.broker_only and args.broker_ip:
                        mask = [is_relevant_broker_flow(m, args.broker_ip, args.broker_port) for m in u_meta]
                    mask_sys = [is_broadcast_or_system_flow(m) for m in u_meta]
                    final_mask = [r and not s for r, s in zip(mask, mask_sys)]
                    if any(final_mask):
                        df_sel = df_u.loc[final_mask]
                        meta_sel = [m for m, k in zip(u_meta, final_mask) if k]
                        preds = um["model"].predict(df_sel)
                        probs = um["model"].predict_proba(df_sel)
                        for i, lbl in enumerate(preds):
                            prob = float(max(probs[i]))
                            label_str = str(lbl)
                            if label_str != "normal" and prob >= args.prob_threshold:
                                attack_count += 1
                                entry = {
                                    "time": time.time(),
                                    "pcap": p.name,
                                    "model": "uniflow",
                                    "flow": meta_sel[i],
                                    "predicted_label": label_str,
                                    "prob": prob
                                }
                                print("[ALERT]", entry)
                                logf.write(json.dumps(entry) + "\n")
                                per_pcap_alerts.append(entry)

            # ----------------------
            # PACKET-level predictions (best-effort)
            # ----------------------
            if "packet" in active_models:
                pm = active_models["packet"]
                # try to extract packet-level rows based on packet meta
                pkt_rows, pkt_meta = extract_packet_level(p, pm["feature_names"], broker_ip=args.broker_ip, broker_port=args.broker_port)
                if pkt_rows:
                    df_p = pd.DataFrame(pkt_rows)
                    # ensure ordering and missing columns filled
                    df_p = df_p.reindex(columns=pm["feature_names"], fill_value=0).astype(float)
                    # apply broker-only & system filters per packet
                    mask = np.ones(len(df_p), dtype=bool)
                    if args.broker_only and args.broker_ip:
                        mask = [is_relevant_broker_flow(m, args.broker_ip, args.broker_port) for m in pkt_meta]
                        if not any(mask):
                            pass
                    mask_sys = [is_broadcast_or_system_flow(m) for m in pkt_meta]
                    final_mask = [r and not s for r, s in zip(mask, mask_sys)]
                    if any(final_mask):
                        df_sel = df_p.loc[final_mask]
                        meta_sel = [m for m, k in zip(pkt_meta, final_mask) if k]
                        preds = pm["model"].predict(df_sel)
                        # not all scikit models have predict_proba; guard it
                        has_proba = hasattr(pm["model"], "predict_proba")
                        probs = pm["model"].predict_proba(df_sel) if has_proba else None
                        for i, lbl in enumerate(preds):
                            prob = float(max(probs[i])) if probs is not None else 1.0
                            label_str = str(lbl)
                            if label_str != "normal" and prob >= args.prob_threshold:
                                attack_count += 1
                                entry = {
                                    "time": time.time(),
                                    "pcap": p.name,
                                    "model": "packet",
                                    "flow": meta_sel[i],
                                    "predicted_label": label_str,
                                    "prob": prob
                                }
                                print("[ALERT]", entry)
                                logf.write(json.dumps(entry) + "\n")
                                per_pcap_alerts.append(entry)

            # write summary line
            with open(args.csv_out, "a") as f:
                status = "ATTACK" if attack_count > 0 else "NO_ATTACK"
                f.write(f"{time.time()},{p.name},{status},{attack_count}\n")

            seen.add(p.name)

        time.sleep(args.poll_interval)

    logf.close()
    print("[INFO] IDS stopped.")

if __name__ == "__main__":
    main()
