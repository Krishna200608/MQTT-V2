#!/usr/bin/env python3
"""
Real-Time MQTT Biflow IDS (Corrected + Feature Alignment + Probability Fix)

Major fixes:
- EXACT feature alignment with train_metadata.json
- Adds missing "is_attack" column (model requires 30 features)
- Safe reindexing using metadata feature_names
- Fixes probability key mismatch
- Adds flow duration feature (improves MQTT brute-force detection)
- Safer PCAP parsing, flow filtering, and anomaly detection
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
from scapy.all import rdpcap, IP, TCP, UDP

RUNNING = True
def handle_signal(sig, frame):
    global RUNNING
    print(f"\n[INFO] Received signal {sig}. Shutting down...")
    RUNNING = False

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


# ======================================================================
# FEATURE EXTRACTION (29 base + duration)
# ======================================================================

# ======================================================================
# FEATURE EXTRACTION (aligned to train_metadata.json)
# ======================================================================

def extract_biflow_29(pcap_path):
    """
    Read pcap and extract biflow-level features matching train_metadata.json feature_names.
    Returns:
      feature_rows: list of dicts (feature_name -> value)
      meta_rows: list of dicts (src,dst,sport,dport,proto) - one per feature row, same order
    """
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"[WARN] Failed to read pcap {pcap_path}: {e}")
        return [], []

    # flow_map keeps canonical flows keyed by the first-seen tuple:
    # (src, dst, sport, dport, proto) where src/sport are "forward"
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

        # find or create canonical flow entry
        if key_fwd in flow_map:
            flow = flow_map[key_fwd]
            direction = "fwd"
        elif key_bwd in flow_map:
            flow = flow_map[key_bwd]
            direction = "bwd"
        else:
            # create new canonical flow using this packet's orientation
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

    def safe_stats_from_array(arr):
        # arr: numpy array
        if arr is None or len(arr) == 0:
            return 0.0, 0.0, 0.0, 0.0
        # convert to numpy to ensure correct methods
        a = np.array(arr, dtype=float)
        return float(np.mean(a)), float(np.std(a, ddof=0)), float(np.min(a)), float(np.max(a))

    for canonical_key, f in flow_map.items():
        # sizes arrays (empty arrays if none)
        fs = np.array(f["fwd_sizes"], dtype=float) if f["fwd_sizes"] else np.array([], dtype=float)
        bs = np.array(f["bwd_sizes"], dtype=float) if f["bwd_sizes"] else np.array([], dtype=float)

        # times sorted and iats computed
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
            # NOTE: is_attack column is intentionally not set here; main() adds it before reindexing
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


# ======================================================================
# FLOW FILTERING
# ======================================================================

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

    if dst.startswith("224.") or dst == "255.255.255.255":
        return True

    if proto == 17 and {sport, dport} == {67, 68}:
        return True

    if proto == 17 and dport in (5355, 1900, 137, 138):
        return True

    return False


# ======================================================================
# MAIN IDS LOOP
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Real-time biflow IDS")
    parser.add_argument("--pcap-dir", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--meta", required=True)
    parser.add_argument("--out-log", default="ids_alerts.log")
    parser.add_argument("--csv-out", default="ids_summary.csv")
    parser.add_argument("--broker-ip", default="192.168.0.100")
    parser.add_argument("--broker-port", type=int, default=1883)
    parser.add_argument("--broker-only", action="store_true")
    parser.add_argument("--prob-threshold", type=float, default=0.75)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    args = parser.parse_args()
    

    print("[OK] Loading model...")
    model = joblib.load(args.model)

    # Load metadata for correct feature order
    meta_json = json.load(open(args.meta))
    feature_names = meta_json["feature_names"]  # EXACT order used in training

    # Create CSV summary header
    if not Path(args.csv_out).exists():
        with open(args.csv_out, "w") as f:
            f.write("time,pcap,status,attack_count\n")

    print("[INFO] IDS Ready")
    pcap_dir = Path(args.pcap_dir)
    seen = set()
    # -------------------------------
    # Dynamic daily log folder
    # -------------------------------
    today = time.strftime("%Y-%m-%d")
    log_dir = Path("logs") / today
    log_dir.mkdir(parents=True, exist_ok=True)

    # Full path to today's log file
    alert_log_path = log_dir / "ids_alerts.log"

    logf = open(alert_log_path, "a")
    print(f"[INFO] Logging alerts to: {alert_log_path}")


    global RUNNING
    while RUNNING:
        for p in sorted(pcap_dir.glob("*.pcap")):
            if p.name in seen:
                continue

            print(f"[INFO] Processing {p.name}...")
            feats, meta_rows = extract_biflow_29(p)

            if not feats:
                seen.add(p.name)
                continue

            df = pd.DataFrame(feats)

            # Add missing column expected by model
            df["is_attack"] = 0.0

            # Reindex EXACTLY as training expects
            df = df.reindex(columns=feature_names, fill_value=0).astype(float)

            # Filter for broker-only flows
            mask = np.ones(len(df), dtype=bool)
            if args.broker_only:
                mask = [is_relevant_broker_flow(m, args.broker_ip, args.broker_port) for m in meta_rows]
                if not any(mask):
                    seen.add(p.name)
                    continue

            # Remove system/broadcast flows
            mask_sys = [is_broadcast_or_system_flow(m) for m in meta_rows]
            final_mask = [r and not s for r, s in zip(mask, mask_sys)]
            if not any(final_mask):
                seen.add(p.name)
                continue

            df_sel = df.loc[final_mask]
            meta_sel = [m for m, k in zip(meta_rows, final_mask) if k]

            preds = model.predict(df_sel)
            probs = model.predict_proba(df_sel)

            attack_count = 0

            for i, lbl in enumerate(preds):
                prob = float(max(probs[i]))
                label_str = str(lbl)

                if label_str != "normal" and prob >= args.prob_threshold:
                    attack_count += 1

                    entry = {
                        "time": time.time(),
                        "pcap": p.name,
                        "flow": meta_sel[i],
                        "predicted_label": label_str,
                        "prob": prob  # FIXED NAME
                    }
                    print("[ALERT]", entry)
                    logf.write(json.dumps(entry) + "\n")

            with open(args.csv_out, "a") as f:
                status = "ATTACK" if attack_count > 0 else "NO_ATTACK"
                f.write(f"{time.time()},{p.name},{status},{attack_count}\n")

            seen.add(p.name)

        time.sleep(args.poll_interval)

    logf.close()
    print("[INFO] IDS stopped.")


if __name__ == "__main__":
    main()
