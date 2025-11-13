#!/usr/bin/env python3
"""
Real-Time Biflow IDS (Full replacement with CSV summary)

New:
- For every PCAP processed, if no attack is detected, write a CSV row:
    pcap, timestamp, NO_ATTACK, 0
- If 1+ attacks: 
    pcap, timestamp, ATTACK, <count>
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

FEATURE_ORDER = [
    "prt_src", "prt_dst", "proto",
    "fwd_num_pkts", "bwd_num_pkts",
    "fwd_mean_iat", "bwd_mean_iat",
    "fwd_std_iat", "bwd_std_iat",
    "fwd_min_iat", "bwd_min_iat",
    "fwd_max_iat", "bwd_max_iat",
    "fwd_mean_pkt_len", "bwd_mean_pkt_len",
    "fwd_std_pkt_len", "bwd_std_pkt_len",
    "fwd_min_pkt_len", "bwd_min_pkt_len",
    "fwd_max_pkt_len", "bwd_max_pkt_len",
    "fwd_num_bytes", "bwd_num_bytes",
    "fwd_num_psh_flags", "bwd_num_psh_flags",
    "fwd_num_rst_flags", "bwd_num_rst_flags",
    "fwd_num_urg_flags", "bwd_num_urg_flags",
]

RUNNING = True
def handle_signal(sig, frame):
    global RUNNING
    print(f"\n[INFO] Received signal {sig}. Shutting down...")
    RUNNING = False

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# ======================================================================
# BIFLOW EXTRACTION
# ======================================================================

def extract_biflow_29(pcap_path):
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"[WARN] Failed to read pcap {pcap_path}: {e}")
        return [], []

    flows = {}

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
        elif pkt.haslayer(UDP):
            proto = 17
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        else:
            continue

        key_fwd = (ip.src, ip.dst, sport, dport, proto)
        key_bwd = (ip.dst, ip.src, dport, sport, proto)

        direction = "fwd" if key_fwd not in flows else "bwd"
        key = key_fwd if direction == "fwd" else key_bwd

        if key not in flows:
            flows[key] = {
                "fwd_sizes": [], "bwd_sizes": [],
                "fwd_times": [], "bwd_times": [],
                "fwd_psh": 0, "bwd_psh": 0,
                "fwd_rst": 0, "bwd_rst": 0,
                "fwd_urg": 0, "bwd_urg": 0,
            }

        size = len(pkt)
        t = float(pkt.time)

        if direction == "fwd":
            flows[key]["fwd_sizes"].append(size)
            flows[key]["fwd_times"].append(t)
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags & 0x08: flows[key]["fwd_psh"] += 1
                if flags & 0x04: flows[key]["fwd_rst"] += 1
                if flags & 0x20: flows[key]["fwd_urg"] += 1
        else:
            flows[key]["bwd_sizes"].append(size)
            flows[key]["bwd_times"].append(t)
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags & 0x08: flows[key]["bwd_psh"] += 1
                if flags & 0x04: flows[key]["bwd_rst"] += 1
                if flags & 0x20: flows[key]["bwd_urg"] += 1

    feature_rows, meta_rows = [], []

    def safe_stats(arr):
        if arr is None or len(arr) == 0:
            return 0.0, 0.0, 0.0, 0.0
        return float(arr.mean()), float(arr.std()), float(arr.min()), float(arr.max())

    for (src, dst, sport, dport, proto), f in flows.items():
        fs = np.array(f["fwd_sizes"]) if f["fwd_sizes"] else np.array([0])
        bs = np.array(f["bwd_sizes"]) if f["bwd_sizes"] else np.array([0])

        ft = np.sort(np.array(f["fwd_times"])) if len(f["fwd_times"]) > 1 else None
        bt = np.sort(np.array(f["bwd_times"])) if len(f["bwd_times"]) > 1 else None

        fiats = np.diff(ft) if ft is not None else np.array([])
        biats = np.diff(bt) if bt is not None else np.array([])

        f_mean_iat, f_std_iat, f_min_iat, f_max_iat = safe_stats(fiats)
        b_mean_iat, b_std_iat, b_min_iat, b_max_iat = safe_stats(biats)

        f_mean_len, f_std_len, f_min_len, f_max_len = safe_stats(fs)
        b_mean_len, b_std_len, b_min_len, b_max_len = safe_stats(bs)

        feat = {
            "prt_src": sport, "prt_dst": dport, "proto": proto,
            "fwd_num_pkts": len(fs), "bwd_num_pkts": len(bs),
            "fwd_mean_iat": f_mean_iat, "bwd_mean_iat": b_mean_iat,
            "fwd_std_iat": f_std_iat, "bwd_std_iat": b_std_iat,
            "fwd_min_iat": f_min_iat, "bwd_min_iat": b_min_iat,
            "fwd_max_iat": f_max_iat, "bwd_max_iat": b_max_iat,
            "fwd_mean_pkt_len": f_mean_len, "bwd_mean_pkt_len": b_mean_len,
            "fwd_std_pkt_len": f_std_len, "bwd_std_pkt_len": b_std_len,
            "fwd_min_pkt_len": f_min_len, "bwd_min_pkt_len": b_min_len,
            "fwd_max_pkt_len": f_max_len, "bwd_max_pkt_len": b_max_len,
            "fwd_num_bytes": int(fs.sum()), "bwd_num_bytes": int(bs.sum()),
            "fwd_num_psh_flags": f["fwd_psh"], "bwd_num_psh_flags": f["bwd_psh"],
            "fwd_num_rst_flags": f["fwd_rst"], "bwd_num_rst_flags": f["bwd_rst"],
            "fwd_num_urg_flags": f["fwd_urg"], "bwd_num_urg_flags": f["bwd_urg"],
        }

        meta_rows.append({"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto})
        feature_rows.append(feat)

    return feature_rows, meta_rows

# ======================================================================
# BROKER FILTERS
# ======================================================================

def is_relevant_broker_flow(meta, broker_ip, broker_port):
    try:
        src = meta["src"]
        dst = meta["dst"]
        sport = int(meta["sport"])
        dport = int(meta["dport"])
    except Exception:
        return False

    if (dst == broker_ip and dport == broker_port) or (src == broker_ip and sport == broker_port):
        return True

    if broker_port == 0 and (src == broker_ip or dst == broker_ip):
        return True

    return False

def is_broadcast_or_system_flow(meta):
    dst = meta.get("dst", "")
    proto = meta.get("proto", None)
    try:
        dport = int(meta.get("dport") or 0)
        sport = int(meta.get("sport") or 0)
    except:
        dport = sport = 0

    if dst.startswith("224.") or dst == "255.255.255.255":
        return True

    if proto == 17 and ({sport, dport} == {67, 68}):
        return True

    if proto == 17 and dport in (5355, 1900, 137, 138):
        return True

    return False

# ======================================================================
# MAIN LOOP
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Real-time biflow IDS with CSV summary")
    parser.add_argument("--pcap-dir", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--meta", required=True)
    parser.add_argument("--out-log", default="alerts.log")
    parser.add_argument("--csv-out", default="ids_summary.csv", help="CSV summary output")  ### >>> ADDED <<<
    parser.add_argument("--broker-ip", default="192.168.0.100")
    parser.add_argument("--broker-port", type=int, default=1883)
    parser.add_argument("--broker-only", action="store_true")
    parser.add_argument("--prob-threshold", type=float, default=0.75)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    args = parser.parse_args()

    print("[OK] Loading model...")
    model = joblib.load(args.model)

    # Prepare CSV summary file header
    if not Path(args.csv_out).exists():                                          ### >>> ADDED <<<
        with open(args.csv_out, "w") as f:
            f.write("time,pcap,status,attack_count\n")

    # Read metadata
    try:
        meta = json.load(open(args.meta))
        feature_level = meta.get("feature_level", "biflow")
    except:
        feature_level = "biflow"

    print(f"[INFO] Feature Level: {feature_level}")
    print("[INFO] IDS Ready")
    print(f"[INFO] CSV summary → {args.csv_out}")                                ### >>> ADDED <<<

    pcap_dir = Path(args.pcap_dir)
    seen = set()
    logf = open(args.out_log, "a")

    global RUNNING

    while RUNNING:
        for p in sorted(pcap_dir.glob("*.pcap")):
            if p.name in seen:
                continue

            print(f"[INFO] Processing {p.name} ...")
            feats, meta_rows = extract_biflow_29(p)

            if not feats:
                seen.add(p.name)
                continue

            df = pd.DataFrame(feats).reindex(columns=FEATURE_ORDER, fill_value=0).astype(float)

            mask = np.ones(len(df), dtype=bool)
            if args.broker_only:
                mask = [is_relevant_broker_flow(m, args.broker_ip, args.broker_port) for m in meta_rows]
                if not any(mask):
                    seen.add(p.name)
                    continue

            mask_system = [is_broadcast_or_system_flow(m) for m in meta_rows]
            final_mask = [r and not s for r, s in zip(mask, mask_system)]

            if not any(final_mask):
                seen.add(p.name)
                continue

            df_sel = df.loc[final_mask, :].reset_index(drop=True)
            meta_sel = [m for m, k in zip(meta_rows, final_mask) if k]

            preds = model.predict(df_sel)
            try:
                probs = model.predict_proba(df_sel)
            except:
                probs = None

            attack_count = 0  ### >>> ADDED <<<

            for i, lbl in enumerate(preds):
                prob = float(max(probs[i])) if probs is not None else None
                is_attack = (lbl != 0)

                if is_attack and (prob is None or prob >= args.prob_threshold):
                    attack_count += 1  ### >>> ADDED <<<
                    entry = {
                        "time": time.time(),
                        "pcap": p.name,
                        "flow": meta_sel[i],
                        "predicted_label": str(lbl),
                        "prob": prob
                    }
                    print("[ALERT]", entry)
                    logf.write(json.dumps(entry) + "\n")

            # After finishing one PCAP → write summary CSV                  ### >>> ADDED <<<
            with open(args.csv_out, "a") as f:
                status = "ATTACK" if attack_count > 0 else "NO_ATTACK"
                f.write(f"{time.time()},{p.name},{status},{attack_count}\n")

            seen.add(p.name)

        time.sleep(args.poll_interval)

    logf.close()
    print("[INFO] IDS stopped.")


if __name__ == "__main__":
    main()
