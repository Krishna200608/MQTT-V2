#!/usr/bin/env python3
"""
scripts/live_ids.py

Monitors a directory of rotating PCAP files, extracts simple biflow features,
loads a saved model (model_rf.joblib), classifies flows and logs alerts.

Usage:
python scripts/live_ids.py --pcap-dir /tmp/pcaps --model ./model_outputs/biflow/random_forest/random_forest/model_rf.joblib
"""

import argparse, time, os, joblib, json
from pathlib import Path
from scapy.all import rdpcap, IP, TCP, UDP
import numpy as np
from collections import defaultdict

# -------------------------
# Simple biflow feature extractor (per flow)
# -------------------------
def extract_biflow_features_from_pcap(pcap_path):
    packets = rdpcap(str(pcap_path))
    # flow key: tuple(sorted(src,dst)) with ports and proto and direction tag
    flows = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        proto = None
        sport = 0
        dport = 0
        if pkt.haslayer(TCP):
            proto = 'TCP'; sport = pkt[TCP].sport; dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = 'UDP'; sport = pkt[UDP].sport; dport = pkt[UDP].dport
        else:
            proto = str(ip.proto)
        src = ip.src; dst = ip.dst
        # canonical flow pair: (src,dst, sport,dport,proto)
        key = (src, dst, sport, dport, proto)
        t = float(pkt.time)
        size = len(pkt)
        if key not in flows:
            flows[key] = {"times":[],"sizes":[],"pkts":0,"src":src,"dst":dst,"sport":sport,"dport":dport,"proto":proto}
        flows[key]["times"].append(t)
        flows[key]["sizes"].append(size)
        flows[key]["pkts"] += 1
    # compute simple features per flow
    feature_rows = []
    for k,v in flows.items():
        times = np.array(v["times"])
        sizes = np.array(v["sizes"])
        if len(times) <= 1:
            iat_mean = 0.0
            iat_std = 0.0
        else:
            iats = np.diff(np.sort(times))
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
        row = {
            "src": v["src"],
            "dst": v["dst"],
            "sport": v["sport"],
            "dport": v["dport"],
            "proto": v["proto"],
            "pkt_count": int(v["pkts"]),
            "pkt_len_mean": float(np.mean(sizes)),
            "pkt_len_std": float(np.std(sizes)),
            "iat_mean": iat_mean,
            "iat_std": iat_std
        }
        feature_rows.append(row)
    return feature_rows

# -------------------------
# Main monitor & classify loop
# -------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pcap-dir", required=True, help="Directory containing rotating pcap files")
    p.add_argument("--model", required=True, help="Path to model joblib")
    p.add_argument("--poll-interval", type=float, default=2.0)
    p.add_argument("--out-log", default="alerts.log")
    args = p.parse_args()

    model = joblib.load(args.model)
    seen = set()
    pcap_dir = Path(args.pcap_dir)
    outfh = open(args.out_log, "a")
    print("Loaded model:", args.model)
    print("Monitoring PCAP dir:", pcap_dir)

    try:
        while True:
            pcap_files = sorted([p for p in pcap_dir.glob("*.pcap")])
            for p in pcap_files:
                if str(p) in seen:
                    continue
                print("Processing new pcap:", p)
                try:
                    flows = extract_biflow_features_from_pcap(p)
                    if not flows:
                        seen.add(str(p))
                        continue
                    # Build simple numeric feature matrix - ensure ordering consistent with model's expected features
                    # NOTE: adjust features to match what your model was trained on.
                    X = []
                    meta = []
                    for f in flows:
                        # feature vector: pkt_count, pkt_len_mean, pkt_len_std, iat_mean, iat_std
                        X.append([f["pkt_count"], f["pkt_len_mean"], f["pkt_len_std"], f["iat_mean"], f["iat_std"]])
                        meta.append(f)
                    import numpy as np
                    X = np.nan_to_num(np.array(X, dtype=float))
                    preds = model.predict(X)
                    # If model supports predict_proba:
                    probs = None
                    try:
                        probs = model.predict_proba(X)
                    except Exception:
                        pass
                    for i,pred in enumerate(preds):
                        label = pred
                        prob = None
                        if probs is not None:
                            # find class index
                            classes = model.classes_
                            idx = list(classes).index(pred)
                            prob = float(probs[i, idx])
                        if str(label).lower() != "normal" and label != 0 and label != "0":
                            # log alert
                            log_entry = {
                                "time": time.time(),
                                "pcap": str(p.name),
                                "flow": {"src": meta[i]["src"], "dst": meta[i]["dst"], "sport": meta[i]["sport"], "dport": meta[i]["dport"], "proto": meta[i]["proto"]},
                                "predicted_label": str(label),
                                "probability": prob
                            }
                            outfh.write(json.dumps(log_entry) + "\n")
                            outfh.flush()
                            print("ALERT:", json.dumps(log_entry))
                except Exception as e:
                    print("Error processing pcap", p, e)
                seen.add(str(p))
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        print("Stopping live IDS.")
    finally:
        outfh.close()

if __name__ == "__main__":
    main()
