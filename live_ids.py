#!/usr/bin/env python3
"""
Unified Real-Time IDS for Packet / Uniflow / Biflow Modes

Automatically:
 - loads model (joblib)
 - loads train_metadata.json
 - loads saved feature order
 - applies scaler if saved
 - extracts features per PCAP
 - classifies flows/packets
 - logs alerts

Usage:
python live_ids.py --pcap-dir C:\pcaps --model model_rf.joblib --meta train_metadata.json
"""

import argparse, time, json, os
from pathlib import Path
import joblib
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP


# ---------------------------------------------------------------------
# FEATURE EXTRACTION FUNCTIONS
# ---------------------------------------------------------------------

def extract_packet_features(pcap_path):
    """Extract simple packet-level features."""
    packets = rdpcap(str(pcap_path))
    features, meta = [], []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        length = len(pkt)
        proto = pkt[IP].proto  # numeric protocol
        src = pkt[IP].src
        dst = pkt[IP].dst

        features.append([
            length,
            proto
        ])
        meta.append({
            "src": src,
            "dst": dst,
            "proto": proto
        })

    return features, meta


def extract_uniflow_features(pcap_path):
    """Extract unidirectional flow features."""
    packets = rdpcap(str(pcap_path))
    flows = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        sport, dport, proto = 0, 0, 0

        if pkt.haslayer(TCP):
            sport, dport, proto = pkt[TCP].sport, pkt[TCP].dport, 6
        elif pkt.haslayer(UDP):
            sport, dport, proto = pkt[UDP].sport, pkt[UDP].dport, 17

        key = (ip.src, ip.dst, sport, dport, proto)
        size = len(pkt)
        t = float(pkt.time)

        if key not in flows:
            flows[key] = {"sizes": [], "times": []}

        flows[key]["sizes"].append(size)
        flows[key]["times"].append(t)

    features, meta = [], []

    for (src, dst, sport, dport, proto), data in flows.items():
        sizes = np.array(data["sizes"])
        times = np.array(data["times"])

        if len(times) > 1:
            iats = np.diff(np.sort(times))
            iat_mean, iat_std = np.mean(iats), np.std(iats)
        else:
            iat_mean = iat_std = 0.0

        feat = [
            len(sizes),
            sizes.mean(),
            sizes.std(),
            iat_mean,
            iat_std
        ]

        features.append(feat)
        meta.append({
            "src": src, "dst": dst, "sport": sport,
            "dport": dport, "proto": proto
        })

    return features, meta


def extract_biflow_features(pcap_path):
    """Extract bidirectional flow features (best for MQTT BF)."""
    packets = rdpcap(str(pcap_path))
    flows = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        if pkt.haslayer(TCP):
            sport, dport, proto = pkt[TCP].sport, pkt[TCP].dport, "TCP"
        elif pkt.haslayer(UDP):
            sport, dport, proto = pkt[UDP].sport, pkt[UDP].dport, "UDP"
        else:
            sport, dport, proto = 0, 0, str(ip.proto)

        key = tuple(sorted([(ip.src, sport), (ip.dst, dport)])) + (proto,)
        size = len(pkt)
        t = float(pkt.time)

        if key not in flows:
            flows[key] = {"sizes": [], "times": [], "src": ip.src, "dst": ip.dst}

        flows[key]["sizes"].append(size)
        flows[key]["times"].append(t)

    features, meta = [], []

    for key, data in flows.items():
        sizes = np.array(data["sizes"])
        times = np.array(data["times"])

        if len(times) > 1:
            iats = np.diff(np.sort(times))
            iat_mean, iat_std = np.mean(iats), np.std(iats)
        else:
            iat_mean = iat_std = 0.0

        feat = [
            len(sizes),
            sizes.mean(),
            sizes.std(),
            iat_mean,
            iat_std
        ]

        features.append(feat)
        meta.append({"src": data["src"], "dst": data["dst"], "proto": key[-1]})

    return features, meta


# ---------------------------------------------------------------------
# MAIN IDS LOOP
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap-dir", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--meta", required=True, help="train_metadata.json")
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--out-log", default="alerts.log")
    args = parser.parse_args()

    # Load model
    model = joblib.load(args.model)
    print(f"[OK] Loaded model: {args.model}")

    # Load metadata
    meta = json.load(open(args.meta))
    feature_level = meta["feature_level"]
    scaler = None

    if "scaler_path" in meta:
        scaler = joblib.load(meta["scaler_path"])
        print("[OK] Loaded scaler")

    print(f"[INFO] Using feature level: {feature_level}")

    pcap_dir = Path(args.pcap_dir)
    seen = set()
    logf = open(args.out_log, "a")

    # Chooser
    extractor = {
        "packet": extract_packet_features,
        "uniflow": extract_uniflow_features,
        "biflow": extract_biflow_features
    }[feature_level]

    print(f"[INFO] Monitoring: {pcap_dir}")

    try:
        while True:
            for p in sorted(pcap_dir.glob("*.pcap")):
                if p.name in seen:
                    continue

                print(f"[INFO] Processing: {p.name}")
                feats, metadata = extractor(p)

                if not feats:
                    seen.add(p.name)
                    continue

                X = np.array(feats, dtype=float)

                if scaler:
                    X = scaler.transform(X)

                preds = model.predict(X)
                try:
                    probs = model.predict_proba(X)
                except:
                    probs = None

                for i, lbl in enumerate(preds):
                    if str(lbl).lower() != "normal":
                        entry = {
                            "time": time.time(),
                            "pcap": p.name,
                            "flow": metadata[i],
                            "predicted_label": str(lbl),
                            "probability": float(probs[i].max()) if probs is not None else None
                        }
                        print("[ALERT]", entry)
                        logf.write(json.dumps(entry) + "\n")
                        logf.flush()

                seen.add(p.name)

            time.sleep(args.poll_interval)

    except KeyboardInterrupt:
        print("[STOP] IDS terminated.")
    finally:
        logf.close()


if __name__ == "__main__":
    main()
