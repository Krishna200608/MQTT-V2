#!/usr/bin/env python3
# live_ids.py
"""
Main IDS runner that loads models_config.json, runs biflow/uniflow/packet models,
and also runs heuristic detectors (from heuristics.py) which are logged as high-confidence alerts.

Usage example:
python live_ids.py --pcap-dir /path/to/pcaps --models-config /path/to/models_config.json --broker-ip 10.0.0.1
"""

import argparse
import json
import joblib
import time
import sys
import signal
from pathlib import Path

import numpy as np
import pandas as pd

from extractor import extract_biflow_29, biflow_to_uniflow_rows, extract_packet_level
from heuristics import detect_mqtt_bruteforce, detect_ssh_bruteforce, detect_tcp_udp_scans

RUNNING = True
def handle_signal(sig, frame):
    global RUNNING
    print(f"\\n[INFO] Received signal {sig}. Shutting down...")
    RUNNING = False

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

def load_models(models_cfg_path):
    project_root = models_cfg_path.parent.parent
    with open(models_cfg_path, "r") as f:
        models_cfg = json.load(f)

    active_models = {}
    for key in ("packet", "uniflow", "biflow"):
        entry = models_cfg.get(key)
        if not entry or not entry.get("enabled", False):
            print(f"[INFO] Model '{key}' disabled or not configured.")
            continue

        model_path = (project_root / entry["model_path"]).resolve()
        meta_path  = (project_root / entry["meta_path"]).resolve()

        if not model_path.exists():
            print(f"[WARN] Model file for '{key}' NOT FOUND: {model_path}")
            continue
        if not meta_path.exists():
            print(f"[WARN] Metadata for '{key}' NOT FOUND: {meta_path}")
            continue

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
    return active_models

def write_alert(logf, entry):
    logf.write(json.dumps(entry) + "\\n")
    logf.flush()

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

    models_cfg_path = Path(args.models_config).resolve()
    if not models_cfg_path.exists():
        print(f"[ERROR] models_config.json not found at {models_cfg_path}")
        sys.exit(1)

    active_models = load_models(models_cfg_path)
    if not active_models:
        print("[FATAL] No models successfully loaded. Exiting.")
        sys.exit(1)

    if not Path(args.csv_out).exists():
        with open(args.csv_out, "w") as f:
            f.write("time,pcap,status,attack_count\\n")

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
            biflow_feats, biflow_meta = extract_biflow_29(p)

            if not biflow_feats:
                seen.add(p.name)
                continue

            # ---------- Heuristics ----------
            heur_alerts = []
            heur_alerts.extend(detect_mqtt_bruteforce(biflow_meta, broker_ip=args.broker_ip, broker_port=args.broker_port))
            heur_alerts.extend(detect_ssh_bruteforce(biflow_meta))
            heur_alerts.extend(detect_tcp_udp_scans(biflow_meta))

            for a in heur_alerts:
                entry = {
                    "time": time.time(),
                    "pcap": p.name,
                    "model": "heuristic",
                    "flow": a.get('flow'),
                    "predicted_label": a.get('type'),
                    "prob": 1.0,
                    "meta": {k:v for k,v in a.items() if k not in ("flow","type")}
                }
                print("[HEURISTIC ALERT]", entry)
                write_alert(logf, entry)

            attack_count = len([1 for a in heur_alerts if a.get('type') != 'normal'])

            # ---------- Biflow model ----------
            if "biflow" in active_models:
                bm = active_models["biflow"]
                df_b = pd.DataFrame(biflow_feats)
                df_b["is_attack"] = 0.0
                df_b = df_b.reindex(columns=bm["feature_names"], fill_value=0).astype(float)

                mask = np.ones(len(df_b), dtype=bool)
                if args.broker_only and args.broker_ip:
                    mask = [ (m.get('dst')==args.broker_ip and int(m.get('dport',0))==args.broker_port) or (m.get('src')==args.broker_ip and int(m.get('sport',0))==args.broker_port) for m in biflow_meta ]

                mask_sys = [ ( (m.get('dst','').startswith('224.') if isinstance(m.get('dst',''),str) else False) or m.get('dst')=='255.255.255.255' or (int(m.get('proto',0))==17 and {int(m.get('sport',0)), int(m.get('dport',0))}=={67,68}) ) for m in biflow_meta ]
                final_mask = [a and not b for a,b in zip(mask, mask_sys)]

                if any(final_mask):
                    df_sel = df_b.loc[final_mask]
                    meta_sel = [m for m,k in zip(biflow_meta, final_mask) if k]

                    preds = bm["model"].predict(df_sel)
                    probs = bm["model"].predict_proba(df_sel)

                    for i, lbl in enumerate(preds):
                        prob = float(max(probs[i]))
                        if lbl != "normal" and prob >= args.prob_threshold:
                            attack_count += 1
                            entry = {"time": time.time(), "pcap": p.name, "model": "biflow", "flow": meta_sel[i], "predicted_label": str(lbl), "prob": prob}
                            print("[ALERT]", entry)
                            write_alert(logf, entry)

            # ---------- Uniflow model ----------
            if "uniflow" in active_models:
                um = active_models["uniflow"]
                u_rows, u_meta = biflow_to_uniflow_rows(biflow_feats, biflow_meta, um["feature_names"])
                if u_rows:
                    df_u = pd.DataFrame(u_rows)
                    df_u["is_attack"] = 0.0
                    df_u = df_u.reindex(columns=um["feature_names"], fill_value=0).astype(float)

                    mask = np.ones(len(df_u), dtype=bool)
                    if args.broker_only and args.broker_ip:
                        mask = [ (m.get('dst')==args.broker_ip and int(m.get('dport',0))==args.broker_port) or (m.get('src')==args.broker_ip and int(m.get('sport',0))==args.broker_port) for m in u_meta ]

                    mask_sys = [ ( (m.get('dst','').startswith('224.') if isinstance(m.get('dst',''),str) else False) or m.get('dst')=='255.255.255.255' or (int(m.get('proto',0))==17 and {int(m.get('sport',0)), int(m.get('dport',0))}=={67,68}) ) for m in u_meta ]
                    final_mask = [a and not b for a,b in zip(mask, mask_sys)]

                    if any(final_mask):
                        df_sel = df_u.loc[final_mask]
                        meta_sel = [m for m,k in zip(u_meta, final_mask) if k]

                        preds = um["model"].predict(df_sel)
                        probs = um["model"].predict_proba(df_sel)

                        for i, lbl in enumerate(preds):
                            prob = float(max(probs[i]))
                            if lbl != "normal" and prob >= args.prob_threshold:
                                attack_count += 1
                                entry = {"time": time.time(), "pcap": p.name, "model": "uniflow", "flow": meta_sel[i], "predicted_label": str(lbl), "prob": prob}
                                print("[ALERT]", entry)
                                write_alert(logf, entry)

            # ---------- Packet model ----------
            if "packet" in active_models:
                pm = active_models["packet"]
                pkt_rows, pkt_meta = extract_packet_level(p, pm["feature_names"], broker_ip=args.broker_ip, broker_port=args.broker_port)
                if pkt_rows:
                    df_p = pd.DataFrame(pkt_rows)
                    df_p = df_p.reindex(columns=pm["feature_names"], fill_value=0).astype(float)

                    mask = np.ones(len(df_p), dtype=bool)
                    if args.broker_only and args.broker_ip:
                        mask = [ (m.get('dst')==args.broker_ip and int(m.get('dport',0))==args.broker_port) or (m.get('src')==args.broker_ip and int(m.get('sport',0))==args.broker_port) for m in pkt_meta ]

                    mask_sys = [ ( (m.get('dst','').startswith('224.') if isinstance(m.get('dst',''),str) else False) or m.get('dst')=='255.255.255.255' or (int(m.get('proto',0))==17 and {int(m.get('sport',0)), int(m.get('dport',0))}=={67,68}) ) for m in pkt_meta ]
                    final_mask = [a and not b for a,b in zip(mask, mask_sys)]

                    if any(final_mask):
                        df_sel = df_p.loc[final_mask]
                        meta_sel = [m for m,k in zip(pkt_meta, final_mask) if k]

                        preds = pm["model"].predict(df_sel)
                        probs = pm["model"].predict_proba(df_sel) if hasattr(pm["model"], "predict_proba") else None

                        for i, lbl in enumerate(preds):
                            prob = float(max(probs[i])) if probs is not None else 1.0
                            if lbl != "normal" and prob >= args.prob_threshold:
                                attack_count += 1
                                entry = {"time": time.time(), "pcap": p.name, "model": "packet", "flow": meta_sel[i], "predicted_label": str(lbl), "prob": prob}
                                print("[ALERT]", entry)
                                write_alert(logf, entry)

            # summary
            with open(args.csv_out, "a") as f:
                status = "ATTACK" if attack_count > 0 else "NO_ATTACK"
                f.write(f"{time.time()},{p.name},{status},{attack_count}\\n")

            seen.add(p.name)

        time.sleep(args.poll_interval)

    logf.close()
    print("[INFO] IDS stopped.")


if __name__ == "__main__":
    main()
