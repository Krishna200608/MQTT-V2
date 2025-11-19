#!/usr/bin/env python3
# live_ids.py (UPDATED FOR PREPROCESSOR SUPPORT + string labels)

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
    print(f"\n[INFO] Received signal {sig}. Shutting down...")
    RUNNING = False

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

INT_TO_LABEL = {
    0: "normal",
    1: "scan_A",
    2: "scan_sU",
    3: "sparta",
    4: "mqtt_bruteforce"
}

# Colors for labels (ANSI)
LABEL_COLORS = {
    "normal": "\033[37m",             # white
    "scan_A": "\033[91m",             # red
    "scan_sU": "\033[95m",            # magenta
    "sparta": "\033[93m",             # yellow
    "mqtt_bruteforce": "\033[96m",    # cyan
}

RESET = "\033[0m"

def colorize_label(lbl, enable=True):
    if not enable:
        return lbl
    color = LABEL_COLORS.get(lbl, "\033[92m")  # green fallback
    return f"{color}{lbl}{RESET}"


# ===================================================================
# LOAD MODELS + PREPROCESSOR (NEW)
# ===================================================================
def load_models(models_cfg_path):
    project_root = models_cfg_path.parent.parent

    with open(models_cfg_path, "r") as f:
        models_cfg = json.load(f)

    active_models = {}

    for key in ("packet", "uniflow", "biflow"):
        entry = models_cfg.get(key)
        if not entry or not entry.get("enabled", False):
            print(f"[INFO] Model '{key}' disabled.")
            continue

        model_path = (project_root / entry["model_path"]).resolve()
        meta_path  = (project_root / entry["meta_path"]).resolve()
        preproc_path = (project_root / entry.get("preproc_path", "")).resolve()

        if not model_path.exists():
            print(f"[WARN] '{key}' model not found:", model_path)
            continue
        if not meta_path.exists():
            print(f"[WARN] '{key}' metadata not found:", meta_path)
            continue
        if not preproc_path.exists():
            print(f"[WARN] '{key}' PREPROCESSOR NOT FOUND:", preproc_path)
            continue

        try:
            model = joblib.load(model_path)
            meta = json.load(open(meta_path))
            preproc = joblib.load(preproc_path)

            feature_names = meta.get("feature_names", [])

            active_models[key] = {
                "model": model,
                "preprocessor": preproc,     # ← NEW
                "feature_names": feature_names,
                "meta_json": meta
            }
            print(f"[OK] Loaded model '{key}' (with preprocessor)")

        except Exception as e:
            print(f"[ERROR] Could not load '{key}': {e}")

    return active_models

def json_safe(obj):
    """Recursively convert sets and numpy types to JSON-safe objects."""
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}

    elif isinstance(obj, (list, tuple)):
        return [json_safe(x) for x in obj]

    elif isinstance(obj, set):
        return [json_safe(x) for x in obj]     # convert set → list

    elif isinstance(obj, np.integer):
        return int(obj)

    elif isinstance(obj, np.floating):
        return float(obj)

    else:
        return obj


def write_alert(logf, entry):
    safe_entry = json_safe(entry)
    logf.write(json.dumps(safe_entry) + "\n")
    logf.flush()




# ===================================================================
# MAIN LOOP
# ===================================================================
def main():
    parser = argparse.ArgumentParser(description="Real-time IDS updated (packet/uniflow/biflow)")
    parser.add_argument("--pcap-dir", required=True)
    parser.add_argument("--models-config", default="../configs/models_config.json")
    parser.add_argument("--out-log", default="ids_alerts.log")
    parser.add_argument("--csv-out", default="ids_summary.csv")
    parser.add_argument("--broker-ip", default=None)
    parser.add_argument("--broker-port", type=int, default=1883)
    parser.add_argument("--broker-only", action="store_true")
    parser.add_argument("--prob-threshold", type=float, default=0.75)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--color-output", action="store_true",
                    help="Display alert labels with colored tags in console output")

    args = parser.parse_args()

    models_cfg_path = Path(args.models_config).resolve()
    if not models_cfg_path.exists():
        print("[FATAL] models_config.json missing.")
        sys.exit(1)

    # Load models
    active_models = load_models(models_cfg_path)
    if not active_models:
        print("[FATAL] No models loaded. Exiting.")
        sys.exit(1)

    # Output dirs
    if not Path(args.csv_out).exists():
        with open(args.csv_out, "w") as f:
            f.write("time,pcap,status,attack_count\n")

    today = time.strftime("%Y-%m-%d")
    log_dir = Path("logs") / today
    log_dir.mkdir(parents=True, exist_ok=True)
    alert_log_path = log_dir / "ids_alerts.log"
    logf = open(alert_log_path, "a", encoding="utf-8")
    print("[INFO] Logging alerts to", alert_log_path)

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

            # ========================
            # HEURISTIC DETECTION
            # ========================
            heur_alerts = []
            heur_alerts.extend(detect_mqtt_bruteforce(biflow_meta, broker_ip=args.broker_ip, broker_port=args.broker_port))
            heur_alerts.extend(detect_ssh_bruteforce(biflow_meta, attacker_ip=args.broker_ip))
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
                colored = colorize_label(entry["predicted_label"], args.color_output)
                print(f"[HEUR ALERT] {colored} {entry}")

                write_alert(logf, entry)

            attack_count = len(heur_alerts)

            # ========================
            # BIFLOW MODEL
            # ========================
            if "biflow" in active_models:
                bm = active_models["biflow"]
                model = bm["model"]
                preproc = bm["preprocessor"]

                df_b = pd.DataFrame(biflow_feats)
                df_raw = df_b.copy()

                # Apply preprocessing (NEW)
                try:
                    X_b = preproc.transform(df_raw)
                except Exception as e:
                    print("[ERROR] Preprocessing failed:", e)
                    X_b = None

                if X_b is not None:
                    preds = model.predict(X_b)
                    probs = model.predict_proba(X_b)

                    for i, lbl in enumerate(preds):
                        if int(lbl) != 0:   # paper mapping: 0=normal
                            prob = float(max(probs[i]))
                            if prob >= args.prob_threshold:
                                if isinstance(lbl, (int, np.integer)):
                                    pred_label_str = INT_TO_LABEL.get(int(lbl), str(int(lbl)))
                                else:
                                    pred_label_str = str(lbl)

                                entry = {
                                    "time": time.time(),
                                    "pcap": p.name,
                                    "model": "biflow",
                                    "flow": biflow_meta[i],
                                    "predicted_label": pred_label_str,
                                    "prob": prob
                                }
                                colored = colorize_label(entry["predicted_label"], args.color_output)
                                print(f"[HEUR ALERT] {colored} {entry}")

                                write_alert(logf, entry)
                                attack_count += 1

            # ========================
            # UNIFLOW MODEL
            # ========================
            if "uniflow" in active_models:
                um = active_models["uniflow"]
                model = um["model"]
                preproc = um["preprocessor"]

                u_rows, u_meta = biflow_to_uniflow_rows(biflow_feats, biflow_meta, um["feature_names"])
                df_u = pd.DataFrame(u_rows)
                df_raw = df_u.copy()

                try:
                    X_u = preproc.transform(df_raw)
                except Exception as e:
                    print("[ERROR] Preprocessing failed:", e)
                    X_u = None

                if X_u is not None:
                    preds = model.predict(X_u)
                    probs = model.predict_proba(X_u)

                    for i, lbl in enumerate(preds):
                        if int(lbl) != 0:
                            prob = float(max(probs[i]))
                            if prob >= args.prob_threshold:
                                if isinstance(lbl, (int, np.integer)):
                                    pred_label_str = INT_TO_LABEL.get(int(lbl), str(int(lbl)))
                                else:
                                    pred_label_str = str(lbl)

                                entry = {
                                    "time": time.time(),
                                    "pcap": p.name,
                                    "model": "uniflow",
                                    "flow": u_meta[i],
                                    "predicted_label": pred_label_str,
                                    "prob": prob
                                }
                                colored = colorize_label(entry["predicted_label"], args.color_output)
                                print(f"[HEUR ALERT] {colored} {entry}")

                                write_alert(logf, entry)
                                attack_count += 1

            # ========================
            # PACKET MODEL
            # ========================
            if "packet" in active_models:
                pm = active_models["packet"]
                model = pm["model"]
                preproc = pm["preprocessor"]

                pkt_rows, pkt_meta = extract_packet_level(p, pm["feature_names"])
                df_p = pd.DataFrame(pkt_rows)
                df_raw = df_p.copy()

                if not df_raw.empty:
                    try:
                        X_p = preproc.transform(df_raw)
                    except Exception as e:
                        print("[ERROR] Packet preprocessing failed:", e)
                        X_p = None

                    if X_p is not None:
                        preds = model.predict(X_p)
                        probs = model.predict_proba(X_p)

                        for i, lbl in enumerate(preds):
                            if int(lbl) != 0:
                                prob = float(max(probs[i]))
                                if prob >= args.prob_threshold:
                                    if isinstance(lbl, (int, np.integer)):
                                        pred_label_str = INT_TO_LABEL.get(int(lbl), str(int(lbl)))
                                    else:
                                        pred_label_str = str(lbl)

                                    entry = {
                                        "time": time.time(),
                                        "pcap": p.name,
                                        "model": "packet",
                                        "flow": pkt_meta[i],
                                        "predicted_label": pred_label_str,
                                        "prob": prob
                                    }
                                    colored = colorize_label(entry["predicted_label"], args.color_output)
                                    print(f"[HEUR ALERT] {colored} {entry}")

                                    write_alert(logf, entry)
                                    attack_count += 1

            # Write summary
            with open(args.csv_out, "a") as f:
                status = "ATTACK" if attack_count > 0 else "NO_ATTACK"
                f.write(f"{time.time()},{p.name},{status},{attack_count}\n")

            seen.add(p.name)

        time.sleep(args.poll_interval)

    logf.close()
    print("[INFO] IDS stopped.")


if __name__ == "__main__":
    main()
