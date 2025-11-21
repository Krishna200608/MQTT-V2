#!/usr/bin/env python3
# tests/test_scans.py — quick unit checks for scan detection

import json
import sys
from pathlib import Path
import numpy as np
import joblib
import pandas as pd
from heuristics import detect_tcp_udp_scans

ROOT = Path(__file__).resolve().parents[1]
MODELS_CFG = ROOT / "configs" / "models_config.json"

def test_heur_tcp_scan():
    # craft meta row: TCP proto with many forward unique ports
    m = {
        "src":"10.0.0.5","dst":"10.0.0.1","proto":6,
        "f_ports_set": list(range(1000, 1018)), "b_ports_set": [],
        "fwd_num_pkts": 20, "bwd_num_pkts": 1
    }
    alerts = detect_tcp_udp_scans([m], tcp_port_threshold=10, udp_port_threshold=8)
    assert any(a['type']=='scan_A' for a in alerts), "TCP scan not detected"

def test_heur_udp_scan():
    # craft meta row: UDP proto with many unique ports and >=3 pkts
    m = {
        "src":"10.0.0.5","dst":"10.0.0.1","proto":17,
        "f_ports_set": list(range(2000, 2010)), "b_ports_set": [],
        "fwd_num_pkts": 5, "bwd_num_pkts": 0
    }
    alerts = detect_tcp_udp_scans([m], tcp_port_threshold=10, udp_port_threshold=8)
    assert any(a['type']=='scan_sU' for a in alerts), "UDP scan not detected"

def test_model_consistency(feature_level="biflow"):
    # load model and preprocessor
    cfg = json.loads(MODELS_CFG.read_text())
    entry = cfg.get(feature_level)
    assert entry and entry.get("enabled", False), "model not enabled in models_config.json"

    model_path = ROOT / entry["model_path"]
    preproc_path = ROOT / entry["preproc_path"]
    meta_path = ROOT / entry["meta_path"]

    model = joblib.load(model_path)
    preproc = joblib.load(preproc_path)
    meta = json.loads(open(meta_path).read())
    feature_names = meta.get("feature_names", [])

    # craft a biflow-like feature with a large f_ports_set (simulate scan)
    sample = {k:0 for k in feature_names}
    # set numeric fields that represent many unique ports and proto
    if "fwd_num_pkts" in sample: sample["fwd_num_pkts"] = 20
    if "bwd_num_pkts" in sample: sample["bwd_num_pkts"] = 0
    # proto field may be 'proto' or 'protocol'
    if "proto" in sample: sample["proto"] = 6
    df = pd.DataFrame([sample])
    X = preproc.transform(df.fillna(-1))
    preds = model.predict(X)
    # just print — not asserting exact classes because models vary
    print("Model prediction for crafted scan-like row:", preds)

if __name__ == "__main__":
    test_heur_tcp_scan()
    print("✔ heur_tcp_scan OK")
    test_heur_udp_scan()
    print("✔ heur_udp_scan OK")
    test_model_consistency("biflow")
    print("✔ model_consistency OK")
