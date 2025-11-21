#!/usr/bin/env python3
"""
augment_dataset.py — Feature & Dataset Augmentation Module

This script:
  ✓ Loads combined CSVs (packet / uniflow / biflow)
  ✓ Adds features helpful for distinguishing:
        - MQTT brute-force vs scan_A / scan_sU / sparta
  ✓ Performs class balancing through oversampling
  ✓ Saves new augmented train/test CSVs
"""

import argparse, json, os
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.utils import resample

# ------------------------------------------------------------------------------
# AUGMENTATION RULES
# ------------------------------------------------------------------------------

def add_augmented_features(df: pd.DataFrame, mode: str) -> pd.DataFrame:
    df = df.copy()
    df.columns = [c.lower() for c in df.columns]

    # ---- MQTT FEATURES ----
    if "f_mqtt_connects" in df.columns and "b_mqtt_connects" in df.columns:
        df["total_connects"] = df["f_mqtt_connects"].fillna(0) + df["b_mqtt_connects"].fillna(0)
    else:
        df["total_connects"] = 0

    if "f_mqtt_connacks" in df.columns and "b_mqtt_connacks" in df.columns:
        df["total_connacks"] = df["f_mqtt_connacks"].fillna(0) + df["b_mqtt_connacks"].fillna(0)
    else:
        df["total_connacks"] = 0

    df["connack_ratio"] = df.apply(
        lambda r: (r["total_connacks"] / r["total_connects"]) if r["total_connects"] > 0 else 0,
        axis=1
    )

    # ---- SCAN FEATURES ----
    def extract_set(x):
        if isinstance(x, list):
            return set(x)
        if isinstance(x, str):
            try: return set(json.loads(x))
            except: return set()
        return set()

    if "f_ports_set" in df.columns:
        df["unique_ports_fwd"] = df["f_ports_set"].apply(extract_set).apply(len)
    else:
        df["unique_ports_fwd"] = 0

    if "b_ports_set" in df.columns:
        df["unique_ports_bwd"] = df["b_ports_set"].apply(extract_set).apply(len)
    else:
        df["unique_ports_bwd"] = 0

    df["total_unique_ports"] = df["unique_ports_fwd"] + df["unique_ports_bwd"]

    # ---- RATES & BURSTINESS ----
    if "fwd_mean_iat" in df.columns and "fwd_std_iat" in df.columns:
        df["burstiness_fwd"] = df.apply(
            lambda r: (r["fwd_std_iat"] / r["fwd_mean_iat"]) if r["fwd_mean_iat"] > 0 else 0,
            axis=1
        )
    else:
        df["burstiness_fwd"] = 0

    if "bwd_mean_iat" in df.columns and "bwd_std_iat" in df.columns:
        df["burstiness_bwd"] = df.apply(
            lambda r: (r["bwd_std_iat"] / r["bwd_mean_iat"]) if r["bwd_mean_iat"] > 0 else 0,
            axis=1
        )
    else:
        df["burstiness_bwd"] = 0

    # ---- CONNECT RATE ----
    if "timestamp" in df.columns:
        t_min = df["timestamp"].min()
        t_max = df["timestamp"].max()
        duration = max((t_max - t_min), 1e-6)
        df["connect_rate"] = df["total_connects"] / duration
    else:
        df["connect_rate"] = df["total_connects"]

    # ---- PACKET RATES ----
    if "fwd_num_pkts" in df.columns:
        df["pkt_rate_fwd"] = df["fwd_num_pkts"]
    if "bwd_num_pkts" in df.columns:
        df["pkt_rate_bwd"] = df["bwd_num_pkts"]

    return df


# ------------------------------------------------------------------------------
# CLASS BALANCING
# ------------------------------------------------------------------------------

def oversample_minority(df: pd.DataFrame, label_col="label"):
    groups = []
    max_count = df[label_col].value_counts().max()

    for lbl, grp in df.groupby(label_col):
        groups.append(
            resample(grp, replace=True, n_samples=max_count, random_state=42)
        )

    df_balanced = pd.concat(groups, ignore_index=True)
    return df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)


# ------------------------------------------------------------------------------
# MAIN PIPELINE
# ------------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--combined-dir", required=True)
    p.add_argument("--feature-level", choices=["packet", "uniflow", "biflow"], required=True)
    args = p.parse_args()

    mode_dir = Path(args.combined_dir) / args.feature_level
    train_csv = mode_dir / f"{args.feature_level}_train.csv"
    test_csv  = mode_dir / f"{args.feature_level}_test.csv"

    if not train_csv.exists():
        raise FileNotFoundError(f"Missing {train_csv}")

    df_train = pd.read_csv(train_csv)
    df_test  = pd.read_csv(test_csv)

    print(f"[INFO] Loaded train={df_train.shape}, test={df_test.shape}")

    # ---- AUGMENT ----
    df_train_aug = add_augmented_features(df_train, args.feature_level)
    df_test_aug  = add_augmented_features(df_test, args.feature_level)

    # ---- BALANCE TRAIN ----
    df_train_aug = oversample_minority(df_train_aug, "label")

    # ---- SAVE ----
    out_train = mode_dir / f"{args.feature_level}_train_augmented.csv"
    out_test  = mode_dir / f"{args.feature_level}_test_augmented.csv"

    df_train_aug.to_csv(out_train, index=False)
    df_test_aug.to_csv(out_test, index=False)

    print(f"[OK] Saved augmented train → {out_train}")
    print(f"[OK] Saved augmented test  → {out_test}")
    print("[DONE] Dataset augmentation complete.")


if __name__ == "__main__":
    main()
