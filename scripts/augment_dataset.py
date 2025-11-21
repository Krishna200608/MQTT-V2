#!/usr/bin/env python3
"""
augment_dataset.py — Safe Dataset Augmentation (RAM-aware)

Changes from your previous version:
    ✔ Uses vectorized operations always
    ✔ Strong guards against corrupted columns
    ✔ Safe oversampling capped to avoid >3GB allocations
    ✔ Logs class distribution before and after balancing
    ✔ Never produces more than ~200k rows per class (good for 16GB RAM)
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.utils import resample

LOG = logging.getLogger(__name__)

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _safe_series(df: pd.DataFrame, col: str, default=0) -> pd.Series:
    """Always returns a Series (even if column missing)."""
    if col in df.columns:
        return df[col].fillna(default)
    return pd.Series([default] * len(df), index=df.index)


def _parse_ports_set(val):
    """Convert JSON/list/string to a Python set safely."""
    if isinstance(val, list):
        return set(val)
    if isinstance(val, str):
        try:
            x = json.loads(val)
            if isinstance(x, list):
                return set(x)
        except Exception:
            return set()
    return set()


# -------------------------------------------------------------------
# Augmented Feature Builder
# -------------------------------------------------------------------

def add_augmented_features(df: pd.DataFrame, mode: Optional[str] = None) -> pd.DataFrame:
    df = df.copy()
    df.columns = [c.lower() for c in df.columns]

    # MQTT connect/connack totals
    f_conn = _safe_series(df, "f_mqtt_connects", 0).astype(float)
    b_conn = _safe_series(df, "b_mqtt_connects", 0).astype(float)
    df["total_connects"] = f_conn + b_conn

    f_ack = _safe_series(df, "f_mqtt_connacks", 0).astype(float)
    b_ack = _safe_series(df, "b_mqtt_connacks", 0).astype(float)
    df["total_connacks"] = f_ack + b_ack

    # connack ratio (vectorized)
    tc = df["total_connects"].to_numpy()
    ta = df["total_connacks"].to_numpy()
    df["connack_ratio"] = np.where(tc > 0, ta / tc, 0.0)

    # unique port counts
    df["unique_ports_fwd"] = df.get("f_ports_set", pd.Series([[]] * len(df))).apply(_parse_ports_set).apply(len)
    df["unique_ports_bwd"] = df.get("b_ports_set", pd.Series([[]] * len(df))).apply(_parse_ports_set).apply(len)
    df["total_unique_ports"] = df["unique_ports_fwd"] + df["unique_ports_bwd"]

    # burstiness
    if "fwd_mean_iat" in df.columns and "fwd_std_iat" in df.columns:
        fmean = _safe_series(df, "fwd_mean_iat", 0).to_numpy()
        fstd = _safe_series(df, "fwd_std_iat", 0).to_numpy()
        df["burstiness_fwd"] = np.where(fmean > 0, fstd / fmean, 0.0)
    else:
        df["burstiness_fwd"] = 0.0

    if "bwd_mean_iat" in df.columns and "bwd_std_iat" in df.columns:
        bmean = _safe_series(df, "bwd_mean_iat", 0).to_numpy()
        bstd = _safe_series(df, "bwd_std_iat", 0).to_numpy()
        df["burstiness_bwd"] = np.where(bmean > 0, bstd / bmean, 0.0)
    else:
        df["burstiness_bwd"] = 0.0

    # connect rate
    if "timestamp" in df.columns:
        try:
            ts = pd.to_numeric(df["timestamp"], errors="coerce")
            dur = max(ts.max() - ts.min(), 1e-6)
            df["connect_rate"] = df["total_connects"] / dur
        except Exception:
            df["connect_rate"] = df["total_connects"]
    else:
        df["connect_rate"] = df["total_connects"]

    # packet rate
    df["pkt_rate_fwd"] = _safe_series(df, "fwd_num_pkts", 0)
    df["pkt_rate_bwd"] = _safe_series(df, "bwd_num_pkts", 0)

    return df


# -------------------------------------------------------------------
# Safe Oversampling
# -------------------------------------------------------------------

def oversample_minority(
    df: pd.DataFrame,
    label_col: str = "label",
    max_cap: int = 200_000    # tuned for 16GB RAM
) -> pd.DataFrame:
    """
    Oversample minority classes safely.
    Caps per-class size to avoid 3GB+ allocations.
    """

    if label_col not in df.columns:
        LOG.error("Label column '%s' not found.", label_col)
        return df

    counts = df[label_col].value_counts()
    LOG.info("Class distribution BEFORE balancing:\n%s", counts)

    if counts.empty:
        return df

    max_class_size = int(counts.max())
    target = min(max_class_size, max_cap)

    LOG.info("Largest class = %d, using target oversample = %d", max_class_size, target)

    parts = []
    for lbl, grp in df.groupby(label_col):
        n = len(grp)
        if n >= target:
            parts.append(grp.sample(n=target, replace=False, random_state=42))
        else:
            parts.append(resample(grp, replace=True, n_samples=target, random_state=42))

    df_bal = pd.concat(parts, ignore_index=True)
    df_bal = df_bal.sample(frac=1, random_state=42).reset_index(drop=True)

    LOG.info("Class distribution AFTER balancing:\n%s", df_bal[label_col].value_counts())

    return df_bal


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

def _parse():
    p = argparse.ArgumentParser(description="Dataset augmentation module (safe).")
    p.add_argument("--data-dir", required=True, help="data/combined folder")
    p.add_argument("--feature-level", required=True, choices=["packet", "uniflow", "biflow"])
    p.add_argument("--balance", choices=["oversample", "none"], default="oversample")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def main():
    args = _parse()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    base = Path(args.data_dir)
    train_csv = base / args.feature_level / f"{args.feature_level}_train.csv"
    test_csv  = base / args.feature_level / f"{args.feature_level}_test.csv"

    LOG.info("Loading %s and %s", train_csv, test_csv)
    df_train = pd.read_csv(train_csv)
    df_test = pd.read_csv(test_csv)

    LOG.info("Adding augmented features...")
    df_train_aug = add_augmented_features(df_train, args.feature_level)
    df_test_aug = add_augmented_features(df_test, args.feature_level)

    if args.balance == "oversample":
        LOG.info("Applying safe oversampling...")
        df_train_aug = oversample_minority(df_train_aug, label_col="label")

    LOG.info("Writing updated CSV files...")
    df_train_aug.to_csv(train_csv, index=False)
    df_test_aug.to_csv(test_csv, index=False)

    LOG.info("Augmentation completed successfully.")


if __name__ == "__main__":
    main()
