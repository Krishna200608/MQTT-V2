#!/usr/bin/env python3
"""
augment_dataset_refactored.py — Refactored Dataset Augmentation Module

This is a cleaned, type-safe, and lint-friendly refactor of the uploaded
`augment_dataset.py` (see original file). Changes made:
  - avoids calling Series methods on ints (Pylance-safe)
  - uses vectorized operations where possible
  - consistent Series-returning branches
  - clearer helper functions and typing
  - faster oversampling (collect then concat)
  - optional balancing mode ("oversample" or "none")
  - better logging and CLI help

Save location: same directory as original when run interactively.
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


# --------------------------- helpers ---------------------------------

def _safe_series(df: pd.DataFrame, col: str, default: int = 0) -> pd.Series:
    """Return a Series for `col` when present, otherwise a constant Series.

    This avoids code like `df.get(col, 0).fillna(0)` which returns an int
    when the column is missing and confuses static checkers (Pylance).
    """
    if col in df.columns:
        return df[col].fillna(default)
    return pd.Series(default, index=df.index)


def _parse_ports_set(val) -> set:
    """Robustly convert stored port-set values to a Python set.

    Accepts actual lists, JSON-encoded lists, strings, or other types.
    """
    if isinstance(val, list):
        return set(val)
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            if isinstance(parsed, list):
                return set(parsed)
        except Exception:
            return set()
    return set()


# --------------------- augmentation ----------------------------------

def add_augmented_features(df: pd.DataFrame, mode: Optional[str] = None) -> pd.DataFrame:
    """Return a copy of df augmented with derived features.

    The function is defensive about missing columns and always returns
    pandas.Series for derived columns so static analyzers do not complain.
    """
    df = df.copy()
    # normalize lowercase column names to make lookups predictable
    df.columns = [c.lower() for c in df.columns]

    # --- MQTT connect/connack totals ---
    f_conn = _safe_series(df, "f_mqtt_connects", 0).astype(float)
    b_conn = _safe_series(df, "b_mqtt_connects", 0).astype(float)
    df["total_connects"] = f_conn + b_conn

    f_connack = _safe_series(df, "f_mqtt_connacks", 0).astype(float)
    b_connack = _safe_series(df, "b_mqtt_connacks", 0).astype(float)
    df["total_connacks"] = f_connack + b_connack

    # avoid row-wise apply for simple ratio -- use numpy where to be faster
    total_connects = df["total_connects"].to_numpy()
    total_connacks = df["total_connacks"].to_numpy()
    connack_ratio = np.where(total_connects > 0, total_connacks / total_connects, 0.0)
    df["connack_ratio"] = connack_ratio

    # --- unique ports (must parse per-row) ---
    if "f_ports_set" in df.columns:
        df["unique_ports_fwd"] = (
            df["f_ports_set"].apply(_parse_ports_set).apply(len)
        )
    else:
        df["unique_ports_fwd"] = pd.Series(0, index=df.index)

    if "b_ports_set" in df.columns:
        df["unique_ports_bwd"] = (
            df["b_ports_set"].apply(_parse_ports_set).apply(len)
        )
    else:
        df["unique_ports_bwd"] = pd.Series(0, index=df.index)

    df["total_unique_ports"] = df["unique_ports_fwd"] + df["unique_ports_bwd"]

    # --- burstiness: std / mean with safe handling ---
    if "fwd_mean_iat" in df.columns and "fwd_std_iat" in df.columns:
        fwd_mean = _safe_series(df, "fwd_mean_iat", 0).to_numpy()
        fwd_std = _safe_series(df, "fwd_std_iat", 0).to_numpy()
        df["burstiness_fwd"] = np.where(fwd_mean > 0, fwd_std / fwd_mean, 0.0)
    else:
        df["burstiness_fwd"] = pd.Series(0.0, index=df.index)

    if "bwd_mean_iat" in df.columns and "bwd_std_iat" in df.columns:
        bwd_mean = _safe_series(df, "bwd_mean_iat", 0).to_numpy()
        bwd_std = _safe_series(df, "bwd_std_iat", 0).to_numpy()
        df["burstiness_bwd"] = np.where(bwd_mean > 0, bwd_std / bwd_mean, 0.0)
    else:
        df["burstiness_bwd"] = pd.Series(0.0, index=df.index)

    # --- connect rate (use timestamp if present) ---
    if "timestamp" in df.columns:
        # keep timestamps numeric if they already are; else try coercion
        try:
            tmin = pd.to_numeric(df["timestamp"], errors="coerce").min()
            tmax = pd.to_numeric(df["timestamp"], errors="coerce").max()
            duration = max((tmax - tmin), 1e-6)
            df["connect_rate"] = df["total_connects"] / duration
        except Exception:
            df["connect_rate"] = df["total_connects"]
    else:
        df["connect_rate"] = df["total_connects"]

    # --- packet rates: just copy if present ---
    if "fwd_num_pkts" in df.columns:
        df["pkt_rate_fwd"] = _safe_series(df, "fwd_num_pkts", 0)
    if "bwd_num_pkts" in df.columns:
        df["pkt_rate_bwd"] = _safe_series(df, "bwd_num_pkts", 0)

    return df


# -------------------- class balancing --------------------------------

def oversample_minority(df: pd.DataFrame, label_col: str = "label") -> pd.DataFrame:
    """Oversample minority classes so each class has size equal to the largest class.

    This function avoids repeated concat inside the loop for performance and
    returns a shuffled DF with reset integer index.
    """
    if label_col not in df.columns:
        LOG.warning("Label column '%s' not found; returning original df", label_col)
        return df.copy()

    max_count = int(df[label_col].value_counts().max())

    parts = []
    for lbl, g in df.groupby(label_col):
        if len(g) == 0:
            continue
        parts.append(
            resample(g, replace=True, n_samples=max_count, random_state=42)
        )

    if not parts:
        return df.copy()

    df_bal = pd.concat(parts, ignore_index=True)
    return df_bal.sample(frac=1, random_state=42).reset_index(drop=True)


# -------------------- main CLI ---------------------------------------

def _parse_args():
    p = argparse.ArgumentParser(description="Augment and optionally balance dataset CSVs")
    p.add_argument("--data-dir", required=True, help="Path to data/combined folder")
    p.add_argument("--feature-level", required=True, choices=["packet", "uniflow", "biflow"])
    p.add_argument("--balance", choices=["oversample", "none"], default="oversample",
                   help="Balancing strategy to apply to the training set")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def main():
    args = _parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="[%(levelname)s] %(message)s")

    combined_dir = Path(args.data_dir) / args.feature_level
    train_csv = combined_dir / f"{args.feature_level}_train.csv"
    test_csv = combined_dir / f"{args.feature_level}_test.csv"

    if not train_csv.exists() or not test_csv.exists():
        LOG.error("Missing required CSVs at %s", combined_dir)
        raise FileNotFoundError(f"Missing train/test CSVs in {combined_dir}")

    LOG.info("Loading train=%s test=%s", train_csv, test_csv)
    df_train = pd.read_csv(train_csv)
    df_test = pd.read_csv(test_csv)

    LOG.info("Adding augmented features")
    df_train_aug = add_augmented_features(df_train, args.feature_level)
    df_test_aug = add_augmented_features(df_test, args.feature_level)

    if args.balance == "oversample":
        LOG.info("Balancing training set with oversampling")
        df_train_aug = oversample_minority(df_train_aug, label_col="label")

    # Overwrite (safe behaviour: write to temp first?) — we write directly for simplicity
    LOG.info("Writing augmented CSVs back to disk")
    df_train_aug.to_csv(train_csv, index=False)
    df_test_aug.to_csv(test_csv, index=False)

    LOG.info("Augmentation finished successfully")


if __name__ == "__main__":
    main()
