#!/usr/bin/env python3
"""
Combine per-class feature CSVs into unified train/test datasets
with deterministic split (same seed = same split).
Now optimized for large CSVs using chunked reading and memory safety.

Example:
python scripts/prepare_combined_csv.py \
  --data-dir ./data \
  --feature-level biflow \
  --out-dir ./data/combined \
  --test-split 0.25 \
  --seed 42
"""
import argparse, os, json, hashlib
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# -------------------------------------------------------------
# LABEL NORMALIZATION MAP
# -------------------------------------------------------------
LABEL_TOKENS = {
    "normal": "normal",
    "scan_a": "scan_A",
    "scan_su": "scan_sU",
    "sparta": "sparta",
    "mqtt_bruteforce": "mqtt_bruteforce",
    "mqtt_brutefor": "mqtt_bruteforce",
    "mqtt_brute": "mqtt_bruteforce",
    "mqtt": "mqtt_bruteforce"
}

# -------------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------------
def sha256_for_file(filepath):
    """Generate a quick hash for file verification."""
    BUF_SIZE = 65536
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(BUF_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()

def find_label_from_name(name: str):
    ln = name.lower()
    for token, label in LABEL_TOKENS.items():
        if token in ln:
            return label
    return Path(name).stem.lower()

# -------------------------------------------------------------
# MAIN COMBINER (CHUNKED & MEMORY SAFE)
# -------------------------------------------------------------
def combine_csvs(feature_dir: Path, chunksize: int = 100000):
    """
    Efficiently combine multiple CSVs from a folder into one DataFrame.
    Uses chunked reading to prevent memory errors.
    """
    csvs = sorted(feature_dir.glob("*.csv"))
    if not csvs:
        raise FileNotFoundError(f"No CSV files found in {feature_dir}")

    dfs = []
    file_checksums = {}

    print(f"Combining CSVs from {feature_dir} ...")

    for p in csvs:
        label = find_label_from_name(p.name)
        print(f"  📄 Reading {p.name} (label={label})")

        try:
            # Read CSV in manageable chunks
            for chunk in pd.read_csv(p, chunksize=chunksize, low_memory=False):
                chunk.columns = [c.strip() for c in chunk.columns]
                chunk["label"] = label
                chunk["is_attack"] = 0 if label == "normal" else 1

                # Keep numeric columns only (reduce memory footprint)
                num_chunk = chunk.select_dtypes(include=[np.number])
                # Preserve label columns at the end
                num_chunk["label"] = chunk["label"]
                num_chunk["is_attack"] = chunk["is_attack"]
                dfs.append(num_chunk)

        except Exception as e:
            print(f"⚠️ Skipping {p.name}: {e}")
            continue

        file_checksums[str(p)] = sha256_for_file(p)

    print(f"  ✅ Loaded {len(dfs)} chunks from {len(csvs)} CSVs.")
    df_all = pd.concat(dfs, ignore_index=True, sort=False)
    print(f"  ✅ Combined total: {len(df_all):,} rows, {df_all.shape[1]} columns.")
    return df_all, file_checksums

# -------------------------------------------------------------
# MAIN FUNCTION
# -------------------------------------------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", required=True, help="Root data folder (contains packet/uniflow/biflow subfolders)")
    p.add_argument("--feature-level", choices=["packet","uniflow","biflow"], default="biflow")
    p.add_argument("--out-dir", required=True, help="Output directory for combined CSVs")
    p.add_argument("--test-split", type=float, default=0.25)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    folder_map = {
        "packet": "packet_features",
        "uniflow": "uniflow_features",
        "biflow": "biflow_features"
    }
    src_folder = Path(args.data_dir) / folder_map[args.feature_level]
    if not src_folder.exists():
        raise FileNotFoundError(f"{src_folder} not found")

    os.makedirs(args.out_dir, exist_ok=True)

    # Combine
    df_all, file_hashes = combine_csvs(src_folder)
    print(f"Loaded total {len(df_all)} rows across {len(file_hashes)} files.")

    # Ensure label presence
    if "label" not in df_all.columns or "is_attack" not in df_all.columns:
        raise ValueError("Missing label or is_attack columns after combining.")

    # Stratified train/test split
    X = df_all.index
    y = df_all["label"]
    train_idx, test_idx = train_test_split(
        X, test_size=args.test_split, stratify=y, random_state=args.seed
    )

    df_train = df_all.loc[train_idx].reset_index(drop=True)
    df_test = df_all.loc[test_idx].reset_index(drop=True)

    train_path = Path(args.out_dir) / f"{args.feature_level}_train.csv"
    test_path = Path(args.out_dir) / f"{args.feature_level}_test.csv"

    df_train.to_csv(train_path, index=False)
    df_test.to_csv(test_path, index=False)

    print(f"Train CSV: {train_path} ({len(df_train)} rows)")
    print(f"Test CSV:  {test_path} ({len(df_test)} rows)")

    # Metadata
    meta = {
        "feature_level": args.feature_level,
        "test_split": args.test_split,
        "seed": args.seed,
        "source_folder": str(src_folder),
        "file_checksums": file_hashes,
        "label_distribution": df_all["label"].value_counts().to_dict(),
        "train_counts": df_train["label"].value_counts().to_dict(),
        "test_counts": df_test["label"].value_counts().to_dict(),
    }
    meta_path = Path(args.out_dir) / "split_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"Saved split metadata to {meta_path}")


if __name__ == "__main__":
    main()
