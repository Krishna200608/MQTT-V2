#!/usr/bin/env python3
"""
prepare_combined_csv.py — FINAL (subfolder output)

New structure:
    combined/packet/packet_train.csv
    combined/packet/packet_test.csv
    combined/packet/split_metadata.json

    combined/uniflow/...
    combined/biflow/...

Fully compatible with train_model.py after modifications.
"""

import argparse, os, json, hashlib
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

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


def sha256_for_file(filepath):
    BUF_SIZE = 65536
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(BUF_SIZE):
            sha.update(chunk)
    return sha.hexdigest()


def find_label_from_name(name: str):
    ln = name.lower()
    for token, label in LABEL_TOKENS.items():
        if token in ln:
            return label
    return Path(name).stem.lower()


def combine_csvs(feature_dir: Path, chunksize=100000):
    csvs = sorted(feature_dir.glob("*.csv"))
    if not csvs:
        raise FileNotFoundError(f"No CSVs in {feature_dir}")

    dfs = []
    hashes = {}

    print(f"Combining {len(csvs)} CSVs from {feature_dir}")

    for p in csvs:
        label = find_label_from_name(p.name)
        print(f"  Reading {p.name} → {label}")

        for chunk in pd.read_csv(p, chunksize=chunksize, low_memory=False):
            chunk.columns = [c.strip() for c in chunk.columns]
            chunk["label"] = label
            chunk["is_attack"] = 0 if label == "normal" else 1

            num = chunk.select_dtypes(include=[np.number])
            num["label"] = chunk["label"]
            num["is_attack"] = chunk["is_attack"]
            dfs.append(num)

        hashes[str(p)] = sha256_for_file(p)

    df = pd.concat(dfs, ignore_index=True, sort=False)
    return df, hashes


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", required=True)
    p.add_argument("--feature-level", choices=["packet", "uniflow", "biflow"], required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--test-split", type=float, default=0.25)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    folder_map = {
        "packet": "packet_features",
        "uniflow": "uniflow_features",
        "biflow": "biflow_features"
    }

    src = Path(args.data_dir) / folder_map[args.feature_level]
    if not src.exists():
        raise FileNotFoundError(f"{src} does not exist")

    base_out = Path(args.out_dir)
    mode_folder = base_out / args.feature_level
    os.makedirs(mode_folder, exist_ok=True)

    df, hashes = combine_csvs(src)

    y = df["label"]
    idx = df.index

    train_idx, test_idx = train_test_split(idx, test_size=args.test_split,
                                           stratify=y, random_state=args.seed)

    df_train = df.loc[train_idx].reset_index(drop=True)
    df_test = df.loc[test_idx].reset_index(drop=True)

    train_path = mode_folder / f"{args.feature_level}_train.csv"
    test_path = mode_folder / f"{args.feature_level}_test.csv"

    df_train.to_csv(train_path, index=False)
    df_test.to_csv(test_path, index=False)

    print(f"Saved train → {train_path}")
    print(f"Saved test  → {test_path}")

    # Metadata
    meta = {
        "feature_level": args.feature_level,
        "test_split": args.test_split,
        "seed": args.seed,
        "source_folder": str(src),
        "file_checksums": hashes,
        "label_distribution": df["label"].value_counts().to_dict(),
        "train_counts": df_train["label"].value_counts().to_dict(),
        "test_counts": df_test["label"].value_counts().to_dict(),
    }
    meta_path = mode_folder / "split_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"Saved metadata → {meta_path}")


if __name__ == "__main__":
    main()
