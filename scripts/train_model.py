#!/usr/bin/env python3
"""
train_model.py — FINAL VERSION (multiclass + compatible with run_all.py)

✔ Works with run_all.py arguments
✔ Uses packet→DecisionTree, uniflow→RF, biflow→RF
✔ Supports multiclass labels
✔ Loads *_train.csv and *_test.csv from data/combined
✔ Falls back to splitting combined CSV if needed
✔ Saves:
    - model_*.joblib
    - train_metadata.json
    - feature_names.json
✔ Clean reproducible pipeline
"""

import argparse, json, os, hashlib, platform
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(8192), b""):
            h.update(b)
    return h.hexdigest()


def load_dataset(data_dir, feature_level, test_split, seed):
    """
    Loads:
        *_train.csv / *_test.csv if available
    else loads:
        feature_level.csv and splits into train/test
    """
    data_dir = Path(data_dir)
    train_path = data_dir / f"{feature_level}_train.csv"
    test_path  = data_dir / f"{feature_level}_test.csv"

    # Case 1: presplit files exist
    if train_path.exists() and test_path.exists():
        df_train = pd.read_csv(train_path)
        df_test  = pd.read_csv(test_path)
        return df_train, df_test, [train_path, test_path]

    # Case 2: combine and split
    combined_path = data_dir / f"{feature_level}.csv"
    if not combined_path.exists():
        raise FileNotFoundError(f"Missing {combined_path}")

    df = pd.read_csv(combined_path)

    # Use multiclass label if exists, else is_attack
    y_col = "label" if "label" in df.columns else "is_attack"

    df_train, df_test = train_test_split(
        df,
        test_size=test_split,
        stratify=df[y_col],
        random_state=seed
    )

    # Save for reproducibility
    df_train.to_csv(train_path, index=False)
    df_test.to_csv(test_path, index=False)

    return df_train, df_test, [train_path, test_path]


def prepare_features(df):
    """
    Returns:
        X (numeric DataFrame)
        y (label vector)
        feature_names (ordered list)
    """
    df = df.copy()
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    # Remove IPs (research paper requirement)
    drop_cols = ["ip_src", "ip_dst", "is_attack", "protocol"]

    # Label column
    if "label" in df.columns:
        y = df["label"].astype(str).values
        drop_cols.append("label")
    else:
        y = df["is_attack"].astype(int).values

    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")

    # Keep numeric only
    X = df.select_dtypes(include=[np.number]).fillna(0)
    return X, y, list(X.columns)


def build_model(model_type, seed):
    """Decision Tree or Random Forest."""
    if model_type == "dt":
        return DecisionTreeClassifier(random_state=seed)
    else:
        return RandomForestClassifier(
            n_estimators=250,
            n_jobs=-1,
            class_weight="balanced_subsample",
            random_state=seed
        )


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", required=True)
    p.add_argument("--feature-level", choices=["packet", "uniflow", "biflow"], required=True)
    p.add_argument("--model-type", choices=["dt", "rf"], required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--cv-folds", type=int, default=5)
    p.add_argument("--test-split", type=float, default=0.25)
    args = p.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # Load dataset
    df_train, df_test, used_files = load_dataset(
        args.data_dir, args.feature_level, args.test_split, args.seed
    )

    # Prepare features
    X_train, y_train, feature_names = prepare_features(df_train)
    X_test,  y_test,  _ = prepare_features(df_test)

    # Build model
    clf = build_model(args.model_type, args.seed)

    # K-Fold CV
    skf = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=args.seed)
    y_pred_cv = np.empty_like(y_train, dtype=object)

    for fold, (tr, val) in enumerate(skf.split(X_train, y_train), 1):
        clf_fold = build_model(args.model_type, args.seed + fold)
        clf_fold.fit(X_train.iloc[tr], y_train[tr])
        y_pred_cv[val] = clf_fold.predict(X_train.iloc[val])

    # Final fit
    clf.fit(X_train, y_train)

    # Evaluate
    y_test_pred = clf.predict(X_test)
    report_train = classification_report(y_train, y_pred_cv, output_dict=True, zero_division=0)
    report_test  = classification_report(y_test, y_test_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_test_pred)
    acc = accuracy_score(y_test, y_test_pred)

    # Save model
    model_path = Path(args.out_dir) / f"model_{args.model_type}.joblib"
    joblib.dump(clf, model_path)

    # Save feature names
    with open(Path(args.out_dir) / "feature_names.json", "w") as f:
        json.dump({"feature_names": feature_names}, f, indent=2)

    # Save metadata
    meta = {
        "feature_level": args.feature_level,
        "model_type": args.model_type,
        "model_path": str(model_path),
        "train_files": {str(f): sha256_file(f) for f in used_files},
        "feature_names": feature_names,
        "test_accuracy": float(acc),
        "report_train": report_train,
        "report_test": report_test,
        "confusion_matrix": cm.tolist(),
        "python_version": platform.python_version(),
    }

    with open(Path(args.out_dir) / "train_metadata.json", "w") as f:
        json.dump(meta, f, indent=2)

    print("\n=== TRAINING COMPLETE ===")
    print("Model       :", model_path)
    print("Accuracy    :", acc)
    print("Confusion\n", cm)


if __name__ == "__main__":
    main()
