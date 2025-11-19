#!/usr/bin/env python3
"""
train_model.py — Paper-faithful, minimal (Option A)

Behaviors:
 - Uses preprocessing ideas from classification.py
 - Packet -> DecisionTree (criterion='entropy')
 - Uniflow/Biflow -> RandomForest (n_estimators=10, criterion='entropy')
 - Uses StratifiedKFold(n_splits=5)
 - Saves:
     model_{dt|rf}.joblib
     preprocessor.joblib
     feature_names.json
     train_metadata.json

Assumptions:
 - Combined CSVs are in: combined/<feature_level>/<feature_level>_train.csv
 - Test CSV in: combined/<feature_level>/<feature_level>_test.csv
 - Label mapping follows the paper: normal:0, scan_A:1, scan_sU:2, sparta:3, mqtt_bruteforce:4
"""

import argparse
import json
import os
import hashlib
import platform
import time
from pathlib import Path

import pandas as pd
import numpy as np
import joblib
from tqdm import tqdm

from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer


# -------------------------
# Label mapping (paper)
# -------------------------
LABEL_ORDER = ["normal", "scan_A", "scan_sU", "sparta", "mqtt_bruteforce"]
LABEL_TO_INT = {lbl: idx for idx, lbl in enumerate(LABEL_ORDER)}
INT_TO_LABEL = {v: k for k, v in LABEL_TO_INT.items()}


# -------------------------
# Helpers
# -------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(8192), b""):
            h.update(b)
    return h.hexdigest()


def eta_formatter(elapsed, progress, total):
    if progress == 0:
        return "calculating..."
    rate = elapsed / progress
    remaining = (total - progress) * rate
    return f"{remaining:.1f}s"


# -------------------------
# Pred label encoder (CRITICAL FIX)
# -------------------------
def encode_pred_labels(preds):
    """Convert predictions to integer labels."""
    out = []
    for p in preds:
        if isinstance(p, str):
            out.append(LABEL_TO_INT.get(p, -1))
        else:
            try:
                out.append(int(p))
            except:
                out.append(-1)
    return np.array(out, dtype=int)


# -------------------------
# Data loader
# -------------------------
def load_dataset(data_dir, feature_level, test_split, seed):
    data_dir = Path(data_dir) / feature_level

    train_path = data_dir / f"{feature_level}_train.csv"
    test_path = data_dir / f"{feature_level}_test.csv"

    tqdm.write(f"📂 Loading dataset from: {data_dir}")

    if train_path.exists() and test_path.exists():
        df_train = pd.read_csv(train_path)
        df_test = pd.read_csv(test_path)
        return df_train, df_test, [train_path, test_path]

    raise FileNotFoundError(
        f"Train/Test CSV not found in {data_dir}. Run prepare_combined_csv.py first."
    )


# -------------------------
# Preprocessor
# -------------------------
def build_preprocessor(df, mode):
    df = df.copy()
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    proto_candidates = [c for c in df.columns if c in ("protocol", "proto")]
    proto_col = proto_candidates[0] if proto_candidates else None

    if mode == "packet":
        drop_cols = [c for c in ["timestamp", "src_ip", "dst_ip", "ip_src", "ip_dst"] if c in df.columns]
        mqtt_cols = [c for c in df.columns if c.startswith("mqtt")]
        drop_cols += mqtt_cols
    else:
        drop_cols = [c for c in ["proto", "protocol", "ip_src", "ip_dst"] if c in df.columns]

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    numeric_cols = [c for c in numeric_cols if c not in drop_cols + ["label", "is_attack"]]

    transformers = []
    final_feature_names = []

    if mode == "packet" and proto_col is not None and proto_col in df.columns:
        ohe = OneHotEncoder(handle_unknown="ignore", sparse=False)
        transformers.append(("proto_ohe", ohe, [proto_col]))
        if numeric_cols:
            transformers.append(("num_passthrough", "passthrough", numeric_cols))
        preprocessor = ColumnTransformer(transformers, remainder="drop")

        X_dummy = preprocessor.fit_transform(df.fillna(-1))
        try:
            ohe_names = preprocessor.named_transformers_["proto_ohe"]\
                        .get_feature_names_out([proto_col]).tolist()
        except:
            ohe = preprocessor.named_transformers_["proto_ohe"]
            ohe_names = [f"{proto_col}_{i}" for i in range(ohe.categories_[0].shape[0])]

        final_feature_names = ohe_names + numeric_cols

    else:
        preprocessor = ColumnTransformer(
            [("num_passthrough", "passthrough", numeric_cols)],
            remainder="drop"
        )
        final_feature_names = numeric_cols

    return preprocessor, final_feature_names, drop_cols, proto_col


# -------------------------
# Label encoding
# -------------------------
def encode_labels(y_series):
    if y_series.dtype in (object, "string"):
        y_mapped = y_series.astype(str).apply(lambda x: LABEL_TO_INT.get(x, x))
        try:
            return y_mapped.astype(int).values
        except:
            return y_series.astype(str).str.lower().map({
                "normal": 0, "scan_a": 1, "scan_su": 2, "sparta": 3, "mqtt_bruteforce": 4
            }).fillna(-1).astype(int).values
    return y_series.astype(int).values


# -------------------------
# Build model
# -------------------------
def build_model_for_mode(mode, seed):
    if mode == "packet":
        return DecisionTreeClassifier(criterion="entropy", random_state=seed)
    else:
        return RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=seed)


# -------------------------
# MAIN
# -------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--feature-level", choices=["packet", "uniflow", "biflow"], required=True)
    parser.add_argument("--model-type", choices=["dt", "rf"], required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--test-split", type=float, default=0.25)
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # Load dataset
    df_train, df_test, used_files = load_dataset(args.data_dir, args.feature_level, args.test_split, args.seed)
    df_train.columns = [c.strip().lower().replace(" ", "_") for c in df_train.columns]
    df_test.columns  = [c.strip().lower().replace(" ", "_") for c in df_test.columns]

    # Labels
    if "label" in df_train.columns:
        y_train_raw = df_train["label"]
        y_test_raw  = df_test["label"]
    else:
        y_train_raw = df_train["is_attack"]
        y_test_raw  = df_test["is_attack"]

    # Preprocessor
    preprocessor, feature_names_pre, drop_cols, proto_col = build_preprocessor(df_train, args.feature_level)
    df_train_proc = df_train.drop(columns=drop_cols, errors="ignore").fillna(-1)
    df_test_proc  = df_test.drop(columns=drop_cols, errors="ignore").fillna(-1)

    X_train = preprocessor.fit_transform(df_train_proc)
    X_test  = preprocessor.transform(df_test_proc)

    # Feature names
    try:
        transformed_names = []
        for name, transformer, cols in preprocessor.transformers_:
            if transformer == "passthrough":
                transformed_names.extend(cols)
            else:
                try:
                    transformed_names.extend(transformer.get_feature_names_out(cols).tolist())
                except:
                    if hasattr(transformer, "categories_"):
                        cats = transformer.categories_[0]
                        transformed_names.extend([f"{cols[0]}_{c}" for c in cats])
                    else:
                        transformed_names.extend([f"{cols[0]}_{i}" for i in range(X_train.shape[1])])
    except:
        transformed_names = feature_names_pre

    # NumPy arrays
    X_train = np.asarray(X_train)
    X_test  = np.asarray(X_test)

    # Encode labels
    y_train = encode_labels(pd.Series(y_train_raw))
    y_test  = encode_labels(pd.Series(y_test_raw))

    # Model
    model = build_model_for_mode(args.feature_level, args.seed)
    tqdm.write(f"🤖 Model: {args.feature_level.upper()} | {model.__class__.__name__}")

    # CV
    skf = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=args.seed)
    y_pred_cv = np.empty_like(y_train, dtype=object)

    pbar = tqdm(total=args.cv_folds, desc="CV Progress", ncols=80)
    cv_start = time.time()

    for i, (tr_idx, val_idx) in enumerate(skf.split(X_train, y_train), start=1):
        fold_model = build_model_for_mode(args.feature_level, args.seed + i)
        fold_model.fit(X_train[tr_idx], y_train[tr_idx])

        fold_preds = fold_model.predict(X_train[val_idx])
        fold_preds = encode_pred_labels(fold_preds)  # FIXED
        y_pred_cv[val_idx] = fold_preds

        pbar.set_postfix({"ETA": eta_formatter(time.time() - cv_start, i, args.cv_folds)})
        pbar.update(1)

    pbar.close()

    # Final training
    model.fit(X_train, y_train)

    # Test evaluation
    y_test_pred = model.predict(X_test)
    y_test_pred = encode_pred_labels(y_test_pred)  # FIXED

    report_train = classification_report(y_train, encode_pred_labels(y_pred_cv),
                                         output_dict=True, zero_division=0)
    report_test  = classification_report(y_test, y_test_pred,
                                         output_dict=True, zero_division=0)
    cm  = confusion_matrix(y_test, y_test_pred)
    acc = accuracy_score(y_test, y_test_pred)

    # Save model
    model_path = Path(args.out_dir) / f"model_{args.model_type}.joblib"
    joblib.dump(model, model_path)

    # Save preprocessor
    preproc_path = Path(args.out_dir) / "preprocessor.joblib"
    joblib.dump(preprocessor, preproc_path)

    # Save feature names
    with open(Path(args.out_dir) / "feature_names.json", "w") as f:
        json.dump({"feature_names": transformed_names}, f, indent=2)

    # Save metadata
    metadata = {
        "feature_level": args.feature_level,
        "model_type": args.model_type,
        "model_path": str(model_path),
        "preprocessor_path": str(preproc_path),
        "used_files": {str(f): sha256_file(f) for f in used_files},
        "feature_names": transformed_names,
        "label_map": LABEL_TO_INT,
        "test_accuracy": float(acc),
        "confusion_matrix": cm.tolist(),
        "report_train": report_train,
        "report_test": report_test,
        "python_version": platform.python_version(),
    }

    with open(Path(args.out_dir) / "train_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    tqdm.write("\n🎉 TRAINING COMPLETE 🎉")
    tqdm.write(f"Model saved at: {model_path}")
    tqdm.write(f"Preprocessor saved at: {preproc_path}")
    tqdm.write(f"Accuracy: {acc:.4f}")


if __name__ == "__main__":
    main()
