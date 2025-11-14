#!/usr/bin/env python3
"""
train_model.py — REAL PROGRESS VERSION (FINAL)
Compatible with run_all.py

Enhancements:
    ✔ Real K-fold progress bar
    ✔ Real final training progress bar
    ✔ Real evaluation progress bar
    ✔ ETA during cross-validation
    ✔ Multiclass support
    ✔ No artificial sleeps
    ✔ Same outputs as before (joblib + metadata)
"""

import argparse, json, os, hashlib, platform, time
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from tqdm import tqdm
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

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


def load_dataset(data_dir, feature_level, test_split, seed):
    data_dir = Path(data_dir)

    train_path = data_dir / f"{feature_level}_train.csv"
    test_path  = data_dir / f"{feature_level}_test.csv"

    tqdm.write("📂 Loading dataset...")

    if train_path.exists() and test_path.exists():
        df_train = pd.read_csv(train_path)
        df_test = pd.read_csv(test_path)
        return df_train, df_test, [train_path, test_path]

    combined_path = data_dir / f"{feature_level}.csv"
    if not combined_path.exists():
        raise FileNotFoundError(f"Missing {combined_path}")

    df = pd.read_csv(combined_path)
    y_col = "label" if "label" in df.columns else "is_attack"

    df_train, df_test = train_test_split(
        df, test_size=test_split, stratify=df[y_col], random_state=seed
    )

    df_train.to_csv(train_path, index=False)
    df_test.to_csv(test_path, index=False)

    return df_train, df_test, [train_path, test_path]


def prepare_features(df):
    df = df.copy()
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    drop_cols = ["ip_src", "ip_dst", "protocol", "mqtt_flag", "mqtt_flags"]

    if "label" in df.columns:
        y = df["label"].astype(str).values
        drop_cols.append("label")
    else:
        y = df["is_attack"].astype(int).values
        drop_cols.append("is_attack")

    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")
    X = df.select_dtypes(include=[np.number]).fillna(0)

    return X, y, list(X.columns)


def build_model(model_type, seed):
    if model_type == "dt":
        return DecisionTreeClassifier(random_state=seed)
    return RandomForestClassifier(
        n_estimators=250,
        n_jobs=-1,
        class_weight="balanced_subsample",
        random_state=seed
    )


# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------

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

    # -------------------------------
    # Load Dataset
    # -------------------------------
    start_time = time.time()
    df_train, df_test, used_files = load_dataset(
        args.data_dir, args.feature_level, args.test_split, args.seed
    )
    tqdm.write(f"⏳ Dataset loaded in {time.time() - start_time:.2f}s")

    # -------------------------------
    # Prepare features
    # -------------------------------
    tqdm.write("🔧 Preparing feature matrices...")
    X_train, y_train, feature_names = prepare_features(df_train)
    X_test,  y_test,  _             = prepare_features(df_test)

    # -------------------------------
    # Build model
    # -------------------------------
    model = build_model(args.model_type, args.seed)
    tqdm.write(f"🤖 Model: {args.model_type.upper()} | Feature level: {args.feature_level}")

    # -------------------------------
    # REAL K-Fold CV Progress Bar
    # -------------------------------
    tqdm.write("\n📊 K-Fold Cross Validation:")

    skf = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=args.seed)
    folds = list(skf.split(X_train, y_train))

    y_pred_cv = np.empty_like(y_train, dtype=object)
    cv_start = time.time()

    pbar = tqdm(total=args.cv_folds, desc="CV Progress", ncols=80)

    for i, (tr, val) in enumerate(folds, start=1):
        clf_fold = build_model(args.model_type, args.seed + i)
        clf_fold.fit(X_train.iloc[tr], y_train[tr])

        # Predict fold
        y_pred_cv[val] = clf_fold.predict(X_train.iloc[val])

        # ETA update
        elapsed = time.time() - cv_start
        eta = eta_formatter(elapsed, i, args.cv_folds)
        pbar.set_postfix({"ETA": eta})
        pbar.update(1)

    pbar.close()

    # -------------------------------
    # REAL Final Training Progress Bar
    # -------------------------------
    tqdm.write("\n🏁 Final model training:")

    fit_start = time.time()
    with tqdm(total=1, desc="Training RF", ncols=80) as bar:
        model.fit(X_train, y_train)
        bar.update(1)

    tqdm.write(f"   ✔ Final fit completed in {time.time() - fit_start:.2f}s")

    # -------------------------------
    # REAL Evaluation Progress Bar
    # -------------------------------
    tqdm.write("\n🧪 Evaluating model:")
    with tqdm(total=1, desc="Evaluating", ncols=80) as bar:
        y_test_pred = model.predict(X_test)
        bar.update(1)

    report_train = classification_report(y_train, y_pred_cv, output_dict=True, zero_division=0)
    report_test  = classification_report(y_test, y_test_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_test_pred)
    acc = accuracy_score(y_test, y_test_pred)

    # -------------------------------
    # Save artifacts
    # -------------------------------
    model_path = Path(args.out_dir) / f"model_{args.model_type}.joblib"
    joblib.dump(model, model_path)

    with open(Path(args.out_dir) / "feature_names.json", "w") as f:
        json.dump({"feature_names": feature_names}, f, indent=2)

    with open(Path(args.out_dir) / "train_metadata.json", "w") as f:
        json.dump({
            "feature_level": args.feature_level,
            "model_type": args.model_type,
            "model_path": str(model_path),
            "used_files": {str(f): sha256_file(f) for f in used_files},
            "feature_names": feature_names,
            "test_accuracy": float(acc),
            "confusion_matrix": cm.tolist(),
            "report_train": report_train,
            "report_test": report_test,
            "python_version": platform.python_version(),
        }, f, indent=2)

    tqdm.write("\n🎉 TRAINING COMPLETE 🎉")
    tqdm.write(f"Model saved at: {model_path}")
    tqdm.write(f"Accuracy: {acc:.4f}")
    tqdm.write(f"Confusion Matrix:\n{cm}")


if __name__ == "__main__":
    main()
