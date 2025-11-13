#!/usr/bin/env python3
"""
Adaptive model evaluator for MQTT-IoT-IDS2020.

Automatically detects whether the model is:
  - Binary classifier (0/1) → uses 'is_attack'
  - Multiclass classifier → uses 'label'

Outputs:
  - Classification report (TXT + CSV)
  - Confusion matrix (PNG)
  - Evaluation summary (JSON)
"""

import argparse
import os
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)

# ----------------------------------------------------------------------
# Helper: Align test features with model training schema
# ----------------------------------------------------------------------
def align_features_with_model(X_test, clf, model_dir):
    """Ensure test features match those used during training."""
    if hasattr(clf, "feature_names_in_"):
        expected_features = list(clf.feature_names_in_)
    else:
        feature_file = Path(model_dir) / "feature_names.json"
        if feature_file.exists():
            with open(feature_file, "r") as f:
                expected_features = json.load(f).get("feature_names", [])
            print(f"✅ Loaded expected feature list from {feature_file}")
        else:
            print("⚠️ Model missing feature metadata; assuming same feature order.")
            return X_test

    missing = [f for f in expected_features if f not in X_test.columns]
    extra = [f for f in X_test.columns if f not in expected_features]

    if missing:
        print(f"⚠️ Adding {len(missing)} missing features (filled with 0): {missing}")
        for col in missing:
            X_test[col] = 0

    if extra:
        print(f"⚠️ Dropping {len(extra)} unexpected features: {extra}")
        X_test = X_test.drop(columns=extra)

    X_test = X_test[expected_features]
    print(f"✅ Aligned test features to {len(expected_features)} columns.")
    return X_test


# ----------------------------------------------------------------------
# Main Evaluation Logic
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, help="Path to trained model (.joblib)")
    parser.add_argument("--test-csv", required=True, help="Path to test CSV")
    parser.add_argument("--out-dir", required=True, help="Output directory for results")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    model_path = Path(args.model)
    model_dir = model_path.parent

    print(f"🔹 Evaluating model: {model_path}")
    clf = joblib.load(model_path)

    # Load test data
    df = pd.read_csv(args.test_csv)
    print(f"✅ Test set: {len(df)} samples, {df.shape[1]} columns")

    # Identify target column automatically
    y_true = None
    target_type = None

    if "is_attack" in df.columns and set(df["is_attack"].unique()) <= {0, 1}:
        y_true = df["is_attack"].astype(int)
        target_type = "binary"
    elif "label" in df.columns:
        y_true = df["label"].astype(str)
        target_type = "multiclass"
    else:
        raise ValueError("Test CSV must contain 'is_attack' or 'label' column.")

    # Prepare features
    X_test = df.drop(columns=["is_attack", "label"], errors="ignore")
    X_test = align_features_with_model(X_test, clf, model_dir)

    # Predict
    y_pred = clf.predict(X_test)

    # ------------------------------------------------------------------
    # Adaptive Evaluation: Binary or Multiclass
    # ------------------------------------------------------------------
    if target_type == "binary":
        print("🧠 Detected: Binary Classification (Normal vs Attack)")
        labels = [0, 1]
        label_names = ["Normal", "Attack"]

    else:
        print("🧠 Detected: Multiclass Classification")
        labels = sorted(df["label"].unique())
        label_names = labels

    # Metrics
    acc = accuracy_score(y_true, y_pred)
    print(f"\nAccuracy: {acc:.4f}")

    report_str = classification_report(y_true, y_pred, digits=4)
    report_dict = classification_report(y_true, y_pred, output_dict=True)
    print("\nClassification Report:")
    print(report_str)

    # Save text and CSV reports
    txt_path = Path(args.out_dir) / "eval_classification_report.txt"
    csv_path = Path(args.out_dir) / "eval_classification_report.csv"
    pd.DataFrame(report_dict).transpose().to_csv(csv_path)
    with open(txt_path, "w") as f:
        f.write(report_str)

    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=label_names)
    disp.plot(cmap="Blues", xticks_rotation=45)
    title = (
        "Confusion Matrix (Binary)" if target_type == "binary"
        else "Confusion Matrix (Multiclass)"
    )
    plt.title(title)
    plt.tight_layout()
    cm_path = Path(args.out_dir) / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=250)
    plt.close()

    # Summary
    summary = {
        "model": str(model_path),
        "test_csv": str(args.test_csv),
        "target_type": target_type,
        "accuracy": acc,
        "n_samples": len(df),
        "n_features": X_test.shape[1],
        "unique_labels": label_names,
    }
    with open(Path(args.out_dir) / "eval_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n📄 Full report saved to {txt_path}")
    print(f"📊 CSV report saved to {csv_path}")
    print(f"📈 Confusion matrix saved to {cm_path}")
    print(f"📝 Evaluation summary saved to {args.out_dir}/eval_summary.json\n")
    print("✅ Evaluation complete.\n")


if __name__ == "__main__":
    main()
