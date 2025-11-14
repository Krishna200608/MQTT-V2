#!/usr/bin/env python3
"""
evaluate_model.py — FINAL VERSION (multiclass)

✔ Works with run_all.py
✔ reads *_test.csv from command line
✔ Aligns test CSV columns with saved feature_names.json
✔ Generates:
    - eval_classification_report.txt
    - eval_classification_report.csv
    - confusion_matrix.png
    - eval_summary.json
"""

import argparse, json, os
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns


def load_test_csv(path):
    df = pd.read_csv(path)
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    y = None
    if "label" in df.columns:
        y = df["label"].astype(str).values
        df = df.drop(columns=["label"])
    elif "is_attack" in df.columns:
        y = df["is_attack"].astype(int).values
        df = df.drop(columns=["is_attack"])

    X = df.select_dtypes(include=[np.number]).fillna(0)
    return X, y


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True)
    p.add_argument("--test-csv", required=True)
    p.add_argument("--out-dir", required=True)
    args = p.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # Load model
    clf = joblib.load(args.model)

    # Load metadata (for feature_names)
    meta_file = Path(args.model).parent / "train_metadata.json"
    meta = json.load(open(meta_file))
    feature_names = meta["feature_names"]

    # Load test CSV
    X, y_true = load_test_csv(args.test_csv)

    # Align columns
    X = X.reindex(columns=feature_names, fill_value=0)

    # Predict
    y_pred = clf.predict(X)

    # Metrics
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    acc = accuracy_score(y_true, y_pred)

    # Save report (CSV + TXT)
    df_report = pd.DataFrame(report).transpose()
    df_report.to_csv(Path(args.out_dir) / "eval_classification_report.csv")
    with open(Path(args.out_dir) / "eval_classification_report.txt", "w") as f:
        f.write(df_report.to_string())

    # Save confusion matrix image
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.tight_layout()
    plt.savefig(Path(args.out_dir) / "confusion_matrix.png")
    plt.close()

    # Save summary
    with open(Path(args.out_dir) / "eval_summary.json", "w") as f:
        json.dump({
            "test_accuracy": float(acc),
            "confusion_matrix": cm.tolist(),
            "classification_report": report
        }, f, indent=2)

    print("\n=== EVALUATION COMPLETE ===")
    print("Accuracy:", acc)
    print("Confusion:\n", cm)


if __name__ == "__main__":
    main()
