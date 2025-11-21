#!/usr/bin/env python3
"""
evaluate_model.py — FINAL FIXED VERSION (supports preprocessing)

✔ Loads preprocessor.joblib
✔ Loads feature_names from train_metadata.json
✔ Applies the SAME preprocessing as training
✔ Avoids feature mismatch errors
✔ Evaluates model properly
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

    # Extract labels
    if "label" in df.columns:
        y = df["label"].astype(str).values
        df = df.drop(columns=["label"])
    elif "is_attack" in df.columns:
        y = df["is_attack"].astype(int).values
        df = df.drop(columns=["is_attack"])
    else:
        raise ValueError("No label column found in test CSV.")

    return df, y


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True)
    p.add_argument("--test-csv", required=True)
    p.add_argument("--out-dir", required=True)
    args = p.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # Load model
    clf = joblib.load(args.model)

    # Load metadata + preprocessor
    model_folder = Path(args.model).parent
    meta = json.load(open(model_folder / "train_metadata.json"))
    preproc_path = model_folder / "preprocessor.joblib"
    preprocessor = joblib.load(preproc_path)

    label_map = meta["label_map"]

    # Load test CSV raw
    X_raw, y_true = load_test_csv(args.test_csv)
    
    if y_true is None:
        raise ValueError("Test CSV has no label column (label/is_attack missing).")

    # Force same column style before preprocessing
    X_raw = X_raw.fillna(-1)

    # --- THE FIX: apply preprocessing pipeline ---
    X = preprocessor.transform(X_raw)

    # Predict
    y_pred = clf.predict(X)

    # If true labels are strings, convert using label_map
    if y_true is not None:
        y_true_clean = []
        for v in y_true:
            if isinstance(v, str):
                y_true_clean.append(label_map.get(v, -1))
            else:
                y_true_clean.append(int(v))
        y_true = np.array(y_true_clean)

    y_pred = y_pred.astype(int)

    # Metrics
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    acc = accuracy_score(y_true, y_pred)

    # Save report CSV
    df_report = pd.DataFrame(report).transpose()
    df_report.to_csv(Path(args.out_dir) / "eval_classification_report.csv")

    # TXT report
    with open(Path(args.out_dir) / "eval_classification_report.txt", "w") as f:
        f.write(df_report.to_string())

    # Confusion matrix plot
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig(Path(args.out_dir) / "confusion_matrix.png")
    plt.close()

    # Summary JSON
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
