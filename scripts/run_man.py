#!/usr/bin/env python3
"""
run_man.py — Mandatory Full Retraining Pipeline

Runs ALL steps for ALL modes:
    packet  → Decision Tree
    uniflow → Random Forest
    biflow  → Random Forest

Always:
    ✔ Clean old combined/<mode> folders
    ✔ Clean model_outputs/<mode> folders
    ✔ Recreate CSVs
    ✔ Retrain models
    ✔ Re-evaluate models

NO command-line arguments required.
"""

import subprocess
import shutil
import os
import sys
from pathlib import Path


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
COMBINED_DIR = DATA_DIR / "combined"
MODEL_DIR = BASE_DIR / "model_outputs"
SCRIPTS_DIR = BASE_DIR / "scripts"

FEATURE_LEVELS = ["packet", "uniflow", "biflow"]

MODEL_MAP = {
    "packet": "dt",
    "uniflow": "rf",
    "biflow": "rf"
}

SEED = 42
TEST_SPLIT = 0.25
CV = 5


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def run_cmd(cmd, desc):
    print("\n" + "=" * 80)
    print(f"▶ {desc}")
    print("=" * 80)

    try:
        subprocess.run(cmd, check=True, text=True)
        print(f"✔ {desc} completed")
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR in: {desc}")
        print("Command:", " ".join(cmd))
        raise


def safe_remove(path: Path):
    if path.exists():
        if path.is_file():
            print(f"🗑 Removing file: {path}")
            path.unlink()
        else:
            print(f"🗑 Removing folder: {path}")
            shutil.rmtree(path)


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    print("\n" + "#" * 80)
    print("🚀 MQTT IDS – FULL MANDATORY REBUILD PIPELINE")
    print("#" * 80 + "\n")

    os.makedirs(COMBINED_DIR, exist_ok=True)
    os.makedirs(MODEL_DIR, exist_ok=True)

    for mode in FEATURE_LEVELS:
        model_type = MODEL_MAP[mode]
        model_name = "decision_tree" if model_type == "dt" else "random_forest"

        print("\n" + "#" * 80)
        print(f"🚀 PIPELINE START: {mode.upper()} ({model_name})")
        print("#" * 80)

        # ------------------------------
        # CLEAN OLD FILES
        # ------------------------------
        combined_folder = COMBINED_DIR / mode
        model_folder = MODEL_DIR / mode / model_name

        safe_remove(combined_folder)
        safe_remove(model_folder)

        os.makedirs(combined_folder, exist_ok=True)
        os.makedirs(model_folder, exist_ok=True)

        # ------------------------------
        # 1. PREPARE CSV
        # ------------------------------
        run_cmd([
            sys.executable, str(SCRIPTS_DIR / "prepare_combined_csv.py"),
            "--data-dir", str(DATA_DIR),
            "--feature-level", mode,
            "--out-dir", str(COMBINED_DIR),
            "--seed", str(SEED),
            "--test-split", str(TEST_SPLIT)
        ], f"Step 1 — Prepare CSV ({mode})")

        # ------------------------------
        # 2. TRAIN MODEL
        # ------------------------------
        run_cmd([
            sys.executable, str(SCRIPTS_DIR / "train_model.py"),
            "--data-dir", str(COMBINED_DIR),
            "--feature-level", mode,
            "--model-type", model_type,
            "--out-dir", str(model_folder),
            "--seed", str(SEED),
            "--cv-folds", str(CV),
            "--test-split", str(TEST_SPLIT)
        ], f"Step 2 — Train Model ({mode})")

        # ------------------------------
        # 3. EVALUATE MODEL
        # ------------------------------
        eval_folder = model_folder / "evaluation_results"
        os.makedirs(eval_folder, exist_ok=True)

        model_path = model_folder / f"model_{model_type}.joblib"
        test_csv_path = COMBINED_DIR / mode / f"{mode}_test.csv"

        run_cmd([
            sys.executable, str(SCRIPTS_DIR / "evaluate_model.py"),
            "--model", str(model_path),
            "--test-csv", str(test_csv_path),
            "--out-dir", str(eval_folder)
        ], f"Step 3 — Evaluate Model ({mode})")

        print(f"\n✔ Completed pipeline for {mode.upper()}\n")

    print("\n✔✔✔ ALL MODES COMPLETED — FULL REBUILD SUCCESSFUL\n")


if __name__ == "__main__":
    main()
