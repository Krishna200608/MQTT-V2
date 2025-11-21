#!/usr/bin/env python3
"""
run_man.py — Mandatory Full Retraining Pipeline
"""

import subprocess, shutil, os, sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
COMBINED_DIR = DATA_DIR / "combined"
MODEL_DIR = BASE_DIR / "model_outputs"
SCRIPTS_DIR = BASE_DIR / "scripts"

PREPARE_SCRIPT = SCRIPTS_DIR / "prepare_combined_csv.py"
AUGMENT_SCRIPT = SCRIPTS_DIR / "augment_dataset.py"
TRAIN_SCRIPT   = SCRIPTS_DIR / "train_model.py"
EVAL_SCRIPT    = SCRIPTS_DIR / "evaluate_model.py"

FEATURE_LEVELS = ["packet", "uniflow", "biflow"]

MODEL_MAP = {
    "packet": "dt",
    "uniflow": "rf",
    "biflow": "rf"
}

SEED = 42
TEST_SPLIT = 0.25
CV = 5

def run_cmd(cmd, desc):
    print("\n" + "="*80)
    print(f"▶ {desc}")
    print("="*80)
    subprocess.run(cmd, check=True, text=True)
    print(f"✔ {desc} completed")

def safe_remove(path: Path):
    if path.exists():
        if path.is_file():
            path.unlink()
        else:
            shutil.rmtree(path)

def main():

    print("\n" + "#"*80)
    print("🚀 MQTT IDS — FULL MANDATORY REBUILD")
    print("#"*80 + "\n")

    os.makedirs(COMBINED_DIR, exist_ok=True)
    os.makedirs(MODEL_DIR, exist_ok=True)

    for mode in FEATURE_LEVELS:
        model_type = MODEL_MAP[mode]
        model_name = "decision_tree" if model_type == "dt" else "random_forest"

        print("\n" + "#"*80)
        print(f"🚀 PIPELINE START: {mode.upper()} ({model_name})")
        print("#"*80)

        combined_folder = COMBINED_DIR / mode
        model_folder = MODEL_DIR / mode / model_name

        safe_remove(combined_folder)
        safe_remove(model_folder)

        os.makedirs(combined_folder, exist_ok=True)
        os.makedirs(model_folder, exist_ok=True)

        # --------------------------------------------------
        # 1. PREPARE CSV
        # --------------------------------------------------
        run_cmd(
            [
                sys.executable, str(PREPARE_SCRIPT),
                "--data-dir", str(DATA_DIR),
                "--feature-level", mode,
                "--out-dir", str(COMBINED_DIR),
                "--seed", str(SEED),
                "--test-split", str(TEST_SPLIT)
            ],
            f"Step 1 — Prepare CSV ({mode})"
        )

        # --------------------------------------------------
        # 2. AUGMENT DATA
        # --------------------------------------------------
        run_cmd(
            [
                sys.executable, str(AUGMENT_SCRIPT),
                "--feature-level", mode,
                "--data-dir", str(COMBINED_DIR)
            ],
            f"Step 2 — Augment Dataset ({mode})"
        )

        # --------------------------------------------------
        # 3. TRAIN MODEL
        # --------------------------------------------------
        run_cmd(
            [
                sys.executable, str(TRAIN_SCRIPT),
                "--data-dir", str(COMBINED_DIR),
                "--feature-level", mode,
                "--model-type", model_type,
                "--out-dir", str(model_folder),
                "--seed", str(SEED),
                "--cv-folds", str(CV),
                "--test-split", str(TEST_SPLIT)
            ],
            f"Step 3 — Train Model ({mode})"
        )

        # --------------------------------------------------
        # 4. EVALUATE MODEL
        # --------------------------------------------------
        eval_folder = model_folder / "evaluation_results"
        os.makedirs(eval_folder, exist_ok=True)

        test_csv_path = COMBINED_DIR / mode / f"{mode}_test.csv"
        model_path = model_folder / f"model_{model_type}.joblib"

        run_cmd(
            [
                sys.executable, str(EVAL_SCRIPT),
                "--model", str(model_path),
                "--test-csv", str(test_csv_path),
                "--out-dir", str(eval_folder)
            ],
            f"Step 4 — Evaluate Model ({mode})"
        )

        print(f"✔ Finished pipeline for {mode.upper()}")

    print("\n✔✔✔ FULL REBUILD SUCCESSFUL\n")


if __name__ == "__main__":
    main()
