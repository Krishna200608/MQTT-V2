#!/usr/bin/env python3
"""
Automated MQTT-IoT-IDS2020 pipeline runner (incremental mode with augmentation).
"""

import subprocess, os, sys
from pathlib import Path

# ----------------------------------------------------------------------
# PATHS
# ----------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
COMBINED_DIR = DATA_DIR / "combined"
MODEL_DIR = BASE_DIR / "model_outputs"
SCRIPTS_DIR = BASE_DIR / "scripts"

PREPARE_SCRIPT = SCRIPTS_DIR / "prepare_combined_csv.py"
AUGMENT_SCRIPT = SCRIPTS_DIR / "augment_dataset.py"
TRAIN_SCRIPT   = SCRIPTS_DIR / "train_model.py"
EVAL_SCRIPT    = SCRIPTS_DIR / "evaluate_model.py"

FEATURE_LEVELS = [ "packet","uniflow", "biflow"]
SEED = 42
TEST_SPLIT = 0.25
CV_FOLDS = 5

MODEL_MAP = {
    "packet": "dt",
    "uniflow": "rf",
    "biflow": "rf"
}

# ----------------------------------------------------------------------
# HELPER
# ----------------------------------------------------------------------
def run_cmd(cmd_list, step_desc):
    print("\n" + "="*80)
    print(f"🧩 {step_desc}")
    print("="*80)
    try:
        subprocess.run(cmd_list, check=True, text=True)
        print(f"✅ Completed: {step_desc}")
    except subprocess.CalledProcessError:
        print(f"❌ Error during {step_desc}")
        sys.exit(1)

# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------
def main():

    print("\n" + "#"*80)
    print("🚀 MQTT-IoT-IDS2020 — Full ML Pipeline Runner (Incremental Mode)")
    print("#"*80 + "\n")

    for feature in FEATURE_LEVELS:

        model_type = MODEL_MAP[feature]
        model_name = "random_forest" if model_type == "rf" else "decision_tree"

        print("\n" + "#"*80)
        print(f"🚀 Starting pipeline for: {feature.upper()} ({model_name})")
        print("#"*80)

        feature_dir = COMBINED_DIR / feature
        train_csv = feature_dir / f"{feature}_train.csv"
        test_csv  = feature_dir / f"{feature}_test.csv"

        # ------------------------------------------------------------------
        # STEP 1 — PREPARE COMBINED CSVs
        # ------------------------------------------------------------------
        if train_csv.exists() and test_csv.exists():
            print("⏭️ Skipping Step 1 (train/test CSVs exist)")
        else:
            run_cmd(
                [
                    sys.executable, str(PREPARE_SCRIPT),
                    "--data-dir", str(DATA_DIR),
                    "--feature-level", feature,
                    "--out-dir", str(COMBINED_DIR),
                    "--test-split", str(TEST_SPLIT),
                    "--seed", str(SEED)
                ],
                f"Step 1 — Prepare Combined CSV ({feature})"
            )

        # ------------------------------------------------------------------
        # STEP 2 — AUGMENT DATASET (AFTER train/test CSV exist)
        # ------------------------------------------------------------------
        run_cmd(
            [
                sys.executable, str(AUGMENT_SCRIPT),
                "--feature-level", feature,
                "--data-dir", str(COMBINED_DIR),
                "--balance", "oversample"
            ],
            f"Step 2 — Augment Dataset ({feature})"
        )

        # ------------------------------------------------------------------
        # STEP 3 — TRAIN MODEL
        # ------------------------------------------------------------------
        model_out = MODEL_DIR / feature / model_name
        model_path = model_out / f"model_{model_type}.joblib"
        preproc_path = model_out / "preprocessor.joblib"

        if model_path.exists() and preproc_path.exists():
            print("⏭️ Skipping Step 3 — Model already exists")
        else:
            run_cmd(
                [
                    sys.executable, str(TRAIN_SCRIPT),
                    "--data-dir", str(COMBINED_DIR),
                    "--feature-level", feature,
                    "--model-type", model_type,
                    "--out-dir", str(model_out),
                    "--seed", str(SEED),
                    "--cv-folds", str(CV_FOLDS),
                    "--test-split", str(TEST_SPLIT)
                ],
                f"Step 3 — Train Model ({feature})"
            )

        # ------------------------------------------------------------------
        # STEP 4 — EVALUATE
        # ------------------------------------------------------------------
        eval_dir = model_out / "evaluation_results"
        os.makedirs(eval_dir, exist_ok=True)

        summary = eval_dir / "eval_summary.json"
        report  = eval_dir / "eval_classification_report.csv"
        plot    = eval_dir / "confusion_matrix.png"

        if summary.exists() and report.exists() and plot.exists():
            print("⏭️ Skipping Step 4 — Evaluation complete")
        else:
            run_cmd(
                [
                    sys.executable, str(EVAL_SCRIPT),
                    "--model", str(model_path),
                    "--test-csv", str(test_csv),
                    "--out-dir", str(eval_dir)
                ],
                f"Step 4 — Evaluate Model ({feature})"
            )

        print(f"🎯 Completed pipeline for {feature.upper()}\n")

    print("\n✔ All pipelines completed successfully.\n")


if __name__ == "__main__":
    main()
