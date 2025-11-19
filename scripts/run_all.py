#!/usr/bin/env python3
"""
Automated MQTT-IoT-IDS2020 pipeline runner (optimized for incremental runs).

Runs all 3 steps (prepare → train → evaluate) for:
  - packet  → Decision Tree
  - uniflow → Random Forest
  - biflow  → Random Forest

Smart behavior:
  ✅ Skip Step 1 if combined/<feature>/<feature>_train.csv already exists
  ✅ Skip Step 2 if model joblib already exists
  ✅ Skip Step 3 if evaluation results already exist
"""

import subprocess, os, sys
from pathlib import Path

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
COMBINED_DIR = DATA_DIR / "combined"
MODEL_DIR = BASE_DIR / "model_outputs"
SCRIPTS_DIR = BASE_DIR / "scripts"

FEATURE_LEVELS = ["uniflow", "biflow", "packet"]
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
    except subprocess.CalledProcessError as e:
        print(f"❌ Error during: {step_desc}")
        print("Command:", " ".join(cmd_list))
        sys.exit(1)

# ----------------------------------------------------------------------
# MAIN PIPELINE
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

        # ------------------------------------------------------------------
        # STEP 1 — PREPARE COMBINED CSVs  (NEW SUBFOLDER STRUCTURE)
        # ------------------------------------------------------------------
        feature_dir = COMBINED_DIR / feature
        train_csv = feature_dir / f"{feature}_train.csv"
        test_csv  = feature_dir / f"{feature}_test.csv"

        if train_csv.exists() and test_csv.exists():
            print("⏭️  Skipping Step 1 — Combined CSVs already exist:")
            print("    ", train_csv)
            print("    ", test_csv)
        else:
            step1 = [
                sys.executable, str(SCRIPTS_DIR / "prepare_combined_csv.py"),
                "--data-dir", str(DATA_DIR),
                "--feature-level", feature,
                "--out-dir", str(COMBINED_DIR),
                "--test-split", str(TEST_SPLIT),
                "--seed", str(SEED)
            ]
            run_cmd(step1, f"Step 1 — Prepare Combined CSV ({feature})")

        # ------------------------------------------------------------------
        # STEP 2 — TRAIN MODEL (correct simplified path)
        # ------------------------------------------------------------------
        model_out_dir = MODEL_DIR / feature / model_name
        model_file = model_out_dir / f"model_{model_type}.joblib"
        preproc_file = model_out_dir / "preprocessor.joblib"

        if model_file.exists() and preproc_file.exists():
            print(f"⏭️  Skipping Step 2 — Model already exists:\n    {model_file}")
        else:
            step2 = [
                sys.executable, str(SCRIPTS_DIR / "train_model.py"),
                "--data-dir", str(COMBINED_DIR),
                "--feature-level", feature,
                "--model-type", model_type,
                "--out-dir", str(model_out_dir),
                "--seed", str(SEED),
                "--cv-folds", str(CV_FOLDS),
                "--test-split", str(TEST_SPLIT)
            ]
            run_cmd(step2, f"Step 2 — Train Model ({feature})")

        if not model_file.exists():
            print(f"❌ ERROR: Model file missing after training: {model_file}")
            sys.exit(1)

        print(f"✔ Model ready: {model_file}")

        # ------------------------------------------------------------------
        # STEP 3 — Evaluate Model (stricter skip logic)
        # ------------------------------------------------------------------
        eval_dir = model_out_dir / "evaluation_results"
        os.makedirs(eval_dir, exist_ok=True)

        # Evaluation outputs (must ALL exist to skip)
        summary_file = eval_dir / "eval_summary.json"
        csv_report  = eval_dir / "eval_classification_report.csv"
        plot_file   = eval_dir / "confusion_matrix.png"

        if summary_file.exists() and csv_report.exists() and plot_file.exists():
            print(f"⏭️  Skipping Step 3 — Evaluation already done:")
            print("    ", summary_file)
        else:
            step3 = [
                sys.executable, str(SCRIPTS_DIR / "evaluate_model.py"),
                "--model", str(model_file),
                "--test-csv", str(test_csv),
                "--out-dir", str(eval_dir)
            ]
            run_cmd(step3, f"Step 3 — Evaluate Model ({feature})")

        print(f"🎯 Completed pipeline for {feature.upper()} ✔️")

    print("\n✔ ALL PIPELINES COMPLETED SUCCESSFULLY.\n")


if __name__ == "__main__":
    main()
