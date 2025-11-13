#!/usr/bin/env python3
"""
Automated MQTT-IoT-IDS2020 pipeline runner (optimized for incremental runs).

Runs all 3 steps (prepare → train → evaluate) for:
  - packet  → Decision Tree (best in research)
  - uniflow → Random Forest
  - biflow  → Random Forest

Smart behavior:
  ✅ Skip Step 1 if combined CSVs already exist
  ✅ Skip Step 2 if model .joblib already exists
  ✅ Skip Step 3 if evaluation results already exist

Outputs:
  model_outputs/<feature_level>/<model_type>/evaluation_results/
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

FEATURE_LEVELS = ["packet", "uniflow", "biflow"]
SEED = 42
TEST_SPLIT = 0.25
CV_FOLDS = 5

MODEL_MAP = {
    "packet": "dt",      # Decision Tree
    "uniflow": "rf",     # Random Forest
    "biflow": "rf"       # Random Forest
}

# ----------------------------------------------------------------------
# HELPER FUNCTION
# ----------------------------------------------------------------------
def run_cmd(cmd_list, step_desc):
    """Run a shell command with visible output and handle errors clearly."""
    print(f"\n{'='*80}")
    print(f"🧩 {step_desc}")
    print("="*80)
    try:
        subprocess.run(cmd_list, check=True, text=True)
        print(f"✅ Completed: {step_desc}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error during: {step_desc}")
        print(f"Command: {' '.join(cmd_list)}")
        print(e)
        sys.exit(1)

# ----------------------------------------------------------------------
# MAIN PIPELINE
# ----------------------------------------------------------------------
def main():
    print(f"\n{'#'*80}")
    print("🚀 MQTT-IoT-IDS2020 — Full ML Pipeline Runner (Optimized)")
    print(f"{'#'*80}\n")

    for feature in FEATURE_LEVELS:
        model_type = MODEL_MAP[feature]
        model_name = "random_forest" if model_type == "rf" else "decision_tree"

        print(f"\n{'#'*80}")
        print(f"🚀 Starting pipeline for feature-level: {feature.upper()} ({model_name.replace('_', ' ').title()})")
        print(f"{'#'*80}\n")

        # ----------------------------------------
        # Step 1 — Prepare combined CSVs (Skip if exists)
        # ----------------------------------------
        train_csv = COMBINED_DIR / f"{feature}_train.csv"
        test_csv = COMBINED_DIR / f"{feature}_test.csv"

        if train_csv.exists() and test_csv.exists():
            print(f"⏭️  Skipping data preparation — combined CSVs already exist:")
            print(f"   {train_csv}\n   {test_csv}")
        else:
            step1 = [
                sys.executable, str(SCRIPTS_DIR / "prepare_combined_csv.py"),
                "--data-dir", str(DATA_DIR),
                "--feature-level", feature,
                "--out-dir", str(COMBINED_DIR),
                "--test-split", str(TEST_SPLIT),
                "--seed", str(SEED)
            ]
            run_cmd(step1, f"Step 1 — Prepare combined CSV ({feature})")

        # ----------------------------------------
        # Step 2 — Train model (Skip if already trained)
        # ----------------------------------------
        model_out_dir = MODEL_DIR / feature / model_name
        os.makedirs(model_out_dir, exist_ok=True)

        # Compatibility: detect existing model in any known structure
        possible_paths = [
            model_out_dir / f"model_{model_type}.joblib",
            model_out_dir / "random_forest" / f"model_{model_type}.joblib",
            model_out_dir / f"model_{model_type}" / f"model_{model_type}.joblib",
        ]
        model_path = next((p for p in possible_paths if p.exists()), None)

        if model_path:
            print(f"⏭️  Skipping training — model already exists at:\n   {model_path}")
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
            run_cmd(step2, f"Step 2 — Train {model_name.replace('_', ' ').title()} Model ({feature})")

            # Re-check all possible locations after training
            model_path = next((p for p in possible_paths if p.exists()), None)
            if model_path is None:
                print(f"❌ Model not found after training. Checked paths:\n  " + "\n  ".join(map(str, possible_paths)))
                sys.exit(1)

        print(f"✅ Using model: {model_path}")

        # ----------------------------------------
        # Step 3 — Evaluate model (Skip if already evaluated)
        # ----------------------------------------
        eval_dir = model_out_dir / "evaluation_results"
        os.makedirs(eval_dir, exist_ok=True)

        # Detect if evaluation already completed
        summary_file = eval_dir / "eval_summary.json"
        txt_report = eval_dir / "eval_classification_report.txt"
        csv_report = eval_dir / "eval_classification_report.csv"
        confusion_plot = eval_dir / "confusion_matrix.png"

        if summary_file.exists() or (txt_report.exists() and csv_report.exists()):
            print(f"⏭️  Skipping evaluation — results already exist in:\n   {eval_dir}")
        else:
            if not model_path.exists():
                print(f"❌ Model file missing before evaluation: {model_path}")
                sys.exit(1)

            step3 = [
                sys.executable, str(SCRIPTS_DIR / "evaluate_model.py"),
                "--model", str(model_path),
                "--test-csv", str(test_csv),
                "--out-dir", str(eval_dir)
            ]
            run_cmd(step3, f"Step 3 — Evaluate Model ({feature})")

        print(f"\n🎯 Completed full pipeline for {feature.upper()} ✔️\n")

    print(f"\n✅ All pipelines (packet, uniflow, biflow) completed successfully!\n")


if __name__ == "__main__":
    main()
