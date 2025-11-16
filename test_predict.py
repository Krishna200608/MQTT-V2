import os
import json
import joblib
import pandas as pd
from live_ids import extract_biflow_29
from tqdm import tqdm
from rich.console import Console
from rich.progress import (
    Progress, TimeRemainingColumn, TimeElapsedColumn,
    BarColumn, TaskProgressColumn, SpinnerColumn
)

console = Console()

# ============================================================
#  PATHS
# ============================================================
pcap_folder = "pcap_files"
report_folder = "reports"
pcap_reports_folder = os.path.join(report_folder, "pcap_reports")

os.makedirs(report_folder, exist_ok=True)
os.makedirs(pcap_reports_folder, exist_ok=True)

biflow_model_path = "model_outputs/biflow/random_forest/model_rf.joblib"
biflow_meta_path  = "model_outputs/biflow/random_forest/train_metadata.json"

# ============================================================
#  STEP 1: LOAD MODEL
# ============================================================
console.rule("[bold cyan]Step 1: Load Model")

model_b = joblib.load(biflow_model_path)
meta_b  = json.load(open(biflow_meta_path))
feature_names_b = meta_b["feature_names"]

# Print model classes
model_classes = [str(c).strip() for c in model_b.classes_]
console.print(f"[bold yellow]Model Classes:[/] {model_classes}")

console.print("✓ Model Loaded.\n", style="bold green")

# ============================================================
#  TRUE ATTACK CLASSES (from model)
# ============================================================
# Normalize model classes
normalized_model_classes = {c.lower().strip(): c for c in model_classes}

# Known attack keywords (case-insensitive)
ATTACK_KEYWORDS = ["scan", "sparta", "mqtt"]

# Determine which model classes are attacks
ATTACK_LABELS = {
    c for c in normalized_model_classes
    if any(k in c for k in ATTACK_KEYWORDS)
}

console.print(f"[bold cyan]Detected Attack Classes:[/] {ATTACK_LABELS}\n")

# ============================================================
#  FIND PCAP FILES
# ============================================================
pcap_files = [
    os.path.join(pcap_folder, f)
    for f in os.listdir(pcap_folder)
    if f.lower().endswith(".pcap")
]

if not pcap_files:
    console.print("[bold red]No PCAP files found![/]")
    exit()

console.print(f"[yellow]Found {len(pcap_files)} PCAP files[/]\n")

summary_rows = []

# ============================================================
#  PROCESS EACH PCAP
# ============================================================
for pcap in pcap_files:

    pcap_name = os.path.basename(pcap)
    console.rule(f"[bold magenta]Processing PCAP: {pcap_name}")

    # ---------------- Extract biflows ----------------
    console.rule("[bold cyan]Step 2: Extract Biflow Features")

    feats, metas = extract_biflow_29(pcap)
    console.print(f"Found {len(feats)} raw biflows", style="bold yellow")

    if not feats:
        console.print("[bold red]NO FLOWS EXTRACTED — skipping[/]")
        summary_rows.append({
            "pcap": pcap_name,
            "flows": 0,
            "attacks": 0,
            "attack_ratio": 0,
            "avg_probability": 0,
            "sample_preds": "[]"
        })
        continue

    # ---------------- DataFrame prep ----------------
    console.rule("[bold cyan]Step 3: Prepare DataFrame")

    df = pd.DataFrame(feats).reindex(columns=feature_names_b, fill_value=0)

    # Convert columns
    for col in df.columns:
        df[col] = df[col].astype(float)

    console.print(f"✓ DF shape = {df.shape}\n", style="bold green")

    # ---------------- Predictions ----------------
    console.rule("[bold cyan]Step 4: Prediction")

    preds = []
    probs = []

    batch_size = 5000
    for i in range(0, len(df), batch_size):
        batch = df.iloc[i:i+batch_size]

        batch_pred = model_b.predict(batch)
        batch_prob = model_b.predict_proba(batch)

        preds.extend(batch_pred)
        probs.extend(batch_prob)

    console.print("✓ Predictions completed\n", style="bold green")

    # Normalize prediction labels
    preds_clean = [str(p).strip().lower() for p in preds]
    prob_max = [max(p) for p in probs]

    # ---------------- Per-PCAP report ----------------
    console.rule("[bold cyan]Step 5: Per-PCAP Report")

    out_csv = os.path.join(pcap_reports_folder, pcap_name.replace(".pcap", ".csv"))
    report_df = pd.DataFrame({
        "pcap_file": pcap_name,
        "flow_index": range(len(preds_clean)),
        "prediction": preds_clean,
        "probability": prob_max,
    })
    report_df.to_csv(out_csv, index=False)

    console.print(f"Saved: {out_csv}", style="bold green")

    # Count attacks
    attack_count = sum(1 for p in preds_clean if p in ATTACK_LABELS)
    attack_ratio = attack_count / len(preds_clean)

    summary_rows.append({
        "pcap": pcap_name,
        "flows": len(preds_clean),
        "attacks": attack_count,
        "attack_ratio": round(attack_ratio, 4),
        "avg_probability": round(sum(prob_max)/len(prob_max), 5),
        "sample_preds": str(preds_clean[:10]),
    })

# ============================================================
#  WRITE SUMMARY
# ============================================================
console.rule("[bold green]Writing Combined Summary Report")

summary_df = pd.DataFrame(summary_rows)
summary_path = os.path.join(report_folder, "summary_report.csv")
summary_df.to_csv(summary_path, index=False)

console.print(f"[bold green]✓ Summary saved to {summary_path}[/]")
