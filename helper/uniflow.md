### ⚙️ **1️⃣ Combine & Split Data**

```bash
python scripts/prepare_combined_csv.py ^
  --data-dir ./data ^
  --feature-level uniflow ^
  --out-dir ./data/combined ^
  --test-split 0.25 ^
  --seed 42
```

✅ **This will create:**

```
data/combined/
 ├── uniflow_train.csv
 └── uniflow_test.csv
```

---

### 🧠 **2️⃣ Train Model (Random Forest only)**

```bash
python scripts/train_model.py ^
  --data-dir ./data/combined ^
  --feature-level uniflow ^
  --model-type rf ^
  --out-dir ./model_outputs ^
  --seed 42 ^
  --cv-folds 5 ^
  --test-split 0.25
```

✅ **Outputs will be saved here:**

```
model_outputs/
 └── random_forest/
     ├── model_rf.joblib
     ├── feature_importance_rf.csv
     ├── feature_importance_rf.png
     └── train_metadata.json
```

---

### 🧪 **3️⃣ Evaluate the Trained Model**

```bash
python scripts/evaluate_model.py ^
  --model ./model_outputs/random_forest/model_rf.joblib ^
  --test-csv ./data/combined/uniflow_test.csv ^
  --out-dir ./model_outputs
```

✅ **Evaluation results will be saved here:**

```
model_outputs/
 └── random_forest/
     └── evaluation_results/
         ├── eval_classification_report.txt
         ├── eval_classification_report.csv
         ├── confusion_matrix_multiclass.png
         └── eval_summary.json
```

---

### 🧭 Optional Tip

If you’d like to **run both biflow and uniflow pipelines automatically**,
I can create a short **`run_all.py` orchestrator script** that:

* Detects both feature levels
* Runs prepare → train → evaluate sequentially
* Stores everything in `model_outputs/biflow/` and `model_outputs/uniflow/`

Would you like me to generate that `run_all.py` script for you? It’ll let you reproduce both pipelines with **one single command**.
