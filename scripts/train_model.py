#!/usr/bin/env python3
"""
Train models for MQTT-IoT-IDS2020 reproduction.

Usage example:
python train_model.py --data-dir ../data --feature-level biflow --model-type rf --out-dir ./model_outputs --seed 42
"""
import argparse, json, os, hashlib, sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_predict
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import joblib
joblib.parallel_backend("threading", n_jobs=1)
import platform
import pkg_resources
from tqdm import tqdm
import matplotlib.pyplot as plt

DROP_FEATURES_DEFAULT = [
    # common variants - we normalize names in prepare_Xy, so these can be human-readable
    "ip src", "ip dest", "protocol",
    "mqtt flag uname", "mqtt flag passwd", "mqtt flag retain",
    "mqtt flag qos", "mqtt flag willflag", "mqtt flag clean", "mqtt flag reserved",
    "mqtt messagetype", "mqtt messagelength"
]

MODEL_MAP = {
    "lr": lambda: LogisticRegression(max_iter=500, solver="lbfgs", n_jobs=1),
    "nb": GaussianNB,
    "knn": KNeighborsClassifier,
    "svm_rbf": lambda: SVC(kernel="rbf", probability=True),
    "svm_linear": lambda: SVC(kernel="linear", probability=True),
    "dt": DecisionTreeClassifier,
    "rf": lambda: RandomForestClassifier(
        n_estimators=200,     # more trees → better stability
        max_depth=None,       # allow full growth (or set ~20 for faster runs)
        n_jobs=-1,            # use all CPU cores
        random_state=42,
        class_weight="balanced_subsample"  # handles any class imbalance
    )
}

def sha256_for_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def load_features(data_dir, feature_level):
    # Expect files named like packet_features.csv / uniflow_features.csv / biflow_features.csv
    name_map = {"packet": "packet_features.csv", "uniflow": "uniflow_features.csv", "biflow": "biflow_features.csv"}
    fn = Path(data_dir) / name_map[feature_level]
    # If combined file exists, use it (train_model will split)
    if fn.exists():
        df = pd.read_csv(fn)
        return {"type": "combined", "df": df, "files": [fn]}
    # Otherwise, check for pre-split train/test files
    train_fn = Path(data_dir) / f"{feature_level}_train.csv"
    test_fn = Path(data_dir) / f"{feature_level}_test.csv"
    if train_fn.exists() and test_fn.exists():
        df_train = pd.read_csv(train_fn)
        df_test = pd.read_csv(test_fn)
        return {"type": "presplit", "train": df_train, "test": df_test, "files": [train_fn, test_fn]}
    raise FileNotFoundError(f"{fn} not found in {data_dir}. Available files: {list(Path(data_dir).glob('*.csv'))}")


def prepare_Xy(df, drop_list):
    """
    Normalize column names, drop configured non-feature columns if present,
    extract y from 'is_attack' (accepts variants), and return numeric X and integer y.
    """
    df = df.copy()

    # Normalize column names: strip, lowercase, replace spaces with underscores
    norm_map = {c: c.strip().lower().replace(" ", "_") for c in df.columns}
    df.rename(columns=norm_map, inplace=True)

    # Normalize drop list to same form
    drop_norm = {d.strip().lower().replace(" ", "_") for d in drop_list}

    # Drop any of the configured drop-columns that are present
    cols_present_drop = [c for c in df.columns if c in drop_norm]
    if cols_present_drop:
        df.drop(columns=cols_present_drop, inplace=True)

    # Accept several common names for the attack flag; prefer 'is_attack' normalized name
    if "is_attack" not in df.columns:
        # check other likely variants (e.g., 'is attack' -> normalized to 'is_attack' already, so this is a fallback)
        alt_candidates = [c for c in df.columns if c.replace("_", "") in ("isattack", "is_attack", "isattackflag")]
        if alt_candidates:
            # rename the first matched candidate to 'is_attack'
            df.rename(columns={alt_candidates[0]: "is_attack"}, inplace=True)
        else:
            raise ValueError(f"'is_attack' column not found in data. Available columns: {list(df.columns)}")

    # y as integer array (0/1)
    y = df["is_attack"].astype(int).values

    # Drop the target column from features
    X = df.drop(columns=["is_attack"])

    # Keep only numeric features (non-numeric will be dropped)
    X = X.select_dtypes(include=[np.number]).fillna(0)

    return X, y


def train_and_evaluate(X_train, y_train, X_test, y_test, model_name, seed, cv_folds):
    """
    Train a model with stratified K-fold cross-validation and show progress using tqdm.
    Returns:
      clf, report_train, report_test, cm, acc, extra_info
    extra_info is a dict that may include 'feature_importances' (pd.Series) for tree models.
    """
    if model_name not in MODEL_MAP:
        raise ValueError("Unknown model type")

    clf_ctor = MODEL_MAP[model_name]

    # Special case: construct RandomForest with sensible defaults and parallelism
    if model_name == "rf":
        clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=seed)
    else:
        clf = clf_ctor() if callable(clf_ctor) else clf_ctor

    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=seed)
    y_pred_cv = np.zeros_like(y_train)

    print(f"\n[⚙️] Performing {cv_folds}-fold cross-validation for {model_name.upper()}...\n")

    # tqdm progress bar for folds
        # --- tqdm progress bar for folds (Windows-safe) ---
    # Materialize all fold indices before iteration to avoid hanging iterators on Windows
    fold_splits = list(skf.split(X_train, y_train))

    for fold_idx, (train_idx, val_idx) in enumerate(
        tqdm(
            fold_splits,
            total=len(fold_splits),
            desc=f"{model_name.upper()} CV",
            unit="fold",
            leave=True,
            ncols=100
        )
    ):
        # Extract train/validation splits
        X_tr, X_val = X_train.iloc[train_idx], X_train.iloc[val_idx]
        y_tr, y_val = y_train[train_idx], y_train[val_idx]

        # Recreate a clean model instance for each fold (prevents state carryover)
        if model_name == "rf":
            clf_fold = RandomForestClassifier(
                n_estimators=100,
                n_jobs=-1,
                random_state=seed + fold_idx
            )
        elif model_name == "lr":
            # More stable Logistic Regression config for large data on Windows
            clf_fold = LogisticRegression(
                max_iter=500,
                solver="lbfgs",
                n_jobs=1,   # Avoid nested joblib parallelism
                verbose=0,
                random_state=seed + fold_idx
            )
        else:
            clf_fold = clf_ctor() if callable(clf_ctor) else clf_ctor

        # Fit and predict validation fold
        clf_fold.fit(X_tr, y_tr)
        y_pred_cv[val_idx] = clf_fold.predict(X_val)


    # fit on the full train set
    print(f"\n[🚀] Training final {model_name.upper()} model on full training data...\n")
    clf.fit(X_train, y_train)

    # test set evaluation
    y_test_pred = clf.predict(X_test)
    report_train = classification_report(y_train, y_pred_cv, output_dict=True, zero_division=0)
    report_test = classification_report(y_test, y_test_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_test_pred)
    acc = accuracy_score(y_test, y_test_pred)

    extra_info = {}
    # If model exposes feature_importances_, capture them (for tree-based models)
    if hasattr(clf, "feature_importances_"):
        try:
            import pandas as _pd
            fi = clf.feature_importances_
            feature_names = X_train.columns if hasattr(X_train, "columns") else [f"f{i}" for i in range(len(fi))]
            extra_info["feature_importances"] = _pd.Series(fi, index=feature_names).sort_values(ascending=False)
        except Exception:
            extra_info["feature_importances"] = None

    return clf, report_train, report_test, cm, acc, extra_info

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", required=True, help="Directory containing combined or pre-split feature CSVs")
    p.add_argument("--feature-level", choices=["packet", "uniflow", "biflow"], default="biflow", help="Feature level to train on")
    p.add_argument("--model-type", default="rf", help="lr,nb,knn,svm_rbf,svm_linear,dt,rf,all")
    p.add_argument("--out-dir", default="./model_outputs", help="Directory to save models and metadata")
    p.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    p.add_argument("--cv-folds", type=int, default=5, help="Cross-validation folds")
    p.add_argument("--test-split", type=float, default=0.25, help="Test split ratio (used only if combined file)")
    args = p.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # --- Load features (auto-detect combined or pre-split) ---
    loaded = load_features(args.data_dir, args.feature_level)
    data_files = {}

    if isinstance(loaded, dict) and "type" in loaded:
        if loaded["type"] == "combined":
            df = loaded["df"]
            src_file = loaded["files"][0]
            data_files[str(src_file)] = sha256_for_file(src_file)
            X, y = prepare_Xy(df, DROP_FEATURES_DEFAULT)
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=args.test_split, stratify=y, random_state=args.seed
            )
        else:
            df_train = loaded["train"]
            df_test = loaded["test"]
            for f in loaded["files"]:
                data_files[str(f)] = sha256_for_file(f)
            X_train, y_train = prepare_Xy(df_train, DROP_FEATURES_DEFAULT)
            X_test, y_test = prepare_Xy(df_test, DROP_FEATURES_DEFAULT)
    else:
        df, src_file = loaded
        data_files[str(src_file)] = sha256_for_file(src_file)
        X, y = prepare_Xy(df, DROP_FEATURES_DEFAULT)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=args.test_split, stratify=y, random_state=args.seed
        )

    # --- Train model(s) ---
    model_types = [args.model_type] if args.model_type != "all" else list(MODEL_MAP.keys())

    metadata = {
        "seed": args.seed,
        "feature_level": args.feature_level,
        "data_files": data_files,
        "python_version": platform.python_version(),
        "packages": {
            pkg.key: pkg.version
            for pkg in pkg_resources.working_set
            if pkg.key in ["numpy", "pandas", "scikit-learn", "joblib", "paho-mqtt", "scapy"]
        },
        "command": " ".join(sys.argv),
    }

    comparison_rows = []

    for m in tqdm(model_types, desc="Models", unit="model"):
        print(f"\n🔹 Training model: {m.upper()}")
        clf, r_train, r_test, cm, acc, extra = train_and_evaluate(
            X_train, y_train, X_test, y_test, m, args.seed, args.cv_folds
        )

        # --- Per-model directory setup ---
        model_root = Path(args.out_dir)
        folder_name = (
            "random_forest" if m == "rf"
            else f"model_{m}"
        )
        model_dir = model_root / folder_name
        model_dir.mkdir(parents=True, exist_ok=True)

        # --- Save model ---
        model_path = model_dir / f"model_{m}.joblib"
        joblib.dump(clf, model_path)
        print(f"✅ Saved model: {model_path}")

        # --- Feature Importance (for RF / DT only) ---
        if hasattr(clf, "feature_importances_"):
            print("[📊] Generating feature importance plot...")
            import matplotlib.pyplot as plt
            import numpy as np
            import pandas as _pd

            feature_importances = clf.feature_importances_
            feature_names = X_train.columns if hasattr(X_train, "columns") else np.arange(len(feature_importances))

            sorted_idx = np.argsort(feature_importances)[::-1]
            top_n = min(20, len(feature_importances))
            top_features = np.array(feature_names)[sorted_idx][:top_n]
            top_importances = feature_importances[sorted_idx][:top_n]

            plt.figure(figsize=(10, 6))
            plt.barh(range(top_n), top_importances[::-1], align="center",
                     color=plt.cm.viridis(np.linspace(0.2, 0.8, top_n)))
            plt.yticks(range(top_n), top_features[::-1], fontsize=9)
            plt.xlabel("Feature Importance", fontsize=11)
            plt.title(f"Top {top_n} Important Features ({m.upper()})", fontsize=13, pad=10)
            plt.grid(axis="x", linestyle="--", alpha=0.4)

            for i, val in enumerate(top_importances[::-1]):
                plt.text(val + 0.001, i, f"{val:.3f}", va="center", fontsize=8)

            plt.tight_layout()

            fig_path = model_dir / f"feature_importance_{m}.png"
            plt.savefig(fig_path, dpi=250, bbox_inches="tight")
            plt.close()
            print(f"📈 Feature importance plot saved to {fig_path}")

            fi_series = _pd.Series(feature_importances, index=feature_names).sort_values(ascending=False)
            fi_csv = model_dir / f"feature_importance_{m}.csv"
            fi_series.to_csv(fi_csv, header=["importance"])
            print(f"📄 Feature importances CSV saved to {fi_csv}")

        # --- Display metrics ---
        print("\n=== 📊 CV (Train) Classification Report ===")
        print(pd.DataFrame(r_train).transpose())
        print("=== 🧪 Test Classification Report ===")
        print(pd.DataFrame(r_test).transpose())
        print("Confusion Matrix:\n", cm)
        print(f"🎯 Test Accuracy: {acc:.4f}")

        metadata[f"model_{m}"] = {
            "model_path": str(model_path),
            "test_accuracy": acc,
            "confusion_matrix": cm.tolist(),
            "report_test": r_test,
            "report_train": r_train
        }

        def safe_metric(report, cls, metric):
            try:
                return report[str(cls)][metric]
            except Exception:
                return None

        comparison_rows.append({
            "model": m,
            "test_accuracy": acc,
            "precision_class_0": safe_metric(r_test, 0, "precision"),
            "recall_class_0": safe_metric(r_test, 0, "recall"),
            "f1_class_0": safe_metric(r_test, 0, "f1-score"),
            "precision_class_1": safe_metric(r_test, 1, "precision"),
            "recall_class_1": safe_metric(r_test, 1, "recall"),
            "f1_class_1": safe_metric(r_test, 1, "f1-score"),
            "support_total": int(sum(sum(cm))) if cm is not None else None
        })

    # --- Model Comparison (All Models) ---
    comp_df = pd.DataFrame(comparison_rows)
    comp_csv = Path(args.out_dir) / "model_comparison.csv"
    comp_png = Path(args.out_dir) / "model_comparison.png"
    comp_df.to_csv(comp_csv, index=False)

    try:
        fig, ax = plt.subplots(figsize=(8, 4))
        comp_df_sorted = comp_df.sort_values("test_accuracy", ascending=False)
        ax.bar(comp_df_sorted["model"], comp_df_sorted["test_accuracy"], color="steelblue")
        ax.set_ylabel("Test accuracy")
        ax.set_xlabel("Model")
        ax.set_title("Model comparison (test accuracy)")
        fig.tight_layout()
        fig.savefig(comp_png, dpi=200)
        plt.close(fig)
        print(f"📊 Model comparison saved to {comp_csv} and {comp_png}")
    except Exception as e:
        print(f"⚠️ Warning: failed to create comparison plot: {e}")

    # --- Metadata Save ---
    meta_path = Path(args.out_dir) / "train_metadata.json"
    with open(meta_path, "w") as fh:
        json.dump(metadata, fh, indent=2)
    print(f"\n📝 Training metadata saved to {meta_path}")


if __name__ == "__main__":
    main()
