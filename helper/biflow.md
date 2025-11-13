1)
python scripts/prepare_combined_csv.py `
  --data-dir ./data `
  --feature-level biflow `
  --out-dir ./data/combined `
  --test-split 0.25 `
  --seed 42

2) train a specific model : random forest
python scripts/train_model.py `
  --data-dir ./data/combined `
  --feature-level biflow `
  --model-type rf `
  --out-dir ./model_outputs `
  --seed 42 `
  --cv-folds 5 `
  --test-split 0.25

    --for all models
  use -model-type all 

3)evaluate
python scripts/evaluate_model.py `
  --model ./model_outputs/random_forest/model_rf.joblib `
  --test-csv ./data/combined/biflow_test.csv `
  --out-dir ./model_outputs




