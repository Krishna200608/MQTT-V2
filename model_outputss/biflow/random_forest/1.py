import joblib
m = joblib.load("random_forest/model_rf.joblib")
print("feature_names_in:", getattr(m, "feature_names_in_", None))
print("n_classes:", m.n_classes_, "classes:", m.classes_)
