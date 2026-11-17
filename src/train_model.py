"""STEP 2 of ML: train + evaluate the Random Forest, save model + graphs."""
import os
import joblib
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             confusion_matrix, ConfusionMatrixDisplay, classification_report)
from sklearn.model_selection import train_test_split, GridSearchCV
from common import FEATURES

DATA_DIR = os.environ.get("DATA_DIR", "data")
MODEL_DIR = os.environ.get("MODEL_DIR", "models")
REPORT_DIR = os.environ.get("REPORT_DIR", "reports")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

df = pd.read_csv(os.path.join(DATA_DIR, "dataset.csv"))
X, y = df[FEATURES], df["label"]

# stratified 80/20 split (keeps the same normal:tunnel ratio in both parts)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42)

# tune the forest with 3-fold cross-validation
grid = GridSearchCV(
    RandomForestClassifier(random_state=42, class_weight="balanced"),
    {"n_estimators": [100, 200], "max_depth": [None, 10, 20]},
    cv=3, scoring="f1", n_jobs=-1)
grid.fit(X_train, y_train)
model = grid.best_estimator_
print("Best parameters:", grid.best_params_)

# evaluate on data the model has NEVER seen
pred = model.predict(X_test)
metrics = {
    "Accuracy": accuracy_score(y_test, pred),
    "Precision": precision_score(y_test, pred),
    "Recall": recall_score(y_test, pred),
    "F1-score": f1_score(y_test, pred),
}
lines = [f"{k}: {v:.4f}" for k, v in metrics.items()]
lines.append("\n" + classification_report(y_test, pred, target_names=["Normal", "Tunnel"]))
lines.append("Confusion matrix [rows=actual, cols=predicted]:\n" + str(confusion_matrix(y_test, pred)))
report = "\n".join(lines)
print(report)
with open(os.path.join(REPORT_DIR, "metrics.txt"), "w") as f:
    f.write(f"Best parameters: {grid.best_params_}\n\n{report}\n")

# graph 1: confusion matrix
ConfusionMatrixDisplay.from_predictions(y_test, pred, display_labels=["Normal", "Tunnel"], cmap="Blues")
plt.title("Confusion Matrix (test set)")
plt.savefig(os.path.join(REPORT_DIR, "confusion_matrix.png"), dpi=150, bbox_inches="tight")
plt.close()

# graph 2: which features mattered most
imp = pd.Series(model.feature_importances_, index=FEATURES).sort_values()
imp.plot(kind="barh", figsize=(7, 5), color="#3b82f6")
plt.title("Feature Importance")
plt.xlabel("Importance")
plt.savefig(os.path.join(REPORT_DIR, "feature_importance.png"), dpi=150, bbox_inches="tight")
plt.close()

joblib.dump({"model": model, "features": FEATURES}, os.path.join(MODEL_DIR, "rf_model.joblib"))
print(f"\nModel saved. Graphs + metrics saved in '{REPORT_DIR}/'.")
