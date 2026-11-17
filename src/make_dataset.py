"""STEP 1 of ML: build the labelled dataset (data/dataset.csv)."""
import os
import random
import pandas as pd
from common import FEATURES, extract_features
from traffic_gen import make_window

N_PER_CLASS = int(os.environ.get("N_PER_CLASS", 3000))
DATA_DIR = os.environ.get("DATA_DIR", "data")

rng = random.Random(42)
rows = []
for label in (0, 1):                      # 0 = normal, 1 = tunnel
    for _ in range(N_PER_CLASS):
        feats = extract_features(make_window(rng, label))
        feats["label"] = label
        rows.append(feats)

df = pd.DataFrame(rows)[FEATURES + ["label"]].sample(frac=1, random_state=1)
os.makedirs(DATA_DIR, exist_ok=True)
path = os.path.join(DATA_DIR, "dataset.csv")
df.to_csv(path, index=False)
print(f"Saved {len(df)} labelled windows -> {path}")
print(df.groupby("label")[["avg_entropy", "avg_sub_len", "qps", "rare_type_ratio"]].mean().round(2))
