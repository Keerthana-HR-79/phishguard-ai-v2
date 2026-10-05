"""inspect_data.py — understand the training data composition & the path artifact source."""
import os, re
import pandas as pd
from urllib.parse import urlparse

FILES = {
    "final_dataset":  "../data/processed/final_dataset.csv",
    "legit_urls":     "../data/processed/legit_urls.csv",
    "adversarial":    "../data/processed/adversarial_phishing.csv",
}

def has_path(u: str) -> bool:
    try:
        u = str(u)
        p = urlparse(u if u.startswith("http") else "http://" + u)
        path = p.path.strip("/")
        return len(path) > 0
    except Exception:
        return False

for name, path in FILES.items():
    ap = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    if not os.path.exists(ap):
        print(f"\n[MISSING] {name}: {ap}")
        continue
    df = pd.read_csv(ap)
    print(f"\n=== {name}  ({len(df):,} rows) ===")
    if "type" in df.columns:
        print(df["type"].value_counts().to_string())
        for t, sub in df.groupby("type"):
            frac = sub["url"].apply(has_path).mean()
            print(f"   {t:<12} with a path: {frac*100:5.1f}%")
    print("   samples:")
    for u in df["url"].head(4):
        print(f"     {u}")
