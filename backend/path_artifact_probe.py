"""
path_artifact_probe.py — is the model keying on "has a path" instead of
on genuine phishing signals? Test identical domains bare vs. with a path.
"""
import re
import predict_ml_only as P
from features import extract_features
from config import stack_features


def model_only(url: str) -> float:
    t = re.sub(r"^https?://", "", url)
    Xc = P.char_vec.transform([t]); Xw = P.word_vec.transform([t])
    Xn = P.scaler.transform([extract_features(url)])
    return float(P.model.predict_proba(stack_features(Xc, Xw, Xn))[0][1])


DOMAINS = [
    "byjus.com", "zerodha.com", "canarabank.com",
    "lenskart.com", "1mg.com", "hotstar.com",
]
PATHS = ["", "/home", "/login", "/products/item/123", "/about-us/contact"]

print(f"{'domain':<16}" + "".join(f"{p or '(bare)':<20}" for p in PATHS))
print("-" * 116)
for d in DOMAINS:
    row = f"{d:<16}"
    for p in PATHS:
        prob = model_only("http://" + d + p)
        tag = f"{prob:.3f} {'PH' if prob>0.5 else 'sf'}"
        row += f"{tag:<20}"
    print(row)

print("\nIf a row goes from 'sf' (bare) to 'PH' the moment a path is added,")
print("the model learned 'URL has a path => phishing' — a dataset artifact,")
print("because legit training URLs were bare Tranco domains while phishing")
print("training URLs carried full paths. This is a training-data problem,")
print("not real phishing detection.")
