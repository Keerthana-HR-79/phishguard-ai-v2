"""
generate_adversarial.py — synthetic phishing URLs for training augmentation.

v2.5 changes (see MODEL_AUDIT.md A3):
  • Vocabulary is DECOUPLED from features.py's 13 brands / 12 keywords. The old
    generator reused the exact feature lists, so the model only learned "these
    25 tokens = phishing" and missed novel phishing wording (e.g. "refund",
    "gift-card"). We now draw from a much larger brand + keyword vocabulary.
  • Emits BOTH bare-host and pathed phishing URLs, so "has a path" no longer
    correlates with the phishing label.

Run from the backend/ folder:
    python generate_adversarial.py
"""

import os
import random
import pandas as pd

from url_augment import add_path

# ── Broad vocabulary (intentionally wider than features.py) ──────────────────
BRANDS = [
    # global tech / commerce
    "google", "amazon", "paypal", "microsoft", "facebook", "apple", "github",
    "openai", "whatsapp", "instagram", "linkedin", "netflix", "spotify",
    "dropbox", "adobe", "steam", "roblox", "tiktok", "snapchat", "youtube",
    # banks / finance (common phishing targets, NOT in the feature list)
    "bankofamerica", "chase", "wellsfargo", "citibank", "hsbc", "barclays",
    "amex", "americanexpress", "capitalone", "usbank", "santander",
    # crypto
    "coinbase", "binance", "metamask", "ledger", "trustwallet", "kraken",
    # logistics
    "dhl", "fedex", "ups", "usps", "royalmail",
    # indian targets
    "sbi", "hdfc", "icici", "axisbank", "kotak", "paytm", "phonepe",
    "flipkart", "irctc", "myntra", "razorpay",
]

KEYWORDS = [
    # in the feature list
    "login", "secure", "verify", "account", "bank", "update", "signin",
    "security", "alert", "confirm", "password", "billing",
    # NOT in the feature list — the model must learn these from data
    "support", "unlock", "suspend", "suspended", "refund", "reward", "gift",
    "giftcard", "prize", "claim", "invoice", "payment", "delivery", "tracking",
    "wallet", "recover", "recovery", "validate", "authenticate", "notify",
    "limited", "expire", "urgent", "review", "verification", "activate",
    "restore", "helpdesk", "service", "portal", "customer",
]

BENIGN_TLDS = ["com", "net", "org", "info", "co", "online", "site", "shop",
               "store", "app", "click", "live", "help", "support", "email"]
SUS_TLDS    = ["xyz", "top", "tk", "ml", "ga", "cf", "pw", "gq", "icu", "rest",
               "cam", "sbs", "zip", "mov"]
TAILS       = ["", "-now", "-official", "-required", "-online", "-support",
               "-help", "-team", "-center", "-verify", "-secure", "-alert"]


def obfuscate(word: str) -> str:
    return (word.replace("o", "0").replace("l", "1")
                .replace("e", "3").replace("i", "1").replace("a", "4"))


def brand_variations(b, rng):
    obf = obfuscate(b)
    kw = rng.choice(KEYWORDS)
    tld = rng.choice(BENIGN_TLDS + SUS_TLDS)
    return [
        f"{b}-{kw}.{rng.choice(BENIGN_TLDS)}",
        f"{obf}-{kw}.{tld}",
        f"{b}-secure-{kw}.{tld}",
        f"{obf}-verify.{tld}",
        f"secure-{b}-{kw}.{rng.choice(SUS_TLDS)}",
        f"{b}.com.secure-{kw}.{rng.choice(SUS_TLDS)}",
        f"verify-{b}-{kw}.{tld}",
        f"{obf}-signin.{tld}",
        f"{b}-{kw}-{rng.choice(['portal','center','team','help'])}.{tld}",
        f"{rng.choice(['my','secure','online','web'])}-{b}-{kw}.{tld}",
    ]


def keyword_salad(rng):
    """Hostname built purely from security keywords, e.g. verify-account-now.net."""
    n = rng.randint(2, 4)
    words = rng.sample(KEYWORDS, min(n, len(KEYWORDS)))
    host = "-".join(words) + rng.choice(TAILS)
    tld = rng.choice(BENIGN_TLDS + SUS_TLDS)
    return f"{host}.{tld}"


def generate_dataset(n=12000, salad_ratio=0.45, path_ratio=0.5, seed=42):
    rng = random.Random(seed)
    urls = []
    for _ in range(n):
        if rng.random() < salad_ratio:
            host = keyword_salad(rng)
        else:
            b = rng.choice(BRANDS)
            host = rng.choice(brand_variations(b, rng))
        url = "http://" + host
        # Half get a realistic path so path-presence is not a phishing tell.
        if rng.random() < path_ratio:
            url = add_path(url, rng)
        urls.append(url)

    df = pd.DataFrame({"url": urls, "type": "phishing"}).drop_duplicates("url")
    return df


if __name__ == "__main__":
    df = generate_dataset()
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "data", "processed", "adversarial_phishing.csv")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    df.to_csv(out, index=False)
    pathed = df["url"].str.contains(r"https?://[^/]+/").mean()
    print(f"[OK] adversarial dataset created: {len(df):,} unique URLs -> {out}")
    print(f"     pathed: {pathed*100:.1f}%  |  brands: {len(BRANDS)}  keywords: {len(KEYWORDS)}")
