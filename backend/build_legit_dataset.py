"""
build_legit_dataset.py  —  PhishGuard AI
=========================================
Builds (or refreshes) a high-quality LEGITIMATE URL dataset from
three free, no-signup public sources:

  1. Tranco Top-1M list  (research-grade, daily updated, no account needed)
     https://tranco-list.eu/top-1m.csv.zip

  2. Your own pending_retrain.csv  (false-positive reports from the extension)

  3. A curated Indian + modern-SaaS seed list embedded here
     (one-time bootstrap — after that, Tranco covers new sites automatically)

Output: ../data/processed/legit_urls.csv   (url, type="legitimate")

Usage:
    python build_legit_dataset.py              # first run / full rebuild
    python build_legit_dataset.py --quick      # skip Tranco re-download if < 24h old
"""

import argparse
import io
import os
import random
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import requests

from url_augment import add_path, strip_to_host

# ── Config ────────────────────────────────────────────────────────────────────
OUT_DIR        = Path("../data/processed")
OUT_FILE       = OUT_DIR / "legit_urls.csv"
TRANCO_ZIP     = OUT_DIR / "tranco_top1m.zip"
FP_LOG         = Path("pending_retrain.csv")      # from /report_false_positive endpoint

TRANCO_URL     = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_TTL_H   = 24          # re-download only if older than this many hours
TRANCO_TAKE    = 80_000      # total Tranco domains to include (keeps file manageable)
TRANCO_HEAD    = 30_000      # ALWAYS include the top-N most-popular domains (people actually
                             #   visit these — skipping them caused false positives on sites
                             #   like dropbox.com / wordpress.com). The long tail is sampled.

# Legit URLs are built from bare domains via url_augment.add_path, which draws
# from a large, varied PATH_POOL (fixes A2: the old 10 fixed templates taught the
# model to memorize those exact path strings as "safe" and flag everything else).


def expand_variants(url: str, n: int, rng: random.Random) -> list[str]:
    """Original URL + up to n DISTINCT host variants (bare + varied paths).

    Genuine up-weighting: the variants are distinct strings, so they survive the
    final dedup instead of collapsing to one (fixes A6 — the old `* 10` / `* 5`
    duplicates were silently cancelled by `dict.fromkeys`). The varied paths also
    break the path artifact at the data level (A2)."""
    out, seen = [url], {url}
    bare = strip_to_host(url)
    if bare not in seen:
        out.append(bare); seen.add(bare)
    tries = 0
    while len(out) < n + 1 and tries < n * 6:
        v = add_path(url, rng)
        tries += 1
        if v not in seen:
            out.append(v); seen.add(v)
    return out

SEED_LEGIT_URLS = [
    # ── Indian banking ──────────────────────────────────────────────────────
    "https://www.sbi.co.in/web/personal-banking",
    "https://www.onlinesbi.sbi/sbicollect/icollecthome.htm",
    "https://netbanking.hdfcbank.com/netbanking/",
    "https://infinity.icicibank.com/corp/AuthenticationController",
    "https://www.axisbank.com/retail/login",
    "https://www.kotakbank.com/personal/net-banking.html",
    "https://www.pnbindia.in/netbanking.html",
    "https://retail.bandhanbank.com/wps/portal/RetailBanking",
    # ── Indian UPI / payments ───────────────────────────────────────────────
    "https://paytm.com/",
    "https://business.paytm.com/payment-gateway",
    "https://web.phonepe.com/",
    "https://dashboard.razorpay.com/",
    "https://www.billdesk.com/pgidsk/pgmerc/paychoice.htm",
    # ── Indian e-commerce ───────────────────────────────────────────────────
    "https://www.flipkart.com/account/login",
    "https://www.myntra.com/",
    "https://www.ajio.com/",
    "https://www.nykaa.com/",
    "https://www.meesho.com/",
    "https://www.snapdeal.com/",
    "https://www.bigbasket.com/",
    "https://www.zepto.com/",
    "https://blinkit.com/",
    "https://swiggy.com/",
    "https://www.zomato.com/",
    # ── Indian edu / gov ────────────────────────────────────────────────────
    "https://nptel.ac.in/courses",
    "https://www.iitb.ac.in/",
    "https://www.iitm.ac.in/",
    "https://www.iitd.ac.in/",
    "https://www.iitk.ac.in/",
    "https://www.bits-pilani.ac.in/",
    "https://www.du.ac.in/",
    "https://www.amity.edu/",
    "https://www.vit.ac.in/",
    "https://uidai.gov.in/",
    "https://www.mygov.in/",
    "https://www.india.gov.in/",
    "https://digilocker.gov.in/",
    "https://incometaxindia.gov.in/",
    "https://www.irctc.co.in/nget/train-search",
    "https://www.makeMyTrip.com/",
    "https://www.cleartrip.com/",
    "https://www.goibibo.com/",
    "https://www.yatra.com/",
    # ── AI / Dev / SaaS ─────────────────────────────────────────────────────
    "https://claude.ai/chat",
    "https://chatgpt.com/",
    "https://platform.openai.com/",
    "https://gemini.google.com/",
    "https://copilot.microsoft.com/",
    "https://www.perplexity.ai/",
    "https://vercel.com/dashboard",
    "https://app.netlify.com/",
    "https://railway.app/",
    "https://render.com/",
    "https://supabase.com/dashboard",
    "https://www.cloudflare.com/",
    "https://console.aws.amazon.com/",
    "https://portal.azure.com/",
    "https://console.cloud.google.com/",
    "https://hub.docker.com/",
    "https://colab.research.google.com/",
    "https://www.kaggle.com/",
    "https://huggingface.co/",
    "https://replit.com/",
    # ── Productivity / work ─────────────────────────────────────────────────
    "https://app.slack.com/",
    "https://teams.microsoft.com/",
    "https://meet.google.com/",
    "https://zoom.us/",
    "https://www.notion.so/",
    "https://linear.app/",
    "https://trello.com/",
    "https://asana.com/",
    "https://jira.atlassian.com/",
    "https://www.figma.com/",
    "https://miro.com/",
    "https://airtable.com/",
    "https://www.loom.com/",
    "https://calendly.com/",
    "https://docs.google.com/",
    "https://drive.google.com/",
    "https://sheets.google.com/",
    # ── Learning platforms ───────────────────────────────────────────────────
    "https://leetcode.com/problems/",
    "https://www.hackerrank.com/dashboard",
    "https://codeforces.com/",
    "https://www.codechef.com/",
    "https://www.geeksforgeeks.org/",
    "https://www.interviewbit.com/",
    "https://coursera.org/",
    "https://www.udemy.com/",
    "https://www.edx.org/",
    "https://www.khanacademy.org/",
    "https://brilliant.org/",
    # ── News / content ───────────────────────────────────────────────────────
    "https://timesofindia.indiatimes.com/",
    "https://www.thehindu.com/",
    "https://www.ndtv.com/",
    "https://indianexpress.com/",
    "https://www.bbc.com/news",
    "https://www.reuters.com/",
    "https://techcrunch.com/",
    "https://www.theverge.com/",
    "https://news.ycombinator.com/",
    "https://medium.com/",
    "https://dev.to/",
    "https://hashnode.com/",
    # ── Common login / account subdomains ────────────────────────────────────
    "https://myaccount.google.com/security",
    "https://accounts.google.com/signin",
    "https://mail.google.com/mail/u/0",
    "https://login.live.com/",
    "https://login.microsoftonline.com/",
    "https://account.microsoft.com/",
    "https://appleid.apple.com/",
    "https://account.amazon.com/",
    "https://www.amazon.in/gp/sign-in.html",
    "https://secure.paypal.com/signin",
    "https://accounts.youtube.com/",
    "https://support.apple.com/en-in",
]


def tranco_needs_refresh() -> bool:
    if not TRANCO_ZIP.exists():
        return True
    age = datetime.now() - datetime.fromtimestamp(TRANCO_ZIP.stat().st_mtime)
    return age > timedelta(hours=TRANCO_TTL_H)


def download_tranco() -> list[str]:
    """Download Tranco top-1M and return a sample of domains."""
    print(f"  Downloading Tranco top-1M from {TRANCO_URL} ...")
    r = requests.get(TRANCO_URL, timeout=60, stream=True)
    r.raise_for_status()
    TRANCO_ZIP.write_bytes(r.content)
    print(f"  Saved to {TRANCO_ZIP}")
    return _parse_tranco(TRANCO_ZIP)


def load_tranco() -> list[str]:
    return _parse_tranco(TRANCO_ZIP)


def _parse_tranco(zip_path: Path) -> list[str]:
    with zipfile.ZipFile(zip_path) as zf:
        csv_name = [n for n in zf.namelist() if n.endswith(".csv")][0]
        with zf.open(csv_name) as f:
            df = pd.read_csv(f, header=None, names=["rank", "domain"])

    # Guarantee the most-popular sites are learned: always take the top-N by rank,
    # then random-sample the long tail for diversity up to TRANCO_TAKE total.
    df = df.sort_values("rank").reset_index(drop=True)
    head = df.head(TRANCO_HEAD)
    tail = df.iloc[TRANCO_HEAD:]
    n_tail = max(0, min(TRANCO_TAKE - len(head), len(tail)))
    tail_sample = tail.sample(n_tail, random_state=42) if n_tail > 0 else tail.iloc[0:0]
    sample = pd.concat([head, tail_sample], ignore_index=True)

    # Convert bare domains -> realistic URLs. Each domain contributes BOTH a bare
    # host and one varied pathed URL (via url_augment), so legit examples are no
    # longer overwhelmingly path-free — that path imbalance vs phishing was the
    # root of the "path => phishing" artifact (A1/A2).
    rng = random.Random(42)
    urls = []
    for domain in sample["domain"]:
        base = f"https://{domain}"
        urls.append(base)                 # bare host
        urls.append(add_path(base, rng))  # varied path from PATH_POOL
    print(f"  Built {len(urls):,} legitimate URLs from Tranco "
          f"(top {len(head):,} + {len(tail_sample):,} sampled, bare+pathed each)")
    return urls


def load_false_positives() -> list[str]:
    if not FP_LOG.exists():
        return []
    df = pd.read_csv(FP_LOG)
    urls = df["url"].dropna().tolist()
    print(f"  Loaded {len(urls)} false-positive reports from {FP_LOG}")
    return urls


def build(quick: bool = False):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    random.seed(42)
    rng = random.Random(7)

    all_urls: list[str] = []

    # 1. Tranco
    print("\n[1/3] Tranco top-1M")
    if quick and not tranco_needs_refresh():
        print("  Using cached Tranco (< 24h old)")
        tranco_urls = load_tranco()
    else:
        tranco_urls = download_tranco()
    all_urls.extend(tranco_urls)

    # 2. Seed list (Indian / SaaS / modern sites your dataset never saw)
    print(f"\n[2/3] Seed list: {len(SEED_LEGIT_URLS)} curated URLs")
    # Up-weight seeds ~10× via DISTINCT variants (bare + varied paths) so the
    # emphasis survives dedup — the old `* 10` produced identical strings that
    # dict.fromkeys collapsed back to one (A6).
    seed_urls: list[str] = []
    for u in SEED_LEGIT_URLS:
        seed_urls.extend(expand_variants(u, 9, rng))
    all_urls.extend(seed_urls)

    # 3. False-positive reports from real usage
    print("\n[3/3] False-positive reports")
    fp_urls = load_false_positives()
    fp_expanded: list[str] = []
    for u in fp_urls:
        fp_expanded.extend(expand_variants(u, 4, rng))   # up-weight user-reported FPs
    all_urls.extend(fp_expanded)

    # De-duplicate (now only removes true collisions — variants are distinct),
    # shuffle, build DataFrame
    all_urls = list(dict.fromkeys(all_urls))   # preserves order, removes dupes
    random.shuffle(all_urls)

    df = pd.DataFrame({"url": all_urls, "type": "legitimate"})
    df.to_csv(OUT_FILE, index=False)

    print(f"\n[OK]  Written {len(df):,} legitimate URLs -> {OUT_FILE}")
    print(f"    Breakdown:")
    print(f"      Tranco (bare+pathed) : {len(tranco_urls):>7,}")
    print(f"      Seed (~10× variants) : {len(seed_urls):>7,}")
    print(f"      FP reports (~5×)     : {len(fp_expanded):>7,}")
    print(f"      After dedup          : {len(df):>7,}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true",
                        help="Skip Tranco re-download if cache is < 24h old")
    args = parser.parse_args()
    build(quick=args.quick)
