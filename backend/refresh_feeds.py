"""
refresh_feeds.py  —  refresh the local phishing blocklist from LIVE feeds
=========================================================================
Why this exists
---------------
The feeds shipped under ``data/raw/`` are an ~April-2025 snapshot. b4_signal_probe.py
proved that staleness is the ROOT CAUSE limiting further detection gains: the
historical phishing domains are mostly dead, so neither the model nor a
domain-age signal can learn a live pattern from them (see MODEL_AUDIT.md §B4),
and the D1 exact-match blocklist in main.py cannot flag anything that first
appeared after April 2025.

This script pulls fresh, currently-live phishing URLs from the OpenPhish
community feed (free, ~300 most-recent) and MERGES them into
``data/raw/openphish.txt`` as a UNION — it never drops existing entries, because
a URL that was phishing months ago is still worth flagging if someone pastes it.
Run it repeatedly (e.g. from cron) to accumulate a fresh corpus over time.

Design choices
--------------
* STANDALONE, not a startup hook. The backend's blocklist load stays offline and
  deterministic (its graceful-degradation property is intact); this script is the
  "drop fresh feeds and restart" refresh path that main.py's D1 comment describes.
* SAFE: bounded network timeout, a timestamped backup of the previous file, and an
  atomic write (temp file + os.replace). A network failure leaves the existing
  file completely untouched — the blocklist never ends up empty or half-written.
* NO HARDCODING / NO SECRETS: the feed URL is env-overridable; PhishTank (whose
  dump now needs a registered key) is fetched only if PHISHTANK_API_KEY is set,
  and the key is read from the environment, never stored here.

Usage
-----
    python refresh_feeds.py
    # then restart the backend so it loads the larger set:
    #   uvicorn main:app --host 127.0.0.1 --port 8000
"""

import os
import io
import csv
import socket
import datetime
import urllib.request

# Anchor to this file's directory so paths work regardless of the caller's cwd
# (the other scripts here assume cwd==backend; anchoring on __file__ is sturdier).
_HERE     = os.path.dirname(os.path.abspath(__file__))
_RAW_DIR  = os.environ.get("RAW_FEED_DIR", os.path.join(_HERE, "..", "data", "raw"))
_OPENPHISH_FILE = os.path.join(_RAW_DIR, "openphish.txt")

OPENPHISH_URL = os.environ.get("OPENPHISH_FEED_URL", "https://openphish.com/feed.txt")
TIMEOUT       = int(os.environ.get("FEED_TIMEOUT_SEC", "20"))
_UA           = "Mozilla/5.0 (PhishGuard-refresh)"


def _fetch(url: str) -> str:
    socket.setdefaulttimeout(TIMEOUT)
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", "ignore")


def _clean(line: str) -> str:
    line = line.strip()
    # keep only plausible URLs; the backend re-normalizes on load, so we just
    # need to avoid storing blanks / comment lines / obviously-broken rows.
    if not line or line.startswith("#") or "." not in line:
        return ""
    return line


def fetch_openphish() -> set[str]:
    print(f"Fetching OpenPhish community feed: {OPENPHISH_URL}")
    try:
        text = _fetch(OPENPHISH_URL)
    except Exception as e:
        print(f"  [WARN] OpenPhish fetch failed ({type(e).__name__}: {e}) — skipping.")
        return set()
    urls = {c for c in (_clean(l) for l in text.splitlines()) if c}
    print(f"  fetched {len(urls):,} live phishing URLs")
    return urls


def fetch_phishtank() -> set[str]:
    key = os.environ.get("PHISHTANK_API_KEY", "").strip()
    if not key:
        print("PhishTank: no PHISHTANK_API_KEY set — skipping (dump now requires a key).")
        return set()
    url = f"http://data.phishtank.com/data/{key}/online-valid.csv"
    print("Fetching PhishTank online-valid dump (key from environment)...")
    try:
        text = _fetch(url)
    except Exception as e:
        print(f"  [WARN] PhishTank fetch failed ({type(e).__name__}: {e}) — skipping.")
        return set()
    urls: set[str] = set()
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        c = _clean((row.get("url") or ""))
        if c:
            urls.add(c)
    print(f"  fetched {len(urls):,} PhishTank URLs")
    return urls


def _read_existing(path: str) -> set[str]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return {c for c in (_clean(l) for l in f) if c}
    except FileNotFoundError:
        return set()


def _atomic_write(path: str, urls: set[str]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        for u in sorted(urls):
            f.write(u + "\n")
    os.replace(tmp, path)   # atomic on the same filesystem


def main() -> None:
    fresh = fetch_openphish() | fetch_phishtank()
    if not fresh:
        print("\nNo fresh URLs retrieved (all feeds unreachable / no key). "
              "Existing file left untouched.")
        return

    existing = _read_existing(_OPENPHISH_FILE)
    union    = existing | fresh
    new_cnt  = len(union) - len(existing)

    print(f"\nExisting entries in openphish.txt : {len(existing):,}")
    print(f"Fresh entries pulled              : {len(fresh):,}")
    print(f"NEW (not already present)         : {new_cnt:,}")

    if new_cnt == 0:
        print("Nothing new to add — file already current. No write performed.")
        return

    # Back up the previous file (timestamped) before the first overwrite.
    if os.path.isfile(_OPENPHISH_FILE):
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        bak = f"{_OPENPHISH_FILE}.bak_{stamp}"
        try:
            with open(_OPENPHISH_FILE, encoding="utf-8", errors="ignore") as src, \
                 open(bak, "w", encoding="utf-8", newline="\n") as dst:
                dst.write(src.read())
            print(f"Backed up previous file -> {os.path.basename(bak)}")
        except Exception as e:
            print(f"  [WARN] backup failed ({type(e).__name__}: {e}); aborting to be safe.")
            return

    _atomic_write(_OPENPHISH_FILE, union)
    print(f"Wrote {len(union):,} total URLs to {_OPENPHISH_FILE}")
    print("\nDone. Restart the backend to load the larger blocklist:")
    print("  uvicorn main:app --host 127.0.0.1 --port 8000")


if __name__ == "__main__":
    main()
