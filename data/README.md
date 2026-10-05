# Data directory

Large source datasets are **git-ignored** (they're multi-MB and regenerable). What's
tracked vs ignored, and how to rebuild the ignored ones:

## Tracked (small, needed to run / reproduce)
- `raw/openphish.txt` — live blocklist seed (loaded at backend startup)
- `processed/adversarial_phishing.csv` — generated adversarial attacks
- `processed/fresh_holdout.csv` — 5k unseen holdout for `fresh_recall_probe.py`

## Ignored (large; regenerate locally)
| File | Rebuild with |
|---|---|
| `raw/kaggle.csv`, `raw/phishtank.csv`, `raw/tranco.csv` | original public downloads |
| `raw/phishing-domains-ACTIVE.txt` | [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) `ACTIVE` list |
| `processed/final_dataset.csv` | `python backend/build_dataset.py` |
| `processed/tranco_top1m.zip`, `processed/legit_urls.csv` | `python backend/build_legit_dataset.py` |
| `processed/fresh_phishing.csv` | `python backend/harvest_fresh_data.py` |

Refresh the live blocklist any time with `python backend/refresh_feeds.py`.
