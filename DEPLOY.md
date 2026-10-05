# 🚀 Deploying PhishGuard AI

Two free services, same stack as most student full-stack projects:

| Piece | Host | Why |
|---|---|---|
| **Backend** (FastAPI + XGBoost) | **Render** | runs Python + the model; free 512 MB tier |
| **Frontend** (static HTML/JS) | **Vercel** | instant static hosting, free, gives a clean URL |

Deploy the **backend first** (you need its URL for the frontend), then the frontend, then lock CORS.

---

## Part 1 — Backend on Render

1. Go to **https://render.com** → sign in with GitHub.
2. **New +** → **Blueprint**.
3. Pick the **`phishguard-ai`** repo. Render detects [`render.yaml`](render.yaml) and shows a `phishguard-backend` web service.
4. Click **Apply**. First build takes ~3–5 min (installs xgboost/scikit-learn/pandas).
5. When it's live you'll get a URL like **`https://phishguard-backend.onrender.com`**.
6. Verify it: open **`https://<your-backend>.onrender.com/health`** — you should see
   `{"status":"ok","version":"3.2.0","model":"v3.5",...}`.

> **Free-tier note (important for demos):** the service **sleeps after ~15 min idle**, so the
> *first* request after a nap takes ~30–50 s to wake (you'll see a spinner). This is normal — the
> frontend already has a 10 s fetch timeout and shows a friendly message; just retry once it wakes.
> If you're demoing live, hit `/health` a minute beforehand to warm it up.

---

## Part 2 — Frontend on Vercel

1. First, point the frontend at your backend. Edit **[`frontend/js/env.js`](frontend/js/env.js)**:
   ```js
   window.PHISHGUARD_API_BASE = "https://phishguard-backend.onrender.com";
   ```
   (use YOUR Render URL, no trailing slash). Then:
   ```bash
   git add frontend/js/env.js && git commit -m "Point frontend at Render backend" && git push
   ```
2. Go to **https://vercel.com** → sign in with GitHub → **Add New… → Project**.
3. Import the **`phishguard-ai`** repo. Vercel reads [`vercel.json`](vercel.json):
   - Framework Preset: **Other**
   - Root/Output: served from **`frontend/`** (already set — don't override)
   - Build command: **none** (it's a static site)
4. Click **Deploy**. You'll get a URL like **`https://phishguard-ai.vercel.app`**.
5. Open it → the landing page. The live checker is at **`/url-checker.html`**, the dashboard at
   **`/dashboard.html`**.

---

## Part 3 — Lock CORS (do this once both are live)

Right now the backend accepts requests from any origin (`CORS_ORIGINS="*"`) so setup "just works".
Tighten it to your Vercel URL:

1. Render dashboard → `phishguard-backend` → **Environment** → edit **`CORS_ORIGINS`**:
   ```
   https://phishguard-ai.vercel.app
   ```
   (your exact Vercel URL). Save → Render redeploys automatically.

That's it — a shareable, live phishing detector. 🎣🛡️

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Checker shows "Could not reach the API" | Backend asleep (wait ~40 s, retry) **or** `env.js` URL wrong/has a trailing slash |
| Browser console: CORS error | `CORS_ORIGINS` on Render doesn't match the Vercel URL exactly (scheme + host, no slash) |
| `/health` 404 | Backend still building, or `rootDir: backend` was overridden — check Render logs |
| First request very slow | Expected on free tier (cold start). Warm with `/health` before demoing |

## What ships in the deployed backend
- `model.pkl` + vectorizers + scaler (the trained v3.5 model) — committed, so no training needed.
- `data/raw/openphish.txt` (~600 live URLs) as the blocklist. `phishtank.csv` is gitignored;
  `main.py` degrades gracefully without it. **The model is the primary decider**, so detection is
  fully functional either way. To refresh the blocklist on the server, run `python refresh_feeds.py`.
