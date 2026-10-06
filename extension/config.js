// PhishGuard AI — shared extension runtime (config + small helpers).
//
// Loaded by BOTH the popup (<script src="config.js"> in popup.html) and the
// background service worker (importScripts("config.js") at the top of
// background.js), so the two contexts share one API base, one fetch-with-timeout
// helper and one bounded result cache instead of each hardcoding its own.
//
// Deploying to a non-local backend needs NO code edit — set an override once:
//   chrome.storage.local.set({ apiBase: "https://phishguard-api.example.com" })
//   chrome.storage.local.set({ dashboardUrl: "https://phishguard.example.com/dashboard.html" })
// (run from the extension's service-worker console). The defaults below are the
// documented local-dev setup.

const DEFAULT_API_BASE       = "https://phishguard-backend-v2-qxrz.onrender.com";
const DEFAULT_DASHBOARD_URL  = "https://phishguard-ai-v2-frontend.vercel.app/dashboard.html";
const API_TIMEOUT_MS         = 8000;        // never hang the UI on a dead backend
const CACHE_TTL_MS           = 60 * 1000;   // per-URL verdict freshness
const CACHE_PREFIX           = "cache:";    // namespaces cache entries from config keys
const CACHE_MAX_ENTRIES      = 200;         // bound storage.local growth (L8)

// ── configurable endpoints ────────────────────────────────────────────────────
async function getApiBase() {
  try {
    const { apiBase } = await chrome.storage.local.get("apiBase");
    if (apiBase) return apiBase;
  } catch (_) { /* storage unavailable — fall back to the default */ }
  return DEFAULT_API_BASE;
}

async function getDashboardUrl() {
  try {
    const { dashboardUrl } = await chrome.storage.local.get("dashboardUrl");
    if (dashboardUrl) return dashboardUrl;
  } catch (_) { /* storage unavailable — fall back to the default */ }
  return DEFAULT_DASHBOARD_URL;
}

// ── fetch that aborts after timeoutMs ─────────────────────────────────────────
function fetchWithTimeout(url, options = {}, timeoutMs = API_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal })
    .finally(() => clearTimeout(timer));
}

// ── bounded per-URL cache (shared by popup + background) ───────────────────────
async function cacheGet(url) {
  try {
    const key = CACHE_PREFIX + url;
    const got = await chrome.storage.local.get(key);
    const hit = got[key];
    if (hit && Date.now() - hit.ts < CACHE_TTL_MS) return hit.result;
  } catch (_) { /* cache is best-effort */ }
  return null;
}

async function cacheSet(url, data) {
  try {
    await chrome.storage.local.set({ [CACHE_PREFIX + url]: { result: data, ts: Date.now() } });
    await evictCache();
  } catch (_) { /* cache is best-effort */ }
}

// Evict the oldest entries once the cache exceeds CACHE_MAX_ENTRIES. Only touches
// keys under CACHE_PREFIX with a numeric .ts, so config keys (apiBase, …) survive.
async function evictCache() {
  try {
    const all = await chrome.storage.local.get(null);
    const entries = Object.entries(all)
      .filter(([k, v]) => k.startsWith(CACHE_PREFIX) && v && typeof v.ts === "number");
    if (entries.length <= CACHE_MAX_ENTRIES) return;
    entries.sort((a, b) => a[1].ts - b[1].ts);                 // oldest first
    const remove = entries.slice(0, entries.length - CACHE_MAX_ENTRIES).map(([k]) => k);
    if (remove.length) await chrome.storage.local.remove(remove);
  } catch (_) { /* ignore — eviction is best-effort */ }
}
