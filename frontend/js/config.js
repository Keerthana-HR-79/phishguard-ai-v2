// PhishGuard AI — frontend API configuration + shared fetch helper.
//
// API_BASE resolves at load time, in priority order:
//   1. window.PHISHGUARD_API_BASE  — set by an inline <script> before this file
//                                     (handy for a build/deploy step that injects it)
//   2. localStorage "phishguard_api_base" — set once in the browser console:
//        localStorage.setItem("phishguard_api_base", "https://phishguard-api.example.com")
//   3. the local-dev default below
// so deploying the static frontend against a hosted backend needs no code edit.
const API_BASE = (() => {
  try {
    if (typeof window !== "undefined" && window.PHISHGUARD_API_BASE) {
      return String(window.PHISHGUARD_API_BASE).replace(/\/+$/, "");
    }
    const stored = localStorage.getItem("phishguard_api_base");
    if (stored) return stored.replace(/\/+$/, "");
  } catch (_) { /* localStorage may be unavailable — fall back to the default */ }
  return "http://localhost:8000";
})();

// fetch() that aborts after timeoutMs so the UI never hangs on a dead/slow backend.
const API_TIMEOUT_MS = 10000;
function fetchWithTimeout(url, options = {}, timeoutMs = API_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal })
    .finally(() => clearTimeout(timer));
}
