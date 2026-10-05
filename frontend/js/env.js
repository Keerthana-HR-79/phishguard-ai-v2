// PhishGuard AI — deploy-time environment override.
//
// This is the ONE place to point the static frontend at a hosted backend.
// It is loaded BEFORE js/config.js, which reads window.PHISHGUARD_API_BASE
// first (then localStorage, then the local-dev default of http://localhost:8000).
//
// Local dev: leave this empty — config.js falls back to http://localhost:8000.
// Deployed:  set it to your Render backend URL, e.g.
//   window.PHISHGUARD_API_BASE = "https://phishguard-backend.onrender.com";
// then commit + push — Vercel auto-redeploys the static site.
window.PHISHGUARD_API_BASE = "https://phishguard-backend-ihvp.onrender.com";
