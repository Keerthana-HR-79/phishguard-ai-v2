// PhishGuard AI — Background Service Worker
// Listens for tab URL changes and auto-checks every new URL, sets a badge, and
// injects a warning banner into the page when phishing is detected.
//
// Shared config + helpers (API base, fetchWithTimeout, bounded cache) come from
// config.js, imported below so the worker and the popup behave identically.
importScripts("config.js");

// Skip these URL patterns — chrome internals, extensions, local files
function shouldSkip(url) {
  if (!url) return true;
  return (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("file://") ||
    url.startsWith("data:")
  );
}

// Check cache first, then call API (with a hard timeout so a dead backend never
// leaves the badge/banner logic hanging).
async function checkUrl(url) {
  const cached = await cacheGet(url);
  if (cached) return cached;

  try {
    const apiBase = await getApiBase();
    const res = await fetchWithTimeout(`${apiBase}/predict_url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    await cacheSet(url, data);
    return data;
  } catch {
    return null;   // API offline / timeout — fail silently
  }
}

// Update extension icon badge
function setBadge(tabId, result) {
  const map = {
    PHISHING:   { text: "⛔", color: "#ef4444" },
    SUSPICIOUS: { text: "⚠",  color: "#f59e0b" },
    SAFE:       { text: "✓",  color: "#22c55e" },
  };
  const entry = map[result];
  if (!entry) return;
  chrome.action.setBadgeText({ tabId, text: entry.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: entry.color });
}

// Runs IN THE PAGE (serialized by chrome.scripting and re-parsed there, so it
// must be self-contained and reference only its args). Builds the warning banner
// entirely with DOM APIs + textContent — no innerHTML, no eval — so an
// attacker-controlled reason string can never inject markup or script. This
// replaces the old `new Function(code)` approach, which the MV3 service-worker
// CSP blocks outright (the banner never appeared).
function renderBanner(score, reasons) {
  if (document.getElementById("phishguard-banner")) return;

  const bar = document.createElement("div");
  bar.id = "phishguard-banner";
  bar.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;" +
    "background:#1a0a0a;border-bottom:3px solid #ef4444;" +
    "padding:12px 20px;display:flex;align-items:flex-start;gap:14px;" +
    "font-family:-apple-system,sans-serif;font-size:14px;color:#fca5a5;" +
    "box-shadow:0 4px 24px rgba(239,68,68,0.35);";
  bar.setAttribute("role", "alert");

  const emoji = document.createElement("span");
  emoji.textContent = "🚨";
  emoji.style.cssText = "font-size:24px;flex-shrink:0";

  const body = document.createElement("div");
  body.style.flex = "1";

  const title = document.createElement("strong");
  title.textContent = "PhishGuard AI: Phishing Detected";
  title.style.cssText = "color:#ef4444;font-size:15px";

  const scoreLine = document.createElement("div");
  const safeScore = (typeof score === "number" && isFinite(score)) ? score : 0;
  scoreLine.textContent = `Risk score: ${safeScore.toFixed(1)} / 10`;
  scoreLine.style.cssText = "margin-top:4px;color:#fca5a5;font-size:13px";

  body.appendChild(title);
  body.appendChild(scoreLine);

  if (Array.isArray(reasons) && reasons.length) {
    const list = document.createElement("ul");
    list.style.cssText = "margin-top:6px;padding-left:0;list-style:none;font-size:12px;color:#fca5a5";
    reasons.slice(0, 3).forEach((r) => {
      const li = document.createElement("li");
      li.textContent = `→ ${r}`;   // textContent — reason text is never parsed as HTML
      list.appendChild(li);
    });
    body.appendChild(list);
  }

  const close = document.createElement("button");
  close.textContent = "✕";
  close.style.cssText =
    "background:none;border:none;color:#fca5a5;font-size:20px;cursor:pointer;flex-shrink:0";
  close.addEventListener("click", () => bar.remove());

  bar.appendChild(emoji);
  bar.appendChild(body);
  bar.appendChild(close);
  (document.body || document.documentElement).prepend(bar);
}

// Inject the warning banner for PHISHING pages via a serializable function +
// args (CSP-safe), not a code string.
async function injectWarning(tabId, score, reasons) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: renderBanner,
      args: [Number(score) || 0, Array.isArray(reasons) ? reasons.slice(0, 3) : []],
    });
  } catch {
    // Scripting genuinely blocked on some pages (e.g. the Chrome Web Store) — ignore.
  }
}

// ── Listen for tab navigation ─────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only act when the page fully loads
  if (changeInfo.status !== "complete") return;
  const url = tab.url;
  if (shouldSkip(url)) return;

  const data = await checkUrl(url);
  if (!data) return;

  setBadge(tabId, data.result);

  if (data.result === "PHISHING") {
    injectWarning(tabId, data.risk_score || 0, data.reasons || []);
  }
});
