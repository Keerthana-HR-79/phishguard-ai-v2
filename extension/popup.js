// PhishGuard AI — Chrome Extension Popup Script
// Calls /predict_url on the FastAPI backend and renders the result.
// Shared config + helpers (API base, fetchWithTimeout, cache) come from config.js,
// loaded before this script in popup.html.

const VERDICT = {
  PHISHING:   { icon: "🚨", label: "Phishing Detected", cls: "phishing",   barColor: "#ef4444" },
  SUSPICIOUS: { icon: "⚠️", label: "Suspicious Page",   cls: "suspicious", barColor: "#f59e0b" },
  SAFE:       { icon: "✅", label: "Safe",               cls: "safe",       barColor: "#22c55e" },
};

// ── DOM refs ─────────────────────────────────────────────────────────────────
const urlBar      = document.getElementById("urlBar");
const loadingArea = document.getElementById("loadingArea");
const resultArea  = document.getElementById("resultArea");
const reasonsArea = document.getElementById("reasonsArea");
const reCheckBtn  = document.getElementById("reCheckBtn");
const dashboardLink = document.getElementById("dashboardLink");

let currentUrl = "";

// ── Main ──────────────────────────────────────────────────────────────────────
async function init() {
  // Point the footer link at the configured dashboard (defaults to local dev).
  if (dashboardLink) {
    try { dashboardLink.href = await getDashboardUrl(); } catch (_) { /* keep default */ }
  }

  // Get current active tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentUrl = tab?.url || "";

  // Skip internal chrome:// pages
  if (!currentUrl || currentUrl.startsWith("chrome://") || currentUrl.startsWith("about:")) {
    showError("This page cannot be checked.");
    return;
  }

  // textContent, never innerHTML — the URL is fully attacker-controlled and must
  // never be parsed as markup inside the popup.
  urlBar.textContent = truncate(currentUrl, 50);
  await checkUrl(currentUrl);
}

async function checkUrl(url) {
  showLoading();
  try {
    const cached = await cacheGet(url);
    if (cached) {
      renderResult(cached);
      setBadge(cached.result);
      return;
    }

    const apiBase = await getApiBase();
    const res = await fetchWithTimeout(`${apiBase}/predict_url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!res.ok) throw new Error(`API error ${res.status}`);
    const data = await res.json();
    renderResult(data);

    // Update badge colour on the extension icon
    setBadge(data.result);

    // Cache result (bounded + TTL, shared with the background worker)
    await cacheSet(url, data);

  } catch (err) {
    const offline = err && (err.name === "AbortError")
      ? "Request timed out."
      : "Could not reach PhishGuard API.";
    showError(`${offline} Make sure the backend is running.`);
  }
}

function renderResult(data) {
  loadingArea.style.display = "none";
  resultArea.style.display  = "flex";

  const v     = VERDICT[data.result] || VERDICT["SAFE"];
  const score = data.risk_score || 0;
  const pct   = Math.min((score / 10) * 100, 100);

  // Static, non-user-controlled markup (icon/label/score) — safe to build once.
  resultArea.innerHTML = `
    <div class="verdict-icon"></div>
    <div class="verdict-text ${v.cls}"></div>
    <div class="score-text"></div>
    <div class="bar-track">
      <div class="bar-fill" style="width:${pct}%;background:${v.barColor}"></div>
    </div>
  `;
  resultArea.querySelector(".verdict-icon").textContent = v.icon;
  resultArea.querySelector(".verdict-text").textContent = v.label;
  resultArea.querySelector(".score-text").textContent   = `Risk score: ${score.toFixed(1)} / 10`;

  // Reasons — built with textContent so a reason string is never parsed as HTML.
  reasonsArea.innerHTML = "";
  if (Array.isArray(data.reasons) && data.reasons.length > 0) {
    reasonsArea.classList.add("show");

    const title = document.createElement("div");
    title.className = "reason-title";
    title.textContent = "Why:";

    const list = document.createElement("ul");
    list.className = "reason-list";
    data.reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      list.appendChild(li);
    });

    reasonsArea.appendChild(title);
    reasonsArea.appendChild(list);
  } else {
    reasonsArea.classList.remove("show");
  }
}

function showLoading() {
  loadingArea.style.display = "block";
  resultArea.style.display  = "none";
  reasonsArea.innerHTML = "";
  reasonsArea.classList.remove("show");
}

function showError(msg) {
  loadingArea.style.display = "none";
  resultArea.style.display  = "flex";
  resultArea.innerHTML = "";
  const box = document.createElement("div");
  box.style.cssText = "text-align:center;color:#8b90b8;font-size:13px;padding:8px";
  box.textContent = msg;               // textContent — no markup from error paths
  resultArea.appendChild(box);
}

function setBadge(result) {
  const colors = { PHISHING: "#ef4444", SUSPICIOUS: "#f59e0b", SAFE: "#22c55e" };
  const texts  = { PHISHING: "⛔",      SUSPICIOUS: "⚠",       SAFE: "✓" };
  chrome.action.setBadgeText({ text: texts[result] || "" });
  chrome.action.setBadgeBackgroundColor({ color: colors[result] || "#6366f1" });
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n) + "…" : str;
}

// ── Re-check button ───────────────────────────────────────────────────────────
reCheckBtn.addEventListener("click", () => {
  if (currentUrl) checkUrl(currentUrl);
});

// ── Boot ─────────────────────────────────────────────────────────────────────
init();
