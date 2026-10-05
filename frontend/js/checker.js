// PhishGuard AI — URL checker page logic (ported from the former url-checker.tsx).

const EXAMPLES = [
  "https://secure-login-update-account.com",
  "http://45.12.67.89/login",
  "https://paypa1.com@secure-update.xyz",
  "https://google.com",
];

const ICONS  = { PHISHING: "\u{1F6A8}", SUSPICIOUS: "⚠️", SAFE: "✅" };
const LABELS = { PHISHING: "Phishing Detected", SUSPICIOUS: "Suspicious", SAFE: "Safe" };
const COLORS = { PHISHING: "#ef4444", SUSPICIOUS: "#f59e0b", SAFE: "#22c55e" };

// ---- small helpers ----------------------------------------------------------
function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function $(id) { return document.getElementById(id); }

// ---- result card ------------------------------------------------------------
function renderResultCard({ result, score, reasons, extra }) {
  const color = COLORS[result] || COLORS.SUSPICIOUS;
  const icon  = ICONS[result]  || ICONS.SUSPICIOUS;
  const label = LABELS[result] || result;
  const pct   = Math.min((score / 10) * 100, 100);

  const reasonItems = (reasons && reasons.length ? reasons : ["No specific signals"])
    .map((r) => `<li>${escapeHtml(r)}</li>`)
    .join("");

  const metaRows = Object.entries(extra || {})
    .map(([k, v]) => `
      <div class="rc-meta-row">
        <span class="rc-meta-key">${escapeHtml(k)}</span>
        <span class="rc-meta-val">${escapeHtml(v)}</span>
      </div>`)
    .join("");

  return `
    <div class="rc-card" style="border-color:${color}55">
      <div class="rc-header">
        <div class="rc-icon">${icon}</div>
        <div>
          <div class="rc-verdict" style="color:${color}">${escapeHtml(label)}</div>
          <div class="rc-sub">Risk score: ${score.toFixed(1)} / 10</div>
        </div>
      </div>
      <div class="rc-bar-track">
        <div class="rc-bar-fill" style="width:${pct}%; background:${color}"></div>
      </div>
      <div class="rc-reasons">
        <div class="rc-reasons-title">Why</div>
        <ul>${reasonItems}</ul>
      </div>
      <div class="rc-meta">${metaRows}</div>
    </div>`;
}

// ---- API call ---------------------------------------------------------------
async function check() {
  const input     = $("urlInput");
  const btn       = $("checkBtn");
  const errorBox  = $("error");
  const resultBox = $("result");
  const url = input.value.trim();

  errorBox.style.display = "none";
  resultBox.innerHTML = "";

  if (!url) {
    errorBox.textContent = "Please enter a URL.";
    errorBox.style.display = "block";
    return;
  }

  btn.disabled = true;
  btn.textContent = "Checking...";

  try {
    const res = await fetchWithTimeout(`${API_BASE}/predict_url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error(`API returned ${res.status}`);
    const data = await res.json();

    const meta = data.meta || {};
    const ageDays = meta.domain_age_days;
    const extra = {
      "Domain": data.domain || "—",
      "ML probability": `${(data.ml_probability * 100).toFixed(1)}%`,
      "Domain age": ageDays != null && ageDays >= 0 ? `${ageDays} days` : "Unknown",
      "SSL valid": meta.ssl_valid == null ? "Not checked" : (meta.ssl_valid ? "Yes ✓" : "No ✗"),
    };

    resultBox.innerHTML = renderResultCard({
      result: data.result,
      score: data.risk_score,
      reasons: data.reasons,
      extra,
    });
  } catch (err) {
    const reason = err && err.name === "AbortError"
      ? "The request timed out."
      : "Could not reach the API.";
    errorBox.textContent =
      reason + " Make sure the backend is running on " + API_BASE +
      ". (" + err.message + ")";
    errorBox.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.textContent = "Check";
  }
}

// ---- wiring -----------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const input = $("urlInput");
  $("checkBtn").addEventListener("click", check);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") check(); });

  const exWrap = $("examples");
  EXAMPLES.forEach((ex) => {
    const b = document.createElement("button");
    b.className = "exBtn";
    b.type = "button";
    b.textContent = ex;
    b.addEventListener("click", () => { input.value = ex; check(); });
    exWrap.appendChild(b);
  });
});
