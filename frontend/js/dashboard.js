// PhishGuard AI — dashboard page logic (ported from the former dashboard.tsx).
// Pulls /stats and /recent from the FastAPI backend and renders KPIs, a 7-day
// trend chart, a recent-scans table and a top-threats table.

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function badgeClass(result) {
  if (result === "PHISHING")   return "badge badge-phishing";
  if (result === "SUSPICIOUS") return "badge badge-suspicious";
  return "badge badge-safe";
}

// ---- renderers --------------------------------------------------------------
function renderKPIs(s) {
  const cards = [
    { val: s.total_scans,                 label: "Total Scans",    color: "" },
    { val: s.phishing_count,              label: "Phishing Found", color: "#ef4444" },
    { val: s.suspicious_count,            label: "Suspicious",     color: "#f59e0b" },
    { val: s.safe_count,                  label: "Safe",           color: "#22c55e" },
    { val: `${s.detection_rate}%`,        label: "Detection Rate", color: "var(--accent-light)" },
    { val: `${s.avg_response_time_ms} ms`, label: "Avg Response",  color: "" },
    { val: s.url_scans,                   label: "URL Scans",      color: "" },
  ];
  const inner = cards.map((c) => `
    <div class="statCard">
      <div class="statVal"${c.color ? ` style="color:${c.color}"` : ""}>${escapeHtml(c.val)}</div>
      <div class="statLabel">${escapeHtml(c.label)}</div>
    </div>`).join("");
  return `<div class="kpiGrid">${inner}</div>`;
}

function renderChart(daily) {
  if (!daily || daily.length === 0) {
    return `<div class="chartCard">
      <div class="chartTitle">Last 7 days</div>
      <div class="noData">No scans yet — check a few URLs to populate this chart.</div>
    </div>`;
  }
  const maxDaily = Math.max(...daily.map((d) => d.total), 1);
  const bars = daily.map((d) => {
    const totalH    = (d.total / maxDaily) * 100;
    const phishingH = ((d.phishing || 0) / maxDaily) * 100;
    return `
      <div class="bar">
        <div class="barWrap">
          <div class="barTotal" style="height:${totalH}%"></div>
          <div class="barPhishing" style="height:${phishingH}%"></div>
        </div>
        <div class="barLabel">${escapeHtml(String(d.day).slice(5))}</div>
      </div>`;
  }).join("");

  return `<div class="chartCard">
    <div class="chartTitle">Last 7 days</div>
    <div class="chart">${bars}</div>
    <div class="chartLegend">
      <span>&#9632; Total scans</span>
      <span style="color:#ef4444">&#9632; Phishing</span>
    </div>
  </div>`;
}

function renderRecent(recent) {
  if (!recent || recent.length === 0) {
    return `<div class="tableCard">
      <div class="tableTitle">Recent scans</div>
      <div class="noData">No recent activity.</div>
    </div>`;
  }
  const rows = recent.map((e) => `
    <tr>
      <td class="tdMuted">${escapeHtml(String(e.timestamp).slice(11, 19))}</td>
      <td><span class="typeBadge">${escapeHtml((e.type || "").toUpperCase())}</span></td>
      <td class="tdContent">${escapeHtml(String(e.content).slice(0, 55))}</td>
      <td><span class="${badgeClass(e.result)}">${escapeHtml(e.result)}</span></td>
      <td class="tdScore">${Number(e.risk_score).toFixed(1)}</td>
    </tr>`).join("");

  return `<div class="tableCard">
    <div class="tableTitle">Recent scans</div>
    <div class="tableWrap">
      <table class="table">
        <thead><tr><th>Time</th><th>Type</th><th>Content</th><th>Result</th><th>Score</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </div>`;
}

function renderTopThreats(threats) {
  if (!threats || threats.length === 0) return "";
  const rows = threats.map((t) => `
    <tr>
      <td class="tdContent">${escapeHtml(String(t.content).slice(0, 60))}</td>
      <td class="tdScore">${escapeHtml(t.cnt)}</td>
    </tr>`).join("");

  return `<div class="tableCard">
    <div class="tableTitle">Top threats (most-flagged URLs)</div>
    <div class="tableWrap">
      <table class="table">
        <thead><tr><th>URL / content</th><th>Times flagged</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </div>`;
}

const EXPORT_HINT = `<div class="exportHint">
  Want richer reporting? Export the scan history to CSV for Power BI:
  <code>python export_to_bi.py</code> in the <code>backend/</code> folder, then follow
  <code>analytics/POWERBI_SETUP.md</code>.
</div>`;

// ---- load -------------------------------------------------------------------
async function load() {
  const root = document.getElementById("dashboardRoot");
  root.innerHTML = `<div class="loading">Loading dashboard…</div>`;

  try {
    const [statsRes, recentRes] = await Promise.all([
      fetchWithTimeout(`${API_BASE}/stats`),
      fetchWithTimeout(`${API_BASE}/recent?limit=15`),
    ]);
    if (!statsRes.ok || !recentRes.ok) throw new Error("API error");
    const stats  = await statsRes.json();
    const recent = await recentRes.json();

    root.innerHTML =
      renderKPIs(stats) +
      renderChart(stats.daily_breakdown) +
      renderRecent(recent) +
      renderTopThreats(stats.top_threats) +
      EXPORT_HINT;
  } catch (err) {
    root.innerHTML = `<div class="error">
      Could not load the dashboard. Make sure the backend is running on ${API_BASE}.<br>
      <small>${escapeHtml(err.message)}</small>
    </div>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("refreshBtn");
  if (btn) btn.addEventListener("click", load);
  load();
});
