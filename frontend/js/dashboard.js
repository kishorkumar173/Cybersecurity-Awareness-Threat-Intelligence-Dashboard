/**
 * Core Dashboard & Chart Logic
 * Renders SOC analytics, threat tables, and IOC searches with high-contrast, vibrant palettes.
 */

const API_BASE = "/api";

// Palette settings (Emerald, Violet, Coral, Amber, Teal, Lavender)
const CHART_COLORS = [
  "#10b981", // Emerald
  "#8b5cf6", // Violet
  "#f43f5e", // Coral
  "#f59e0b", // Amber
  "#14b8a6", // Teal
  "#ec4899", // Pink
  "#a855f7", // Purple
  "#e11d48", // Rose
  "#06b6d4", // Cyan
  "#84cc16"  // Lime
];

let threatsCache = [];

async function fetchStats() {
  try {
    const res = await fetch(`${API_BASE}/dashboard/stats`);
    const data = await res.json();
    renderStatsCards(data.cards);
    renderCharts(data);
    renderRecentThreats(data.recent_threats);
  } catch (err) {
    console.error("Failed to load dashboard metrics:", err);
  }
}

function renderStatsCards(cards) {
  if (!cards) return;
  document.getElementById("statTotalThreats").textContent = cards.total_threats || 0;
  document.getElementById("statCriticalThreats").textContent = cards.critical_threats || 0;
  document.getElementById("statHighThreats").textContent = cards.high_threats || 0;
  document.getElementById("statActiveIndicators").textContent = cards.active_indicators || 0;
  document.getElementById("statOpenInvestigations").textContent = cards.open_investigations || 0;
  document.getElementById("statAvgConfidence").textContent = (cards.average_confidence || 0) + "%";
  document.getElementById("statVulnsTracked").textContent = cards.vulnerabilities_tracked || 0;
}

function renderCharts(data) {
  // 1. Threats by Category (Doughnut)
  const catCtx = document.getElementById("chartCategory")?.getContext("2d");
  if (catCtx && data.by_category) {
    new Chart(catCtx, {
      type: "doughnut",
      data: {
        labels: data.by_category.map(c => c.category),
        datasets: [{
          data: data.by_category.map(c => c.count),
          backgroundColor: CHART_COLORS,
          borderColor: "#1f242c",
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "right", labels: { color: "#8b949e", font: { size: 10 } } }
        }
      }
    });
  }

  // 2. Threats by Severity (Polar Area / Bar)
  const sevCtx = document.getElementById("chartSeverity")?.getContext("2d");
  if (sevCtx && data.by_severity) {
    const sevMap = {
      "CRITICAL": "#ef4444",
      "HIGH": "#f97316",
      "MEDIUM": "#eab308",
      "LOW": "#10b981",
      "INFORMATIONAL": "#a855f7"
    };
    new Chart(sevCtx, {
      type: "bar",
      data: {
        labels: data.by_severity.map(s => s.severity),
        datasets: [{
          label: "Threat Count",
          data: data.by_severity.map(s => s.count),
          backgroundColor: data.by_severity.map(s => sevMap[s.severity] || "#8b5cf6"),
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: "#8b949e" }, grid: { display: false } },
          y: { ticks: { color: "#8b949e" }, grid: { color: "#30363d" } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  // 3. IOC Type Distribution (Pie)
  const iocCtx = document.getElementById("chartIocType")?.getContext("2d");
  if (iocCtx && data.by_ioc_type) {
    new Chart(iocCtx, {
      type: "pie",
      data: {
        labels: data.by_ioc_type.map(i => i.indicator_type),
        datasets: [{
          data: data.by_ioc_type.map(i => i.count),
          backgroundColor: ["#10b981", "#8b5cf6", "#f43f5e", "#f59e0b", "#14b8a6", "#a855f7"],
          borderColor: "#1f242c"
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "right", labels: { color: "#8b949e", font: { size: 10 } } }
        }
      }
    });
  }

  // 4. Top ATT&CK Tactics (Horizontal Bar)
  const attackCtx = document.getElementById("chartAttackTactics")?.getContext("2d");
  if (attackCtx && data.attack_summary?.top_tactics) {
    const tactics = data.attack_summary.top_tactics;
    new Chart(attackCtx, {
      type: "bar",
      indexAxis: "y",
      data: {
        labels: tactics.map(t => t.tactic),
        datasets: [{
          label: "Sightings",
          data: tactics.map(t => t.count),
          backgroundColor: "#8b5cf6",
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: "#8b949e" }, grid: { color: "#30363d" } },
          y: { ticks: { color: "#8b949e" }, grid: { display: false } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }
}

function renderRecentThreats(threats) {
  const tbody = document.getElementById("recentThreatsBody");
  if (!tbody || !threats) return;
  tbody.innerHTML = "";

  threats.forEach(t => {
    const tr = document.createElement("tr");
    const sevClass = `badge-${t.severity ? t.severity.toLowerCase() : 'info'}`;
    const riskPill = t.risk_score >= 80 ? 'score-high' : t.risk_score >= 50 ? 'score-med' : 'score-low';

    tr.innerHTML = `
      <td><a href="threat-details.html?id=${t.threat_id}" style="color:#c4b5fd; text-decoration:none; font-weight:700;">${t.threat_id}</a></td>
      <td style="font-weight:600;">${escapeHtml(t.threat_name)}</td>
      <td><span class="badge badge-category">${t.category}</span></td>
      <td style="font-family:monospace; color:#34d399;">${escapeHtml(t.indicator_value || 'N/A')}</td>
      <td><span class="badge ${sevClass}">${t.severity}</span></td>
      <td><span class="score-pill ${riskPill}">${t.risk_score}/100</span></td>
      <td><span style="color:#a78bfa; font-weight:600;">${t.confidence_score}%</span></td>
      <td><span class="badge badge-status">${t.status}</span></td>
      <td style="font-size:0.75rem; color:#8b949e;">${t.last_seen || ''}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function performIocSearch() {
  const q = document.getElementById("iocSearchInput")?.value.trim();
  const resContainer = document.getElementById("iocSearchResult");
  if (!q) return;

  resContainer.style.display = "block";
  resContainer.innerHTML = `<div style="color:var(--violet);">Analyzing defensive indicator in local repository...</div>`;

  try {
    const res = await fetch(`${API_BASE}/indicators/search?query=${encodeURIComponent(q)}`);
    const data = await res.json();

    const isKnownBadge = data.is_known_in_dataset 
      ? `<span class="badge badge-critical" style="background:rgba(239, 68, 68, 0.25);">YES – Observed in Telemetry</span>`
      : `<span class="badge badge-low">NO PRIOR OBSERVATIONS</span>`;

    resContainer.innerHTML = `
      <div style="background:var(--bg-secondary); border:1px solid var(--border-color); border-radius:var(--radius-md); padding:18px; margin-top:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid var(--border-subtle); padding-bottom:8px;">
          <div>
            <h4 style="color:#fff; font-size:1.1rem; display:flex; align-items:center; gap:8px;">
              <span>${escapeHtml(data.indicator_value)}</span>
              <span class="badge badge-category">${data.indicator_type}</span>
            </h4>
            <div style="font-size:0.75rem; color:#8b949e; margin-top:4px;">${data.validation?.validation_notes || ''}</div>
          </div>
          <div>${isKnownBadge}</div>
        </div>

        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-bottom:16px;">
          <div style="background:var(--bg-card); padding:10px; border-radius:4px;">
            <div style="font-size:0.7rem; color:#8b949e;">DEFENSIVE RISK SCORE</div>
            <div style="font-size:1.3rem; font-weight:700; color:${data.risk_score >= 70 ? '#f43f5e' : '#10b981'};">${data.risk_score} / 100</div>
          </div>
          <div style="background:var(--bg-card); padding:10px; border-radius:4px;">
            <div style="font-size:0.7rem; color:#8b949e;">ANALYTICAL CONFIDENCE</div>
            <div style="font-size:1.3rem; font-weight:700; color:#8b5cf6;">${data.confidence_score}%</div>
          </div>
          <div style="background:var(--bg-card); padding:10px; border-radius:4px;">
            <div style="font-size:0.7rem; color:#8b949e;">SEVERITY CLASSIFICATION</div>
            <div style="font-size:1.1rem; font-weight:700; color:#fff;">${data.severity}</div>
          </div>
          <div style="background:var(--bg-card); padding:10px; border-radius:4px;">
            <div style="font-size:0.7rem; color:#8b949e;">TELEMETRY SIGHTINGS</div>
            <div style="font-size:1.3rem; font-weight:700; color:#34d399;">${data.observation_count} Hit(s)</div>
          </div>
        </div>

        <div style="font-size:0.85rem; color:#e2e8f0; margin-bottom:12px;">
          <strong>Defensive Assessment:</strong> ${data.analyst_notes}
        </div>

        <div style="background:rgba(16, 185, 129, 0.08); border-left:3px solid var(--emerald); padding:10px; border-radius:4px; font-size:0.8rem; color:#a7f3d0;">
          <strong>Recommended SOC Actions:</strong>
          <ul style="margin-left:18px; margin-top:4px;">
            ${data.defensive_recommendations.map(r => `<li>${r}</li>`).join("")}
          </ul>
        </div>
      </div>
    `;
  } catch (err) {
    resContainer.innerHTML = `<div style="color:var(--coral);">Lookup failed: ${err.message}</div>`;
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("statTotalThreats")) {
    fetchStats();
  }
});
