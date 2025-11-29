const API_BASE = "https://api.sanatdhir.com";

// Small helper for safe JSON fetch
async function fetchJson(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} for ${url}`);
  }
  return res.json();
}

async function loadTrafficStats() {
  const errorEl = document.getElementById("traffic-error");
  errorEl.style.display = "none";

  try {
    const data = await fetchJson(`${API_BASE}/api/stats/summary`);
    // Expected shape:
    // {
    //   "status": "ok",
    //   "total_days": N,
    //   "counts": { human, agent, unknown },
    //   "days": [ { day, counts: { human, agent, unknown } }, ... ]
    // }

    const totalDays = data.total_days ?? data.totalDays ?? 0;
    const counts = (data && data.counts) || {};
    const days = (data && data.days) || [];

    // All-time totals
    document.getElementById("stat-human-total").textContent = counts.human ?? 0;
    document.getElementById("stat-agent-total").textContent = counts.agent ?? 0;
    document.getElementById("stat-unknown-total").textContent = counts.unknown ?? 0;
    document.getElementById("stat-total-days").textContent = totalDays;

    // Latest day (if any)
    if (days.length > 0) {
      const latest = days[days.length - 1];
      document.getElementById("stat-latest-day").textContent = latest.day || "–";
      const c = latest.counts || {};
      document.getElementById("stat-human-latest").textContent = c.human ?? 0;
      document.getElementById("stat-agent-latest").textContent = c.agent ?? 0;
      document.getElementById("stat-unknown-latest").textContent = c.unknown ?? 0;
    } else {
      document.getElementById("stat-latest-day").textContent = "–";
      document.getElementById("stat-human-latest").textContent = 0;
      document.getElementById("stat-agent-latest").textContent = 0;
      document.getElementById("stat-unknown-latest").textContent = 0;
    }

    // History table
    const historyBody = document.getElementById("history-tbody");
    historyBody.innerHTML = "";
    if (!days.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.style.color = "var(--text-muted)";
      td.textContent = "No history yet.";
      tr.appendChild(td);
      historyBody.appendChild(tr);
    } else {
      days.forEach(entry => {
        const tr = document.createElement("tr");
        const d = entry.day || "—";
        const c = entry.counts || {};
        tr.innerHTML = `
          <td>${d}</td>
          <td>${c.human ?? 0}</td>
          <td>${c.agent ?? 0}</td>
          <td>${c.unknown ?? 0}</td>
        `;
        historyBody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error("Error loading stats summary:", err);
    errorEl.textContent = `Error loading stats: ${err.message}`;
    errorEl.style.display = "block";
  }
}

async function loadBillingAndWallets() {
  const errorEl = document.getElementById("billing-error");
  errorEl.style.display = "none";

  const walletBody = document.getElementById("wallet-tbody");
  const sessionsBody = document.getElementById("sessions-tbody");

  try {
    const data = await fetchJson(`${API_BASE}/api/billing/agents`);
    // Expected shape:
    // {
    //   "status": "ok",
    //   "wallets": [...],
    //   "paymentSessions": {
    //       "total": N,
    //       "byStatus": { paid: X, pending: Y, ... }
    //   }
    // }

    const wallets = (data && data.wallets) || [];
    const paymentSessions = (data && data.paymentSessions) || {};
    const byStatus = paymentSessions.byStatus || {};

    // Wallet table
    walletBody.innerHTML = "";
    if (!wallets.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 3;
      td.style.color = "var(--text-muted)";
      td.textContent = "No agent wallets yet.";
      tr.appendChild(td);
      walletBody.appendChild(tr);
    } else {
      wallets.forEach(w => {
        const tr = document.createElement("tr");
        const agentId = w.agentId || "—";
        const credits = w.credits ?? 0;
        const updatedAt = w.updatedAt || "—";
        tr.innerHTML = `
          <td>${agentId}</td>
          <td>${credits}</td>
          <td>${updatedAt}</td>
        `;
        walletBody.appendChild(tr);
      });
    }

    // Payment sessions summary
    document.getElementById("sessions-total").textContent = paymentSessions.total ?? 0;
    document.getElementById("sessions-paid").textContent = byStatus.paid ?? 0;
    document.getElementById("sessions-pending").textContent = byStatus.pending ?? 0;

    // Payment sessions table
    sessionsBody.innerHTML = "";
    if (!paymentSessions.total) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.style.color = "var(--text-muted)";
      td.textContent = "No payment sessions yet.";
      tr.appendChild(td);
      sessionsBody.appendChild(tr);
    } else {
      // We only have counts by status from the API at the moment,
      // but if you later extend the backend to return the raw session list,
      // you can render it here. For now, show a summary row.
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td colspan="4">
          Total: ${paymentSessions.total ?? 0} · Paid: ${byStatus.paid ?? 0} · Pending: ${byStatus.pending ?? 0}
        </td>
      `;
      sessionsBody.appendChild(tr);
    }
  } catch (err) {
    console.error("Error loading billing/wallets:", err);
    errorEl.textContent = `Error loading billing data: ${err.message}`;
    errorEl.style.display = "block";
  }
}

window.addEventListener("load", () => {
  loadTrafficStats();
  loadBillingAndWallets();
});
