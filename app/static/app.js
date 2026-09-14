const state = { page: 1, type: "", severity: "", q: "" };

const el = (id) => document.getElementById(id);

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

async function loadStats() {
  const res = await fetch("/api/stats");
  const data = await res.json();

  el("stat-total").textContent = data.total.toLocaleString();
  el("stat-corroborated").textContent = data.corroborated.toLocaleString();
  el("stat-critical").textContent = (data.by_severity.critical || 0).toLocaleString();

  const feedNames = Object.keys(data.feeds);
  const activeCount = feedNames.filter((f) => data.feeds[f].status === "success").length;
  el("stat-feeds").textContent = `${activeCount}/${feedNames.length || 3}`;

  const list = el("feed-list");
  if (feedNames.length === 0) {
    list.innerHTML = '<li class="empty-row">No feed runs yet</li>';
  } else {
    list.innerHTML = feedNames
      .map((name) => {
        const f = data.feeds[name];
        return `<li>
          <span class="feed-name">${name}</span>
          <span class="feed-status status-${f.status}">
            ${f.status}${f.new_iocs ? ` · +${f.new_iocs}` : ""} · ${fmtTime(f.ran_at)}
          </span>
        </li>`;
      })
      .join("");
  }

  const indicator = el("sync-indicator");
  const anySuccess = feedNames.some((f) => data.feeds[f].status === "success");
  indicator.textContent = anySuccess ? "live" : "waiting for first sync";
  indicator.classList.toggle("live", anySuccess);
}

async function loadIocs() {
  const params = new URLSearchParams({
    page: state.page,
    type: state.type,
    severity: state.severity,
    q: state.q,
  });
  const res = await fetch(`/api/iocs?${params}`);
  const data = await res.json();

  const tbody = el("ioc-tbody");
  if (data.items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-row">No indicators match these filters yet.</td></tr>';
  } else {
    tbody.innerHTML = data.items
      .map(
        (i) => `<tr>
          <td>${severityBadge(i.severity)}</td>
          <td><span class="type-pill">${i.type}</span></td>
          <td class="ioc-value">${i.reference ? `<a href="${i.reference}" target="_blank" rel="noopener" style="color:inherit">${i.value}</a>` : i.value}</td>
          <td>${i.threat_type || "—"}</td>
          <td>${i.malware_family || "—"}</td>
          <td>${i.sources} ${i.source_count > 1 ? `(${i.source_count})` : ""}</td>
          <td>${fmtTime(i.last_seen)}</td>
        </tr>`
      )
      .join("");
  }

  el("page-indicator").textContent = `Page ${data.page} of ${Math.max(data.pages, 1)}`;
  el("prev-page").disabled = data.page <= 1;
  el("next-page").disabled = data.page >= data.pages;
}

function refreshAll() {
  loadStats();
  loadIocs();
}

el("filter-search").addEventListener("input", (e) => {
  state.q = e.target.value;
  state.page = 1;
  clearTimeout(window._searchDebounce);
  window._searchDebounce = setTimeout(loadIocs, 300);
});

el("filter-type").addEventListener("change", (e) => {
  state.type = e.target.value;
  state.page = 1;
  loadIocs();
});

el("filter-severity").addEventListener("change", (e) => {
  state.severity = e.target.value;
  state.page = 1;
  loadIocs();
});

el("prev-page").addEventListener("click", () => {
  if (state.page > 1) { state.page -= 1; loadIocs(); }
});
el("next-page").addEventListener("click", () => {
  state.page += 1; loadIocs();
});

el("refresh-btn").addEventListener("click", async (e) => {
  const btn = e.target;
  btn.disabled = true;
  btn.textContent = "Refreshing…";
  try {
    await fetch("/api/refresh", { method: "POST" });
    await refreshAll();
  } finally {
    btn.disabled = false;
    btn.textContent = "Refresh feeds";
  }
});

refreshAll();
setInterval(refreshAll, 20000); // light polling so the desk stays live
