"use strict";

const POLL_MS = 3000;
const MAX_FEED_ENTRIES = 60;

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

function fmtTs(ts) {
  if (!ts) return "—";
  const d = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
  return d.toLocaleString();
}

function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

function el(tag, props = {}, children = []) {
  const e = document.createElement(tag);
  Object.entries(props).forEach(([k, v]) => {
    if (k === "class") e.className = v;
    else if (k === "onclick") e.addEventListener("click", v);
    else if (k === "html") e.innerHTML = v;
    else e.setAttribute(k, v);
  });
  (Array.isArray(children) ? children : [children]).forEach(c => {
    if (c == null) return;
    e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  });
  return e;
}

async function refreshHealth() {
  const badge = document.getElementById("health-badge");
  const text = document.getElementById("health-text");
  const ksBtn = document.getElementById("killswitch-btn");
  try {
    const h = await api("/healthz");
    const ks = await api("/killswitch");
    if (ks.active) {
      badge.className = "badge err";
      text.textContent = `KILLSWITCH ACTIVE — ${ks.reason || "manual"}`;
      ksBtn.textContent = "DISENGAGE KILLSWITCH";
      ksBtn.onclick = async () => { await fetch("/killswitch/disengage", { method: "POST" }); refreshAll(); };
    } else {
      badge.className = "badge ok";
      text.textContent = `OK · ${h.scenarios_loaded} scenarios · ${h.agents_registered} agents`;
      ksBtn.textContent = "ENGAGE KILLSWITCH";
      ksBtn.onclick = async () => {
        if (!confirm("Engage killswitch? All running scenarios will abort.")) return;
        await fetch("/killswitch/engage", { method: "POST" });
        refreshAll();
      };
    }
  } catch (e) {
    badge.className = "badge err";
    text.textContent = `unreachable: ${e.message}`;
  }
}

async function refreshAgents() {
  const tbody = document.querySelector("#agents-table tbody");
  const empty = document.getElementById("agents-empty");
  try {
    const data = await api("/agents");
    const rows = Object.entries(data);
    clear(tbody);
    empty.hidden = rows.length > 0;
    for (const [id, a] of rows) {
      tbody.appendChild(el("tr", {}, [
        el("td", { class: "mono" }, id),
        el("td", {}, a.hostname),
        el("td", {}, a.platform),
        el("td", {}, String(a.pid)),
        el("td", {}, fmtTs(a.last_seen)),
      ]));
    }
  } catch (e) { /* swallow */ }
}

async function refreshScenarios() {
  const list = document.getElementById("scenarios-list");
  try {
    const data = await api("/scenarios");
    clear(list);
    for (const [name, s] of Object.entries(data)) {
      const card = el("div", { class: "card" }, [
        el("h3", {}, s.name),
        el("div", { class: "meta" }, [s.actor || "unattributed", " · ", `${s.steps.length} steps`]),
        el("div", { class: "tags" }, (s.tags || []).join(" · ")),
        el("div", { style: "margin-top:8px" }, [
          el("button", { class: "primary", onclick: () => runScenario(name) }, "Run"),
        ]),
      ]);
      list.appendChild(card);
    }
  } catch (e) { /* swallow */ }
}

async function runScenario(name) {
  try {
    await fetch("/scenarios/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    refreshRuns();
  } catch (e) { alert(`Failed to start: ${e.message}`); }
}

async function refreshRuns() {
  const tbody = document.querySelector("#runs-table tbody");
  const empty = document.getElementById("runs-empty");
  try {
    const runs = await api("/runs");
    clear(tbody);
    empty.hidden = runs.length > 0;
    for (const r of runs.sort((a, b) => b.started_at - a.started_at)) {
      const stepCells = Object.entries(r.step_summary || {}).map(([sid, st]) =>
        el("span", { class: `status-${st}`, title: `${sid}: ${st}` }, "■")
      );
      const row = el("tr", { class: "run-row", style: "cursor:pointer", title: "Click for step details" }, [
        el("td", { class: "mono" }, r.id),
        el("td", {}, r.scenario),
        el("td", { class: `status-${r.status}` }, r.status),
        el("td", {}, fmtTs(r.started_at)),
        el("td", {}, stepCells),
      ]);
      row.addEventListener("click", () => showRunDetail(r.id));
      tbody.appendChild(row);
    }
  } catch (e) { /* swallow */ }
}

async function showRunDetail(runId) {
  const modal = document.getElementById("step-modal");
  const title = document.getElementById("modal-title");
  const body = document.getElementById("modal-body");
  title.textContent = `Run: ${runId}`;
  clear(body);
  body.appendChild(el("p", { class: "muted" }, "Loading…"));
  modal.hidden = false;
  try {
    const detail = await api(`/runs/${runId}/steps`);
    clear(body);
    const tbl = el("table", {});
    tbl.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", {}, "Step ID"), el("th", {}, "TTP"), el("th", {}, "Status"),
      el("th", {}, "Agent"), el("th", {}, "Started"), el("th", {}, "Duration"),
      el("th", {}, "Output / Error"),
    ])]));
    const tb = el("tbody");
    for (const s of detail.steps) {
      const dur = (s.started_at && s.finished_at)
        ? `${(s.finished_at - s.started_at).toFixed(2)}s` : "—";
      tb.appendChild(el("tr", {}, [
        el("td", { class: "mono" }, s.id),
        el("td", { class: "mono" }, s.attack_id),
        el("td", { class: `status-${s.status}` }, s.status),
        el("td", { class: "muted" }, s.agent_id || "—"),
        el("td", {}, fmtTs(s.started_at)),
        el("td", {}, dur),
        el("td", { class: "muted", style: "max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap",
          title: s.error || s.output || "" }, s.error ? `❌ ${s.error}` : (s.output || "—")),
      ]));
    }
    tbl.appendChild(tb);
    body.appendChild(tbl);
  } catch (e) {
    clear(body);
    body.appendChild(el("p", { class: "muted" }, `Error: ${e.message}`));
  }
}

async function refreshCoverage() {
  const container = document.getElementById("coverage-matrix");
  const summary = document.getElementById("coverage-summary");
  try {
    const matrix = await api("/coverage/matrix");
    const tactics = Object.keys(matrix.tactics || {}).sort();
    clear(summary);
    [
      ["TTPs", matrix.total],
      ["Rules", matrix.with_rules],
      ["Coverage", `${matrix.rule_coverage_percent}%`],
      ["Packs", Object.keys(matrix.packs || {}).length],
    ].forEach(([label, value]) => {
      summary.appendChild(el("div", { class: "summary-item" }, [
        el("span", { class: "summary-value" }, String(value)),
        el("span", { class: "summary-label" }, String(label)),
      ]));
    });
    clear(container);
    const table = el("table", { class: "matrix" });
    const thead = el("thead", {}, [el("tr", {}, tactics.map(t => el("th", {}, t)))]);
    table.appendChild(thead);
    const maxRows = Math.max(...tactics.map(t => matrix.tactics[t].items.length));
    const tbody = el("tbody");
    for (let i = 0; i < maxRows; i++) {
      const tr = el("tr");
      for (const t of tactics) {
        const techs = matrix.tactics[t].items;
        const ttp = techs[i];
        if (ttp) {
          const hasRule = ttp.has_rule;
          tr.appendChild(el("td", { class: hasRule ? "has-rule" : "no-rule", title: ttp.description }, [
            el("span", { class: "ttp-id" }, ttp.id),
            el("span", { class: "ttp-name" }, `${ttp.name} · ${ttp.pack} · ${ttp.safety_tier}`),
          ]));
        } else {
          tr.appendChild(el("td", {}, ""));
        }
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    container.appendChild(table);
  } catch (e) { /* swallow */ }
}

async function refreshDetectionScores() {
  const tbody = document.querySelector("#detection-score-table tbody");
  if (!tbody) return;
  try {
    const scores = await api("/detections/score");
    clear(tbody);
    Object.entries(scores)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .slice(0, 80)
      .forEach(([id, score]) => {
        tbody.appendChild(el("tr", {}, [
          el("td", { class: "mono" }, id),
          el("td", {}, `${score.coverage_score}%`),
          el("td", {}, `${score.events_matched}/${score.events_total}`),
          el("td", { class: `risk-${score.false_positive_risk}` }, score.false_positive_risk),
          el("td", { class: "muted" }, (score.missing_fields || []).join(", ") || "—"),
        ]));
      });
  } catch (e) { /* swallow */ }
}

function pushEventFeed(ev) {
  const feed = document.getElementById("event-feed");
  if (!feed) return;
  const ts = ev.ts ? new Date(ev.ts * 1000).toLocaleTimeString() : "—";
  const kind = ev.event || "?";
  const payload = ev.payload ? JSON.stringify(ev.payload, null, 0) : "";
  const cls = kind.startsWith("kill") ? "feed-entry feed-kill"
    : kind.startsWith("run.") ? "feed-entry feed-run"
    : kind.startsWith("task.") ? "feed-entry feed-task"
    : kind.startsWith("agent.") ? "feed-entry feed-agent"
    : "feed-entry";
  const entry = el("div", { class: cls }, [
    el("span", { class: "feed-ts" }, ts + " "),
    el("span", { class: "feed-kind" }, kind + " "),
    el("span", { class: "feed-payload" }, payload.slice(0, 120)),
  ]);
  feed.insertBefore(entry, feed.firstChild);
  // Trim old entries
  while (feed.childElementCount > MAX_FEED_ENTRIES) {
    feed.removeChild(feed.lastChild);
  }
}

function refreshAll() {
  refreshHealth();
  refreshAgents();
  refreshScenarios();
  refreshRuns();
  refreshCoverage();
  refreshDetectionScores();
}

function connectWs() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/ws`);
  ws.addEventListener("open", () => {
    console.log("[ws] connected");
  });
  ws.addEventListener("message", (msg) => {
    try {
      const ev = JSON.parse(msg.data);
      if (ev.event === "ws.heartbeat") return;
      pushEventFeed(ev);
      // Lightweight: refresh affected sections.
      if (ev.event && ev.event.startsWith("agent.")) refreshAgents();
      if (ev.event && (ev.event.startsWith("run.") || ev.event.startsWith("task."))) refreshRuns();
      if (ev.event && ev.event.startsWith("killswitch.")) refreshHealth();
    } catch (e) { /* ignore */ }
  });
  ws.addEventListener("close", () => {
    console.log("[ws] disconnected, retrying in 2s");
    setTimeout(connectWs, 2000);
  });
  ws.addEventListener("error", () => ws.close());
}

refreshAll();
// Periodic full refresh as fallback if WS misses an event.
setInterval(refreshAll, POLL_MS * 4);
connectWs();
