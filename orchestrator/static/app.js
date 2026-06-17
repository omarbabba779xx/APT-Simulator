"use strict";

const MAX_CATALOG_ROWS = 220;
const MAX_FEED_ENTRIES = 80;
const LIVE_REFRESH_MS = 6000;

const state = {
  agents: {},
  health: null,
  killswitch: null,
  scenarios: {},
  runs: [],
  ttps: [],
  matrix: null,
  scores: {},
  space: null,
  preview: null,
  batch: null,
  feed: [],
};

const byId = (id) => document.getElementById(id);
const clear = (node) => {
  while (node.firstChild) node.removeChild(node.firstChild);
};

function node(tag, props = {}, children = []) {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") element.className = value;
    else if (key === "text") element.textContent = value;
    else if (key === "title") element.title = value;
    else if (key === "onclick") element.addEventListener("click", value);
    else if (key === "dataset") {
      for (const [name, dataValue] of Object.entries(value)) element.dataset[name] = dataValue;
    } else element.setAttribute(key, value);
  }
  const items = Array.isArray(children) ? children : [children];
  for (const child of items) {
    if (child == null) continue;
    element.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return element;
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let message = response.statusText;
    try {
      const body = await response.json();
      message = body.detail || message;
    } catch (_error) {
      message = response.statusText;
    }
    throw new Error(`${response.status} ${message}`);
  }
  return response.json();
}

function postJson(path, body) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function fmtTs(value) {
  if (!value) return "-";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}

function fmtInt(value) {
  return Number(value || 0).toLocaleString();
}

function setStatus(label, kind = "neutral") {
  const element = byId("preview-status");
  if (!element) return;
  element.className = `pill ${kind}`;
  element.textContent = label;
}

function optionValue(value) {
  return value == null || value === "" ? "unknown" : String(value);
}

function fillSelect(select, values, allLabel = "All") {
  const current = select.value;
  clear(select);
  select.appendChild(node("option", { value: "" }, allLabel));
  for (const value of values) {
    select.appendChild(node("option", { value }, value));
  }
  if ([...select.options].some((option) => option.value === current)) select.value = current;
}

function unique(items) {
  return [...new Set(items.map(optionValue))].sort((a, b) => a.localeCompare(b));
}

function ttpLookup() {
  const out = new Map();
  for (const ttp of state.ttps) out.set(ttp.attack_id, ttp);
  return out;
}

async function refreshLive() {
  const tasks = [
    api("/healthz").then((data) => { state.health = data; }),
    api("/killswitch").then((data) => { state.killswitch = data; }),
    api("/agents").then((data) => { state.agents = data; }),
    api("/runs").then((data) => { state.runs = data; }),
  ];
  await Promise.allSettled(tasks);
  renderHealth();
  renderAgents();
  renderRuns();
  renderOverview();
}

async function refreshStatic() {
  const tasks = [
    api("/scenarios").then((data) => { state.scenarios = data; }),
    api("/ttps").then((data) => { state.ttps = data; }),
    api("/coverage/matrix").then((data) => { state.matrix = data; }),
    api("/detections/score").then((data) => { state.scores = data; }),
    api("/scenario-builder/space").then((data) => { state.space = data; }),
  ];
  await Promise.allSettled(tasks);
  renderScenarioSelect();
  renderCatalogFilters();
  renderCatalog();
  renderDetection();
  renderVariantSpace();
  renderOverview();
}

function renderHealth() {
  const health = state.health;
  const killswitch = state.killswitch;
  const line = byId("health-line");
  const button = byId("killswitch-button");
  if (!line || !button) return;

  if (!health) {
    line.textContent = "System unavailable";
    button.className = "danger";
    return;
  }

  const agents = health.agents_registered ?? Object.keys(state.agents).length;
  const scenarios = health.scenarios_loaded ?? Object.keys(state.scenarios).length;
  if (killswitch?.active) {
    line.textContent = `Killswitch active - ${killswitch.reason || "manual"}`;
    button.textContent = "Disengage";
    button.className = "danger";
  } else {
    line.textContent = `Ready - ${scenarios} scenarios - ${agents} agents`;
    button.textContent = "Killswitch";
    button.className = "danger";
  }
}

function renderMetrics() {
  const grid = byId("metrics-grid");
  if (!grid) return;
  clear(grid);
  const matrix = state.matrix || {};
  const runs = state.runs || [];
  const agents = Object.keys(state.agents || {}).length;
  const scored = Object.keys(state.scores || {}).length;
  const metrics = [
    ["TTPs", matrix.total ?? state.ttps.length, "Coverage catalog"],
    ["Sigma", matrix.with_rules ?? scored, "Rules linked"],
    ["Rule Fit", `${matrix.rule_coverage_percent ?? 0}%`, "Rule coverage"],
    ["Variants", fmtInt(state.space?.total_variants), "Generable"],
    ["Scenarios", Object.keys(state.scenarios || {}).length, "Loaded"],
    ["Runs", runs.length, "In memory"],
    ["Agents", agents, "Registered"],
  ];
  for (const [label, value, hint] of metrics) {
    grid.appendChild(node("div", { class: "metric" }, [
      node("span", { class: "metric-value" }, String(value)),
      node("span", { class: "metric-label" }, label),
      node("span", { class: "metric-hint" }, hint),
    ]));
  }
}

function renderVariantSpace() {
  if (!state.space) return;
  const total = byId("variant-total");
  const detail = byId("variant-detail");
  if (!total || !detail) return;
  total.textContent = fmtInt(state.space.total_variants);
  detail.textContent = [
    `${state.space.actors.length} actors`,
    `${state.space.difficulties.length} difficulties`,
    `${state.space.max_steps} step counts`,
    `${state.space.seed_values} seeds`,
    `${state.space.platform_combinations} platform sets`,
  ].join(" - ");
}

function renderBars(containerId, rows) {
  const container = byId(containerId);
  if (!container) return;
  clear(container);
  if (!rows.length) {
    container.appendChild(node("p", { class: "empty" }, "No data"));
    return;
  }
  const max = Math.max(...rows.map((row) => row.count), 1);
  for (const row of rows) {
    const width = Math.max(4, Math.round((row.count / max) * 100));
    container.appendChild(node("div", { class: "bar-row" }, [
      node("div", { class: "bar-label" }, [
        node("span", {}, row.label),
        node("strong", {}, row.value || String(row.count)),
      ]),
      node("div", { class: "bar-track" }, node("span", { style: `width:${width}%` })),
    ]));
  }
}

function renderOverview() {
  renderMetrics();
  const matrix = state.matrix || {};
  const tactics = Object.entries(matrix.tactics || {})
    .map(([label, data]) => ({
      label,
      count: data.total || 0,
      value: `${data.with_rules || 0}/${data.total || 0}`,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  const tiers = Object.entries(matrix.safety_tiers || {})
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  renderBars("tactic-bars", tactics);
  renderBars("tier-bars", tiers);
  byId("coverage-label").textContent = `${matrix.rule_coverage_percent ?? 0}%`;

  const activeRuns = state.runs.filter((run) => run.status === "running").length;
  byId("run-label").textContent = `${activeRuns} active`;
  byId("agent-label").textContent = `${Object.keys(state.agents).length} online`;

  const overviewRuns = byId("overview-runs");
  clear(overviewRuns);
  for (const run of [...state.runs].sort((a, b) => b.started_at - a.started_at).slice(0, 8)) {
    overviewRuns.appendChild(node("tr", { onclick: () => showRunDetail(run.id) }, [
      node("td", { class: "mono" }, run.id),
      node("td", {}, run.scenario),
      node("td", {}, statusPill(run.status)),
      node("td", {}, stepDots(run.step_summary || {})),
    ]));
  }
  if (!state.runs.length) overviewRuns.appendChild(emptyRow(4, "No runs"));
}

function renderAgents() {
  const tbody = byId("agents-table");
  if (!tbody) return;
  clear(tbody);
  const entries = Object.entries(state.agents || {});
  for (const [id, agent] of entries) {
    tbody.appendChild(node("tr", {}, [
      node("td", { class: "mono" }, id),
      node("td", {}, agent.hostname || "-"),
      node("td", {}, agent.platform || "-"),
      node("td", {}, fmtTs(agent.last_seen)),
    ]));
  }
  if (!entries.length) tbody.appendChild(emptyRow(4, "No agents"));
}

function renderScenarioSelect() {
  const select = byId("scenario-select");
  if (!select) return;
  clear(select);
  for (const name of Object.keys(state.scenarios || {}).sort()) {
    select.appendChild(node("option", { value: name }, name));
  }
  if (!select.options.length) select.appendChild(node("option", { value: "" }, "No scenarios"));
}

function renderCatalogFilters() {
  if (!state.ttps.length) return;
  fillSelect(byId("catalog-tactic"), unique(state.ttps.map((ttp) => ttp.tactic)), "All tactics");
  fillSelect(byId("catalog-pack"), unique(state.ttps.map((ttp) => ttp.pack)), "All packs");
  fillSelect(byId("catalog-tier"), unique(state.ttps.map((ttp) => ttp.safety_tier)), "All tiers");
  fillSelect(
    byId("catalog-platform"),
    unique(state.ttps.flatMap((ttp) => ttp.supported_platforms || [])),
    "All platforms",
  );
}

function renderCatalog() {
  const tbody = byId("catalog-table");
  if (!tbody) return;
  const search = byId("catalog-search").value.trim().toLowerCase();
  const tactic = byId("catalog-tactic").value;
  const pack = byId("catalog-pack").value;
  const tier = byId("catalog-tier").value;
  const platform = byId("catalog-platform").value;

  const filtered = state.ttps.filter((ttp) => {
    const text = [
      ttp.attack_id,
      ttp.base_attack_id,
      ttp.name,
      ttp.tactic,
      ttp.pack,
      ttp.safety_tier,
      ...(ttp.supported_platforms || []),
    ].join(" ").toLowerCase();
    if (search && !text.includes(search)) return false;
    if (tactic && ttp.tactic !== tactic) return false;
    if (pack && optionValue(ttp.pack) !== pack) return false;
    if (tier && optionValue(ttp.safety_tier) !== tier) return false;
    if (platform && !(ttp.supported_platforms || []).includes(platform)) return false;
    return true;
  });

  clear(tbody);
  for (const ttp of filtered.slice(0, MAX_CATALOG_ROWS)) {
    tbody.appendChild(node("tr", {}, [
      node("td", { class: "mono" }, ttp.attack_id),
      node("td", { title: ttp.description || "" }, ttp.name),
      node("td", {}, ttp.tactic),
      node("td", {}, ttp.pack || "core"),
      node("td", {}, tierPill(ttp.safety_tier || "lab-write")),
      node("td", {}, (ttp.supported_platforms || []).join(", ")),
    ]));
  }
  if (!filtered.length) tbody.appendChild(emptyRow(6, "No matching TTPs"));
  const shown = Math.min(filtered.length, MAX_CATALOG_ROWS);
  byId("catalog-count").textContent = `${shown}/${filtered.length} items`;
}

function renderDetection() {
  const tbody = byId("score-table");
  if (!tbody) return;
  clear(tbody);
  const scores = Object.entries(state.scores || {}).sort((a, b) => a[0].localeCompare(b[0]));
  for (const [id, score] of scores.slice(0, 180)) {
    tbody.appendChild(node("tr", {}, [
      node("td", { class: "mono" }, id),
      node("td", {}, `${score.coverage_score}%`),
      node("td", {}, `${score.events_matched}/${score.events_total}`),
      node("td", {}, riskPill(score.false_positive_risk)),
      node("td", { class: "muted" }, (score.missing_fields || []).join(", ") || "-"),
    ]));
  }
  if (!scores.length) tbody.appendChild(emptyRow(5, "No scores"));
  byId("score-count").textContent = `${scores.length} scored`;

  const packs = Object.entries((state.matrix || {}).packs || {})
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);
  renderBars("pack-bars", packs);
}

function renderRuns() {
  const tbody = byId("runs-table");
  if (!tbody) return;
  clear(tbody);
  const runs = [...state.runs].sort((a, b) => b.started_at - a.started_at);
  for (const run of runs) {
    tbody.appendChild(node("tr", { onclick: () => showRunDetail(run.id), title: "Open run" }, [
      node("td", { class: "mono" }, run.id),
      node("td", {}, run.scenario),
      node("td", {}, statusPill(run.status)),
      node("td", {}, fmtTs(run.started_at)),
      node("td", {}, stepDots(run.step_summary || {})),
    ]));
  }
  if (!runs.length) tbody.appendChild(emptyRow(5, "No runs"));
  byId("runs-count").textContent = `${runs.length} runs`;
}

function emptyRow(cols, text) {
  return node("tr", { class: "empty-row" }, node("td", { colspan: String(cols) }, text));
}

function statusPill(status) {
  return node("span", { class: `pill status-${status}` }, status || "unknown");
}

function tierPill(tier) {
  const value = optionValue(tier);
  const kind = value === "marker-only" || value === "read-only" ? "ok" : "warn";
  return node("span", { class: `pill ${kind}` }, value);
}

function riskPill(risk) {
  const value = optionValue(risk);
  const kind = value === "low" ? "ok" : value === "medium" ? "warn" : "bad";
  return node("span", { class: `pill ${kind}` }, value);
}

function stepDots(summary) {
  const wrap = node("div", { class: "step-dots" });
  for (const [id, status] of Object.entries(summary)) {
    wrap.appendChild(node("span", { class: `dot status-${status}`, title: `${id}: ${status}` }));
  }
  if (!Object.keys(summary).length) wrap.appendChild(node("span", { class: "muted" }, "-"));
  return wrap;
}

function currentBuilderPlatforms() {
  return [...document.querySelectorAll("input[name='builder-platform']:checked")]
    .map((item) => item.value);
}

async function refreshPreview() {
  const actor = byId("builder-actor").value;
  const difficulty = byId("builder-difficulty").value;
  const steps = byId("builder-steps").value;
  const seed = byId("builder-seed").value;
  const platforms = currentBuilderPlatforms();
  if (!platforms.length) {
    setStatus("Select platform", "bad");
    return;
  }

  setStatus("Loading", "neutral");
  const params = new URLSearchParams({
    actor,
    difficulty,
    steps,
    seed,
    platforms: platforms.join(","),
  });
  try {
    state.preview = await api(`/scenario-builder/preview?${params.toString()}`);
    setStatus("Preview ready", "ok");
    renderPreview();
  } catch (error) {
    setStatus("Preview failed", "bad");
    state.preview = null;
    renderPreview(error.message);
  }
}

function renderPreview(error = "") {
  const title = byId("scenario-title");
  const meta = byId("scenario-meta");
  const graph = byId("scenario-graph");
  clear(graph);
  if (error) {
    title.textContent = "Preview error";
    meta.textContent = "0 steps";
    graph.appendChild(node("p", { class: "empty" }, error));
    return;
  }
  const scenario = state.preview;
  if (!scenario) {
    title.textContent = "No preview";
    meta.textContent = "0 steps";
    graph.appendChild(node("p", { class: "empty" }, "No scenario"));
    return;
  }

  title.textContent = scenario.name;
  meta.textContent = `${scenario.steps.length} steps`;
  const lookup = ttpLookup();
  for (const step of scenario.steps) {
    const ttp = lookup.get(step.ttp);
    graph.appendChild(node("article", { class: "scenario-step" }, [
      node("div", { class: "step-index" }, step.id.split("_")[0].replace("s", "")),
      node("div", { class: "step-body" }, [
        node("div", { class: "step-main" }, [
          node("span", { class: "mono" }, step.ttp),
          node("strong", {}, ttp?.name || step.ttp),
        ]),
        node("div", { class: "step-sub" }, [
          node("span", {}, ttp?.tactic || "unknown"),
          node("span", {}, ttp?.pack || "core"),
          node("span", {}, (step.depends_on || []).length ? `depends ${step.depends_on.join(", ")}` : "entry"),
        ]),
      ]),
    ]));
  }
}

async function previewBatch() {
  const count = byId("batch-count").value;
  const offset = byId("batch-offset").value;
  setStatus("Batch loading", "neutral");
  const params = new URLSearchParams({ count, offset });
  try {
    state.batch = await api(`/scenario-builder/batch-preview?${params.toString()}`);
    setStatus("Batch ready", "ok");
    renderBatchPreview();
  } catch (error) {
    setStatus("Batch failed", "bad");
    renderPreview(error.message);
  }
}

function renderBatchPreview() {
  const title = byId("scenario-title");
  const meta = byId("scenario-meta");
  const graph = byId("scenario-graph");
  clear(graph);
  if (!state.batch) return;
  title.textContent = "Batch Preview";
  meta.textContent = `${state.batch.count} scenarios`;
  for (const scenario of state.batch.scenarios) {
    graph.appendChild(node("article", { class: "scenario-step" }, [
      node("div", { class: "step-index" }, String(scenario.steps.length)),
      node("div", { class: "step-body" }, [
        node("div", { class: "step-main" }, [
          node("span", { class: "mono" }, scenario.name),
          node("strong", {}, scenario.actor || "unknown"),
        ]),
        node("div", { class: "step-sub" }, [
          node("span", {}, `${scenario.steps.length} steps`),
          node("span", {}, (scenario.target_platforms || []).join(", ")),
          node("span", {}, (scenario.tags || []).join(", ")),
        ]),
      ]),
    ]));
  }
}

async function runPreview() {
  if (!state.preview) await refreshPreview();
  if (!state.preview) return;
  try {
    const run = await postJson("/scenarios/run", { inline: state.preview });
    pushFeed({ event: "run.start", ts: Date.now() / 1000, payload: { run_id: run.id, scenario: run.scenario } });
    await refreshLive();
    switchView("runs");
  } catch (error) {
    setStatus("Run failed", "bad");
    pushFeed({ event: "run.error", ts: Date.now() / 1000, payload: { error: error.message } });
  }
}

async function runSelectedScenario() {
  const name = byId("scenario-select").value;
  if (!name) return;
  try {
    const run = await postJson("/scenarios/run", { name });
    pushFeed({ event: "run.start", ts: Date.now() / 1000, payload: { run_id: run.id, scenario: run.scenario } });
    await refreshLive();
  } catch (error) {
    pushFeed({ event: "run.error", ts: Date.now() / 1000, payload: { error: error.message } });
  }
}

async function copyPreview() {
  if (!state.preview) await refreshPreview();
  if (!state.preview) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(state.preview, null, 2));
    setStatus("Copied", "ok");
  } catch (_error) {
    setStatus("Copy blocked", "warn");
  }
}

async function showRunDetail(runId) {
  const dialog = byId("run-dialog");
  const title = byId("dialog-title");
  const body = byId("dialog-body");
  title.textContent = `Run ${runId}`;
  clear(body);
  body.appendChild(node("p", { class: "empty" }, "Loading"));
  if (!dialog.open) dialog.showModal();
  try {
    const detail = await api(`/runs/${runId}/steps`);
    clear(body);
    const table = node("table");
    table.appendChild(node("thead", {}, node("tr", {}, [
      node("th", {}, "Step"),
      node("th", {}, "TTP"),
      node("th", {}, "Status"),
      node("th", {}, "Agent"),
      node("th", {}, "Started"),
      node("th", {}, "Output"),
    ])));
    const tbody = node("tbody");
    for (const step of detail.steps) {
      tbody.appendChild(node("tr", {}, [
        node("td", { class: "mono" }, step.id),
        node("td", { class: "mono" }, step.attack_id),
        node("td", {}, statusPill(step.status)),
        node("td", {}, step.agent_id || "-"),
        node("td", {}, fmtTs(step.started_at)),
        node("td", { class: "muted output-cell", title: step.error || step.output || "" }, step.error || step.output || "-"),
      ]));
    }
    table.appendChild(tbody);
    body.appendChild(table);
  } catch (error) {
    clear(body);
    body.appendChild(node("p", { class: "empty" }, error.message));
  }
}

function pushFeed(event) {
  state.feed.unshift(event);
  state.feed = state.feed.slice(0, MAX_FEED_ENTRIES);
  renderFeed();
}

function renderFeed() {
  const feed = byId("event-feed");
  if (!feed) return;
  clear(feed);
  for (const event of state.feed) {
    const kind = event.event || "event";
    feed.appendChild(node("div", { class: "feed-row" }, [
      node("span", { class: "feed-time" }, fmtTs(event.ts)),
      node("span", { class: "feed-kind" }, kind),
      node("span", { class: "feed-payload" }, JSON.stringify(event.payload || {}).slice(0, 180)),
    ]));
  }
  if (!state.feed.length) feed.appendChild(node("p", { class: "empty" }, "No events"));
  byId("event-count").textContent = `${state.feed.length} events`;
}

function connectWs() {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${protocol}//${location.host}/ws`);
  socket.addEventListener("message", (message) => {
    try {
      const event = JSON.parse(message.data);
      if (event.event === "ws.heartbeat") return;
      pushFeed(event);
      if (event.event?.startsWith("agent.")) refreshLive();
      if (event.event?.startsWith("run.") || event.event?.startsWith("task.")) refreshLive();
      if (event.event?.startsWith("killswitch.")) refreshLive();
    } catch (_error) {
      return;
    }
  });
  socket.addEventListener("close", () => {
    setTimeout(connectWs, 2000);
  });
  socket.addEventListener("error", () => socket.close());
}

function switchView(view) {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.classList.toggle("is-active", tab.dataset.view === view);
  }
  for (const panel of document.querySelectorAll(".view")) {
    panel.classList.toggle("is-active", panel.id === `view-${view}`);
  }
}

async function toggleKillswitch() {
  try {
    if (state.killswitch?.active) {
      await api("/killswitch/disengage", { method: "POST" });
    } else if (confirm("Engage killswitch?")) {
      await api("/killswitch/engage?reason=dashboard", { method: "POST" });
    }
    await refreshLive();
  } catch (error) {
    pushFeed({ event: "killswitch.error", ts: Date.now() / 1000, payload: { error: error.message } });
  }
}

function bindEvents() {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  }
  byId("refresh-button").addEventListener("click", async () => {
    await refreshLive();
    await refreshStatic();
  });
  byId("killswitch-button").addEventListener("click", toggleKillswitch);
  for (const id of ["catalog-search", "catalog-tactic", "catalog-pack", "catalog-tier", "catalog-platform"]) {
    byId(id).addEventListener("input", renderCatalog);
    byId(id).addEventListener("change", renderCatalog);
  }
  byId("scenario-form").addEventListener("submit", (event) => {
    event.preventDefault();
    refreshPreview();
  });
  byId("run-preview").addEventListener("click", runPreview);
  byId("batch-preview").addEventListener("click", previewBatch);
  byId("copy-preview").addEventListener("click", copyPreview);
  byId("run-selected").addEventListener("click", runSelectedScenario);
  byId("dialog-close").addEventListener("click", () => byId("run-dialog").close());
}

async function init() {
  bindEvents();
  renderPreview();
  renderFeed();
  await refreshLive();
  await refreshStatic();
  await refreshPreview();
  connectWs();
  setInterval(refreshLive, LIVE_REFRESH_MS);
}

document.addEventListener("DOMContentLoaded", init);
