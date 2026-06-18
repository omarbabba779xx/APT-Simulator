"use strict";

const MAX_CATALOG_ROWS = 220;
const MAX_LIBRARY_ROWS = 300;
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
  attackSync: null,
  workbench: null,
  exposure: null,
  maturity: null,
  space: null,
  library: { items: [], counts: {}, total: 0, filtered: 0 },
  campaigns: [],
  history: { items: [], total: 0 },
  queue: { items: [], total: 0 },
  labProfiles: [],
  access: null,
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
    api("/campaigns").then((data) => { state.campaigns = data; }),
    api("/history/runs").then((data) => { state.history = data; }),
    api("/execution/queue").then((data) => { state.queue = data; }),
  ];
  await Promise.allSettled(tasks);
  renderHealth();
  renderAgents();
  renderRuns();
  renderCampaigns();
  renderHistory();
  renderOverview();
}

async function refreshStatic() {
  const tasks = [
    api("/scenarios").then((data) => { state.scenarios = data; }),
    api("/ttps").then((data) => { state.ttps = data; }),
    api("/coverage/matrix").then((data) => { state.matrix = data; }),
    api("/detections/score").then((data) => { state.scores = data; }),
    api("/attack/sync/status").then((data) => { state.attackSync = data; }),
    api("/detections/workbench").then((data) => { state.workbench = data; }),
    api("/exposure/graph").then((data) => { state.exposure = data; }),
    api("/scenario-maturity").then((data) => { state.maturity = data; }),
    api("/scenario-builder/space").then((data) => { state.space = data; }),
    api("/scenario-library").then((data) => { state.library = data; }),
    api("/lab-profiles").then((data) => { state.labProfiles = data; }),
    api("/access/rbac").then((data) => { state.access = data; }),
  ];
  await Promise.allSettled(tasks);
  renderScenarioSelect();
  renderLibraryFilters();
  renderScenarioLibrary();
  renderCatalogFilters();
  renderCatalog();
  renderAttackMatrix();
  renderDetection();
  renderAttackSync();
  renderWorkbench();
  renderExposure();
  renderMaturity();
  renderLabProfiles();
  renderAccess();
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
  const sync = state.attackSync || state.matrix?.attack_sync || {};
  const maturity = state.maturity || {};
  const metrics = [
    ["TTPs", matrix.total ?? state.ttps.length, "Coverage catalog"],
    ["Sigma", matrix.with_rules ?? scored, "Rules linked"],
    ["ATT&CK", sync.coverage_label || "-", "Enterprise tactics"],
    ["Rule Fit", `${matrix.rule_coverage_percent ?? 0}%`, "Rule coverage"],
    ["Variants", fmtInt(state.space?.total_variants), "Generable"],
    ["Scenarios", Object.keys(state.scenarios || {}).length, "Loaded"],
    ["Validated", maturity.validated_scenarios ?? 0, "Actor-chain"],
    ["Runs", state.history?.total ?? runs.length, "Stored"],
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
  const boundary = byId("boundary-scenario-line");
  if (boundary) {
    boundary.textContent = `Stores the complete ${fmtInt(Object.keys(state.scenarios || {}).length)}-scenario loaded library as YAML; larger variant batches are generated on demand.`;
  }

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

function renderLibraryFilters() {
  const items = state.library.items || [];
  if (!items.length || !byId("library-actor")) return;
  fillSelect(byId("library-actor"), unique(items.map((item) => item.actor || "unknown")), "All actors");
  fillSelect(byId("library-difficulty"), unique(items.map((item) => item.difficulty || "unknown")), "All difficulties");
  fillSelect(
    byId("library-platform"),
    unique(items.flatMap((item) => item.platforms || [])),
    "All platforms",
  );
  fillSelect(
    byId("library-source"),
    unique(items.flatMap((item) => [item.source, item.kind])),
    "All sources",
  );
}

function filteredLibraryItems() {
  const items = state.library.items || [];
  const search = byId("library-search")?.value.trim().toLowerCase() || "";
  const actor = byId("library-actor")?.value || "";
  const difficulty = byId("library-difficulty")?.value || "";
  const platform = byId("library-platform")?.value || "";
  const source = byId("library-source")?.value || "";
  return items.filter((item) => {
    const text = [
      item.name,
      item.actor,
      item.difficulty,
      item.source,
      item.kind,
      ...(item.platforms || []),
      ...(item.ttps || []),
    ].join(" ").toLowerCase();
    if (search && !text.includes(search)) return false;
    if (actor && (item.actor || "unknown") !== actor) return false;
    if (difficulty && (item.difficulty || "unknown") !== difficulty) return false;
    if (platform && !(item.platforms || []).includes(platform)) return false;
    if (source && source !== item.source && source !== item.kind) return false;
    return true;
  });
}

function renderScenarioLibrary() {
  const tbody = byId("library-table");
  if (!tbody) return;
  const filtered = filteredLibraryItems();
  clear(tbody);
  for (const item of filtered.slice(0, MAX_LIBRARY_ROWS)) {
    tbody.appendChild(node("tr", {}, [
      node("td", { class: "mono", title: item.description || "" }, item.name),
      node("td", {}, item.actor || "-"),
      node("td", {}, item.difficulty || "-"),
      node("td", {}, (item.platforms || []).join(", ")),
      node("td", {}, String(item.step_count)),
      node("td", {}, node("span", { class: "pill neutral" }, item.source)),
      node("td", {}, node("span", { class: "pill ok" }, item.kind)),
      node("td", {}, node("button", { class: "secondary", onclick: () => runNamedScenario(item.name) }, "Run")),
    ]));
  }
  if (!filtered.length) tbody.appendChild(emptyRow(8, "No scenarios"));
  const shown = Math.min(filtered.length, MAX_LIBRARY_ROWS);
  byId("library-count").textContent = `${shown}/${filtered.length} scenarios`;
}

function renderMaturity() {
  const tbody = byId("maturity-table");
  if (!tbody) return;
  const maturity = state.maturity || {};
  const items = maturity.items || [];
  clear(tbody);
  for (const item of items.slice(0, 160)) {
    tbody.appendChild(node("tr", {}, [
      node("td", { class: "mono", title: (item.tags || []).join(", ") }, item.name),
      node("td", {}, item.actor || "-"),
      node("td", {}, `${item.score}%`),
      node("td", {}, maturityPill(item.maturity)),
      node("td", {}, `${item.tactic_count} (${(item.tactics || []).slice(0, 3).join(", ")})`),
      node("td", {}, `${item.detection_coverage_percent}%`),
      node("td", {}, [
        node("span", { class: item.evidence_status === "fixture-backed" ? "pill ok" : "pill warn" }, item.evidence_status || "missing"),
        node("a", {
          href: `/reports/scenarios/${item.name}.json`,
          target: "_blank",
          rel: "noreferrer",
          class: "inline-report",
        }, "JSON"),
      ]),
    ]));
  }
  if (!items.length) tbody.appendChild(emptyRow(7, "No maturity data"));
  byId("maturity-count").textContent = `${fmtInt(maturity.validated_scenarios)} validated / ${fmtInt(maturity.total_scenarios)} scenarios`;
  byId("maturity-score").textContent = `${maturity.average_score || 0}% avg`;
  const bars = Object.entries(maturity.counts_by_maturity || {})
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);
  renderBars("maturity-bars", bars);
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

function renderAttackMatrix() {
  const container = byId("attack-matrix");
  if (!container) return;
  clear(container);
  const tactics = Object.entries((state.matrix || {}).tactics || {});
  let total = 0;
  for (const [tactic, data] of tactics) {
    const items = data.items || [];
    total += items.length;
    const column = node("div", { class: "matrix-column" }, [
      node("h3", {}, `${tactic} (${items.length})`),
    ]);
    for (const item of items) {
      column.appendChild(node("button", {
        class: item.has_rule ? "matrix-tech has-rule" : "matrix-tech",
        title: item.name,
        onclick: () => {
          byId("catalog-search").value = item.id;
          renderCatalog();
          switchView("catalog");
        },
      }, [
        node("span", { class: "mono" }, item.id),
        node("small", {}, item.name),
      ]));
    }
    container.appendChild(column);
  }
  byId("matrix-count").textContent = `${total} TTPs`;
}

function renderAttackSync() {
  const sync = state.attackSync || state.matrix?.attack_sync;
  const status = byId("sync-status");
  const summary = byId("sync-summary");
  const drift = byId("sync-drift");
  const driftLabel = byId("sync-drift-label");
  if (!status || !summary || !drift || !driftLabel) return;
  clear(summary);
  clear(drift);
  if (!sync) {
    status.textContent = "Unavailable";
    status.className = "pill bad";
    drift.appendChild(node("p", { class: "empty" }, "No sync data"));
    return;
  }
  const driftTotal = (sync.missing_count || 0)
    + (sync.extra_count || 0)
    + (sync.deprecated_present_count || 0)
    + (sync.revoked_present_count || 0);
  status.textContent = sync.status || "unknown";
  status.className = sync.status === "synced" ? "pill ok" : "pill warn";
  driftLabel.textContent = `${driftTotal} drift`;
  driftLabel.className = driftTotal ? "pill warn" : "pill ok";
  const rows = [
    ["Tactics", sync.coverage_label || "-"],
    ["Active techniques", fmtInt(sync.official_active)],
    ["Local base IDs", fmtInt(sync.local_base_ids)],
    ["Latest modified", sync.latest_modified || "-"],
    ["Snapshot", sync.snapshot_generated_at || "-"],
    ["Excluded IDs", (sync.excluded_attack_ids || []).join(", ") || "-"],
  ];
  for (const [label, value] of rows) {
    summary.appendChild(node("div", { class: "summary-row" }, [
      node("span", {}, label),
      node("strong", {}, String(value)),
    ]));
  }
  const groups = [
    ["Missing", sync.missing || []],
    ["Extra", sync.extra || []],
    ["Deprecated local", sync.deprecated_present || []],
    ["Revoked local", sync.revoked_present || []],
  ];
  for (const [label, values] of groups) {
    drift.appendChild(node("div", { class: "drift-group" }, [
      node("strong", {}, `${label} (${values.length})`),
      node("p", { class: values.length ? "mono" : "muted" }, values.slice(0, 20).join(", ") || "none"),
    ]));
  }
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

function renderWorkbench() {
  const tbody = byId("workbench-table");
  if (!tbody) return;
  const workbench = state.workbench || {};
  const items = workbench.items || [];
  clear(tbody);
  for (const item of items.slice(0, 180)) {
    tbody.appendChild(node("tr", {}, [
      node("td", { class: "mono", title: item.name || "" }, item.attack_id),
      node("td", {}, `${item.quality_score}%`),
      node("td", {}, riskPill(item.false_positive_risk)),
      node("td", { class: "muted" }, (item.missing_fields || []).join(", ") || "-"),
      node("td", {}, (item.exports || []).join(", ")),
    ]));
  }
  if (!items.length) tbody.appendChild(emptyRow(5, "No workbench data"));
  byId("workbench-count").textContent = `${fmtInt(workbench.total_rules)} rules`;
  byId("workbench-score").textContent = `${workbench.average_quality_score || 0}% avg`;

  const gaps = Object.entries(workbench.missing_field_counts || {})
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);
  renderBars("workbench-bars", gaps);
}

function renderExposure() {
  const container = byId("exposure-graph");
  if (!container) return;
  const graph = state.exposure || {};
  clear(container);
  const domains = Object.entries(graph.domain_counts || {})
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);
  renderBars("exposure-bars", domains);
  byId("exposure-count").textContent = `${fmtInt(graph.scenario_count)} scenarios`;

  for (const path of graph.reference_paths || []) {
    container.appendChild(node("div", { class: "exposure-path" }, path.map((part, index) => [
      node("span", { class: "pill neutral" }, part),
      index < path.length - 1 ? node("span", { class: "path-arrow" }, "->") : null,
    ]).flat()));
  }
  const edges = (graph.edges || []).filter((edge) => edge.label === "path").slice(0, 60);
  if (edges.length) {
    container.appendChild(node("h3", {}, "Observed scenario paths"));
    for (const edge of edges) {
      container.appendChild(node("div", { class: "edge-row" }, [
        node("span", {}, edge.source.replace("domain:", "")),
        node("span", { class: "path-arrow" }, "->"),
        node("strong", {}, edge.target.replace("domain:", "")),
      ]));
    }
  }
  if (!container.childNodes.length) container.appendChild(node("p", { class: "empty" }, "No graph data"));
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
      node("td", {}, reportLinks(`/reports/runs/${run.id}`, `/reports/runs/${run.id}.zip`)),
    ]));
  }
  if (!runs.length) tbody.appendChild(emptyRow(6, "No runs"));
  byId("runs-count").textContent = `${runs.length} runs`;
}

function reportLinks(basePath, zipPath = "") {
  const links = [
    node("a", { href: `${basePath}.json`, target: "_blank", rel: "noreferrer", onclick: (event) => event.stopPropagation() }, "JSON"),
    node("a", { href: `${basePath}.html`, target: "_blank", rel: "noreferrer", onclick: (event) => event.stopPropagation() }, "HTML"),
  ];
  if (zipPath) {
    links.push(node("a", { href: zipPath, target: "_blank", rel: "noreferrer", onclick: (event) => event.stopPropagation() }, "ZIP"));
  }
  return node("div", { class: "report-links" }, links);
}

function renderHistory() {
  const tbody = byId("history-table");
  if (!tbody) return;
  clear(tbody);
  const items = state.history.items || [];
  for (const run of items.slice(0, 120)) {
    tbody.appendChild(node("tr", {}, [
      node("td", { class: "mono" }, run.id),
      node("td", {}, run.scenario),
      node("td", {}, statusPill(run.status)),
      node("td", {}, String(run.step_count || 0)),
      node("td", {}, String(run.artifact_count || 0)),
      node("td", {}, reportLinks(`/reports/runs/${run.id}`, `/reports/runs/${run.id}.zip`)),
    ]));
  }
  if (!items.length) tbody.appendChild(emptyRow(6, "No persistent runs"));
  byId("history-count").textContent = `${state.history.total || items.length} runs`;

  const queueItems = state.queue.items || [];
  const counts = {};
  for (const item of queueItems) counts[item.status] = (counts[item.status] || 0) + 1;
  const bars = Object.entries(counts).map(([label, count]) => ({ label, count }));
  renderBars("queue-bars", bars);
  byId("queue-count").textContent = `${state.queue.total || queueItems.length} tasks`;
}

function renderLabProfiles() {
  const tbody = byId("lab-table");
  if (!tbody) return;
  clear(tbody);
  for (const profile of state.labProfiles || []) {
    tbody.appendChild(node("tr", {}, [
      node("td", {}, [
        node("strong", {}, profile.name),
        node("div", { class: "mono muted" }, profile.id),
      ]),
      node("td", {}, (profile.platforms || []).join(", ")),
      node("td", {}, (profile.telemetry_sources || []).join(", ")),
      node("td", { class: "muted" }, (profile.recommended_scenarios || []).join(", ")),
      node("td", { class: "muted" }, (profile.success_checks || []).join(" | ")),
    ]));
  }
  if (!state.labProfiles.length) tbody.appendChild(emptyRow(5, "No lab profiles"));
  byId("lab-count").textContent = `${state.labProfiles.length} profiles`;
}

function renderAccess() {
  const access = state.access || {};
  const status = byId("access-status");
  const summary = byId("access-summary");
  const tbody = byId("access-table");
  if (!status || !summary || !tbody) return;
  status.textContent = access.enabled ? "enabled" : "disabled";
  status.className = access.enabled ? "pill ok" : "pill warn";
  clear(summary);
  clear(tbody);
  const rows = [
    ["Roles", (access.roles || []).join(", ") || "-"],
    ["Token CLI", access.token_cli || "-"],
  ];
  for (const [label, value] of rows) {
    summary.appendChild(node("div", { class: "summary-row" }, [
      node("span", {}, label),
      node("strong", {}, value),
    ]));
  }
  for (const [role, capabilities] of Object.entries(access.matrix || {})) {
    tbody.appendChild(node("tr", {}, [
      node("td", { class: "mono" }, role),
      node("td", {}, (capabilities || []).join(", ")),
    ]));
  }
  if (!Object.keys(access.matrix || {}).length) tbody.appendChild(emptyRow(2, "No RBAC data"));
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

function maturityPill(value) {
  const label = optionValue(value);
  const kind = label === "fixture-backed" || label === "operational" ? "ok"
    : label === "coverage" || label === "variant" ? "warn" : "bad";
  return node("span", { class: `pill ${kind}` }, label);
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
  const stride = byId("batch-stride").value;
  setStatus("Batch loading", "neutral");
  const params = new URLSearchParams({ count, offset, stride });
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

async function runNamedScenario(name) {
  try {
    const run = await postJson("/scenarios/run", { name });
    pushFeed({ event: "run.start", ts: Date.now() / 1000, payload: { run_id: run.id, scenario: run.scenario } });
    await refreshLive();
  } catch (error) {
    pushFeed({ event: "run.error", ts: Date.now() / 1000, payload: { error: error.message } });
  }
}

async function runSelectedScenario() {
  const name = byId("scenario-select").value;
  if (!name) return;
  await runNamedScenario(name);
}

async function startCampaign(count) {
  const names = filteredLibraryItems().slice(0, count).map((item) => item.name);
  const status = byId("campaign-status");
  if (!names.length) {
    status.textContent = "No match";
    status.className = "pill bad";
    return;
  }
  status.textContent = "Starting";
  status.className = "pill neutral";
  try {
    const body = { count, scenario_names: names };
    const startAt = byId("campaign-start-at").value;
    const repeatInterval = Number(byId("campaign-repeat-interval").value || 0);
    const repeatCount = Number(byId("campaign-repeat-count").value || 1);
    if (startAt) {
      const startDate = new Date(startAt);
      if (!Number.isNaN(startDate.getTime())) body.scheduled_at = startDate.getTime() / 1000;
    }
    if (repeatInterval > 0) body.repeat_interval_seconds = repeatInterval;
    if (repeatCount > 1) body.repeat_count = repeatCount;
    const campaign = await postJson("/campaigns/run", body);
    status.textContent = campaign.status === "scheduled" ? `Scheduled ${campaign.total_runs}` : `Started ${campaign.total_runs}`;
    status.className = "pill ok";
    await refreshLive();
    switchView("campaigns");
  } catch (error) {
    status.textContent = "Failed";
    status.className = "pill bad";
    pushFeed({ event: "campaign.error", ts: Date.now() / 1000, payload: { error: error.message } });
  }
}

async function campaignAction(id, action) {
  try {
    await api(`/campaigns/${id}/${action}`, { method: "POST" });
    await refreshLive();
  } catch (error) {
    pushFeed({ event: "campaign.error", ts: Date.now() / 1000, payload: { id, action, error: error.message } });
  }
}

function renderCampaigns() {
  const tbody = byId("campaign-table");
  if (!tbody) return;
  clear(tbody);
  for (const campaign of [...state.campaigns].sort((a, b) => b.created_at - a.created_at)) {
    tbody.appendChild(node("tr", {}, [
      node("td", { class: "mono" }, campaign.id),
      node("td", {}, statusPill(campaign.status)),
      node("td", {}, `${campaign.progress_percent}%`),
      node("td", {}, `${campaign.total_runs} (${Object.entries(campaign.run_statuses || {}).map(([k, v]) => `${k}:${v}`).join(", ")})`),
      node("td", {}, [
        node("div", {}, campaign.scheduled_at ? fmtTs(campaign.scheduled_at) : "immediate"),
        node("small", { class: "muted" }, campaign.repeat_interval_seconds ? `${campaign.repeat_remaining} repeats / ${campaign.repeat_interval_seconds}s` : "no repeat"),
      ]),
      node("td", {}, node("div", { class: "button-row compact" }, [
        node("button", { class: "secondary", onclick: () => campaignAction(campaign.id, "pause") }, "Pause"),
        node("button", { class: "secondary", onclick: () => campaignAction(campaign.id, "resume") }, "Resume"),
        node("button", { class: "secondary", onclick: () => campaignAction(campaign.id, "retry-failed") }, "Retry Failed"),
      ])),
      node("td", {}, reportLinks(`/reports/campaigns/${campaign.id}`)),
    ]));
  }
  if (!state.campaigns.length) tbody.appendChild(emptyRow(7, "No campaigns"));
  byId("campaign-count").textContent = `${state.campaigns.length} campaigns`;
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
  for (const id of ["library-search", "library-actor", "library-difficulty", "library-platform", "library-source"]) {
    byId(id).addEventListener("input", renderScenarioLibrary);
    byId(id).addEventListener("change", renderScenarioLibrary);
  }
  for (const button of document.querySelectorAll(".campaign-size")) {
    button.addEventListener("click", () => startCampaign(Number(button.dataset.count || 10)));
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
