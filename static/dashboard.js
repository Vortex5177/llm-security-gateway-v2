"use strict";

/* LLM Gateway 仪表盘：拉取 /api/stats 并用本地 Chart.js 渲染（零构建、零 CDN）。 */

const state = { days: 7, tag: "" };
const charts = {};
const C = {
  blue: "#4da3ff", green: "#3fbf7f", orange: "#e0a13e",
  purple: "#b07ce8", red: "#e05c5c", gray: "#7d8b99",
};

const fmtInt = (n) => Number(n == null ? 0 : n).toLocaleString("zh-CN");
const fmtMs = (v) => (v == null ? "—" : Number(v).toFixed(1) + " ms");
const fmtTps = (v) => (v == null ? "—" : Number(v).toFixed(1) + " t/s");
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString("zh-CN", { hour12: false }) : "—");
const esc = (s) =>
  String(s == null ? "" : s).replace(/[&<>"']/g, (ch) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));

function fmtShort(iso) {
  const d = new Date(iso);
  const p = (x) => String(x).padStart(2, "0");
  if (state.days <= 1) return p(d.getHours()) + ":" + p(d.getMinutes());
  return p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
}

function axisCfg(right, title) {
  return {
    position: right ? "right" : "left",
    beginAtZero: true,
    grid: { color: "rgba(125,139,153,.12)", drawOnChartArea: !right },
    ticks: { color: "#7d8b99", font: { size: 11 }, maxTicksLimit: 7 },
    title: { display: !!title, text: title || "", color: "#7d8b99", font: { size: 11 } },
  };
}

function chartOptions(yTitle, y1Title) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    interaction: { mode: "index", intersect: false },
    plugins: {
      legend: { labels: { color: "#d8dee6", boxWidth: 12, font: { size: 11 } } },
      tooltip: { backgroundColor: "#1c242d", borderColor: "#242c35", borderWidth: 1 },
    },
    scales: {
      x: { grid: { color: "rgba(125,139,153,.08)" }, ticks: { color: "#7d8b99", font: { size: 11 }, maxTicksLimit: 9 } },
      y: axisCfg(false, yTitle),
      y1: axisCfg(true, y1Title),
    },
  };
}

function line(label, data, color, axis, fill) {
  return {
    type: "line", label: label, data: data, yAxisID: axis || "y",
    borderColor: color, backgroundColor: fill ? color + "22" : color,
    borderWidth: 1.6, tension: 0.25, spanGaps: true, fill: !!fill,
    pointRadius: 2, pointHoverRadius: 4, pointBackgroundColor: color,
  };
}

function upsertChart(id, config) {
  const existing = charts[id];
  if (existing) {
    existing.data.labels = config.data.labels;
    existing.data.datasets = config.data.datasets;
    existing.options = config.options;
    existing.update("none");
    return;
  }
  charts[id] = new Chart(document.getElementById("chart-" + id), config);
}

function renderCards(t) {
  const cards = [
    { label: "请求数", value: fmtInt(t.requests) },
    { label: "Tokens", value: fmtInt(t.tokens) },
    { label: "错误数", value: fmtInt(t.errors) },
    { label: "平均延迟", value: fmtMs(t.avg_latency_ms) },
    { label: "p95 延迟", value: fmtMs(t.p95_latency_ms) },
    { label: "平均 TTFT", value: fmtMs(t.avg_ttft_ms) },
    { label: "平均生成速度", value: fmtTps(t.avg_output_tps) },
  ];
  document.getElementById("cards").innerHTML = cards
    .map((c) => '<div class="card"><div class="label">' + c.label + '</div><div class="value">' + c.value + "</div></div>")
    .join("");
}

function renderTagOptions(byTag) {
  const select = document.getElementById("tag");
  const names = byTag.map((e) => e.tag).filter((t) => t);
  const options = ['<option value="">全部 tag</option>'].concat(
    names.map((t) => '<option value="' + esc(t) + '">' + esc(t) + "</option>")
  );
  if (state.tag && names.indexOf(state.tag) === -1) {
    options.push('<option value="' + esc(state.tag) + '">' + esc(state.tag) + "</option>");
  }
  select.innerHTML = options.join("");
  select.value = state.tag || "";
}

function renderCharts(data) {
  const trafficLabels = data.timeseries.map((p) => fmtShort(p.ts));
  upsertChart("traffic", {
    type: "bar",
    data: {
      labels: trafficLabels,
      datasets: [
        { type: "bar", label: "请求数", data: data.timeseries.map((p) => p.requests), yAxisID: "y", backgroundColor: "rgba(77,163,255,.55)", borderRadius: 3, maxBarThickness: 46 },
        line("Tokens", data.timeseries.map((p) => p.tokens), C.green, "y1", false),
      ],
    },
    options: chartOptions("请求数", "Tokens"),
  });

  upsertChart("latency", {
    type: "line",
    data: {
      labels: trafficLabels,
      datasets: [
        line("平均延迟 ms", data.timeseries.map((p) => p.avg_latency_ms), C.blue, "y", false),
        line("TTFT ms", data.timeseries.map((p) => p.avg_ttft_ms), C.orange, "y", false),
      ],
    },
    options: chartOptions("毫秒", null),
  });

  const tpsTs = Array.from(
    new Set(data.timeseries.map((p) => p.ts).concat(data.engine.map((p) => p.ts)))
  ).sort();
  const reqTps = new Map(data.timeseries.map((p) => [p.ts, p.avg_tps]));
  const engTps = new Map(data.engine.map((p) => [p.ts, p.gen_tps]));
  upsertChart("tps", {
    type: "line",
    data: {
      labels: tpsTs.map(fmtShort),
      datasets: [
        line("请求平均 t/s", tpsTs.map((ts) => (reqTps.has(ts) ? reqTps.get(ts) : null)), C.green, "y", false),
        line("引擎吞吐 t/s", tpsTs.map((ts) => (engTps.has(ts) ? engTps.get(ts) : null)), C.purple, "y", false),
      ],
    },
    options: chartOptions("tokens/s", null),
  });

  upsertChart("gpu", {
    type: "line",
    data: {
      labels: data.gpu.map((p) => fmtShort(p.ts)),
      datasets: [
        line("GPU 利用率 %", data.gpu.map((p) => p.avg_util), C.orange, "y", true),
        line("显存 used (MB)", data.gpu.map((p) => p.avg_mem_used_mb), C.purple, "y1", false),
      ],
    },
    options: chartOptions("利用率 %", "显存 MB"),
  });

  upsertChart("engine", {
    type: "line",
    data: {
      labels: data.engine.map((p) => fmtShort(p.ts)),
      datasets: [
        line("运行中", data.engine.map((p) => p.max_running), C.green, "y", false),
        line("排队中", data.engine.map((p) => p.max_waiting), C.orange, "y", false),
        line("KV cache %", data.engine.map((p) => (p.avg_kv_cache_perc == null ? null : p.avg_kv_cache_perc * 100)), C.blue, "y1", false),
      ],
    },
    options: chartOptions("请求数", "KV cache %"),
  });
}

function renderRecent(rows) {
  const body = document.getElementById("recent-body");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="9" class="muted">窗口内暂无请求</td></tr>';
    return;
  }
  const known = ["ok", "upstream_error", "client_abort", "timeout"];
  body.innerHTML = rows
    .map((r) => {
      const cls = known.indexOf(r.status) !== -1 ? r.status : "timeout";
      const tagCell = r.tag ? esc(r.tag) : '<span class="muted">—</span>';
      const modelCell = esc(r.resolved_model) + (r.fallback_used ? ' <span class="muted">fallback</span>' : "");
      const tokenCell = fmtInt(r.total_tokens) + ' <span class="muted">(' + fmtInt(r.prompt_tokens) + "+" + fmtInt(r.completion_tokens) + ")</span>";
      return (
        "<tr><td>" + fmtTime(r.ts) + "</td><td>" + tagCell + "</td><td>" + modelCell +
        "</td><td>" + tokenCell + "</td><td>" + fmtMs(r.latency_ms) + "</td><td>" + fmtMs(r.ttft_ms) +
        "</td><td>" + fmtTps(r.output_tps) +
        '</td><td><span class="status ' + cls + '">' + esc(r.status) + "</span></td><td>" + r.attempts + "</td></tr>"
      );
    })
    .join("");
}

/* ---- 模型目录 / Provider 接入（/api/models，含连通性探测） ---- */

function kindBadge(kind) {
  return kind === "local"
    ? '<span class="badge local">本地</span>'
    : '<span class="badge cloud">API</span>';
}

function fallbackCell(entries) {
  if (!entries || !entries.length) return '<span class="muted">—</span>';
  return entries
    .map((e) => (e.tag ? '<span class="muted">@' + esc(e.tag) + "</span> " : "") +
      "→ " + e.chain.map(esc).join(" → "))
    .join("<br>");
}

function keyCellHtml(p) {
  const key = p.key || {};
  if (key.source === "literal") return '<span class="muted">字面量</span>';
  const desc = key.source === "env"
    ? esc(key.name) + " " + (key.configured
        ? '<span class="status ok">已配置</span>'
        : '<span class="status upstream_error">未配置</span>')
    : '<span class="status upstream_error">未配置</span>';
  const btn = key.source === "env"
    ? '<button class="mini" data-act="edit" data-name="' + esc(p.name) + '">' +
      (key.configured ? "更新" : "配置") + "</button>"
    : "";
  return desc + btn;
}

function renderCatalog(data) {
  const def = data.aliases && data.aliases["default"];
  document.getElementById("catalog-hint").textContent =
    def ? "· 默认 default → " + def : "";

  const models = document.getElementById("models-body");
  const modelRows = (data.models || []).map((m) => {
    const aliases = (m.aliases || []).length
      ? m.aliases.map((a) => '<span class="badge">' + esc(a) + "</span>").join(" ")
      : '<span class="muted">—</span>';
    return "<tr><td>" + esc(m.id) + "</td><td>" + kindBadge(m.kind) + "</td><td>" +
      esc(m.provider) + '</td><td class="muted">' + esc(m.upstream) + "</td><td>" +
      aliases + "</td><td>" + fallbackCell(m.fallbacks) + "</td></tr>";
  });
  models.innerHTML = modelRows.join("") ||
    '<tr><td colspan="6" class="muted">无模型</td></tr>';

  const providers = document.getElementById("providers-body");
  const providerRows = (data.providers || []).map((p) => {
    const conn = p.reachable
      ? '<span class="status ok">可达</span> <span class="muted">' + fmtMs(p.latency_ms) + "</span>"
      : '<span class="status upstream_error">不可达</span> <span class="muted cellwrap">' + esc(p.detail) + "</span>";
    const served = p.kind === "local"
      ? '<span data-local-carrier>' + localCarrierHtml() + "</span>"
      : ((p.models || []).length ? p.models.map(esc).join("、") : '<span class="muted">—</span>');
    return '<tr data-provider="' + esc(p.name) + '"><td>' + esc(p.name) + "</td><td>" + kindBadge(p.kind) +
      '</td><td class="muted cellwrap">' + esc(p.base_url) + '</td><td class="cellwrap keycell">' + keyCellHtml(p) +
      "</td><td>" + conn + "</td><td>" + served + "</td></tr>";
  });
  providers.innerHTML = providerRows.join("") ||
    '<tr><td colspan="6" class="muted">无 provider</td></tr>';
}

async function loadCatalog() {
  const resp = await fetch("/api/models");
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  renderCatalog(await resp.json());
}

function showError(err) {
  document.getElementById("updated").textContent = "加载失败：" + err.message;
}

async function load() {
  const params = new URLSearchParams({ days: String(state.days) });
  if (state.tag) params.set("tag", state.tag);
  const resp = await fetch("/api/stats?" + params.toString());
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  const data = await resp.json();
  renderCards(data.totals);
  renderTagOptions(data.by_tag);
  renderCharts(data);
  renderRecent(data.recent);
  const bucket = data.bucket_seconds >= 3600 ? "1 小时" : "5 分钟";
  document.getElementById("updated").textContent =
    "更新于 " + new Date().toLocaleTimeString("zh-CN", { hour12: false }) + " · 桶粒度 " + bucket;
}

/* ---- 本地服务控制：独立轮询，所有详情作为纯文本展示 ---- */

let serviceView = null;
let serviceReading = false;
let servicePosting = false;
let serviceEpoch = 0;
let serviceOptionsKey = "";
let serviceSelected = null;
const serviceLabels = {
  stopped: "已停止", starting: "启动中", running: "运行中", stopping: "停止中",
  failed: "失败", unavailable: "控制不可用", conflict: "实例冲突",
};

function localCarrierHtml() {
  // 本地 provider 为单实例：承载模型列展示运行时“当前模型”（候选列表见“可切换模型”表）
  if (!serviceView) return '<span class="muted">读取中…</span>';
  if (serviceView.state === "running" && serviceView.current) return esc(serviceView.current);
  return '<span class="muted">—</span>';
}

function renderServiceModels(view) {
  const select = document.getElementById("service-select");
  const models = Array.isArray(view.models) ? view.models : [];
  const key = models.join("\u0000");
  if (key !== serviceOptionsKey) {
    // 仅在候选集合变化时重建选项，保留用户当前选择。
    serviceOptionsKey = key;
    select.textContent = "";
    for (const name of models) {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      select.appendChild(option);
    }
  }
  if (!models.includes(serviceSelected)) {
    serviceSelected = models.includes(view.current) ? view.current
      : (models.includes(view.model) ? view.model : (models[0] || null));
  }
  if (serviceSelected !== null) select.value = serviceSelected;
  const transitional = view.state === "starting" || view.state === "stopping";
  select.disabled = servicePosting || transitional || models.length === 0;
}

function renderServiceButtons(view) {
  const start = document.getElementById("service-start");
  const stop = document.getElementById("service-stop");
  const selected = document.getElementById("service-select").value || null;
  const transitional = view.state === "starting" || view.state === "stopping";
  if (view.state === "running" && (selected === null || selected === view.current)) {
    start.textContent = "已运行";
    start.disabled = true;
  } else if (view.state === "running") {
    start.textContent = "切换";
    start.disabled = servicePosting || view.can_stop !== true;
  } else {
    start.textContent = transitional ? "启动中…" : "启动";
    start.disabled = servicePosting || transitional || view.can_start !== true;
  }
  stop.textContent = transitional ? "停止中…" : "停止";
  stop.disabled = servicePosting || view.can_stop !== true;
}

function renderLocalService(view) {
  serviceView = view;
  const label = serviceLabels[view.state] || serviceLabels.unavailable;
  renderServiceModels(view);
  document.getElementById("service-url").textContent = view.url || "";
  const status = document.getElementById("service-state");
  status.textContent = label;
  status.dataset.state = serviceLabels[view.state] ? view.state : "unavailable";
  document.getElementById("service-detail").textContent = view.detail || "";
  renderServiceButtons(view);
  for (const cell of document.querySelectorAll("[data-local-carrier]")) {
    cell.innerHTML = localCarrierHtml();
  }
}

function serviceFailure(message) {
  renderLocalService({ model: serviceView && serviceView.model, models: serviceView && serviceView.models,
    current: serviceView && serviceView.current, url: serviceView && serviceView.url,
    state: "unavailable", can_start: false, can_stop: false, detail: message });
}

async function loadLocalService() {
  if (serviceReading || servicePosting) return;
  serviceReading = true;
  const epoch = serviceEpoch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    const resp = await fetch("/api/local-vllm", { cache: "no-store", signal: controller.signal });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const view = await resp.json();
    if (epoch === serviceEpoch) renderLocalService(view);
  } catch (err) {
    if (epoch === serviceEpoch) serviceFailure("无法核验服务状态：" + err.message);
  } finally {
    clearTimeout(timeout);
    serviceReading = false;
  }
}

async function controlLocalService(action, model) {
  if (servicePosting || !serviceView) return;
  if (action === "stop") {
    if (serviceView.can_stop !== true) return;
    if (!window.confirm(
      "停止本地 Qwen 服务？\n\n正在生成的回答可能中断，已输出的内容不能无缝转到云端。\n后续请求仍按现有回退链处理，可能发送到 DeepSeek 并产生云端费用。"
    )) return;
  } else if (action === "switch") {
    if (!model || serviceView.can_stop !== true) return;
    if (!window.confirm(
      "切换到 " + model + "？\n\n将先停止当前运行中的 " + (serviceView.current || "模型") +
      "，在途回答会中断；切换通常需要约 1 分钟。\n期间请求仍按现有回退链处理，可能发送到 DeepSeek 并产生云端费用。"
    )) return;
  } else {
    if (!model || serviceView.can_start !== true) return;
  }
  servicePosting = true;
  serviceEpoch += 1;  // 丢弃动作之前已发出的旧状态请求。
  renderLocalService(serviceView);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25000);
  try {
    const resp = await fetch("/api/local-vllm/" + action, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: action === "stop" ? "{}" : JSON.stringify({ model: model }),
      signal: controller.signal,
    });
    const view = await resp.json();
    if (view.state) renderLocalService(view);
    else throw new Error(view.detail || "HTTP " + resp.status);
  } catch (err) {
    serviceFailure("控制请求未确认，请等待状态刷新；不会自动重复操作。" + err.message);
  } finally {
    clearTimeout(timeout);
    servicePosting = false;
    if (serviceView) renderLocalService(serviceView);
  }
}

async function pollLocalService() {
  await loadLocalService();
  setTimeout(pollLocalService, 3000);
}

document.getElementById("service-select").addEventListener("change", (event) => {
  serviceSelected = event.target.value || null;
  if (serviceView) renderServiceButtons(serviceView);
});
document.getElementById("service-start").addEventListener("click", () => {
  const view = serviceView;
  if (!view) return;
  const selected = document.getElementById("service-select").value || null;
  if (view.state === "running" && selected && selected !== view.current) {
    controlLocalService("switch", selected);
  } else {
    controlLocalService("start", selected);
  }
});
document.getElementById("service-stop").addEventListener("click", () => controlLocalService("stop", null));

/* ---- provider 密钥行内编辑（POST /api/providers/{name}/key，仅本机） ---- */

function keyCellOf(name) {
  const row = document.querySelector('tr[data-provider="' + CSS.escape(name) + '"]');
  return row ? row.querySelector(".keycell") : null;
}

function startKeyEdit(name) {
  const td = keyCellOf(name);
  if (!td || td.dataset.original) return;
  td.dataset.original = td.innerHTML;
  td.innerHTML =
    '<div class="keyedit">' +
    '<input type="password" autocomplete="off" placeholder="粘贴 API Key">' +
    '<div class="keyedit-actions">' +
    '<button class="mini" data-act="save" data-name="' + esc(name) + '">保存</button>' +
    '<button class="mini" data-act="cancel" data-name="' + esc(name) + '">取消</button>' +
    '</div><div class="err"></div></div>';
  const input = td.querySelector("input");
  if (input) input.focus();
}

function cancelKeyEdit(name) {
  const td = keyCellOf(name);
  if (!td || !td.dataset.original) return;
  td.innerHTML = td.dataset.original;
  delete td.dataset.original;
}

async function saveProviderKey(name) {
  const td = keyCellOf(name);
  if (!td) return;
  const input = td.querySelector("input");
  const errBox = td.querySelector(".err");
  const value = input ? input.value : "";
  if (!value.trim()) {
    if (errBox) errBox.textContent = "请输入 API Key";
    return;
  }
  const saveBtn = td.querySelector('button[data-act="save"]');
  if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = "保存中…"; }
  let resp;
  try {
    resp = await fetch("/api/providers/" + encodeURIComponent(name) + "/key", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_key: value }),
    });
  } catch (err) {
    if (errBox) errBox.textContent = "网络错误：" + err.message;
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = "保存"; }
    return;
  }
  if (!resp.ok) {
    let detail = "HTTP " + resp.status;
    try { detail = (await resp.json()).detail || detail; } catch (e) { /* 响应非 JSON */ }
    if (errBox) errBox.textContent = detail;
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = "保存"; }
    return;
  }
  delete td.dataset.original;
  loadCatalog().catch(showError);
}

/* ---- 添加 Provider（POST /api/providers，仅本机；前缀路由 provider/模型名 直通） ---- */

const PROVIDER_PRESET_OPTIONS = [
  ["moonshot", "Moonshot (Kimi)"],
  ["zhipu", "智谱 GLM"],
  ["siliconflow", "SiliconFlow"],
  ["custom", "自定义"],
];

function addFormOf() {
  return document.querySelector("#providers-body .addrow .addform");
}

function startAddProvider() {
  if (document.querySelector("#providers-body .addrow")) return;
  const options = PROVIDER_PRESET_OPTIONS
    .map((o) => '<option value="' + o[0] + '">' + o[1] + "</option>")
    .join("");
  document.getElementById("providers-body").insertAdjacentHTML(
    "beforeend",
    '<tr class="addrow"><td colspan="6"><div class="addform">' +
    '<select data-act="add-preset">' + options + "</select>" +
    '<input class="nameinput" placeholder="名称（如 my-gw）" style="display:none">' +
    '<input class="baseinput" placeholder="Base URL（https://…/v1）" style="display:none">' +
    '<input class="keyinput" type="password" autocomplete="off" placeholder="粘贴 API Key">' +
    '<button class="mini" data-act="add-save">保存</button>' +
    '<button class="mini" data-act="add-cancel">取消</button>' +
    '<div class="err"></div></div></td></tr>'
  );
  const key = document.querySelector("#providers-body .addform .keyinput");
  if (key) key.focus();
}

function cancelAddProvider() {
  const row = document.querySelector("#providers-body .addrow");
  if (row) row.remove();
}

async function saveAddProvider() {
  const form = addFormOf();
  if (!form) return;
  const errBox = form.querySelector(".err");
  const value = form.querySelector(".keyinput").value;
  const preset = form.querySelector("select").value;
  const body = { preset: preset, api_key: value };
  if (preset === "custom") {
    body.name = form.querySelector(".nameinput").value.trim();
    body.base_url = form.querySelector(".baseinput").value.trim();
    if (!body.name) { errBox.textContent = "请填写名称"; return; }
    if (!body.base_url) { errBox.textContent = "请填写 Base URL"; return; }
  }
  if (!value.trim()) { errBox.textContent = "请输入 API Key"; return; }
  const btn = form.querySelector('button[data-act="add-save"]');
  btn.disabled = true;
  btn.textContent = "保存中…";
  let resp;
  try {
    resp = await fetch("/api/providers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (err) {
    errBox.textContent = "网络错误：" + err.message;
    btn.disabled = false;
    btn.textContent = "保存";
    return;
  }
  if (!resp.ok) {
    let detail = "HTTP " + resp.status;
    try { detail = (await resp.json()).detail || detail; } catch (e) { /* 响应非 JSON */ }
    errBox.textContent = detail;
    btn.disabled = false;
    btn.textContent = "保存";
    return;
  }
  loadCatalog().catch(showError);  // 表格重建后添加行随之移除
}

document.getElementById("add-provider").addEventListener("click", startAddProvider);

document.getElementById("providers-body").addEventListener("change", (event) => {
  const sel = event.target.closest('select[data-act="add-preset"]');
  if (!sel) return;
  const custom = sel.value === "custom";
  const form = sel.closest(".addform");
  form.querySelector(".nameinput").style.display = custom ? "" : "none";
  form.querySelector(".baseinput").style.display = custom ? "" : "none";
});

document.getElementById("providers-body").addEventListener("click", (event) => {
  const btn = event.target.closest("button[data-act]");
  if (!btn) return;
  const name = btn.dataset.name;
  if (btn.dataset.act === "edit") startKeyEdit(name);
  else if (btn.dataset.act === "save") saveProviderKey(name);
  else if (btn.dataset.act === "cancel") cancelKeyEdit(name);
  else if (btn.dataset.act === "add-save") saveAddProvider();
  else if (btn.dataset.act === "add-cancel") cancelAddProvider();
});

// 支持 ?days=N&tag=xx 初始化（便于书签/分享/自动化截图）
const urlParams = new URLSearchParams(location.search);
if (urlParams.get("days")) {
  const d = Number(urlParams.get("days"));
  if (Number.isFinite(d) && d >= 1 && d <= 90) state.days = Math.floor(d);
}
if (urlParams.get("tag")) state.tag = urlParams.get("tag");
document.getElementById("days").value = String(state.days);
document.getElementById("tag").value = state.tag;

document.getElementById("days").addEventListener("change", (event) => {
  state.days = Number(event.target.value);
  load().catch(showError);
});
document.getElementById("tag").addEventListener("change", (event) => {
  state.tag = event.target.value;
  load().catch(showError);
});
document.getElementById("refresh").addEventListener("click", () => {
  load().catch(showError);
  loadCatalog().catch(showError);
  loadLocalService();
});

pollLocalService();
load().catch(showError);
// 目录含 provider 连通性探测：仅页面加载/手动刷新时拉取，不随 30s 轮询
loadCatalog().catch(showError);
setInterval(() => load().catch(() => {}), 30000);