const $ = (id) => document.getElementById(id);
const form = $("f"), input = $("apex"), btn = $("btn"),
      meta = $("meta"), results = $("results"), toolbar = $("toolbar"),
      stagesBar = $("stages"),
      filterInput = $("filter"), toast = $("toast");

const STAGE_LABELS = { dns: "DNS 验证", http: "HTTP 探测", ports: "端口扫描", security: "安全检查" };
const STAGE_ORDER = ["dns", "http", "ports", "security"];
const RUNNING_STATES = new Set(["queued", "running"]);
const STALL_MS = 30000;   // silence from the server before we say so, non-fatally

let current = {
  apex: "", jobId: "", state: "", subdomains: [], stages: [], progress: {},
  dns: {}, http: {}, ports: {}, sec: {}, cached: false, truncated: {},
  pending: new Set(),
};
// Every poll chain takes the next generation number; a chain whose number is
// no longer the newest stops dead. Without it a slow response from a superseded
// scan would repaint the table over the current one.
let pollToken = 0;
let pollTimer = null;

function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 1600);
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function statusClass(code) {
  return `st-${String(code)[0]}`;
}

const isRunning = () => RUNNING_STATES.has(current.state);

// --------------------------------------------------------------------------- //
// stage pills
// --------------------------------------------------------------------------- //
function renderStages() {
  const stages = current.stages || [];
  if (!stages.length) { stagesBar.innerHTML = ""; return; }
  stagesBar.innerHTML = stages.map(name => {
    const p = current.progress[name] || {};
    const state = p.state || "pending";
    const bits = [];
    if (state === "running" && p.total) bits.push(`<time>${p.checked || 0}/${p.total}</time>`);
    else if (p.from_cache) bits.push(`<time>缓存</time>`);
    else if (p.elapsed_ms != null) bits.push(`<time>${(p.elapsed_ms / 1000).toFixed(1)}s</time>`);
    const title = p.error ? esc(p.error) : (p.reason ? esc(p.reason) : "");
    return `<span class="pill ${state}"${title ? ` title="${title}"` : ""}>${esc(STAGE_LABELS[name] || name)}${bits.join("")}</span>`;
  }).join("");
}

// --------------------------------------------------------------------------- //
// table
// --------------------------------------------------------------------------- //
function renderList(items) {
  if (!items.length) {
    results.innerHTML = current.subdomains.length
      ? '<div class="empty">没有匹配的子域名</div>'
      : `<div class="empty">${isRunning() ? "正在聚合 CT 日志…" : "没有匹配的子域名"}</div>`;
    return;
  }
  // Column presence follows the stages the job asked for, not the live
  // checkboxes: toggling a box mid-scan must not reflow a table that is
  // already half filled from a different stage set.
  const showDns = current.stages.includes("dns"),
        showHttp = current.stages.includes("http"),
        showPorts = current.stages.includes("ports"),
        showSec = current.stages.includes("security");
  let html = `<table><thead><tr>
    <th style="width:28%">子域名</th>
    ${showDns ? "<th>状态</th><th style=\"width:18%\">IP (A 记录)</th>" : ""}
    ${showHttp ? "<th style=\"width:6%\">HTTP</th><th style=\"width:16%\">标题</th>" : ""}
    ${showPorts ? "<th>开放端口</th>" : ""}
    ${showSec ? "<th style=\"width:20%\">安全检查</th>" : ""}
  </tr></thead><tbody>`;
  for (const name of items) {
    const ips = current.dns[name];
    const info = current.http[name];
    const ports = current.ports[name];
    const sec = current.sec[name];
    html += `<tr data-name="${esc(name)}" title="点击复制 ${esc(name)}">`;
    html += `<td class="sub">${esc(name)}</td>`;
    if (showDns) {
      html += ips
        ? `<td><span class="badge alive">存活</span></td><td class="ips">${ips.map(esc).join(", ")}</td>`
        : (current.pending.has("dns")
            ? `<td colspan="2" class="ips">扫描中…</td>`
            : `<td><span class="badge dead">无解析</span></td><td class="ips">—</td>`);
    }
    if (showHttp) {
      html += info
        ? `<td class="status"><span class="${statusClass(info.status)}">${info.status}</span></td><td class="title">${info.title ? esc(info.title) : "—"}</td>`
        : (current.pending.has("http")
            ? `<td colspan="2" class="ips">扫描中…</td>`
            : `<td class="status">—</td><td class="title">—</td>`);
    }
    if (showPorts) {
      html += ports
        ? `<td class="ips">${Object.entries(ports).map(([p, v]) => `<span class="port" title="${esc(v.service)}">${esc(p)}</span>`).join(" ")}</td>`
        : `<td class="ips">${current.pending.has("ports") ? "扫描中…" : "—"}</td>`;
    }
    if (showSec) {
      if (!sec) { html += `<td class="ips">${current.pending.has("security") ? "扫描中…" : "—"}</td>`; }
      else {
        let cells = [];
        if (sec.paths?.length) cells.push(sec.paths.map(p => `<span class="path" title="HTTP ${p.status}">${esc(p.path)}</span>`).join(" "));
        if (sec.headers?.missing?.length) cells.push(`<span class="sec-miss" title="缺失安全头">缺: ${sec.headers.missing.map(esc).join(", ")}</span>`);
        if (sec.tls) {
          const t = sec.tls;
          const cls = t.expiring_soon ? "tls-warn" : "tls-ok";
          cells.push(`<span class="${cls}" title="SAN: ${esc((t.sans||[]).join(", "))}">TLS ${t.days_left}天${t.expiring_soon ? " ⚠️" : ""} · ${esc((t.issuer||"").slice(0,40))}</span>`);
        }
        html += `<td>${cells.length ? cells.join("<br>") : '<span class="sec-ok">基线通过</span>'}</td>`;
      }
    }
    html += `</tr>`;
  }
  html += "</tbody></table>";
  results.innerHTML = html;
  results.querySelectorAll("tr[data-name]").forEach(tr => {
    tr.onclick = () => {
      navigator.clipboard?.writeText(tr.dataset.name);
      showToast("已复制: " + tr.dataset.name);
    };
  });
}

function applyFilter() {
  const q = filterInput.value.trim().toLowerCase();
  renderList(q ? current.subdomains.filter(s => s.includes(q)) : current.subdomains);
}

function renderMeta() {
  const parts = [`共 ${current.subdomains.length} 个子域名`];
  const r = current.results || {};
  if (r.dns) parts.push(`<span class="alive">存活 ${r.dns.alive_count}</span>`);
  if (r.http) parts.push(`Web 服务 ${r.http.web_count}`);
  if (r.ports) parts.push(`开放端口主机 ${r.ports.hosts_with_open}`);
  if (r.security) parts.push(`安全告警 ${r.security.flagged_count}`);
  if (current.cached) parts.push("子域名缓存命中 ✓");
  if (current.force) parts.push("已忽略缓存");
  for (const name of STAGE_ORDER) {
    const p = current.progress[name];
    if (p && p.summary?.elapsed_seconds != null && p.state !== "skipped")
      parts.push(`${STAGE_LABELS[name]} ${p.summary.elapsed_seconds}s`);
  }
  if (current.elapsed_seconds != null) parts.push(`耗时 ${current.elapsed_seconds}s`);
  if (current.error) parts.push(`<span class="err">${esc(current.error)}</span>`);
  for (const [stage, dropped] of Object.entries(current.truncated || {}))
    parts.push(`<span class="err">${STAGE_LABELS[stage] || stage} 已按上限截断 ${dropped} 台</span>`);
  if (isRunning() && Date.now() - lastProgressAt > STALL_MS)
    parts.push(`<span class="err">已 ${Math.round((Date.now() - lastProgressAt) / 1000)}s 无新进展，仍在等待…</span>`);
  meta.innerHTML = parts.join("  ·  ");
}

// --------------------------------------------------------------------------- //
// export
// --------------------------------------------------------------------------- //
function download(content, filename, mime, prefix) {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast((prefix || "") + "已导出 " + filename);
}

function exportAs(fmt) {
  const { apex, subdomains } = current;
  if (!subdomains.length) return;
  const partial = isRunning() ? "部分结果 · " : "";
  const stages = current.stages;
  const hasDns = stages.includes("dns"), hasHttp = stages.includes("http"),
        hasPorts = stages.includes("ports"), hasSec = stages.includes("security");
  // A stage counts as exportable only once it has produced something: a
  // requested-but-unfinished column exports as an empty cell, not as "no".
  const dnsReady = hasDns && !!current.results?.dns;
  const httpReady = hasHttp && !!current.results?.http;
  const portsReady = hasPorts && !!current.results?.ports;
  const secReady = hasSec && !!current.results?.security;
  const stamp = new Date().toISOString().slice(0, 10);
  const base = `panoptes_${apex}_${stamp}`;
  if (fmt === "txt") {
    download(subdomains.join("\n") + "\n", base + ".txt", "text/plain;charset=utf-8", partial);
  } else if (fmt === "csv") {
    const head = ["subdomain"];
    if (dnsReady) head.push("alive", "ips");
    if (httpReady) head.push("http_status", "title");
    if (portsReady) head.push("open_ports", "open_port_count");
    if (secReady) head.push("security_flags", "tls_days_left");
    const rows = subdomains.map(s => {
      const r = [s];
      if (dnsReady) r.push(current.dns[s] ? "yes" : "no", (current.dns[s] || []).join(" "));
      if (httpReady) r.push(current.http[s] ? current.http[s].status : "", current.http[s]?.title || "");
      if (portsReady) {
        const ports = current.ports[s];
        r.push(ports ? Object.keys(ports).join(" ") : "", ports ? Object.keys(ports).length : "");
      }
      if (secReady) {
        const sec = current.sec[s];
        const flags = [];
        for (const p of sec?.paths || []) flags.push(`${p.path}[${p.status}]`);
        for (const h of sec?.headers?.missing || []) flags.push(`missing:${h}`);
        if (sec?.tls?.expiring_soon) flags.push("tls_expiring_soon");
        r.push(flags.join(" "), sec?.tls?.days_left ?? "");
      }
      return r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",");
    });
    download("﻿" + head.join(",") + "\n" + rows.join("\n") + "\n",
      base + ".csv", "text/csv;charset=utf-8", partial);
  } else if (fmt === "json") {
    const payload = {
      apex, count: subdomains.length,
      state: current.state || undefined,
      exported_at: new Date().toISOString(),
      subdomains,
    };
    if (dnsReady) payload.dns = current.results.dns;
    if (httpReady) payload.http = current.results.http;
    if (portsReady) payload.ports = current.results.ports;
    if (secReady) payload.security = current.results.security;
    download(JSON.stringify(payload, null, 2), base + ".json", "application/json;charset=utf-8", partial);
  }
}

document.querySelectorAll(".chip[data-fmt]").forEach(b =>
  b.onclick = () => exportAs(b.dataset.fmt)
);

filterInput.oninput = applyFilter;

// --------------------------------------------------------------------------- //
// scan: POST /scan, then poll the job
// --------------------------------------------------------------------------- //
let lastProgressAt = Date.now();
let lastProgressSig = "";

function resetView(apex, stages) {
  current = {
    apex, jobId: "", state: "queued", subdomains: [], stages, progress: {},
    dns: {}, http: {}, ports: {}, sec: {}, cached: false, truncated: {},
    pending: new Set(stages),
  };
  lastProgressAt = Date.now();
  lastProgressSig = "";
  meta.textContent = "正在查询 CT 日志…";
  toolbar.style.display = "none";
  filterInput.value = "";
  renderStages();
  results.innerHTML = '<div class="empty">Loading…</div>';
  btn.textContent = stages.length ? "取消" : "查询";
}

function render() {
  const stages = current.stages || [];
  const progress = current.progress || {};
  current.pending = new Set(stages.filter(s => {
    const p = progress[s];
    return !p || p.state === "pending" || p.state === "running";
  }));
  applyFilter();
  renderStages();
  renderMeta();
  toolbar.style.display = "flex";
  btn.textContent = isRunning() ? "取消" : "查询";
}

function applyJob(data) {
  const res = data.results || {};
  const dnsMap = {}, httpMap = {}, portMap = {}, secMap = {};
  if (res.dns?.alive) for (const [s, ips] of Object.entries(res.dns.alive)) dnsMap[s] = ips;
  if (res.http?.results) for (const [s, info] of Object.entries(res.http.results)) { if (info) httpMap[s] = info; }
  if (res.ports?.results) Object.assign(portMap, res.ports.results);
  if (res.security?.results) Object.assign(secMap, res.security.results);
  Object.assign(current, {
    jobId: data.job_id || current.jobId,
    apex: data.apex || current.apex,
    state: data.state || current.state,
    subdomains: data.subdomains || [],
    stages: data.stages || current.stages,
    progress: data.progress || {},
    results: res,
    dns: dnsMap, http: httpMap, ports: portMap, sec: secMap,
    cached: !!data.cached,
    truncated: data.truncated || {},
    elapsed_seconds: data.elapsed_seconds,
    error: data.error,
  });
}

function stopPolling() {
  pollToken++;
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
}

async function fetchJSON(url) {
  const r = await fetch(url);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `${r.status} ${r.statusText}`);
  return data;
}

async function startScan(apex) {
  const stages = [];
  if ($("dnsCheck").checked) stages.push("dns");
  if ($("httpCheck").checked) stages.push("http");
  if ($("portCheck").checked) stages.push("ports");
  if ($("secCheck").checked) stages.push("security");
  stopPolling();
  const token = ++pollToken;
  resetView(apex, stages);
  if (!stages.length) return listOnly(apex, token);
  try {
    const r = await fetch("/api/v1/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apex }),
    });
    const data = await r.json().catch(() => ({}));
    if (token !== pollToken) return;
    if (!r.ok) throw new Error(data.error || `${r.status} ${r.statusText}`);
    current.jobId = data.job_id;
    current.stages = data.stages || stages;
    history.replaceState(null, "", `?apex=${encodeURIComponent(apex)}&job=${data.job_id}`);
    pollJob(data.job_id, Math.max(500, data.poll_interval_ms || 1000), token);
  } catch (e) {
    if (token !== pollToken) return;
    meta.textContent = "";
    btn.textContent = "查询";
    results.innerHTML = `<div class="empty err">查询失败: ${esc(e.message)}</div>`;
  }
}

/** No stage checked: the subdomain list alone, straight from the cached path. */
async function listOnly(apex, token) {
  try {
    const data = await fetchJSON(`/api/v1/search?apex=${encodeURIComponent(apex)}`);
    if (token !== pollToken) return;
    current.state = "done";
    current.subdomains = data.subdomains || [];
    current.cached = !!data.cached;
    current.results = {};
    history.replaceState(null, "", `?apex=${encodeURIComponent(apex)}`);
    render();
  } catch (e) {
    if (token !== pollToken) return;
    meta.textContent = "";
    results.innerHTML = `<div class="empty err">查询失败: ${esc(e.message)}</div>`;
  } finally {
    if (token === pollToken) { btn.textContent = "查询"; renderMeta(); }
  }
}

async function pollJob(jobId, interval, token) {
  try {
    while (token === pollToken) {
      const data = await fetchJSON(`/api/v1/jobs/${jobId}`);
      if (token !== pollToken) return;
      applyJob(data);
      // Progress signature: anything the user can see move resets the stall timer.
      const sig = JSON.stringify(Object.fromEntries(
        Object.entries(data.progress || {}).map(([s, p]) => [s, [p.state, p.checked]])
      ));
      if (sig !== lastProgressSig) { lastProgressSig = sig; lastProgressAt = Date.now(); }
      render();
      if (!RUNNING_STATES.has(data.state)) return;
      await new Promise(res => { pollTimer = setTimeout(res, interval); });
    }
  } catch (e) {
    if (token !== pollToken) return;
    current.state = "error";
    current.error = e.message;
    render();
    showToast("轮询失败: " + e.message);
  }
}

/** Re-attach to a job id (page reload, or a shared link). */
async function attach(jobId) {
  stopPolling();
  const token = ++pollToken;
  resetView(input.value.trim().toLowerCase(), []);
  try {
    const data = await fetchJSON(`/api/v1/jobs/${jobId}`);
    if (token !== pollToken) return;
    if (!data.apex) throw new Error("任务已过期");
    input.value = data.apex;
    applyJob(data);
    render();
    if (RUNNING_STATES.has(data.state)) pollJob(jobId, 1000, token);
  } catch (e) {
    if (token !== pollToken) return;
    current.state = "error";
    btn.textContent = "查询";
    meta.textContent = "";
    results.innerHTML = `<div class="empty err">无法恢复任务: ${esc(e.message)}</div>`;
  }
}

async function cancelCurrent() {
  const jobId = current.jobId;
  if (!jobId) return;
  stopPolling();
  btn.disabled = true;
  try {
    await fetch(`/api/v1/jobs/${jobId}`, { method: "DELETE" });
    // A soft cancel: whatever stages already finished stay in the table, and
    // the persisted rows stay in the database for the next scan to reuse.
    const data = await fetchJSON(`/api/v1/jobs/${jobId}`).catch(() => null);
    if (data) applyJob(data);
    current.state = RUNNING_STATES.has(current.state) ? "cancelled" : current.state;
    current.pending = new Set();
    render();
    showToast("已取消 · 部分结果保留");
  } catch (e) {
    showToast("取消失败: " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "查询";
  }
}

form.onsubmit = (e) => {
  e.preventDefault();
  if (isRunning()) { cancelCurrent(); return; }
  const apex = input.value.trim().toLowerCase();
  if (!apex) return;
  startScan(apex);
};

const params = new URLSearchParams(location.search);
const initialApex = params.get("apex");
const initialJob = params.get("job");
if (initialApex) input.value = initialApex;
if (initialJob) attach(initialJob);
else if (initialApex) startScan(initialApex.trim().toLowerCase());
