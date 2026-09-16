const $ = (id) => document.getElementById(id);
const form = $("f"), input = $("apex"), btn = $("btn"),
      meta = $("meta"), results = $("results"), toolbar = $("toolbar"),
      filterInput = $("filter"), toast = $("toast");

let current = { apex: "", subdomains: [], dns: {}, dnsChecked: false, http: {}, httpChecked: false };

function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 1600);
}

function esc(s) {
  return s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function statusClass(code) {
  return `st-${String(code)[0]}`;
}

function renderList(items) {
  if (!items.length) {
    results.innerHTML = '<div class="empty">没有匹配的子域名</div>';
    return;
  }
  const showDns = current.dnsChecked, showHttp = current.httpChecked;
  let html = `<table><thead><tr>
    <th style="width:34%">子域名</th>
    ${showDns ? "<th>状态</th><th style=\"width:24%\">IP (A 记录)</th>" : ""}
    ${showHttp ? "<th style=\"width:8%\">HTTP</th><th>标题</th>" : ""}
  </tr></thead><tbody>`;
  for (const name of items) {
    const ips = current.dns[name];
    const info = current.http[name];
    html += `<tr data-name="${esc(name)}" title="点击复制 ${esc(name)}">`;
    html += `<td class="sub">${esc(name)}</td>`;
    if (showDns) {
      html += ips
        ? `<td><span class="badge alive">存活</span></td><td class="ips">${ips.map(esc).join(", ")}</td>`
        : `<td><span class="badge dead">无解析</span></td><td class="ips">—</td>`;
    }
    if (showHttp) {
      html += info
        ? `<td class="status"><span class="${statusClass(info.status)}">${info.status}</span></td><td class="title">${info.title ? esc(info.title) : "—"}</td>`
        : `<td class="status">—</td><td class="title">—</td>`;
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

function download(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast("已导出 " + filename);
}

function exportAs(fmt) {
  const { apex, subdomains, dns, dnsChecked, http, httpChecked } = current;
  if (!subdomains.length) return;
  const stamp = new Date().toISOString().slice(0, 10);
  const base = `subdomains_${apex}_${stamp}`;
  if (fmt === "txt") {
    download(subdomains.join("\n") + "\n", base + ".txt", "text/plain;charset=utf-8");
  } else if (fmt === "csv") {
    let csv;
    if (dnsChecked || httpChecked) {
      const head = ["subdomain"];
      if (dnsChecked) head.push("alive", "ips");
      if (httpChecked) head.push("http_status", "title");
      const rows = subdomains.map(s => {
        const r = [s];
        if (dnsChecked) r.push(dns[s] ? "yes" : "no", (dns[s] || []).join(" "));
        if (httpChecked) r.push(http[s] ? http[s].status : "", http[s]?.title || "");
        return r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",");
      });
      csv = head.join(",") + "\n" + rows.join("\n") + "\n";
    } else {
      csv = "subdomain\n" + subdomains.map(s => `"${s}"`).join("\n") + "\n";
    }
    download("﻿" + csv, base + ".csv", "text/csv;charset=utf-8");
  } else if (fmt === "json") {
    download(JSON.stringify({ apex, count: subdomains.length, exported_at: new Date().toISOString(), subdomains }, null, 2),
      base + ".json", "application/json;charset=utf-8");
  }
}

document.querySelectorAll(".chip[data-fmt]").forEach(b =>
  b.onclick = () => exportAs(b.dataset.fmt)
);

filterInput.oninput = () => {
  const q = filterInput.value.trim().toLowerCase();
  const filtered = q ? current.subdomains.filter(s => s.includes(q)) : current.subdomains;
  renderList(filtered);
};

async function search(apex) {
  btn.disabled = true;
  const dnsChecked = $("dnsCheck").checked;
  const httpChecked = $("httpCheck").checked;
  meta.textContent = "正在查询 CT 日志…";
  toolbar.style.display = "none";
  results.innerHTML = '<div class="empty">Loading…</div>';
  try {
    const r = await fetch(`/api/v1/search?apex=${encodeURIComponent(apex)}&dns_check=${dnsChecked}&http_check=${httpChecked}`);
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || r.statusText);
    const dnsMap = {}, httpMap = {};
    if (data.dns?.alive) for (const [s, ips] of Object.entries(data.dns.alive)) dnsMap[s] = ips;
    if (data.http?.results) for (const [s, info] of Object.entries(data.http.results)) { if (info) httpMap[s] = info; }
    current = { apex, subdomains: data.subdomains, dns: dnsMap, dnsChecked, http: httpMap, httpChecked };
    const parts = [`共 ${data.count} 个子域名`];
    if (dnsChecked && data.dns) parts.push(`<span class="alive">存活 ${data.dns.alive_count}</span>`);
    if (httpChecked && data.http) parts.push(`Web 服务 ${data.http.web_count}`);
    if (data.cached) parts.push("缓存命中 ✓");
    if (data.elapsed_seconds != null) parts.push(`耗时 ${data.elapsed_seconds}s`);
    if (data.dns?.elapsed_seconds != null) parts.push(`DNS ${data.dns.elapsed_seconds}s`);
    if (data.http?.elapsed_seconds != null) parts.push(`HTTP ${data.http.elapsed_seconds}s`);
    meta.innerHTML = parts.join("  ·  ");
    toolbar.style.display = "flex";
    filterInput.value = "";
    renderList(data.subdomains);
    history.replaceState(null, "", `?apex=${encodeURIComponent(apex)}`);
  } catch (e) {
    meta.textContent = "";
    results.innerHTML = `<div class="empty err">查询失败: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
  }
}

form.onsubmit = (e) => {
  e.preventDefault();
  const apex = input.value.trim().toLowerCase();
  if (apex) search(apex);
};

const initial = new URLSearchParams(location.search).get("apex");
if (initial) { input.value = initial; search(initial); }
