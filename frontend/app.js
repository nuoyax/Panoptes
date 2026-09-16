const $ = (id) => document.getElementById(id);
const form = $("f"), input = $("apex"), btn = $("btn"),
      meta = $("meta"), results = $("results"), toolbar = $("toolbar"),
      filterInput = $("filter"), toast = $("toast");

let current = { apex: "", subdomains: [], dns: {}, dnsChecked: false };

function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 1600);
}

function renderList(items) {
  results.innerHTML = "";
  if (!items.length) {
    results.innerHTML = '<div class="empty">没有匹配的子域名</div>';
    return;
  }
  const frag = document.createDocumentFragment();
  for (const name of items) {
    const row = document.createElement("div");
    row.className = "row";
    const ips = current.dns[name];
    let badge = "", ipSpan = "";
    if (current.dnsChecked) {
      badge = ips
        ? '<span class="badge alive">存活</span>'
        : '<span class="badge dead">无解析</span>';
      if (ips) ipSpan = `<span class="ips">${ips.join(", ")}</span>`;
    }
    row.innerHTML = `<span class="name"></span>${badge}${ipSpan}<span class="copy">复制</span>`;
    row.querySelector(".name").textContent = name;
    row.onclick = () => {
      navigator.clipboard?.writeText(name);
      showToast("已复制: " + name);
    };
    frag.appendChild(row);
  }
  results.appendChild(frag);
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
  const { apex, subdomains } = current;
  if (!subdomains.length) return;
  const stamp = new Date().toISOString().slice(0, 10);
  const base = `subdomains_${apex}_${stamp}`;
  if (fmt === "txt") {
    download(subdomains.join("\n") + "\n", base + ".txt", "text/plain;charset=utf-8");
  } else if (fmt === "csv") {
    const csv = "subdomain\n" + subdomains.map(s => `"${s}"`).join("\n") + "\n";
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
  meta.textContent = dnsChecked ? "正在查询 CT 日志并验证 DNS…" : "正在查询 CT 日志…";
  toolbar.style.display = "none";
  results.innerHTML = '<div class="empty">Loading…</div>';
  try {
    const r = await fetch(`/api/v1/search?apex=${encodeURIComponent(apex)}&dns_check=${dnsChecked}`);
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || r.statusText);
    const dnsMap = {};
    if (data.dns?.alive) for (const [s, ips] of Object.entries(data.dns.alive)) dnsMap[s] = ips;
    current = { apex, subdomains: data.subdomains, dns: dnsMap, dnsChecked };
    const parts = [`共 ${data.count} 个子域名`];
    if (dnsChecked && data.dns) parts.push(`<span class="alive">存活 ${data.dns.alive_count}</span>`);
    if (data.cached) parts.push("缓存命中 ✓");
    if (data.elapsed_seconds != null) parts.push(`耗时 ${data.elapsed_seconds}s`);
    if (data.dns?.elapsed_seconds != null) parts.push(`DNS ${data.dns.elapsed_seconds}s`);
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
