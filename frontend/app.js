const $ = (id) => document.getElementById(id);
const form = $("f"), input = $("apex"), btn = $("btn"),
      meta = $("meta"), results = $("results"), toolbar = $("toolbar"),
      filterInput = $("filter"), toast = $("toast");

let current = { apex: "", subdomains: [] };

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
    row.innerHTML = `<span class="name"></span><span class="copy">复制</span>`;
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
  meta.textContent = "正在查询 CT 日志…";
  toolbar.style.display = "none";
  results.innerHTML = '<div class="empty">Loading…</div>';
  try {
    const r = await fetch(`/api/v1/search?apex=${encodeURIComponent(apex)}`);
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || r.statusText);
    current = { apex, subdomains: data.subdomains };
    const parts = [`共 ${data.count} 个子域名`];
    if (data.cached) parts.push("缓存命中 ✓");
    if (data.elapsed_seconds != null) parts.push(`耗时 ${data.elapsed_seconds}s`);
    meta.textContent = parts.join("  ·  ");
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
