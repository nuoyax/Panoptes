const $ = (id) => document.getElementById(id);
const form = $("f"), input = $("apex"), btn = $("btn"),
      meta = $("meta"), results = $("results");

function renderList(items) {
  results.innerHTML = "";
  if (!items.length) {
    results.innerHTML = '<div class="empty">No subdomains found.</div>';
    return;
  }
  const frag = document.createDocumentFragment();
  for (const name of items) {
    const d = document.createElement("div");
    d.textContent = name;
    d.title = "Copy";
    d.onclick = () => navigator.clipboard?.writeText(name);
    frag.appendChild(d);
  }
  results.appendChild(frag);
}

async function search(apex) {
  btn.disabled = true;
  meta.textContent = "Querying CT logs…";
  results.innerHTML = '<div class="empty">Loading…</div>';
  try {
    const r = await fetch(`/api/v1/search?apex=${encodeURIComponent(apex)}`);
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || r.statusText);
    const parts = [`count: ${data.count}`];
    if (data.cached) parts.push("cached ✓");
    if (data.elapsed_seconds != null) parts.push(`${data.elapsed_seconds}s`);
    for (const [src, n] of Object.entries(data.sources || {})) parts.push(`${src}: ${n}`);
    meta.textContent = parts.join("  ·  ");
    renderList(data.subdomains);
    history.replaceState(null, "", `?apex=${encodeURIComponent(apex)}`);
  } catch (e) {
    meta.textContent = "";
    results.innerHTML = `<div class="empty err">Error: ${e.message}</div>`;
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
