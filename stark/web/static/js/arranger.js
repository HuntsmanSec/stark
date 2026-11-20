// Log Arranger UI. Results live ONLY in this module's memory (never localStorage,
// never the server DB) and are wiped on purge, on leaving the case, or after 30 minutes.
import { api, busy, download, empty, fail, fmtTime, h, icon, ioc, mount, toast, TYPE_LABEL, debounce } from "./core.js";

const TTL_MS = 30 * 60 * 1000;
const PAGE = 300;
let store = null; // { caseId, result, names, at, filters, selected:Set, sideTab }
let ticker = null;

export function purgeArranger() {
  if (store && store.result) { store.result.rows.length = 0; }
  store = null;
  if (ticker) { clearInterval(ticker); ticker = null; }
}

const SOURCES = ["Microsoft Sentinel", "Microsoft Defender", "Splunk", "Elastic / ELK", "IBM QRadar", "LogRhythm", "CrowdStrike Falcon", "SentinelOne",
  "Palo Alto", "Fortinet", "Cisco ASA/FTD", "AWS WAF", "Cloudflare", "Azure WAF", "ModSecurity", "Zeek", "Suricata", "Windows Event XML", "Syslog / CEF / LEEF", "CSV / JSON"];

export function renderArranger(caseData, actions) {
  if (store && store.caseId !== caseData.id) purgeArranger();
  const root = h("div", { class: "col gap-16" });
  const redraw = () => mount(root, privacyNotice(redraw), store && store.result ? resultsView(caseData, actions, redraw) : inputView(caseData, redraw));
  redraw();
  return root;
}

function privacyNotice(redraw) {
  const timer = h("span", { class: "timer" });
  const tick = () => {
    if (!store || !store.result) { timer.textContent = ""; return; }
    const left = store.at + TTL_MS - Date.now();
    if (left <= 0) { purgeArranger(); toast("Arranged logs were purged automatically after 30 minutes", "info"); if (document.body.contains(timer)) redraw(); return; }
    const m = Math.floor(left / 60000); const s = Math.floor((left % 60000) / 1000);
    timer.textContent = `auto-purge in ${m}:${String(s).padStart(2, "0")}`;
  };
  if (ticker) clearInterval(ticker);
  ticker = setInterval(tick, 1000); tick();
  return h("div", { class: "notice privacy" }, icon("lock"), h("div", { class: "grow" },
    h("b", null, "Temporary workspace: client logs are never stored"),
    h("span", { class: "small muted" }, "Files are processed in memory and the arranged view exists only in this browser tab. Leave the case, click Purge, or wait 30 minutes and it's gone. Only items you add to the case (indicators, artifacts, techniques, pinned events) are saved.")),
    store && store.result ? h("div", { class: "col", style: { alignItems: "flex-end" } }, timer,
      h("button", { class: "btn sm danger", onclick: () => { purgeArranger(); toast("Logs purged from memory"); redraw(); } }, icon("trash"), "Purge now")) : null);
}

// ------------------------------------------------------------------ input
function inputView(caseData, redraw) {
  const files = [];
  const chips = h("div", { class: "file-chips" });
  const fileInput = h("input", { type: "file", multiple: true, class: "hidden", accept: ".log,.txt,.csv,.tsv,.json,.jsonl,.ndjson,.xml,.cef,.leef,.syslog,*/*" });
  const paste = h("textarea", { class: "input mono", rows: 7, placeholder: "…or paste log lines here: syslog, CEF/LEEF, JSON events, CSV with a header row, Windows event XML…" });
  const go = h("button", { class: "btn primary lg" }, icon("layers"), "Arrange logs");
  const drawChips = () => mount(chips, files.map((f, i) => h("span", { class: "file-chip" }, icon("file"), f.name, h("span", { class: "faint tiny" }, ` ${(f.size / 1024).toFixed(0)} KB`),
    h("button", { class: "btn ghost sm icon", onclick: (e) => { e.stopPropagation(); files.splice(i, 1); drawChips(); } }, icon("x")))));
  const addFiles = (list) => { for (const f of list) files.push(f); drawChips(); };
  fileInput.addEventListener("change", () => { addFiles(fileInput.files); fileInput.value = ""; });
  const dz = h("div", { class: "dropzone", tabindex: "0", role: "button", onclick: () => fileInput.click(), onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") fileInput.click(); } },
    h("div", { class: "ill" }, icon("upload")), h("h3", null, "Drop log exports here"),
    h("div", { class: "muted small" }, "or click to browse. Mix files from different tools; they're merged into one timeline. Up to 64 MB per batch."), chips);
  ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("over"); }));
  dz.addEventListener("drop", (e) => addFiles(e.dataTransfer.files));
  go.onclick = async () => {
    if (!files.length && !paste.value.trim()) { toast("Add a file or paste some log lines first", "info"); return; }
    const fd = new FormData(); files.forEach((f) => fd.append("files", f, f.name)); if (paste.value.trim()) fd.append("text", paste.value);
    busy(go, true, "Arranging…");
    try {
      const result = await api("POST", "/arrange", fd);
      paste.value = "";
      store = { caseId: caseData.id, result, names: files.map((f) => f.name).concat(fd.has("text") ? ["pasted text"] : []), at: Date.now(),
        filters: { q: "", product: null, severity: null, withIoc: false }, selected: new Set(), sideTab: "iocs", limit: PAGE };
      files.length = 0;
      redraw();
    } catch (e) { fail(e); busy(go, false); }
  };
  return h("div", { class: "card card-pad col gap-16" }, dz, fileInput, paste,
    h("div", { class: "row wrap" }, h("div", { class: "grow" }, h("div", { class: "label mb-8" }, "Recognised automatically"),
      h("div", { class: "row wrap gap-4" }, SOURCES.map((s) => h("span", { class: "tag" }, s)))), go));
}

// ---------------------------------------------------------------- results
function filtered() {
  const { q, product, severity, withIoc } = store.filters;
  const needle = q.trim().toLowerCase();
  return store.result.rows.filter((r) => (!product || r.product === product) && (!severity || r.severity === severity) && (!withIoc || r.iocs.length)
    && (!needle || [r.event, r.host, r.user, r.src_ip, r.dst_ip, r.command_line, r.url, r.domain, r.message, r.process, r.action, r.raw].some((v) => v && String(v).toLowerCase().includes(needle))));
}

function resultsView(caseData, actions, redraw) {
  const res = store.result; const st = res.stats;
  const tableBox = h("div");
  const drawTable = () => mount(tableBox, timelineTable(actions, drawTable));
  const search = h("input", { class: "input", placeholder: "Filter events: host, user, IP, command…", value: store.filters.q, style: { width: "280px" } });
  search.addEventListener("input", debounce(() => { store.filters.q = search.value; store.limit = PAGE; drawTable(); }, 200));
  const chip = (label, n, on, onclick) => h("button", { class: `chip-btn${on ? " on" : ""}`, onclick }, label, h("span", { class: "n" }, n));
  const productChips = Object.entries(st.products).map(([p, n]) => chip(p, n, store.filters.product === p, () => { store.filters.product = store.filters.product === p ? null : p; store.limit = PAGE; redraw(); }));
  const sevChips = Object.entries(st.severities).map(([s, n]) => chip(h("span", { class: "row gap-4" }, h("span", { class: `sev-dot ${s}` }), s), n, store.filters.severity === s, () => { store.filters.severity = store.filters.severity === s ? null : s; store.limit = PAGE; redraw(); }));
  const iocToggle = h("label", { class: "check small" }, h("input", { type: "checkbox", checked: store.filters.withIoc, onchange: (e) => { store.filters.withIoc = e.target.checked; store.limit = PAGE; drawTable(); } }), "Only rows with indicators");
  const pin = h("button", { class: "btn sm", onclick: async () => {
    const rows = res.rows.filter((r) => store.selected.has(r.id));
    if (!rows.length) { toast("Tick the events you want to pin first", "info"); return; }
    try { await actions.addEvents(rows.map((r) => ({ time: r.time, text: summarise(r) }))); store.selected.clear(); drawTable(); actions.refreshCounts(); } catch (e) { fail(e); }
  } }, icon("pin"), "Pin selected to case timeline");
  const exportCsv = h("button", { class: "btn sm", title: "Download the arranged timeline to your computer (not stored in S.T.A.R.K)", onclick: () => {
    const cols = ["time", "product", "event", "severity", "action", "host", "user", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "process", "parent_process", "command_line", "hash", "url", "domain", "message", "source_file"];
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    download(`arranged-${new Date().toISOString().slice(0, 19).replace(/:/g, "")}.csv`, [cols.join(","), ...filtered().map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n"), "text/csv");
  } }, icon("download"), "Export CSV");
  drawTable();
  return h("div", { class: "col gap-16" },
    h("div", { class: "grid grid-4" },
      statBox(st.rows.toLocaleString(), "events arranged", st.truncated ? "truncated at 100,000" : `from ${store.names.length} source(s)`),
      statBox(Object.keys(st.products).length, "log sources detected", Object.keys(st.products).slice(0, 2).join(", ")),
      statBox(res.iocs.filter((i) => !i.internal).length, "external indicators", `${res.iocs.filter((i) => i.internal).length} internal`),
      statBox(res.mitre.length, "ATT&CK suggestions", st.first ? `${fmtTime(st.first).slice(0, 16)} → ${fmtTime(st.last).slice(0, 16)}` : "no timestamps")),
    h("div", { class: "arr-layout" },
      h("div", { class: "card" },
        h("div", { class: "arr-toolbar" }, search, iocToggle, h("span", { class: "spacer" }), pin, exportCsv,
          h("button", { class: "btn sm ghost", onclick: () => { purgeArranger(); redraw(); } }, icon("plus"), "New batch")),
        h("div", { class: "arr-toolbar", style: { paddingTop: "8px", paddingBottom: "8px" } }, h("span", { class: "label" }, "Sources"), productChips,
          sevChips.length ? [h("span", { class: "label", style: { marginLeft: "8px" } }, "Severity"), sevChips] : null),
        tableBox),
      sidePanel(actions, redraw)));
}
const statBox = (n, label, sub) => h("div", { class: "card stat" }, h("div", null, h("b", null, n), h("span", null, label), sub ? h("div", { class: "tiny faint" }, sub) : null));

function summarise(r) {
  const parts = [`[${r.product}]`];
  if (r.event) parts.push(r.event);
  if (r.host) parts.push(`on ${r.host}`);
  if (r.user) parts.push(`user ${r.user}`);
  if (r.src_ip || r.dst_ip) parts.push(`${r.src_ip || "?"}${r.src_port ? ":" + r.src_port : ""} → ${r.dst_ip || "?"}${r.dst_port ? ":" + r.dst_port : ""}`);
  if (r.action) parts.push(`(${r.action})`);
  const detail = r.command_line || r.url || r.domain || (r.message && r.message.length < 300 ? r.message : "");
  if (detail) parts.push(`- ${detail}`);
  return parts.join(" ").slice(0, 3900);
}

function highlight(text, iocs) {
  if (!text) return "";
  const vals = [...new Set(iocs)].filter((v) => v.length >= 4 && text.includes(v)).sort((a, b) => b.length - a.length);
  if (!vals.length) return text;
  const out = []; let rest = String(text);
  while (rest) {
    let best = -1; let val = null;
    for (const v of vals) { const i = rest.indexOf(v); if (i >= 0 && (best < 0 || i < best)) { best = i; val = v; } }
    if (best < 0) { out.push(rest); break; }
    if (best) out.push(rest.slice(0, best));
    out.push(ioc(val)); rest = rest.slice(best + val.length);
  }
  return out;
}

function timelineTable(actions, redrawTable) {
  const rows = filtered();
  if (!rows.length) return empty("filter", "No events match", "Clear the filters to see every event.");
  const shown = rows.slice(0, store.limit);
  const allOn = shown.every((r) => store.selected.has(r.id));
  const tbody = h("tbody");
  for (const r of shown) {
    const tr = h("tr", { class: "clickable" },
      h("td", { onclick: (e) => e.stopPropagation() }, h("input", { type: "checkbox", checked: store.selected.has(r.id), onchange: (e) => { e.target.checked ? store.selected.add(r.id) : store.selected.delete(r.id); } })),
      h("td", { class: "time" }, r.time ? fmtTime(r.time) : h("span", { class: "faint" }, "no time")),
      h("td", null, h("span", { class: "row gap-4" }, r.severity ? h("span", { class: `sev-dot ${r.severity}`, title: r.severity }) : null, h("span", { class: "small" }, r.product))),
      h("td", { class: "small", style: { maxWidth: "180px" } }, h("div", { class: "ellipsis", title: r.event }, r.event || h("span", { class: "faint" }, "-"))),
      h("td", { class: "small" }, r.host ? h("div", null, r.host) : null, r.user ? h("div", { class: "faint" }, r.user) : null),
      h("td", { class: "flow" }, r.src_ip || r.dst_ip ? [r.src_ip || "?", r.src_port ? `:${r.src_port}` : "", " → ", r.dst_ip || "?", r.dst_port ? `:${r.dst_port}` : ""].join("") : ""),
      h("td", { class: "small" }, r.action),
      h("td", { class: "detail" }, h("div", { class: "ellipsis" }, highlight(r.command_line || r.url || r.domain || r.message || r.process || "", r.iocs))));
    tr.addEventListener("click", () => {
      const next = tr.nextSibling;
      if (next && next.classList && next.classList.contains("raw-row")) { next.remove(); tr.classList.remove("expanded"); return; }
      tr.classList.add("expanded");
      const fields = ["time", "product", "event", "severity", "action", "host", "user", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "process", "parent_process", "command_line", "hash", "url", "domain", "source_file"]
        .filter((f) => r[f]).map((f) => h("div", { class: "row top", style: { gap: "10px" } }, h("span", { class: "label", style: { width: "110px", flex: "none" } }, f.replace("_", " ")), h("div", { class: "grow small", style: { wordBreak: "break-all" } }, highlight(String(r[f]), r.iocs))));
      tr.after(h("tr", { class: "raw-row" }, h("td", { colspan: 8, style: { background: "var(--bg-sunk)" } },
        h("div", { class: "grid grid-2" }, h("div", { class: "col gap-4" }, fields), h("div", null, h("div", { class: "label mb-8" }, "Original line"), h("div", { class: "raw" }, r.raw))),
        h("div", { class: "row mt-8" }, h("span", { class: "spacer" }), h("button", { class: "btn sm", onclick: async () => { try { await actions.addEvents([{ time: r.time, text: summarise(r) }]); actions.refreshCounts(); } catch (e) { fail(e); } } }, icon("pin"), "Pin to case timeline")))));
    });
    tbody.appendChild(tr);
  }
  return h("div", null,
    h("div", { class: "table-wrap arr-table" }, h("table", { class: "table compact" },
      h("thead", null, h("tr", null, h("th", null, h("input", { type: "checkbox", checked: allOn, title: "Select shown", onchange: (e) => { shown.forEach((r) => e.target.checked ? store.selected.add(r.id) : store.selected.delete(r.id)); redrawTable(); } })),
        h("th", null, "Time (UTC)"), h("th", null, "Source"), h("th", null, "Event"), h("th", null, "Host / user"), h("th", null, "Network"), h("th", null, "Action"), h("th", null, "Details"))),
      tbody)),
    h("div", { class: "row", style: { padding: "10px 14px", borderTop: "1px solid var(--border)" } }, h("span", { class: "small muted grow" }, `Showing ${shown.length.toLocaleString()} of ${rows.length.toLocaleString()} events · click a row for details`),
      rows.length > shown.length ? h("button", { class: "btn sm", onclick: () => { store.limit += PAGE * 3; redrawTable(); } }, "Show more") : null));
}

// ------------------------------------------------------------- side panel
function sidePanel(actions, redraw) {
  const res = store.result;
  const tabs = [["iocs", "Indicators", res.iocs.length], ["entities", "Entities", res.entities.hosts.length + res.entities.users.length + res.entities.processes.length], ["mitre", "ATT&CK", res.mitre.length]];
  const body = h("div", { class: "card-body" });
  const head = h("div", { class: "tabs", style: { margin: 0, padding: "0 10px" } }, tabs.map(([k, l, n]) => h("button", { class: `tab${store.sideTab === k ? " active" : ""}`, onclick: () => { store.sideTab = k; redraw(); } }, l, h("span", { class: "count" }, n))));
  if (store.sideTab === "iocs") mount(body, iocPanel(actions));
  else if (store.sideTab === "entities") mount(body, entityPanel(actions));
  else mount(body, mitrePanel(actions));
  return h("div", { class: "card", style: { position: "sticky", top: "0" } }, head, body);
}

function iocPanel(actions) {
  const list = store.result.iocs;
  if (!list.length) return h("div", { class: "muted small" }, "No indicators found in these logs.");
  const sel = new Set(list.filter((i) => !i.internal).slice(0, 200).map((i) => i.value));
  const count = h("span", { class: "small muted" });
  const upd = () => { count.textContent = `${sel.size} selected`; };
  const add = (enrich) => async (e) => {
    const items = list.filter((i) => sel.has(i.value)).map((i) => ({ value: i.value, type: i.type }));
    if (!items.length) { toast("Select at least one indicator", "info"); return; }
    const btn = e.currentTarget; busy(btn, true);
    try { await actions.addObservables(items); if (enrich) await api("POST", `/cases/${store.caseId}/enrich`, {}); actions.refreshCounts(); if (enrich) toast("Reputation check started. See the Observables tab.", "info"); }
    catch (ex) { fail(ex); }
    busy(btn, false);
  };
  upd();
  return h("div", { class: "col gap-12" },
    h("div", { class: "hint" }, "Internal/private addresses are left unticked: reputation sources can't rate them."),
    h("div", { class: "side-list" }, list.map((i) => h("label", { class: "side-item", style: { cursor: "pointer" } },
      h("input", { type: "checkbox", checked: sel.has(i.value), onchange: (e) => { e.target.checked ? sel.add(i.value) : sel.delete(i.value); upd(); } }),
      h("div", { class: "grow", style: { minWidth: 0 } }, ioc(i.value, null, i.internal ? "internal" : ""), h("div", { class: "tiny faint" }, TYPE_LABEL[i.type] || i.type, i.internal ? " · internal" : "")),
      h("span", { class: "count" }, `×${i.count}`)))),
    h("div", { class: "row" }, count, h("span", { class: "spacer" }), h("button", { class: "btn sm", onclick: add(false) }, "Add to case"), h("button", { class: "btn sm primary", onclick: add(true) }, icon("zap"), "Add & check")));
}

function entityPanel(actions) {
  const e = store.result.entities;
  const groups = [["host", "Hosts", e.hosts], ["user", "Accounts", e.users], ["process", "Processes", e.processes], ["command_line", "Command lines", e.command_lines]].filter(([, , l]) => l.length);
  if (!groups.length) return h("div", { class: "muted small" }, "No hosts, accounts or processes identified.");
  const sel = new Set();
  return h("div", { class: "col gap-12" },
    groups.map(([kind, label, items]) => h("div", null, h("div", { class: "label mb-8" }, label),
      h("div", { class: "side-list", style: { maxHeight: "170px" } }, items.slice(0, 100).map((it) => h("label", { class: "side-item", style: { cursor: "pointer" } },
        h("input", { type: "checkbox", onchange: (ev) => { const k = `${kind}\u0000${it.value}`; ev.target.checked ? sel.add(k) : sel.delete(k); } }),
        h("div", { class: "grow ellipsis small mono", title: it.value }, it.value), h("span", { class: "count" }, `×${it.count}`)))))),
    h("div", { class: "row" }, h("span", { class: "spacer" }), h("button", { class: "btn sm primary", onclick: async (ev) => {
      if (!sel.size) { toast("Tick the entities to add", "info"); return; }
      const btn = ev.currentTarget; busy(btn, true);
      try { await actions.addArtifacts([...sel].map((k) => { const [kind, value] = k.split("\u0000"); return { kind, value, note: "from Log Arranger" }; })); actions.refreshCounts(); } catch (ex) { fail(ex); }
      busy(btn, false);
    } }, icon("plus"), "Add as artifacts")));
}

function mitrePanel(actions) {
  const list = store.result.mitre;
  if (!list.length) return h("div", { class: "muted small" }, "No technique patterns matched. Map techniques by hand on the ATT&CK tab.");
  return h("div", { class: "col gap-12" },
    h("div", { class: "hint" }, "Suggestions come from keyword and behaviour patterns in the logs. Review the evidence before you add one."),
    h("div", { class: "side-list", style: { maxHeight: "460px" } }, list.map((t) => h("div", { class: "tech-card suggest" },
      h("div", { class: "row" }, h("span", { class: "tid" }, t.id), h("span", { class: "tiny faint" }, t.tactic), h("span", { class: "spacer" }), h("span", { class: "tiny faint" }, `${t.count} hit(s)`)),
      h("div", { class: "name" }, t.name),
      t.evidence.slice(0, 2).map((ev) => h("div", { class: "raw", style: { padding: "4px 7px", marginTop: "4px", maxHeight: "60px" } }, ev)),
      h("div", { class: "row mt-8" }, h("span", { class: "spacer" }), h("button", { class: "btn sm", onclick: async (e) => {
        const btn = e.currentTarget; busy(btn, true);
        try { await actions.addTechniques([{ technique_id: t.id, note: `Seen ${t.count}× in logs, e.g.: ${t.evidence[0] || ""}`.slice(0, 1900) }]); actions.refreshCounts(); btn.replaceChildren(icon("check"), "Added"); btn.disabled = true; }
        catch (ex) { fail(ex); busy(btn, false); }
      } }, icon("plus"), "Add to case"))))),
    h("button", { class: "btn sm", onclick: async () => { try { await actions.addTechniques(list.map((t) => ({ technique_id: t.id, note: `Seen ${t.count}× in logs, e.g.: ${t.evidence[0] || ""}`.slice(0, 1900) }))); actions.refreshCounts(); } catch (e) { fail(e); } } }, "Add all suggestions"));
}
