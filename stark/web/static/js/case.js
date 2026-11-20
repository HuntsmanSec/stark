import {
  api, avatar, busy, confirmDialog, copy, download, empty, fail, fmtTime, go, h, icon, ioc, link, modal, mount, onLeave,
  sevPill, state, statusPill, timeAgo, toast, verdictPill, TYPE_LABEL, TYPE_ICON, STATUS_LABEL, SEV_LABEL, debounce, fmtDate,
} from "./core.js";
import { renderMarkdown } from "./md.js";
import { renderArranger, purgeArranger } from "./arranger.js";

const TABS = [
  ["overview", "home", "Overview"], ["logs", "layers", "Log Arranger"], ["observables", "target", "Observables"],
  ["artifacts", "server", "Artifacts"], ["attack", "grid", "ATT&CK"], ["timeline", "clock", "Timeline & actions"],
  ["report", "file", "Report"], ["activity", "activity", "Activity"],
];
const KIND_LABEL = { host: "Hosts", user: "Accounts", process: "Processes", command_line: "Command lines", file: "Files", registry: "Registry keys", email: "Email messages", other: "Other" };
const KIND_ICON = { host: "server", user: "user", process: "terminal", command_line: "terminal", file: "file", registry: "key", email: "mail", other: "info" };

let ctx = null; // { id, data, tab, root, body, dirty }

export async function renderCase(id, query) {
  const tab = query.get("tab") || (ctx && ctx.id === id ? ctx.tab : "overview");
  const fresh = !ctx || ctx.id !== id;
  if (fresh) ctx = { id, data: null, tab, dirty: false, lastSeen: 0 };
  ctx.tab = tab;
  const { shell } = await import("./app.js");
  const root = h("div", null, h("div", { class: "empty" }, h("span", { class: "spinner" })));
  shell("Case", [link("/cases", null, "Cases"), icon("chevron"), h("b", { id: "crumb-ref" }, "…")], root);
  ctx.root = root;
  try {
    if (fresh || !ctx.data) ctx.data = await api("GET", `/cases/${id}`);
    syncWorkspace();
    draw();
  } catch (e) { mount(root, empty("alert", "Case not available", e.message, link("/cases", { class: "btn" }, "Back to cases"))); return; }

  // Live sync: poll for changes made by teammates (or the background enrichment job).
  const timer = setInterval(poll, 4000);
  onLeave(() => {
    clearInterval(timer);
    const next = location.pathname;
    if (!next.startsWith(`/cases/${id}`)) { purgeArranger(); ctx = null; }
  });
}

function syncWorkspace() {
  const w = state.user.workspaces.find((x) => x.id === ctx.data.workspace_id);
  if (w && (!state.ws || state.ws.id !== w.id)) state.ws = w;
}

async function poll() {
  if (!ctx || !ctx.data) return;
  try {
    const v = await api("GET", `/cases/${ctx.id}/version`);
    const jobChanged = JSON.stringify(v.job) !== JSON.stringify(ctx.data.job);
    if (v.updated_at > ctx.data.updated_at || jobChanged) {
      const byOther = v.updated_by && v.updated_by !== state.user.id && v.updated_at > ctx.data.updated_at;
      if (ctx.dirty) { if (byOther) toast(`${v.updated_by_name} updated this case. Save your changes to see theirs.`, "info"); ctx.data.updated_at = v.updated_at; return; }
      ctx.data = await api("GET", `/cases/${ctx.id}`);
      if (byOther) toast(`Updated by ${v.updated_by_name}`, "info", 2000);
      // Don't wipe in-progress work: in the Log Arranger, or while a field has focus,
      // only refresh the header counts; otherwise redraw the tab with the new data.
      const ae = document.activeElement;
      const typing = ae && ctx.root.contains(ae) && /^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName);
      if (ctx.tab === "logs" || typing) refreshChrome(); else draw();
    } else if (v.job && v.job.running) { ctx.data.job = v.job; updateJobBar(); }
  } catch { /* transient */ }
}

export function setCase(data) { ctx.data = data; draw(); }
async function call(method, path, body, msg) {
  try { const d = await api(method, `/cases/${ctx.id}${path}`, body); if (d && d.id === ctx.id) setCase(d); if (msg) toast(msg); return d; }
  catch (e) { fail(e); return null; }
}

// ------------------------------------------------------------------ frame
function draw() {
  const c = ctx.data;
  const ref = document.getElementById("crumb-ref"); if (ref) ref.textContent = c.ref;
  document.title = `${c.ref} · S.T.A.R.K`;
  ctx.body = h("div");
  mount(ctx.root, header(c), stepper(c), tabsEl(c), ctx.body);
  drawTab();
}
function tabsEl(c) {
  const counts = { observables: c.observables.length, artifacts: c.artifacts.length, attack: c.techniques.length, timeline: c.events.length + c.actions.length };
  return h("div", { class: "tabs", id: "case-tabs", role: "tablist" }, TABS.map(([k, ic, label]) =>
    h("button", { class: `tab${ctx.tab === k ? " active" : ""}`, role: "tab", onclick: () => switchTab(k) }, icon(ic), label,
      counts[k] ? h("span", { class: "count" }, counts[k]) : null)));
}
function refreshChrome() {
  const s = ctx.root.querySelector(".stepper"); if (s) s.replaceWith(stepper(ctx.data));
  const t = document.getElementById("case-tabs"); if (t) t.replaceWith(tabsEl(ctx.data));
}
function switchTab(k) {
  if (k === ctx.tab) return;
  if (ctx.dirty && !window.confirm("You have unsaved report changes. Leave this tab?")) return;
  ctx.dirty = false; ctx.tab = k;
  history.replaceState(null, "", `/cases/${ctx.id}?tab=${k}`);
  draw();
}
function drawTab() {
  const fn = { overview: tabOverview, logs: tabLogs, observables: tabObservables, artifacts: tabArtifacts, attack: tabAttack,
    timeline: tabTimeline, report: tabReport, activity: tabActivity }[ctx.tab] || tabOverview;
  mount(ctx.body, fn(ctx.data));
}

function header(c) {
  const title = h("input", { class: "title-input", value: c.title, "aria-label": "Case title" });
  title.addEventListener("change", () => title.value.trim() && call("PATCH", "", { title: title.value.trim() }, "Title saved"));
  title.addEventListener("keydown", (e) => { if (e.key === "Enter") title.blur(); });
  const sel = (field, options, labels) => {
    const s = h("select", { class: "meta-select", "aria-label": field }, options.map((o) => h("option", { value: o, selected: c[field] === o }, labels ? labels[o] : o)));
    s.addEventListener("change", () => call("PATCH", "", { [field]: s.value }, "Updated"));
    return s;
  };
  const assignee = h("select", { class: "meta-select", "aria-label": "Assignee" }, h("option", { value: "" }, "Unassigned"),
    c.members.map((m) => h("option", { value: m.id, selected: c.assignee_id === m.id }, m.name)));
  assignee.addEventListener("change", () => call("PATCH", "", { assignee_id: assignee.value ? Number(assignee.value) : null }, "Assignee updated"));
  return h("div", { class: "case-head" },
    h("div", { class: "grow" },
      h("div", { class: "row small faint" }, h("span", { class: "mono" }, c.ref), "·", c.workspace.kind === "team" ? h("span", { class: "row gap-4" }, h("span", { class: "sync-dot" }), `Shared with ${c.workspace.name}`) : "Personal workspace",
        "·", `updated ${timeAgo(c.updated_at)}${c.updated_by_name ? ` by ${c.updated_by_name}` : ""}`),
      title,
      h("div", { class: "meta-row" },
        h("span", { class: "label" }, "Severity"), sel("severity", ["info", "low", "medium", "high", "critical"], SEV_LABEL),
        h("span", { class: "label" }, "Status"), sel("status", ["open", "in_progress", "contained", "closed"], STATUS_LABEL),
        h("span", { class: "label" }, "TLP"), sel("tlp", ["clear", "green", "amber", "amber+strict", "red"], { clear: "TLP:CLEAR", green: "TLP:GREEN", amber: "TLP:AMBER", "amber+strict": "TLP:AMBER+STRICT", red: "TLP:RED" }),
        h("span", { class: "label" }, "Assignee"), assignee)),
    h("div", { class: "row" },
      h("button", { class: "btn", onclick: (e) => exportMenu(e.currentTarget) }, icon("download"), "Export"),
      h("button", { class: "btn primary", onclick: () => switchTab("report") }, icon("file"), "Report")));
}
async function exportMenu(anchor) {
  const { popMenu } = await import("./core.js");
  const dl = (fmt) => { window.location.href = `/api/cases/${ctx.id}/export/${fmt}`; };
  popMenu(anchor, [
    { icon: "file", label: "Report (Markdown)", onclick: () => dl("report") },
    { icon: "layers", label: "STIX 2.1 bundle", onclick: () => dl("stix") },
    { icon: "grid", label: "Indicators (CSV)", onclick: () => dl("csv") },
    { icon: "target", label: "IRFlow Timeline IOC list", onclick: () => dl("irflow") },
    { icon: "hash", label: "VESTIGEX IOC sweep list", onclick: () => dl("vestigex") },
    { icon: "hash", label: "Known-bad hash set", onclick: () => dl("hashset") },
    "-",
    { icon: "trash", label: "Delete case…", onclick: async () => {
      if (!await confirmDialog(`Delete ${ctx.data.ref}?`, "This permanently removes the case, its indicators, artifacts and report. It cannot be undone.")) return;
      try { await api("DELETE", `/cases/${ctx.id}`); toast("Case deleted"); ctx = null; go("/cases"); } catch (e) { fail(e); }
    } },
  ]);
}

function stepper(c) {
  const steps = [
    ["logs", "Arrange logs", c.events.length ? `${c.events.length} event(s) pinned` : "Add evidence", c.events.length > 0 || c.observables.length > 0],
    ["observables", "Check indicators", c.observables.length ? `${c.observables.filter((o) => o.verdict !== "pending").length}/${c.observables.length} checked` : "None yet", c.observables.length > 0 && c.observables.every((o) => o.verdict !== "pending")],
    ["attack", "Map ATT&CK", c.techniques.length ? `${c.techniques.length} technique(s)` : "Not mapped", c.techniques.length > 0],
    ["report", "Write report", c.report_md ? `Saved ${timeAgo(c.report_updated_at)}` : "Not started", !!c.report_md],
  ];
  const current = steps.findIndex((s) => !s[3]);
  return h("div", { class: "stepper" }, steps.map(([tab, t, sub, done], i) =>
    h("button", { class: `step${done ? " done" : ""}${i === current ? " current" : ""}`, onclick: () => switchTab(tab) },
      h("div", { class: "n" }, done ? icon("check") : String(i + 1)), h("div", null, h("b", null, t), h("span", null, sub)))));
}

// --------------------------------------------------------------- overview
function tabOverview(c) {
  const desc = h("textarea", { class: "input", rows: 6, placeholder: "Summarise what happened, how it was detected and the current understanding. This becomes the start of the executive summary." }, c.description || "");
  desc.value = c.description || "";
  desc.addEventListener("input", () => { ctx.dirty = true; });
  desc.addEventListener("change", async () => { ctx.dirty = false; await call("PATCH", "", { description: desc.value }, "Notes saved"); });
  const counts = { malicious: 0, suspicious: 0, harmless: 0, other: 0 };
  c.observables.forEach((o) => { counts[o.verdict in counts ? o.verdict : "other"]++; });
  const comment = h("textarea", { class: "input", rows: 2, placeholder: c.workspace.kind === "team" ? "Write a note for the team…" : "Add a note…" });
  const kpi = (n, label, color, tab) => h("button", { class: "card stat", style: { cursor: "pointer", textAlign: "left", border: "1px solid var(--border)" }, onclick: () => switchTab(tab) },
    h("div", null, h("b", { style: { color } }, n), h("span", null, label)));
  return h("div", { class: "grid grid-main" },
    h("div", { class: "col gap-16" },
      h("div", { class: "grid grid-4" },
        kpi(counts.malicious, "Malicious indicators", "var(--mal)", "observables"), kpi(counts.suspicious, "Suspicious indicators", "var(--sus)", "observables"),
        kpi(c.artifacts.filter((a) => a.kind === "host").length, "Affected hosts", "var(--text)", "artifacts"), kpi(c.techniques.length, "ATT&CK techniques", "var(--accent)", "attack")),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h3", null, "Case notes"), h("span", { class: "hint" }, "Saves when you click outside")),
        h("div", { class: "card-body" }, desc,
          h("div", { class: "form-grid mt-16" },
            h("div", { class: "field" }, h("label", null, "Incident type"), (() => {
              const s = h("select", { class: "input" }, ["", "Malware", "Phishing", "Ransomware", "Unauthorized access", "Account compromise", "Data exfiltration", "Web application attack", "Denial of service", "Insider threat", "Policy violation", "Other"]
                .map((x) => h("option", { value: x, selected: c.classification === x }, x || "Not sure yet")));
              s.onchange = () => call("PATCH", "", { classification: s.value }, "Saved"); return s; })()),
            h("div", { class: "field" }, h("label", null, "Opened"), h("input", { class: "input", value: fmtDate(c.created_at), disabled: true }))))),
      c.observables.some((o) => o.verdict === "malicious" || o.verdict === "suspicious") ? h("div", { class: "card" },
        h("div", { class: "card-head" }, h("h3", null, "Flagged indicators"), h("button", { class: "link-btn small", onclick: () => switchTab("observables") }, "View all")),
        h("div", { class: "card-body" }, c.observables.filter((o) => o.verdict === "malicious" || o.verdict === "suspicious").slice(0, 8).map((o) =>
          h("div", { class: "list-row" }, ioc(o.value, o.verdict), h("span", { class: "tag" }, TYPE_LABEL[o.type]), h("span", { class: "spacer" }),
            o.families.length ? h("span", { class: "small muted ellipsis", style: { maxWidth: "220px" } }, o.families.slice(0, 2).join(", ")) : null, verdictPill(o.verdict))))) : null),
    h("div", { class: "col gap-16" },
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h3", null, c.workspace.kind === "team" ? "Team discussion" : "Notes"), h("span", { class: "faint small" }, c.comments.length || "")),
        h("div", { class: "card-body col gap-12" },
          c.comments.length ? c.comments.map((m) => h("div", { class: "row top gap-12" }, avatar(m.user_name || "?"),
            h("div", { class: "grow comment" }, h("div", { class: "row small" }, h("b", null, m.user_name), h("span", { class: "faint" }, timeAgo(m.created_at))), h("div", { style: { whiteSpace: "pre-wrap" } }, m.body)))) :
            h("div", { class: "muted small" }, "No messages yet."),
          comment, h("div", { class: "row" }, h("span", { class: "spacer" }), h("button", { class: "btn sm primary", onclick: async () => {
            if (!comment.value.trim()) return; await call("POST", "/comments", { body: comment.value });
          } }, icon("message"), "Post")))),
      h("div", { class: "card card-pad" }, h("h3", { class: "mb-8" }, "Next step"), nextStep(c))));
}
function nextStep(c) {
  let text, tab, label;
  if (!c.observables.length && !c.events.length) { text = "Start with the evidence: drop log exports into the Log Arranger, or paste indicators directly."; tab = "logs"; label = "Open Log Arranger"; }
  else if (c.observables.some((o) => o.verdict === "pending")) { text = "Some indicators haven't been checked yet. Run a reputation check on them."; tab = "observables"; label = "Check indicators"; }
  else if (!c.techniques.length) { text = "Map what the attacker did to MITRE ATT&CK. Suggestions come from your logs."; tab = "attack"; label = "Map techniques"; }
  else if (!c.report_md) { text = "You have enough to draft the initial incident report."; tab = "report"; label = "Generate report"; }
  else { text = "Keep the report up to date as the investigation goes on, and record the response actions you take."; tab = "timeline"; label = "Record actions"; }
  return h("div", null, h("p", { class: "muted small" }, text), h("button", { class: "btn primary sm", onclick: () => switchTab(tab) }, label, icon("chevron")));
}

// ------------------------------------------------------------------ logs
function tabLogs(c) {
  return renderArranger(c, {
    addObservables: async (items) => { const d = await api("POST", `/cases/${ctx.id}/observables`, { items, source: "log arranger" }); toast(`Added ${d.added} indicator(s)${d.skipped ? `, ${d.skipped} already in the case` : ""}`); ctx.data = d.case; return d; },
    addArtifacts: async (items) => { ctx.data = await api("POST", `/cases/${ctx.id}/artifacts`, { items }); toast(`Added ${items.length} artifact(s)`); },
    addTechniques: async (items) => { ctx.data = await api("POST", `/cases/${ctx.id}/techniques`, { items }); toast(`Mapped ${items.length} technique(s)`); },
    addEvents: async (items) => { ctx.data = await api("POST", `/cases/${ctx.id}/events`, { items }); toast(`Pinned ${items.length} event(s) to the case timeline`); },
    refreshCounts: refreshChrome,
  });
}

// ----------------------------------------------------------- observables
let obsFilter = "all";
function tabObservables(c) {
  const ta = h("textarea", { class: "input mono", rows: 3, placeholder: "Paste indicators: IPs, domains, URLs, hashes, emails. One per line or free text, defanged is fine." });
  const addBtn = h("button", { class: "btn" }, icon("plus"), "Add");
  const addCheck = h("button", { class: "btn primary" }, icon("zap"), "Add & check");
  const add = async (enrich, btn) => {
    if (!ta.value.trim()) return;
    busy(btn, true);
    try { const d = await api("POST", `/cases/${ctx.id}/observables`, { text: ta.value, enrich }); toast(d.added ? `Added ${d.added} indicator(s)` : "No new indicators found", d.added ? "ok" : "info"); setCase(d.case); }
    catch (e) { fail(e); busy(btn, false); }
  };
  addBtn.onclick = () => add(false, addBtn); addCheck.onclick = () => add(true, addCheck);
  const pending = c.observables.filter((o) => o.verdict === "pending").length;
  const job = c.job;
  const enrichAll = h("button", { class: "btn primary", disabled: !c.observables.length || (job && job.running) }, icon("zap"), pending ? `Check ${pending} new` : "Re-check all");
  enrichAll.onclick = async () => {
    const ids = pending ? c.observables.filter((o) => o.verdict === "pending").map((o) => o.id) : [];
    busy(enrichAll, true, "Starting…");
    try { await api("POST", `/cases/${ctx.id}/enrich`, { ids }); ctx.data.job = { running: true, done: 0, total: 0 }; drawTab(); } catch (e) { fail(e); busy(enrichAll, false); }
  };
  const filters = [["all", "All"], ["malicious", "Malicious"], ["suspicious", "Suspicious"], ["harmless", "Clean"], ["unknown", "No data"], ["pending", "Not checked"]];
  const rows = c.observables.filter((o) => obsFilter === "all" || o.verdict === obsFilter);
  const order = { malicious: 0, suspicious: 1, pending: 2, unknown: 3, error: 3, harmless: 4 };
  rows.sort((a, b) => (order[a.verdict] ?? 3) - (order[b.verdict] ?? 3));
  const selected = new Set();
  const delSel = h("button", { class: "btn sm danger hidden" }, icon("trash"), "Remove selected");
  delSel.onclick = async () => { if (await confirmDialog(`Remove ${selected.size} indicator(s)?`, "They will be removed from this case.", { ok: "Remove" })) call("POST", "/observables/delete", { ids: [...selected] }); };
  const onSel = (id, on) => { on ? selected.add(id) : selected.delete(id); delSel.classList.toggle("hidden", !selected.size); };

  return h("div", { class: "col gap-16" },
    h("div", { class: "card card-pad" }, h("div", { class: "row top gap-12" }, h("div", { class: "grow" }, ta), h("div", { class: "col" }, addCheck, addBtn))),
    job && (job.running || job.error) ? jobBar(job) : null,
    h("div", { class: "card" },
      h("div", { class: "arr-toolbar" },
        filters.map(([k, l]) => { const n = k === "all" ? c.observables.length : c.observables.filter((o) => o.verdict === k).length;
          return n || k === "all" ? h("button", { class: `chip-btn${obsFilter === k ? " on" : ""}`, onclick: () => { obsFilter = k; drawTab(); } }, l, h("span", { class: "n" }, n)) : null; }),
        h("span", { class: "spacer" }), delSel, enrichAll),
      c.observables.length ? h("div", { class: "table-wrap", style: { maxHeight: "640px" } }, h("table", { class: "table" },
        h("thead", null, h("tr", null, h("th", { style: { width: "28px" } }), h("th", null, "Indicator"), h("th", null, "Type"), h("th", null, "Verdict"), h("th", null, "Score"), h("th", null, "Flagged by"), h("th", null, "Context"), h("th", null, ""))),
        h("tbody", null, rows.map((o) => h("tr", { class: "clickable", onclick: () => obsDrawer(o) },
          h("td", { onclick: (e) => e.stopPropagation() }, h("input", { type: "checkbox", class: "check", onchange: (e) => onSel(o.id, e.target.checked) })),
          h("td", { style: { maxWidth: "380px" } }, ioc(o.value, o.verdict), o.note ? h("div", { class: "tiny faint mt-8 ellipsis" }, o.note) : null),
          h("td", null, h("span", { class: "row gap-4 small muted" }, icon(TYPE_ICON[o.type] || "info"), TYPE_LABEL[o.type])),
          h("td", null, verdictPill(o.verdict)), h("td", { class: "num" }, o.score ?? ""),
          h("td", { class: "small" }, o.flagged_by.join(", ") || h("span", { class: "faint" }, "-")),
          h("td", { class: "small muted", style: { maxWidth: "240px" } }, h("div", { class: "ellipsis" }, o.families.slice(0, 3).join(", ") || o.tags.slice(0, 3).join(", "))),
          h("td", null, h("button", { class: "btn ghost sm icon", title: "Details" }, icon("chevron"))))))))
        : empty("target", "No indicators yet", "Paste them above, or pull them out of logs with the Log Arranger.", h("button", { class: "btn", onclick: () => switchTab("logs") }, icon("layers"), "Open Log Arranger"))));
}
function jobBar(job) {
  const pct = job.total ? Math.round((100 * job.done) / job.total) : 5;
  return h("div", { class: "card card-pad", id: "job-bar" },
    job.error ? h("div", { class: "notice warn" }, icon("alert"), h("div", null, h("b", null, "Reputation check failed"), h("span", { class: "small" }, job.error, " "), link("/settings", { class: "small" }, "Open API key settings")))
      : h("div", null, h("div", { class: "row mb-8" }, h("span", { class: "spinner" }), h("b", null, "Checking reputation…"), h("span", { class: "spacer" }), h("span", { class: "small muted", id: "job-text" }, job.total ? `${job.done} / ${job.total} lookups` : "starting")),
        h("div", { class: "progress" }, h("div", { id: "job-progress", style: { width: `${pct}%` } })),
        h("div", { class: "hint mt-8" }, "You can keep working, and teammates will see the results as they arrive. Free API tiers are rate-limited, so large batches take a few minutes.")));
}
function updateJobBar() {
  const j = ctx.data.job; const p = document.getElementById("job-progress"); const t = document.getElementById("job-text");
  if (p && j.total) p.style.width = `${Math.round((100 * j.done) / j.total)}%`;
  if (t && j.total) t.textContent = `${j.done} / ${j.total} lookups`;
}
function obsDrawer(o) {
  const note = h("textarea", { class: "input", rows: 3, placeholder: "Analyst note (why it matters, where it was seen)…" }); note.value = o.note || "";
  const override = h("select", { class: "input" }, ["", "malicious", "suspicious", "harmless", "unknown"].map((v) => h("option", { value: v }, v ? `Mark as ${v}` : "Keep source verdict")));
  const m = modal({ drawer: true, title: o.value, subtitle: `${TYPE_LABEL[o.type]} · added ${timeAgo(o.created_at)}${o.source ? ` via ${o.source}` : ""}${o.enriched_at ? ` · checked ${timeAgo(o.enriched_at)}` : ""}`,
    body: h("div", { class: "col gap-16" },
      h("div", { class: "row wrap" }, verdictPill(o.verdict), o.score != null ? h("span", { class: "tag" }, `score ${o.score}`) : null, ...o.families.map((f) => h("span", { class: "tag" }, f)),
        h("span", { class: "spacer" }), h("button", { class: "btn sm", onclick: () => copy(o.value) }, icon("copy"), "Copy"),
        h("button", { class: "btn sm", onclick: () => copy(o.value.replace(/\./g, "[.]").replace(/^http/i, "hxxp"), "Defanged copy") }, "Copy defanged")),
      o.results.length ? h("div", { class: "card card-pad" }, h("h3", { class: "mb-8" }, "Source results"),
        h("div", null, o.results.map((p) => h("div", { class: "provider-row" }, h("b", null, p.provider), h("div", null, verdictPill(p.verdict)),
          h("div", { class: "small" }, p.error ? h("span", { style: { color: "var(--err)" } }, p.error) : p.summary,
            p.tags && p.tags.length ? h("div", { class: "row wrap gap-4 mt-8" }, p.tags.slice(0, 8).map((t) => h("span", { class: "tag" }, t))) : null,
            p.link ? h("div", null, h("a", { href: p.link, target: "_blank", rel: "noopener noreferrer", class: "tiny" }, "Open in source ↗")) : null)))))
        : h("div", { class: "notice info" }, icon("info"), h("div", { class: "small" }, "Not checked yet. Use “Check” on the Observables tab.")),
      h("div", { class: "field" }, h("label", null, "Analyst note"), note), h("div", { class: "field" }, h("label", null, "Verdict override"), override)),
    foot: [h("button", { class: "btn danger", onclick: async () => { m.close(); await call("POST", "/observables/delete", { ids: [o.id] }, "Removed"); } }, icon("trash"), "Remove"),
      h("span", { class: "spacer" }),
      h("button", { class: "btn", onclick: async () => { m.close(); await api("POST", `/cases/${ctx.id}/enrich`, { ids: [o.id] }).catch(fail); ctx.data.job = { running: true }; ctx.tab = "observables"; draw(); } }, icon("refresh"), "Check"),
      h("button", { class: "btn primary", onclick: async () => { m.close(); await call("PATCH", `/observables/${o.id}`, { note: note.value, ...(override.value ? { verdict: override.value } : {}) }, "Saved"); } }, "Save")] });
}

// -------------------------------------------------------------- artifacts
function tabArtifacts(c) {
  const kind = h("select", { class: "input", style: { width: "170px" } }, Object.entries(KIND_LABEL).map(([k, l]) => h("option", { value: k }, l.replace(/s$/, ""))));
  const value = h("input", { class: "input mono", placeholder: "e.g. FIN-WS-014, CONTOSO\\jdoe, C:\\Users\\Public\\run.ps1" });
  const note = h("input", { class: "input", placeholder: "Note (optional)" });
  const add = async () => { if (!value.value.trim()) return; await call("POST", "/artifacts", { items: [{ kind: kind.value, value: value.value, note: note.value }] }, "Artifact added"); };
  value.addEventListener("keydown", (e) => { if (e.key === "Enter") add(); });
  const groups = Object.keys(KIND_LABEL).map((k) => [k, c.artifacts.filter((a) => a.kind === k)]).filter(([, l]) => l.length);
  return h("div", { class: "col gap-16" },
    h("div", { class: "card card-pad" }, h("div", { class: "row wrap" }, kind, h("div", { class: "grow" }, value), h("div", { style: { width: "240px" } }, note), h("button", { class: "btn primary", onclick: add }, icon("plus"), "Add")),
      h("div", { class: "hint mt-8" }, "Artifacts are affected assets and evidence that aren't reputation indicators: hosts, accounts, processes, files, registry keys. Add them from the Log Arranger in bulk.")),
    groups.length ? h("div", { class: "grid grid-2" }, groups.map(([k, items]) => h("div", { class: "card" },
      h("div", { class: "card-head" }, icon(KIND_ICON[k]), h("h3", null, KIND_LABEL[k]), h("span", { class: "faint small" }, items.length)),
      h("div", { class: "card-body" }, items.map((a) => h("div", { class: "list-row" },
        h("div", { class: "grow", style: { minWidth: 0 } }, k === "command_line" ? h("pre", { class: "raw", style: { margin: 0 } }, a.value) : ioc(a.value), a.note ? h("div", { class: "tiny muted mt-8" }, a.note) : null),
        h("button", { class: "btn ghost sm icon", title: "Remove", onclick: () => call("DELETE", `/artifacts/${a.id}`) }, icon("x"))))))))
      : h("div", { class: "card" }, empty("server", "No artifacts yet", "Record the hosts, accounts and files involved. They feed the “Affected assets” part of the report.")));
}

// ----------------------------------------------------------------- attack
let mitreCache = null;
function tabAttack(c) {
  const wrap = h("div", { class: "col gap-16" });
  const search = h("input", { class: "input", placeholder: "Search techniques, e.g. “powershell”, “T1003”, “lateral”…" });
  const results = h("div", { class: "side-list", style: { maxHeight: "340px" } });
  const draw2 = async () => {
    if (!mitreCache) mitreCache = await api("GET", "/mitre");
    const q = search.value.trim().toLowerCase();
    const have = new Set(c.techniques.map((t) => t.technique_id));
    const list = mitreCache.techniques.filter((t) => !q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q) || t.tactic.toLowerCase().includes(q)).slice(0, 60);
    mount(results, list.map((t) => h("div", { class: "side-item" },
      h("span", { class: "mono tiny", style: { color: "var(--accent)", width: "70px", flex: "none" } }, t.id),
      h("div", { class: "grow" }, h("div", { class: "small" }, t.name), h("div", { class: "tiny faint" }, t.tactic)),
      have.has(t.id) ? h("span", { class: "pill harmless" }, "Added") : h("button", { class: "btn sm", onclick: () => call("POST", "/techniques", { items: [{ technique_id: t.id }] }, `${t.id} mapped`) }, icon("plus")))));
  };
  search.addEventListener("input", debounce(draw2, 150));
  const tactics = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
  const by = {}; c.techniques.forEach((t) => { (by[t.tactic] = by[t.tactic] || []).push(t); });
  const board = c.techniques.length ? h("div", { class: "attack-board" }, tactics.filter((t) => by[t]).map((tac) => h("div", { class: "tactic-col" },
    h("h4", null, tac, h("span", { class: "faint" }, by[tac].length)),
    by[tac].map((t) => h("div", { class: "tech-card" },
      h("div", { class: "row" }, h("a", { class: "tid", href: `https://attack.mitre.org/techniques/${t.technique_id.replace(".", "/")}/`, target: "_blank", rel: "noopener noreferrer" }, t.technique_id),
        h("span", { class: "spacer" }), h("button", { class: "btn ghost sm icon", title: "Remove", onclick: () => call("DELETE", `/techniques/${t.id}`) }, icon("x"))),
      h("div", { class: "name" }, t.name),
      (() => { const n = h("textarea", { class: "input", rows: 2, placeholder: "Evidence / note", style: { fontSize: "12px" } }); n.value = t.note || "";
        n.addEventListener("change", () => call("PATCH", `/techniques/${t.id}`, { note: n.value }, "Note saved")); return n; })())))))
    : empty("grid", "No techniques mapped yet", "Use the suggestions from the Log Arranger, or search the catalogue on the right.", h("button", { class: "btn", onclick: () => switchTab("logs") }, icon("layers"), "Get suggestions from logs"));
  mount(wrap, h("div", { class: "grid grid-main" },
    h("div", { class: "card card-pad" }, h("div", { class: "row mb-16" }, h("h3", { class: "grow" }, "Attack chain"), h("span", { class: "small muted" }, `${c.techniques.length} technique(s) across ${Object.keys(by).length} tactic(s)`)), board),
    h("div", { class: "card card-pad" }, h("h3", { class: "mb-8" }, "Add a technique"), search, h("div", { class: "mt-8" }, results),
      h("div", { class: "hint mt-8" }, "A curated set of commonly seen Enterprise techniques. Any other ID can be added too: type it and press Enter."))));
  search.addEventListener("keydown", (e) => { if (e.key === "Enter" && /^t\d{4}(\.\d{3})?$/i.test(search.value.trim())) call("POST", "/techniques", { items: [{ technique_id: search.value.trim() }] }, "Technique mapped"); });
  draw2().catch(fail);
  return wrap;
}

// --------------------------------------------------------------- timeline
function tabTimeline(c) {
  const when = h("input", { class: "input mono", placeholder: "2026-11-01 10:00:01 (UTC)", style: { width: "220px" } });
  const what = h("input", { class: "input", placeholder: "What happened? e.g. powershell.exe spawned by WINWORD.EXE on FIN-WS-014" });
  const addEv = () => what.value.trim() && call("POST", "/events", { items: [{ time: when.value.trim().replace(" ", "T") + (when.value.trim() && !/Z$/.test(when.value.trim()) ? "Z" : ""), text: what.value }] }, "Event added");
  what.addEventListener("keydown", (e) => { if (e.key === "Enter") addEv(); });
  const act = h("input", { class: "input", placeholder: "e.g. Isolated FIN-WS-014 via EDR; blocked 185.220.101.1 on perimeter firewall" });
  const addAct = () => act.value.trim() && call("POST", "/actions", { text: act.value }, "Action recorded");
  act.addEventListener("keydown", (e) => { if (e.key === "Enter") addAct(); });
  return h("div", { class: "grid grid-2" },
    h("div", { class: "card" }, h("div", { class: "card-head" }, icon("clock"), h("h3", null, "Key events"), h("span", { class: "faint small" }, c.events.length)),
      h("div", { class: "card-body" },
        h("div", { class: "row wrap mb-16" }, when, h("div", { class: "grow" }, what), h("button", { class: "btn", onclick: addEv }, icon("plus"))),
        c.events.length ? c.events.map((e) => h("div", { class: "list-row" }, h("span", { class: "mono tiny muted", style: { width: "150px", flex: "none" } }, fmtTime(e.time) || "-"),
          h("div", { class: "grow small" }, e.text), h("button", { class: "btn ghost sm icon", onclick: () => call("DELETE", `/events/${e.id}`) }, icon("x"))))
          : h("div", { class: "muted small" }, "Pin important log lines from the Log Arranger, or add events by hand. They become the report timeline."))),
    h("div", { class: "card" }, h("div", { class: "card-head" }, icon("check"), h("h3", null, "Actions taken"), h("span", { class: "faint small" }, c.actions.length)),
      h("div", { class: "card-body" },
        h("div", { class: "row mb-16" }, h("div", { class: "grow" }, act), h("button", { class: "btn primary", onclick: addAct }, icon("plus"), "Record")),
        c.actions.length ? c.actions.map((a) => h("div", { class: "list-row" }, h("div", { class: "stat-icon", style: { width: "26px", height: "26px", background: "var(--ok-soft)", color: "var(--ok)", borderRadius: "50%" } }, icon("check")),
          h("div", { class: "grow" }, h("div", { class: "small" }, a.text), h("div", { class: "tiny faint" }, `${fmtTime(a.done_at)} · ${a.added_by_name || ""}`)),
          h("button", { class: "btn ghost sm icon", onclick: () => call("DELETE", `/actions/${a.id}`) }, icon("x"))))
          : h("div", { class: "muted small" }, "Record each containment, eradication or recovery step as you take it. They appear in section 4 of the report."))));
}

// ----------------------------------------------------------------- report
function tabReport(c) {
  const editor = h("textarea", { class: "input report-editor", spellcheck: "true", placeholder: "Generate a draft, or start writing in Markdown. Wrap indicators in `backticks` to highlight them." });
  editor.value = c.report_md || "";
  const preview = h("div", { class: "md" });
  const status = h("span", { class: "small muted" }, c.report_md ? `Saved ${timeAgo(c.report_updated_at)}` : "Not saved yet");
  const render = () => { preview.innerHTML = renderMarkdown(editor.value) || '<p class="muted">The preview appears here.</p>'; };
  editor.addEventListener("input", debounce(() => { render(); ctx.dirty = editor.value !== (ctx.data.report_md || ""); status.textContent = ctx.dirty ? "Unsaved changes" : "Saved"; }, 120));
  const defang = h("input", { type: "checkbox" });
  const gen = h("button", { class: "btn primary" }, icon("sparkle"), c.report_md ? "Regenerate draft" : "Generate draft");
  gen.onclick = async () => {
    if (editor.value.trim() && !await confirmDialog("Replace the current text?", "A new draft will replace what's in the editor. Your saved version stays until you click Save.", { ok: "Generate", danger: false })) return;
    busy(gen, true, "Writing…");
    try { const r = await api("POST", `/cases/${ctx.id}/report/generate`, { defang: defang.checked }); editor.value = r.markdown; render(); ctx.dirty = true; status.textContent = "Draft generated (not saved)"; toast("Draft ready. Review it, then save."); }
    catch (e) { fail(e); }
    busy(gen, false);
  };
  const save = h("button", { class: "btn" }, icon("check"), "Save");
  save.onclick = async () => { busy(save, true); const d = await call("PATCH", "", { report_md: editor.value }, "Report saved"); if (d) { ctx.dirty = false; } else busy(save, false); };
  editor.addEventListener("keydown", (e) => { if ((e.metaKey || e.ctrlKey) && e.key === "s") { e.preventDefault(); save.click(); } });
  render();
  const checklist = [
    ["Executive summary", true], ["Technical analysis", c.observables.length > 0 || c.events.length > 0], ["MITRE ATT&CK", c.techniques.length > 0],
    ["Recommendations", true], ["Actions taken", c.actions.length > 0], ["Artifacts list", c.observables.length + c.artifacts.length > 0],
  ];
  return h("div", { class: "col gap-16" },
    h("div", { class: "card card-pad no-print" }, h("div", { class: "row wrap gap-12" },
      h("div", { class: "grow" }, h("h3", null, "Incident report writer"), h("div", { class: "small muted" }, "Drafts the initial analysis from this case: executive summary, technical analysis, ATT&CK mapping, recommendations, actions taken and artifacts. Indicators appear as code.")),
      h("label", { class: "check small" }, defang, "Defang indicators"), gen, save),
      h("div", { class: "row wrap gap-12 mt-16" }, checklist.map(([t, ok]) => h("span", { class: "row gap-4 small", style: { color: ok ? "var(--ok)" : "var(--text-3)" } }, icon(ok ? "check" : "info"), t, ok ? "" : " (no data yet)")))),
    h("div", { class: "report-layout" },
      h("div", { class: "card" }, h("div", { class: "card-head no-print" }, icon("edit"), h("h3", null, "Markdown"), status), h("div", { class: "card-body" }, editor)),
      h("div", { class: "card" }, h("div", { class: "card-head no-print" }, icon("eye"), h("h3", null, "Preview"),
        h("button", { class: "btn sm", onclick: () => copy(editor.value, "Markdown copied") }, icon("copy"), "Copy"),
        h("button", { class: "btn sm", onclick: () => download(`${c.ref}-report.md`, editor.value, "text/markdown") }, icon("download"), ".md"),
        h("button", { class: "btn sm", onclick: () => window.print() }, icon("printer"), "Print / PDF")),
        h("div", { class: "report-paper" }, preview))));
}

// --------------------------------------------------------------- activity
function tabActivity(c) {
  return h("div", { class: "card card-pad" }, c.activity.length ? h("div", { class: "feed" }, c.activity.map((a) => h("div", { class: "feed-item" }, avatar(a.user_name || "?"),
    h("div", { class: "grow" }, h("div", null, h("b", null, a.user_name || "Someone"), " ", a.text), h("time", null, `${fmtDate(a.created_at)} · ${timeAgo(a.created_at)}`)))))
    : h("div", { class: "muted" }, "No activity yet."));
}

export { statusPill, sevPill };
