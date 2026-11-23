import {
  api, avatar, busy, confirmDialog, copy, download, empty, fail, fmtTime, go, h, icon, ioc, link, modal, mount, onLeave,
  sevPill, state, statusPill, timeAgo, toast, verdictPill, TYPE_LABEL, TYPE_ICON, STATUS_LABEL, SEV_LABEL, debounce, fmtDate,
} from "./core.js";
import { renderMarkdown } from "./md.js";
import { renderArranger, purgeArranger } from "./arranger.js";

const TABS = [
  ["overview", "home", "Overview"], ["logs", "layers", "Log Arranger"], ["findings", "alert", "Findings"], ["observables", "target", "Observables"], ["related", "folder", "Related"],
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
  const counts = { findings: c.findings.filter((f) => f.status !== "dismissed").length, observables: c.observables.length, artifacts: c.artifacts.length, attack: c.techniques.length, timeline: c.events.length + c.actions.length };
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
  const fn = { overview: tabOverview, logs: tabLogs, findings: tabFindings, observables: tabObservables, related: tabRelated, artifacts: tabArtifacts, attack: tabAttack,
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
        h("span", { class: "label" }, "Status"), sel("status", ["open", "in_progress", "on_hold", "contained", "resolved", "closed", "cancelled"], STATUS_LABEL),
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
    { icon: "layers", label: "MISP event (JSON)", onclick: () => dl("misp") },
    { icon: "upload", label: "Send to MISP", onclick: () => sendToMisp() },
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

async function sendToMisp() {
  if (!await confirmDialog(`Send ${ctx.data.ref} to MISP?`, "Malicious, suspicious and unrated indicators are added to an unpublished MISP event shared with your organisation only, tagged with the case TLP and ATT&CK techniques. Sending again updates the same event.", { danger: false, ok: "Send to MISP" })) return;
  try {
    const r = await api("POST", `/cases/${ctx.id}/misp`);
    toast(`${r.created ? "Created" : "Updated"} MISP event ${r.id} with ${r.attributes} indicator(s)`, "ok", 5000);
    window.open(r.url, "_blank", "noopener");
  } catch (e) { fail(e); }
}

function stepper(c) {
  const steps = [
    ["logs", "Analyse logs", c.findings.length ? `${c.findings.length} finding(s)` : c.events.length ? `${c.events.length} event(s) pinned` : "Add evidence", c.findings.length > 0 || c.events.length > 0 || c.observables.length > 0],
    ["observables", "Check indicators", c.observables.length ? `${c.observables.filter((o) => o.verdict !== "pending").length}/${c.observables.length} checked` : "None yet", c.observables.length > 0 && c.observables.every((o) => o.verdict !== "pending")],
    ["attack", "Review ATT&CK", c.techniques.length ? `${c.techniques.length} technique(s) mapped` : "Maps as evidence arrives", c.techniques.length > 0],
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
        kpi(new Set([...c.artifacts.filter((a) => a.kind === "host").map((a) => a.value.toLowerCase().split(".")[0]),
          ...c.findings.filter((f) => f.status !== "dismissed").flatMap((f) => ((f.entities || {}).hosts || []).map((x) => x.toLowerCase().split(".")[0]))]).size,
          "Affected hosts", "var(--text)", "findings"), kpi(c.techniques.length, "ATT&CK techniques", "var(--accent)", "attack")),
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
      verdictCard(c),
      alertCard(c),
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
  else if (!c.techniques.length) { text = "No ATT&CK techniques are supported by the evidence yet. Analyse logs or check indicators and they map automatically."; tab = "logs"; label = "Open Log Arranger"; }
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
    autoMap: async (items, products) => {
      const d = await api("POST", `/cases/${ctx.id}/techniques/from-logs`, { items, products });
      ctx.data = d.case; refreshChrome();
      if (d.added) toast(`Mapped ${d.added} ATT&CK technique(s) automatically from these logs`, "info");
    },
    addFindings: async (items) => { ctx.data = await api("POST", `/cases/${ctx.id}/findings`, { items }); toast(`Added ${items.length} finding(s); their ATT&CK techniques were mapped too`); },
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
        : h("div", { class: "notice info" }, icon("info"), h("div", { class: "small" }, o.enriched_at ? `None of the ${o.sources_checked || ""} sources checked has a record of this indicator. Sources without data are not shown.` : "Not checked yet. Use “Check” on the Observables tab.")),
      seenIn(o.value),
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
  const SRC_LABEL = { finding: "finding", intel: "threat intel", logs: "logs", event: "timeline", artifact: "artifact", alert: "alert name", manual: "added by analyst", auto: "auto" };
  const hide = (t) => call("POST", "/techniques/hide", { technique_id: t.technique_id }, `${t.technique_id} removed from the mapping`);
  const board = c.techniques.length ? h("div", { class: "attack-board" }, tactics.filter((t) => by[t]).map((tac) => h("div", { class: "tactic-col" },
    h("h4", null, tac, h("span", { class: "faint" }, by[tac].length)),
    by[tac].map((t) => h("div", { class: "tech-card" },
      h("div", { class: "row" }, h("a", { class: "tid", href: `https://attack.mitre.org/techniques/${t.technique_id.replace(".", "/")}/`, target: "_blank", rel: "noopener noreferrer" }, t.technique_id),
        t.auto ? h("span", { class: "tag", title: "Mapped automatically from the case evidence" }, icon("zap"), "Auto") : null,
        h("span", { class: "spacer" }), h("button", { class: "btn ghost sm icon", title: "Remove from the mapping", onclick: () => hide(t) }, icon("x"))),
      h("div", { class: "name" }, t.name),
      (t.sources || []).length ? h("div", { class: "row wrap gap-4 mt-8" }, t.sources.map((s2) => h("span", { class: "tiny faint" }, SRC_LABEL[s2] || s2))) : null,
      (t.basis || []).length ? h("ul", { class: "tiny muted", style: { paddingLeft: "16px", margin: "4px 0", wordBreak: "break-word" } }, t.basis.slice(0, 4).map((b) => h("li", null, b))) : null,
      (() => { const n = h("textarea", { class: "input", rows: 2, placeholder: "Analyst note (optional)", style: { fontSize: "12px" } }); n.value = t.note || "";
        n.addEventListener("change", () => (t.id ? call("PATCH", `/techniques/${t.id}`, { note: n.value }, "Note saved")
          : call("POST", "/techniques", { items: [{ technique_id: t.technique_id, note: n.value, source: "auto" }] }, "Note saved"))); return n; })())))))
    : empty("grid", "Nothing mapped yet", "Techniques are mapped automatically as evidence arrives: security findings, logs in the Log Arranger, threat intelligence on indicators, pinned events and artifacts. You can also search the catalogue.", h("button", { class: "btn", onclick: () => switchTab("logs") }, icon("layers"), "Open Log Arranger"));
  const hidden = c.techniques_hidden || [];
  const autoN = c.techniques.filter((t) => t.auto).length;
  mount(wrap, h("div", { class: "grid grid-main" },
    h("div", { class: "card card-pad" }, h("div", { class: "row mb-16 wrap" }, h("h3", { class: "grow" }, "Attack chain"), h("span", { class: "small muted" }, `${c.techniques.length} technique(s) across ${Object.keys(by).length} tactic(s)${autoN ? ` · ${autoN} mapped automatically` : ""}`)),
      h("div", { class: "hint mb-16" }, "Mapping follows the evidence: findings, the logs you arrange, threat intelligence on the case indicators, pinned events and artifacts. Each technique lists what supports it. Remove anything that doesn't fit and it stays removed."),
      board,
      hidden.length ? h("details", { class: "mt-16" }, h("summary", { class: "small", style: { cursor: "pointer" } }, `Removed by an analyst (${hidden.length})`),
        h("div", { class: "row wrap gap-4 mt-8" }, hidden.map((t) => h("button", { class: "chip-btn", title: "Restore", onclick: () => call("POST", "/techniques/restore", { technique_id: t.id }, `${t.id} restored`) }, `${t.id} ${t.name}`, icon("refresh"))))) : null),
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
  const template = h("select", { class: "meta-select", "aria-label": "Template" },
    h("option", { value: "soc" }, "SOC write-up (decides append / close / incident)"), h("option", { value: "technical" }, "Detailed technical report"));
  const outcome = h("select", { class: "meta-select", "aria-label": "Outcome" },
    [["", "Outcome: decide automatically"], ["1", "Force: append to ticket"], ["2", "Force: close as non-threatening"], ["3", "Force: raise an incident"]].map(([v, l]) => h("option", { value: v }, l)));
  template.onchange = () => { outcome.disabled = template.value !== "soc"; };
  const banner = h("div");
  const gen = h("button", { class: "btn primary" }, icon("sparkle"), c.report_md ? "Regenerate draft" : "Generate draft");
  gen.onclick = async () => {
    if (editor.value.trim() && !await confirmDialog("Replace the current text?", "A new draft will replace what's in the editor. Your saved version stays until you click Save.", { ok: "Generate", danger: false })) return;
    busy(gen, true, "Writing…");
    try {
      const r = await api("POST", `/cases/${ctx.id}/report/generate`, { template: template.value, outcome: outcome.value ? Number(outcome.value) : undefined });
      editor.value = r.markdown; render(); ctx.dirty = true; status.textContent = "Draft generated (not saved)";
      mount(banner, r.template === "soc" ? [decisionBanner(r), r.note ? h("div", { class: "notice warn mt-8" }, icon("info"), h("div", { class: "small" }, r.note)) : null] : null);
      toast("Draft ready. Review it, then save.");
    } catch (e) { fail(e); }
    busy(gen, false);
  };
  const save = h("button", { class: "btn" }, icon("check"), "Save");
  save.onclick = async () => { busy(save, true); const d = await call("PATCH", "", { report_md: editor.value }, "Report saved"); if (d) { ctx.dirty = false; } else busy(save, false); };
  editor.addEventListener("keydown", (e) => { if ((e.metaKey || e.ctrlKey) && e.key === "s") { e.preventDefault(); save.click(); } });
  render();
  const MARK = "**END ANALYST-ONLY — CUSTOMER REPORT STARTS BELOW**";
  const part = (which) => { const t = editor.value; const i = t.indexOf(MARK); if (i < 0) return t; return which === "analyst" ? t.slice(0, i).trim() : t.slice(i + MARK.length).trim(); };
  const ready = [["alert name", !!c.alert_name], ["customer", !!c.customer], ["finding ID", !!c.finding_id], ["alert link", !!c.alert_url],
    ["log evidence", c.findings.length + c.events.length > 0], ["indicators checked", c.observables.length > 0 && c.observables.every((o) => o.verdict !== "pending")]];
  return h("div", { class: "col gap-16" },
    h("div", { class: "card card-pad no-print" }, h("div", { class: "row wrap gap-12" },
      h("div", { class: "grow", style: { minWidth: "min(100%, 340px)" } }, h("h3", null, "Report writer"), h("div", { class: "small muted" }, "Correlates the logs, OSINT enrichment, past tickets, closures and pentest notes, reaches a verdict and writes exactly one outcome: an append note, a closure note, or an incident (analyst-only assessment plus customer report). Nothing is invented: missing data is written as Not available.")),
      h("span", { class: "tag", title: "Investigated domains, URLs and external IPv4 addresses are written as bad.example[.]com / 192.0.2[.]10 / hxxps://…; the alert link stays live" }, icon("lock"), " Final-dot defanging"),
      template, outcome, gen, save),
      h("div", { class: "row wrap gap-12 mt-16" }, ready.map(([t, ok]) => h("span", { class: "row gap-4 small", style: { color: ok ? "var(--ok)" : "var(--text-3)" } }, icon(ok ? "check" : "info"), t, ok ? "" : " (missing)")),
        h("button", { class: "link-btn small", onclick: () => switchTab("related") }, "Past tickets, closures & pentest notes"))),
    banner,
    h("div", { class: "report-layout" },
      h("div", { class: "card" }, h("div", { class: "card-head no-print" }, icon("edit"), h("h3", null, "Markdown"), status), h("div", { class: "card-body" }, editor)),
      h("div", { class: "card" }, h("div", { class: "card-head no-print" }, icon("eye"), h("h3", null, "Preview"),
        h("button", { class: "btn sm", onclick: () => copy(editor.value, "Markdown copied") }, icon("copy"), "Copy"),
        h("button", { class: "btn sm", title: "Copy only the customer report (everything below the analyst-only marker)", onclick: () => copy(part("customer"), "Customer report copied") }, icon("copy"), "Customer part"),
        h("button", { class: "btn sm", title: "Copy only the analyst-only assessment", onclick: () => copy(part("analyst"), "Analyst assessment copied") }, icon("copy"), "Analyst part"),
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

// ------------------------------------------------------------- verdict card
const VERDICT_LABELS = { true_positive: "True positive", likely_malicious: "Likely malicious", suspicious: "Suspicious", benign: "Benign",
  false_positive: "False positive", inconclusive: "Inconclusive" };
const SOC_VERDICT = { true_positive: "True Positive - Malicious", likely_malicious: "True Positive - Malicious", suspicious: "Inconclusive",
  benign: "True Positive - Benign", false_positive: "False Positive", inconclusive: "Inconclusive" };
const VERDICT_COLOR = { true_positive: "var(--mal)", likely_malicious: "var(--high)", suspicious: "var(--sus)", benign: "var(--ok)", false_positive: "var(--ok)", inconclusive: "var(--unk)" };
function verdictCard(c) {
  const a = c.assessment;
  const vSel = h("select", { class: "meta-select" }, h("option", { value: "" }, `Automatic (${VERDICT_LABELS[a.auto.verdict]})`),
    Object.entries(VERDICT_LABELS).map(([k, l]) => h("option", { value: k, selected: c.verdict === k }, l)));
  const cSel = h("select", { class: "meta-select" }, h("option", { value: "" }, `Automatic (${a.auto.confidence})`),
    ["high", "medium", "low"].map((k) => h("option", { value: k, selected: c.confidence === k }, k[0].toUpperCase() + k.slice(1))));
  vSel.onchange = () => call("PATCH", "", { verdict: vSel.value }, "Verdict updated");
  cSel.onchange = () => call("PATCH", "", { confidence: cSel.value }, "Confidence updated");
  const color = VERDICT_COLOR[a.verdict] || "var(--unk)";
  return h("div", { class: "card", style: { borderTop: `3px solid ${color}` } },
    h("div", { class: "card-head" }, icon("flag"), h("h3", null, "Quick verdict"), a.overridden ? h("span", { class: "tag" }, "set by analyst") : h("span", { class: "tag" }, "automatic")),
    h("div", { class: "card-body" },
      h("div", { style: { fontSize: "20px", fontWeight: 750, color } }, VERDICT_LABELS[a.verdict] || a.verdict),
      h("div", { class: "row mt-8 mb-8" }, h("span", { class: "small muted" }, "Confidence"),
        h("span", { class: `pill ${a.confidence === "high" ? "harmless" : a.confidence === "medium" ? "suspicious" : ""}` }, a.confidence)),
      h("div", { class: "small mb-8" }, h("span", { class: "muted" }, "In SOC write-ups: "), h("b", null, SOC_VERDICT[a.verdict] || "Inconclusive")),
      h("ul", { class: "small muted", style: { paddingLeft: "18px", margin: "6px 0 12px" } }, a.factors.map((f) => h("li", null, f))),
      h("div", { class: "row wrap" }, h("span", { class: "label" }, "Override"), vSel, cSel)));
}

function seenIn(value) {
  const box = h("div");
  api("GET", `/workspaces/${ctx.data.workspace_id}/search?q=${encodeURIComponent(value)}`).then((s) => {
    const others = s.hits.filter((x) => x.kind === "indicator" && x.id !== ctx.id);
    const assets = s.assets || [];
    mount(box,
      others.length ? h("div", { class: "notice info" }, icon("folder"), h("div", { class: "small" }, h("b", null, `Also seen in ${others.length} other case(s)`),
        others.map((x, i) => [i ? ", " : "", link(`/cases/${x.id}`, null, `${x.ref}: ${x.title}`)]))) : null,
      assets.length ? h("div", { class: "notice info mt-8" }, icon("server"), h("div", { class: "small" }, h("b", null, "Matches an inventory asset"),
        assets.slice(0, 3).map((a) => h("div", null, `${a.hostname || "?"} · ${a.ip || ""} · ${a.mac || ""}${a.owner ? ` · owner ${a.owner}` : ""}${a.criticality ? ` · ${a.criticality}` : ""}`)))) : null);
  }).catch(() => {});
  return box;
}

// ----------------------------------------------------------------- findings
const CAT_LABEL = { auth: "Authentication", process: "Process & command line", malware: "Malware & files", network: "Network & C2" };
const CAT_ICON = { auth: "user", process: "terminal", malware: "bug", network: "globe" };
let findingFilter = "active";
function tabFindings(c) {
  const list = c.findings.filter((f) => findingFilter === "all" || (findingFilter === "active" ? f.status !== "dismissed" : f.status === findingFilter));
  const chips = [["active", "Active"], ["confirmed", "Confirmed"], ["dismissed", "Dismissed"], ["all", "All"]].map(([k, l]) =>
    h("button", { class: `chip-btn${findingFilter === k ? " on" : ""}`, onclick: () => { findingFilter = k; drawTab(); } }, l,
      h("span", { class: "n" }, k === "all" ? c.findings.length : k === "active" ? c.findings.filter((f) => f.status !== "dismissed").length : c.findings.filter((f) => f.status === k).length)));
  if (!c.findings.length) {
    return h("div", { class: "card" }, empty("alert", "No security findings yet",
      "Drop logs into the Log Arranger. S.T.A.R.K looks for authentication anomalies, suspicious processes and LOLBins, malware traces and C2 / typosquatting, then you add the relevant findings here.",
      h("button", { class: "btn primary", onclick: () => switchTab("logs") }, icon("layers"), "Open Log Arranger")));
  }
  return h("div", { class: "col gap-12" }, h("div", { class: "row wrap" }, chips),
    list.map((f) => findingCard(f)));
}
export function findingCard(f, { onAdd, added, onEvidence, collapsed = false } = {}) {
  const sevColor = { critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)" }[f.severity] || "var(--info)";
  const ent = f.entities || {};
  const entityChips = Object.entries(ent).flatMap(([k, vals]) => (vals || []).slice(0, 6).map((v) => h("span", { class: "tag", title: k }, `${k.replace(/s$/, "")}: ${v}`)));
  const ev = f.evidence || [];
  const body = h("div", { class: "card-body col gap-8" },
    h("div", { class: "small" }, h("b", null, "What was seen. "), f.description),
    f.extra && f.extra.decoded ? h("div", null, h("div", { class: "label mb-8" }, "Decoded command"), h("div", { class: "raw" }, f.extra.decoded.join("\n\n"))) : null,
    f.decoded ? h("div", null, h("div", { class: "label mb-8" }, "Decoded command"), h("div", { class: "raw" }, f.decoded.join("\n\n"))) : null,
    h("div", { class: "small" }, h("b", null, "Interpretation. "), f.interpretation),
    h("div", { class: "small" }, h("b", null, "Recommended action. "), f.recommendation),
    entityChips.length ? h("div", { class: "row wrap gap-4" }, entityChips) : null,
    (f.mitre || []).length ? h("div", { class: "row wrap gap-4" }, f.mitre.map((m) => h("a", { class: "tag", href: m.url, target: "_blank", rel: "noopener noreferrer" }, `${m.id} ${m.name}`))) : null,
    ev.length ? h("details", null, h("summary", { class: "small", style: { cursor: "pointer" } }, `Evidence (${f.count} event${f.count !== 1 ? "s" : ""})`),
      h("div", { class: "table-wrap mt-8" }, h("table", { class: "table compact" }, h("thead", null, h("tr", null, ["Time", "Source", "Host / user", "Event", "Detail"].map((x) => h("th", null, x)))),
        h("tbody", null, ev.map((e) => h("tr", null, h("td", { class: "mono tiny" }, fmtTime(e.time)), h("td", { class: "small" }, e.product),
          h("td", { class: "small" }, [e.host, e.user].filter(Boolean).join(" / ")), h("td", { class: "small" }, e.event), h("td", { class: "small", style: { wordBreak: "break-all" } }, e.detail || e.flow))))))) : null);
  const actions = [];
  if (onAdd) {
    actions.push(added ? h("span", { class: "pill harmless" }, icon("check"), "In case") : h("button", { class: "btn sm primary", onclick: (e) => onAdd(f, e.currentTarget) }, icon("plus"), "Add to case"));
    if (onEvidence) actions.push(h("button", { class: "btn sm", onclick: () => onEvidence(f) }, icon("filter"), "Show events"));
  } else {
    const st = h("select", { class: "meta-select" }, [["open", "Open"], ["confirmed", "Confirmed"], ["dismissed", "Dismissed (false positive)"]].map(([k, l]) => h("option", { value: k, selected: f.status === k }, l)));
    st.onchange = () => call("PATCH", `/findings/${f.id}`, { status: st.value }, `Finding ${st.value}`);
    const note = h("textarea", { class: "input", rows: 2, placeholder: "Analyst note (appears in the report)" }); note.value = f.note || "";
    note.addEventListener("change", () => call("PATCH", `/findings/${f.id}`, { note: note.value }, "Note saved"));
    body.appendChild(note);
    actions.push(st, h("button", { class: "btn ghost sm icon", title: "Remove", onclick: () => call("DELETE", `/findings/${f.id}`, undefined, "Finding removed") }, icon("x")));
  }
  if (collapsed) body.classList.add("hidden");
  const toggle = collapsed ? h("button", { class: "btn ghost sm icon", title: "Show details", onclick: (e) => { body.classList.toggle("hidden"); e.currentTarget.replaceChildren(icon(body.classList.contains("hidden") ? "chevdown" : "x")); } }, icon("chevdown")) : null;
  return h("div", { class: "card", style: { borderLeft: `4px solid ${sevColor}`, opacity: f.status === "dismissed" ? 0.6 : 1 } },
    h("div", { class: "card-head" }, toggle, h("span", { style: { color: sevColor } }, icon(CAT_ICON[f.category] || "alert")),
      h("div", { class: "grow" }, h("h3", null, f.title), h("div", { class: "tiny faint" }, `${CAT_LABEL[f.category] || f.category} · ${f.count} event(s)${f.first ? ` · ${fmtTime(f.first).slice(0, 16)}` : ""}`)),
      h("span", { class: `pill sev-${f.severity}` }, f.severity), h("span", { class: "tag", title: "How confident the detection rule is" }, `${f.confidence} confidence`), actions),
    body);
}


// ------------------------------------------------------------ alert & ticket
const DISPOSITION_LABEL = { "": "Not decided", incident: "Raised as incident", appended: "Appended to a ticket", non_threatening: "Closed as non-threatening" };
function alertCard(c) {
  const field = (key, label, ph, opts = {}) => {
    const el = opts.area ? h("textarea", { class: "input", rows: 3, placeholder: ph }) : h("input", { class: "input" + (opts.mono ? " mono" : ""), placeholder: ph });
    el.value = c[key] || "";
    if (opts.area) el.addEventListener("input", () => { ctx.dirty = true; });
    el.addEventListener("change", async () => { ctx.dirty = false; await call("PATCH", "", { [key]: el.value.trim() }, "Saved"); });
    return h("div", { class: `field${opts.full ? " full" : ""}` }, h("label", null, label), el);
  };
  const disp = h("select", { class: "input" }, Object.entries(DISPOSITION_LABEL).map(([k, l]) => h("option", { value: k, selected: (c.disposition || "") === k }, l)));
  disp.onchange = () => call("PATCH", "", { disposition: disp.value }, "Disposition saved");
  const linked = h("input", { class: "input mono", placeholder: "F-1001, F-1002", value: (c.linked_findings || []).join(", ") });
  linked.addEventListener("change", () => call("PATCH", "", { linked_findings: linked.value.split(/[\s,;]+/).filter(Boolean) }, "Saved"));
  const filled = ["alert_name", "customer", "finding_id"].filter((k) => c[k]).length;
  return h("div", { class: "card" },
    h("div", { class: "card-head" }, icon("alert"), h("h3", null, "Alert & ticket"), h("span", { class: "tag" }, filled === 3 ? "ready for triage" : "add alert details")),
    h("div", { class: "card-body" },
      h("div", { class: "form-grid" },
        field("alert_name", "Alert name", "As named in the SIEM", { full: true }), field("customer", "Customer", "Client"),
        field("finding_id", "Finding ID", "F-1001", { mono: true }), field("siem", "Log source / SIEM", "Microsoft Sentinel"),
        field("alert_created", "Alert created", "2026-11-20T02:20:00Z", { mono: true }), field("threat_id", "Incident / threat ID", "", { mono: true }),
        field("alert_url", "Alert link (kept live in reports)", "https://…", { full: true, mono: true }),
        field("ticket_number", "Ticket (INC) number", "INC0012345", { mono: true }),
        h("div", { class: "field" }, h("label", null, "Disposition"), disp),
        h("div", { class: "field full" }, h("label", null, "Finding IDs in this ticket"), linked),
        field("close_notes", "Close notes (what was done)", "e.g. Blocked 45.77.12.9 on the firewall; reset jdoe's password and revoked sessions on 2026-11-20.", { area: true, full: true })),
      h("div", { class: "hint mt-8" }, "Past cases with the same alert name and customer are used as past tickets; cases closed as non-threatening become past closures. Close notes that record a real remediation let later findings for the same entities be closed.")));
}

// ---------------------------------------------------------------- related
const OUTCOME_ICON = { 1: "link", 2: "check", 3: "alert" };
const INSTR_LABEL = { ignore: "Ignore alerts from the test", raise_and_confirm: "Raise and confirm scope", unannounced: "Unannounced: raise as incident" };
function decisionBanner(a) {
  if (!a) return null;
  return h("div", { class: `card card-pad decision o${a.outcome}` },
    h("div", { class: "row wrap gap-12" }, icon(OUTCOME_ICON[a.outcome] || "info"),
      h("div", { class: "grow" }, h("b", null, a.outcome_label + (a.target ? `: ${a.target}` : "")),
        h("div", { class: "small muted" }, `Verdict ${a.verdict.label} (${a.verdict.confidence} confidence)` + (a.reason ? ` · ${a.reason}` : ""))),
      a.signs && a.signs.length ? h("span", { class: "pill malicious" }, `${a.signs.length} sign(s) of compromise`) : null));
}
function tabRelated(c) {
  const wrap = h("div", { class: "col gap-16" }, h("div", { class: "empty" }, h("span", { class: "spinner" })));
  const load = async () => {
    let d;
    try { d = await api("GET", `/cases/${ctx.id}/context`); } catch (e) { mount(wrap, h("div", { class: "notice warn" }, icon("alert"), e.message)); return; }
    const rel = d.analysis.related;
    const matchChips = (ms) => (ms || []).map((m) => h("span", { class: "match-chip", title: `in ${m.where}` }, `${m.type}: ${m.value}`));
    const tickets = rel.tickets.length ? rel.tickets.map((t) => h("div", { class: "rel-row" }, icon("folder"),
      h("div", { class: "grow" },
        h("div", { class: "row wrap gap-8" }, t.case_id ? link(`/cases/${t.case_id}`, { class: "mono" }, t.case_number) : h("b", { class: "mono" }, t.case_number || "Ticket"),
          h("span", { class: `pill ${t.open ? "suspicious" : ""}` }, t.status || "?"), t.involves ? h("span", { class: "tag" }, "already contains this finding") : null,
          h("span", { class: "tiny faint" }, t.source === "imported" ? "imported" : "from this workspace")),
        t.matches.length ? h("div", { class: "row wrap gap-4 mt-8" }, matchChips(t.matches)) : h("div", { class: "tiny faint mt-8" }, "No shared entities (same alert name only, which is not a match)"),
        t.remediation ? h("div", { class: "small mt-8" }, h("b", null, t.remediation.can_close ? "Remediation settles this finding: " : "Remediation does not settle this finding: "), `${t.remediation.done.join(", ")}. ${t.remediation.reason}.`) : null)))
      : [h("div", { class: "muted small" }, c.alert_name ? "No other case in this workspace has the same alert name" + (c.customer ? " and customer." : ".") : "Add the alert name (Overview → Alert & ticket) to match past tickets for the same alert.")];
    const closures = rel.closures.length ? rel.closures.map((x) => h("div", { class: "rel-row" }, icon("check"),
      h("div", { class: "grow" }, h("div", { class: "row wrap gap-8" }, x.case_id ? link(`/cases/${x.case_id}`, null, x.finding_id || "Closure") : h("b", null, x.finding_id || "Closure"),
        h("span", { class: "small muted" }, `closed by ${x.closed_by || "?"} on ${x.closed_on || "?"}`)),
        x.matches.length ? h("div", { class: "row wrap gap-4 mt-8" }, matchChips(x.matches)) : h("div", { class: "tiny faint mt-8" }, "No shared entities")))) : [h("div", { class: "muted small" }, "No past non-threatening closures for this alert.")];
    const pentests = rel.pentests.length ? rel.pentests.map((p) => h("div", { class: "rel-row" }, icon("shield"),
      h("div", { class: "grow" }, h("div", { class: "row wrap gap-8" }, h("b", null, p.title), h("span", { class: "tag" }, INSTR_LABEL[p.instruction] || p.instruction),
        p.related ? h("span", { class: `pill ${p.covered ? "harmless" : "suspicious"}` }, p.covered ? "covers this activity" : "related, not covering") : h("span", { class: "tiny faint" }, "not related: left out of the report")),
        p.matched.length ? h("div", { class: "small mt-8" }, "Matched: ", p.matched.join(", ").replace(/`/g, "")) : null,
        p.related && !p.covered && p.gaps.length ? h("div", { class: "tiny muted mt-8" }, p.gaps.join("; ").replace(/`/g, "")) : null),
      p.source === "workspace" && p.id ? h("button", { class: "btn ghost sm icon", title: "Edit", onclick: () => pentestDialog(c, d.records.pentests.find((n) => n.id === p.id), load) }, icon("edit")) : null))
      : [h("div", { class: "muted small" }, "No pentest notes for this customer.")];
    const imported = [...d.records.tickets, ...d.records.closures, ...d.records.pentests].filter((r) => r.context_id);
    const ta = h("textarea", { class: "input mono", rows: 5, placeholder: '[{"_type": "fusion-closure", "detail": "…", "closure_note": "…", "closed_by": "…", "closed_on": "…"},\n {"case number": "INC0012345", "status": "IN_PROGRESS", "subject": "…", "close_notes": "…", "findings": ["F-1"]},\n {"_type": "pentest-note", "title": "…", "tester_ips": ["198.51.100.0/24"], "starts_on": "…", "ends_on": "…", "client_instruction": "ignore"}]' });
    const imp = h("button", { class: "btn" }, icon("upload"), "Import records");
    imp.onclick = async () => { if (!ta.value.trim()) return; busy(imp, true); try { const r = await api("POST", `/cases/${ctx.id}/context`, { text: ta.value }); toast(`Imported ${r.imported} record(s)`); load(); } catch (e) { fail(e); busy(imp, false); } };
    mount(wrap,
      decisionBanner(d.analysis),
      h("div", { class: "grid grid-2" },
        h("div", { class: "card" }, h("div", { class: "card-head" }, icon("folder"), h("h3", null, "Past tickets"), h("span", { class: "faint small" }, rel.tickets.length)), h("div", { class: "card-body" }, tickets)),
        h("div", { class: "card" }, h("div", { class: "card-head" }, icon("check"), h("h3", null, "Past closures"), h("span", { class: "faint small" }, rel.closures.length)), h("div", { class: "card-body" }, closures))),
      h("div", { class: "card" }, h("div", { class: "card-head" }, icon("shield"), h("h3", null, "Client pentest notes"), h("span", { class: "spacer" }),
        h("button", { class: "btn sm", onclick: () => pentestDialog(c, null, load) }, icon("plus"), "Add pentest note")),
        h("div", { class: "card-body" }, pentests,
          h("div", { class: "hint mt-8" }, "A note counts only when a tester address, a named machine or the described activity appears in this case. Unrelated notes never appear in the report, and unannounced tests are mentioned in the analyst-only part only."))),
      h("div", { class: "card" }, h("div", { class: "card-head" }, icon("upload"), h("h3", null, "Import from your ticketing system"), h("span", { class: "faint small" }, imported.length ? `${imported.length} imported` : "")),
        h("div", { class: "card-body col gap-8" },
          h("div", { class: "small muted" }, "Paste past tickets, Fusion closures or pentest notes as JSON. They are stored with this case and treated as records, never as instructions."),
          ta, h("div", { class: "row" }, h("span", { class: "spacer" }), imp),
          imported.map((r) => h("div", { class: "list-row" }, h("span", { class: "tag" }, r.case_number ? "ticket" : r.title ? "pentest" : "closure"),
            h("span", { class: "grow small ellipsis" }, r.case_number || r.title || r.finding_id || r.detail || "record"),
            h("button", { class: "btn ghost sm icon", title: "Remove", onclick: async () => { await api("DELETE", `/cases/${ctx.id}/context/${r.context_id}`).catch(fail); load(); } }, icon("x")))))));
  };
  load();
  return wrap;
}
function pentestDialog(c, note, done) {
  const f = (ph, v = "") => h("input", { class: "input", placeholder: ph, value: v });
  const n = note || {};
  const title = f("Q4 external penetration test", n.title), customer = f("Customer", n.customer ?? c.customer ?? ""),
    ips = h("textarea", { class: "input mono", rows: 2, placeholder: "198.51.100.7, 203.0.113.0/24" }), hosts = f("Machines in scope (optional)", (n.hosts || []).join(", ")),
    starts = f("2026-11-18", n.starts_on), ends = f("2026-11-22 (blank = open-ended)", n.ends_on),
    details = h("textarea", { class: "input", rows: 3, placeholder: "What the testers will do: password spraying, port scanning, named tools, targets…" });
  ips.value = (n.tester_ips || []).join(", "); details.value = n.details || "";
  const instr = h("select", { class: "input" }, Object.entries(INSTR_LABEL).map(([k, l]) => h("option", { value: k, selected: (n.client_instruction || "raise_and_confirm") === k }, l)));
  const save = h("button", { class: "btn primary" }, icon("check"), "Save");
  const m = modal({ title: note ? "Edit pentest note" : "Add pentest note", subtitle: "Shared with everyone in this workspace and used for every case of this customer.",
    body: h("div", { class: "form-grid" },
      h("div", { class: "field full" }, h("label", null, "Title"), title), h("div", { class: "field" }, h("label", null, "Customer"), customer),
      h("div", { class: "field" }, h("label", null, "Client instruction"), instr),
      h("div", { class: "field full" }, h("label", null, "Tester IP addresses / ranges"), ips),
      h("div", { class: "field" }, h("label", null, "Starts on"), starts), h("div", { class: "field" }, h("label", null, "Ends on"), ends),
      h("div", { class: "field full" }, h("label", null, "Machines"), hosts), h("div", { class: "field full" }, h("label", null, "Details"), details)),
    foot: [note ? h("button", { class: "btn danger", onclick: async () => { if (!await confirmDialog("Delete this pentest note?", "It will no longer be considered for any case.", { ok: "Delete" })) return; await api("DELETE", `/workspaces/${c.workspace_id}/pentests/${note.id}`).catch(fail); m.close(); done(); } }, icon("trash"), "Delete") : null,
      h("span", { class: "spacer" }), h("button", { class: "btn", onclick: () => m.close() }, "Cancel"), save] });
  save.onclick = async () => {
    busy(save, true);
    const payload = { title: title.value, customer: customer.value, tester_ips: ips.value, hosts: hosts.value, starts_on: starts.value, ends_on: ends.value, details: details.value, client_instruction: instr.value };
    try { await api(note ? "PUT" : "POST", `/workspaces/${c.workspace_id}/pentests${note ? `/${note.id}` : ""}`, payload); m.close(); toast("Pentest note saved"); done(); }
    catch (e) { fail(e); busy(save, false); }
  };
}
