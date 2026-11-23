// Onboarding (API keys before the first case), global IOC search with a quick reputation
// summary, and the asset inventory (lookup by IP, hostname or MAC).
import {
  api, busy, copy, download, empty, fail, go, h, icon, ioc, link, mount, state, timeAgo, toast, verdictPill, TYPE_LABEL,
  sevPill, statusPill, debounce,
} from "./core.js";

const TIERS = [
  ["Recommended free sources", "Free accounts, quick to set up. Start here.", ["virustotal", "abuseipdb", "abusech", "otx", "urlscan", "greynoise", "pulsedive"]],
  ["Sandboxes & enterprise intelligence", "Use these if your organisation has a subscription.", ["recordedfuture", "anyrun", "joesandbox", "hybridanalysis", "shodan"]],
  ["Specialist sources", "Email breach exposure, mail/IP blocklists and IP context.", ["hibp", "mxtoolbox", "ipinfo"]],
  ["Your threat-sharing platform", "MISP: look indicators up in your own MISP and send cases to it. Needs the server address and an automation key (MISP: My profile → Auth keys).", ["misp_url", "misp"]],
];

export const defangText = (v) => String(v).replace(/^http/i, "hxxp").replace("://", "[://]").replace(/@/g, "[@]").replace(/\./g, "[.]");

// ------------------------------------------------------------ keys editor
export async function keysEditor(wsId, { compact = false, onSaved } = {}) {
  const k = await api("GET", `/workspaces/${wsId}/keys`);
  const byName = Object.fromEntries(k.keys.map((x) => [x.name, x]));
  const inputs = {};
  const statusEl = {};
  const row = (key) => {
    const setting = key.kind === "setting";
    const inp = h("input", { class: "input mono", type: setting ? "url" : "password", autocomplete: "off", disabled: !k.can_edit,
      placeholder: setting ? (key.set ? key.masked : key.local_fallback ? "Using the address from this computer's config" : "https://misp.example.org")
        : key.set ? `Saved (${key.masked})` : key.local_fallback ? "Using the key from this computer's config" : key.required ? "Paste API key" : "Optional: works without a key" });
    inputs[key.name] = inp;
    const st = h("span", null, key.set || key.local_fallback ? h("span", { class: "pill harmless" }, h("span", { class: "dot" }), setting ? "Saved" : "Connected")
      : key.required ? h("span", { class: "pill" }, "Not set") : h("span", { class: "pill pending", title: "Works without a key; a key raises rate limits" }, "Optional"));
    statusEl[key.name] = st;
    const test = h("button", { class: "btn sm", disabled: !k.can_edit, title: "Run a harmless test lookup with this key", style: setting ? { visibility: "hidden" } : null }, "Test");
    test.onclick = async () => {
      busy(test, true);
      try {
        const r = await api("POST", `/workspaces/${wsId}/keys/test`, { name: key.name, value: inp.value.trim() });
        mount(st, h("span", { class: `pill ${r.ok ? "harmless" : "malicious"}`, title: r.message }, h("span", { class: "dot" }), r.ok ? "Key works" : "Failed"));
        toast(r.message, r.ok ? "ok" : "err", 4500);
      } catch (e) { fail(e); }
      busy(test, false);
    };
    return h("div", { class: "list-row" },
      h("div", { style: { width: compact ? "40%" : "34%" } }, h("b", null, key.providers.join(", ")), h("div", { class: "tiny faint" }, key.description)),
      h("div", { style: { width: "130px" } }, st),
      h("div", { class: "grow" }, inp),
      test,
      key.homepage ? h("a", { style: setting ? { visibility: "hidden" } : null, href: key.homepage, target: "_blank", rel: "noopener noreferrer", class: "btn ghost sm", title: "Get a key" }, icon("external")) : null);
  };
  const groups = TIERS.map(([title, sub, names]) => h("div", { class: "mb-16" }, h("div", { class: "label" }, title), h("div", { class: "hint mb-8" }, sub),
    names.filter((n) => byName[n]).map((n) => row(byName[n]))));
  const save = h("button", { class: "btn primary" }, icon("check"), "Save keys");
  save.onclick = async () => {
    const keys = {}; for (const [n, i] of Object.entries(inputs)) if (i.value.trim()) keys[n] = i.value.trim();
    // the Test button reads the saved address, so typing a key and an address then pressing Test works after saving
    if (!Object.keys(keys).length) { toast("Paste at least one key first, or skip for now.", "info"); return false; }
    busy(save, true);
    try { await api("PUT", `/workspaces/${wsId}/keys`, { keys }); toast(`Saved ${Object.keys(keys).length} key(s)`); onSaved && onSaved(); }
    catch (e) { fail(e); } finally { busy(save, false); }
    return true;
  };
  const free = h("div", { class: "notice info mb-16" }, icon("info"), h("div", { class: "small" },
    h("b", null, "Talos and crt.sh need no key"), "Sources you don't connect are skipped quietly: they never show errors in an investigation."));
  return { el: h("div", null, free, groups), save, canEdit: k.can_edit, configured: k.keys.filter((x) => x.set || x.local_fallback).length };
}

// ------------------------------------------------------------- onboarding
export async function renderSetup() {
  const { shell, setUser } = await import("./app.js");
  const ws = state.ws;
  const content = h("div");
  shell("Get started", [h("b", null, "Get started")], content);
  let step = 1;
  const finish = async (to) => {
    try { const r = await api("PATCH", "/me", { onboarded: true }); setUser(r.user); } catch { /* ignore */ }
    go(to || "/");
  };
  const steps = ["Connect intelligence sources", ws.kind === "team" ? "Invite your team" : "Your workspace", "Open your first case"];
  const draw = async () => {
    const head = h("div", { class: "stepper", style: { gridTemplateColumns: "repeat(3, minmax(0, 1fr))" } }, steps.map((t, i) =>
      h("div", { class: `step${i + 1 < step ? " done" : ""}${i + 1 === step ? " current" : ""}` }, h("div", { class: "n" }, i + 1 < step ? icon("check") : String(i + 1)), h("div", null, h("b", null, t)))));
    if (step === 1) {
      const ed = await keysEditor(ws.id, { onSaved: () => { step = 2; draw(); } });
      mount(content, h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, `Welcome to S.T.A.R.K, ${state.user.name.split(" ")[0]}`),
        h("div", { class: "sub" }, "First, connect the threat-intelligence sources you have accounts for. Every indicator in your cases is checked against all of them automatically."))),
      head,
      h("div", { class: "card" }, h("div", { class: "card-head" }, icon("key"), h("h3", null, `API keys for ${ws.name}`),
        ws.kind === "team" ? h("span", { class: "small muted" }, "Shared with everyone in the team") : null),
      h("div", { class: "card-body" }, ed.canEdit ? ed.el : h("div", { class: "notice info" }, icon("info"), h("div", null, h("b", null, "Your team admin manages API keys"),
        h("span", { class: "small" }, `${ed.configured} source(s) are already connected for ${ws.name}.`)))),
      h("div", { class: "modal-foot" }, h("button", { class: "btn ghost", onclick: () => { step = 2; draw(); } }, ed.canEdit ? "Skip for now" : "Continue"),
        ed.canEdit ? h("button", { class: "btn primary", onclick: async () => { const ok = await ed.save.onclick(); if (ok === false) return; } }, icon("check"), "Save & continue") : null)));
    } else if (step === 2) {
      let body;
      if (ws.kind === "team") {
        const info = await api("GET", `/workspaces/${ws.id}`);
        body = h("div", { class: "card card-pad" }, h("h3", { class: "mb-8" }, "Invite teammates"),
          info.invite_code ? h("div", null, h("p", { class: "muted" }, "Teammates create an account on this S.T.A.R.K server, choose “Join a team” and enter:"),
            h("div", { class: "row mt-8" }, h("code", { class: "ioc", style: { fontSize: "18px", padding: "8px 14px" } }, info.invite_code), h("button", { class: "btn", onclick: () => copy(info.invite_code) }, icon("copy"), "Copy code")))
            : h("p", { class: "muted" }, `You're a member of ${ws.name}. Cases you open here are shared with ${info.members.length - 1} teammate(s).`));
      } else {
        body = h("div", { class: "card card-pad" }, h("h3", { class: "mb-8" }, "Your personal workspace"),
          h("p", { class: "muted" }, "Cases here are private to you. Working with others? Create a team workspace from the workspace menu at any time and share its invite code."));
      }
      mount(content, h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, steps[1]))), head, body,
        h("div", { class: "modal-foot" }, h("button", { class: "btn ghost", onclick: () => { step = 1; draw(); } }, "Back"), h("button", { class: "btn primary", onclick: () => { step = 3; draw(); } }, "Continue", icon("chevron"))));
    } else {
      const ioc = h("input", { class: "input mono", placeholder: "e.g. 185.220.101[.]1 or hxxps://evil[.]com/login" });
      mount(content, h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, "You're ready"))), head,
        h("div", { class: "grid grid-2" },
          h("div", { class: "card card-pad" }, h("div", { class: "stat-icon mb-8", style: { background: "var(--accent-soft)", color: "var(--accent)" } }, icon("folder")),
            h("h3", { class: "mb-8" }, "Open a case"), h("p", { class: "muted small" }, "Drop in logs from your SIEM, EDR or firewall. S.T.A.R.K arranges them, flags suspicious activity, checks indicators and drafts the report."),
            h("button", { class: "btn primary mt-8", onclick: async () => { await finish("/cases"); const { newCaseDialog } = await import("./app.js"); newCaseDialog(); } }, icon("plus"), "Open my first case")),
          h("div", { class: "card card-pad" }, h("div", { class: "stat-icon mb-8", style: { background: "var(--sus-soft)", color: "var(--sus)" } }, icon("zap")),
            h("h3", { class: "mb-8" }, "Or check one indicator"), h("p", { class: "muted small" }, "Paste any IP, domain, URL, hash or email (fanged or defanged) for a quick reputation summary."),
            h("div", { class: "row mt-8" }, ioc, h("button", { class: "btn", onclick: () => ioc.value.trim() && finish(`/search?q=${encodeURIComponent(ioc.value.trim())}`) }, "Check")))),
        h("div", { class: "modal-foot" }, h("button", { class: "btn ghost", onclick: () => finish("/") }, "Go to dashboard")));
    }
  };
  try { await draw(); } catch (e) { fail(e); }
}

// ------------------------------------------------------- reputation card
export function reputationCard(rep, { onAdd } = {}) {
  const sum = h("div", { class: `notice ${rep.verdict === "malicious" ? "warn" : "info"}`, style: rep.verdict === "malicious" ? { background: "var(--mal-soft)" } : null },
    icon(rep.verdict === "malicious" ? "alert" : rep.verdict === "harmless" ? "check" : "info"), h("div", { class: "small" }, rep.summary));
  const seen = rep.seen_in && rep.seen_in.length ? h("div", { class: "mt-8 small" }, h("b", null, "Seen in your cases: "),
    rep.seen_in.map((c, i) => [i ? ", " : "", link(`/cases/${c.id}`, null, c.ref), ` (${c.verdict || "not checked"})`])) : null;
  return h("div", { class: "card card-pad" },
    h("div", { class: "row wrap mb-8" }, ioc(rep.observable, rep.verdict), h("span", { class: "tag" }, TYPE_LABEL[rep.type] || rep.type), verdictPill(rep.verdict),
      h("span", { class: "spacer" }), h("button", { class: "btn sm", title: "Copy defanged", onclick: () => copy(defangText(rep.observable), "Defanged copy") }, icon("copy"), "Defanged"),
      onAdd ? h("button", { class: "btn sm primary", onclick: () => onAdd(rep) }, icon("plus"), "Add to case") : null),
    sum, seen,
    rep.results.length ? h("div", { class: "mt-8" }, rep.results.map((p) => h("div", { class: "provider-row" },
      h("b", null, p.provider), h("div", null, verdictPill(p.verdict)),
      h("div", { class: "small" }, p.summary, p.link ? h("div", null, h("a", { href: p.link, target: "_blank", rel: "noopener noreferrer", class: "tiny" }, "Open report ↗")) : null)))) : null,
    rep.sources_checked > rep.results.length ? h("div", { class: "hint mt-8" }, `${rep.sources_checked - rep.results.length} other source(s) had no record of it and are not shown.`) : null);
}

async function addToCaseDialog(rep) {
  const { modal } = await import("./core.js");
  const cases = await api("GET", `/workspaces/${state.ws.id}/cases?status=active`);
  if (!cases.length) { toast("Open a case first", "info"); return; }
  const sel = h("select", { class: "input" }, cases.map((c) => h("option", { value: c.id }, `${c.ref}: ${c.title}`)));
  const m = modal({ title: "Add to a case", body: h("div", { class: "field" }, h("label", null, "Case"), sel),
    foot: [h("button", { class: "btn", onclick: () => m.close() }, "Cancel"), h("button", { class: "btn primary", onclick: async () => {
      try { await api("POST", `/cases/${sel.value}/observables`, { items: [{ value: rep.observable, type: rep.type }], source: "quick lookup" }); m.close(); toast("Added to the case"); } catch (e) { fail(e); }
    } }, "Add")] });
}

// ------------------------------------------------------------ global search
export async function renderSearch(r) {
  const { shell } = await import("./app.js");
  const q = r.query.get("q") || "";
  const input = h("input", { class: "input lg mono", value: q, placeholder: "Paste an IOC (fanged or defanged), a hostname, IP, MAC, user or case name…", style: { height: "46px", fontSize: "15px" } });
  const out = h("div", { class: "col gap-16 mt-16" });
  const run = async () => {
    const v = input.value.trim();
    if (!v) return;
    history.replaceState(null, "", `/search?q=${encodeURIComponent(v)}`);
    mount(out, h("div", { class: "empty" }, h("span", { class: "spinner" })));
    try {
      const s = await api("GET", `/workspaces/${state.ws.id}/search?q=${encodeURIComponent(v)}`);
      const blocks = [];
      if (s.ioc) {
        const holder = h("div", null, h("div", { class: "card card-pad row" }, h("span", { class: "spinner" }), h("span", { class: "muted" }, "Checking reputation across your connected sources…")));
        blocks.push(holder);
        api("POST", "/lookup", { workspace_id: state.ws.id, text: s.ioc.value })
          .then((res) => mount(holder, reputationCard(res.results[0], { onAdd: addToCaseDialog })))
          .catch((e) => mount(holder, h("div", { class: "notice warn" }, icon("alert"), h("div", { class: "small" }, e.message, " ", link("/settings", null, "Connect sources")))));
      }
      if (s.assets.length) blocks.push(assetTable(s.assets, "Matching assets"));
      if (s.hits.length) {
        blocks.push(h("div", { class: "card" }, h("div", { class: "card-head" }, icon("folder"), h("h3", null, "Found in cases"), h("span", { class: "faint small" }, s.hits.length)),
          h("div", { class: "card-body" }, s.hits.map((x) => h("div", { class: "list-row" }, link(`/cases/${x.id}`, { class: "mono small", style: { width: "130px" } }, x.ref),
            h("span", { class: "tag" }, x.kind), h("div", { class: "grow small ellipsis" }, x.value), h("span", { class: "small muted ellipsis", style: { maxWidth: "260px" } }, x.title))))));
      }
      if (s.cases.length) {
        blocks.push(h("div", { class: "card" }, h("div", { class: "card-head" }, h("h3", null, "Cases")),
          h("div", { class: "card-body" }, s.cases.map((c) => h("div", { class: "list-row" }, link(`/cases/${c.id}`, { class: "mono small", style: { width: "130px" } }, c.ref), h("div", { class: "grow" }, c.title), sevPill(c.severity), statusPill(c.status))))));
      }
      if (!blocks.length) blocks.push(h("div", { class: "card" }, empty("search", "Nothing found", "No case, indicator, artifact or asset matches. Paste an IP, domain, URL, hash or email to check its reputation.")));
      mount(out, blocks);
    } catch (e) { fail(e); out.replaceChildren(); }
  };
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  shell("Search", [h("b", null, "Search & quick reputation")], h("div", null,
    h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, "Search & quick reputation"),
      h("div", { class: "sub" }, "Paste a bare IOC to get a reputation summary straight away, or look up any host, IP, MAC address or user across your cases and asset inventory."))),
    h("div", { class: "row" }, h("div", { class: "grow" }, input), h("button", { class: "btn primary lg", onclick: run }, icon("search"), "Search")), out));
  if (q) run();
  setTimeout(() => input.focus(), 50);
}

// ---------------------------------------------------------------- assets
function assetTable(rows, title, onDelete) {
  return h("div", { class: "card" }, h("div", { class: "card-head" }, icon("server"), h("h3", null, title), h("span", { class: "faint small" }, rows.length)),
    h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", null, h("tr", null, ["Hostname", "IP address", "MAC address", "Owner", "OS", "Department / location", "Criticality", ""].map((x) => h("th", null, x)))),
      h("tbody", null, rows.map((a) => h("tr", null,
        h("td", null, a.hostname ? h("b", null, a.hostname) : h("span", { class: "faint" }, "-")), h("td", { class: "mono small" }, a.ip || ""),
        h("td", { class: "mono small" }, a.mac || ""), h("td", { class: "small" }, a.owner || ""), h("td", { class: "small" }, a.os || ""),
        h("td", { class: "small muted" }, [a.department, a.location].filter(Boolean).join(" · ")),
        h("td", null, a.criticality ? h("span", { class: `pill ${/crit|high|tier ?0|1/i.test(a.criticality) ? "malicious" : ""}` }, a.criticality) : ""),
        h("td", null, onDelete ? h("button", { class: "btn ghost sm icon", title: "Remove", onclick: () => onDelete(a) }, icon("x")) : null)))))));
}

export async function renderAssets() {
  const { shell } = await import("./app.js");
  const list = h("div");
  const q = h("input", { class: "input", placeholder: "Look up by IP, hostname, MAC (any format) or owner", style: { maxWidth: "480px" } });
  const load = async () => {
    try {
      const rows = await api("GET", `/workspaces/${state.ws.id}/assets?q=${encodeURIComponent(q.value.trim())}`);
      mount(list, rows.length ? assetTable(rows, q.value.trim() ? "Matches" : "All assets", async (a) => { await api("DELETE", `/workspaces/${state.ws.id}/assets/${a.id}`); load(); })
        : h("div", { class: "card" }, q.value.trim() ? empty("search", "No asset matches", "Try another IP, hostname or MAC.") :
          empty("server", "No assets yet", "Import your CMDB / EDR device export (CSV) or add assets by hand. Then you can look up who owns an IP, hostname or MAC during an investigation.")));
    } catch (e) { fail(e); }
  };
  q.addEventListener("input", debounce(load, 250));
  const f = { hostname: h("input", { class: "input", placeholder: "Hostname" }), ip: h("input", { class: "input mono", placeholder: "IP" }), mac: h("input", { class: "input mono", placeholder: "MAC" }),
    owner: h("input", { class: "input", placeholder: "Owner / user" }), criticality: h("select", { class: "input" }, ["", "Critical", "High", "Medium", "Low"].map((x) => h("option", { value: x }, x || "Criticality"))) };
  const addBtn = h("button", { class: "btn primary" }, icon("plus"), "Add");
  addBtn.onclick = async () => {
    const item = Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value.trim()]));
    if (!item.hostname && !item.ip && !item.mac) { toast("Enter a hostname, IP or MAC", "info"); return; }
    try { await api("POST", `/workspaces/${state.ws.id}/assets`, { items: [item] }); Object.values(f).forEach((el) => { el.value = ""; }); toast("Asset saved"); load(); } catch (e) { fail(e); }
  };
  const file = h("input", { type: "file", accept: ".csv,text/csv", class: "hidden" });
  file.addEventListener("change", async () => {
    const fl = file.files[0]; if (!fl) return;
    try { const r = await api("POST", `/workspaces/${state.ws.id}/assets`, { csv: await fl.text() }); toast(`Imported ${r.saved} asset(s)`); load(); } catch (e) { fail(e); }
    file.value = "";
  });
  shell("Assets", [h("b", null, "Asset inventory")], h("div", null,
    h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, "Asset inventory"),
      h("div", { class: "sub" }, `Hosts known to ${state.ws.name}. Look one up by IP, hostname or MAC to see who owns it and how critical it is.`)),
      h("button", { class: "btn", onclick: () => download("assets-template.csv", "hostname,ip,mac,os,owner,department,location,criticality,notes\nFIN-WS-014,10.0.4.21,00:1A:2B:3C:4D:5E,Windows 11,Jane Doe,Finance,HQ,High,\n", "text/csv") }, icon("download"), "CSV template"),
      h("button", { class: "btn", onclick: () => file.click() }, icon("upload"), "Import CSV"), file),
    h("div", { class: "card card-pad mb-16" }, h("div", { class: "row wrap" }, f.hostname, f.ip, f.mac, f.owner, f.criticality, addBtn)),
    h("div", { class: "row mb-16" }, icon("search"), q), list));
  load();
}

export { timeAgo };
