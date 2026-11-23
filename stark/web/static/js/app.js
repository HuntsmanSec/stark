import {
  api, applyTheme, avatar, busy, colorFor, copy, dispatch, empty, fail, go, h, icon, initials, link, modal, mount,
  onLeave, popMenu, route, sevPill, state, statusPill, timeAgo, toast, verdictPill, ioc, TYPE_LABEL, debounce,
  confirmDialog,
} from "./core.js";
import { renderCase } from "./case.js";
import { keysEditor, renderAssets, renderSearch, renderSetup, reputationCard } from "./intel.js";

const app = document.getElementById("app");
const LS = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* */ } } };

// ------------------------------------------------------------------ boot
async function boot() {
  try { state.meta = await api("GET", "/meta"); } catch (e) { mount(app, empty("alert", "Server unavailable", e.message)); return; }
  try { const r = await api("GET", "/me", undefined, { noAuthRedirect: true }); setUser(r.user); }
  catch { state.user = null; }
  dispatch();
}
export function setUser(u) {
  state.user = u;
  applyTheme(u && u.theme);
  if (!u) return;
  const saved = Number(LS.get("stark.ws"));
  state.ws = u.workspaces.find((w) => w.id === (state.ws && state.ws.id)) || u.workspaces.find((w) => w.id === saved) || u.workspaces[0];
}
export function setWorkspace(id) {
  const w = state.user.workspaces.find((x) => x.id === id);
  if (w) { state.ws = w; LS.set("stark.ws", String(id)); }
}

function guard(fn) {
  return (r) => { if (!state.user) { go("/login", true); return; } fn(r); };
}

// ------------------------------------------------------------------ auth
function renderAuth(mode = "login") {
  const err = h("div", { class: "form-error hidden" });
  let accountType = "personal";
  const name = h("input", { class: "input", placeholder: "Jane Analyst", autocomplete: "name" });
  const email = h("input", { class: "input", type: "email", placeholder: "you@company.com", autocomplete: "email" });
  const pw = h("input", { class: "input", type: "password", placeholder: mode === "login" ? "Your password" : "At least 10 characters",
    autocomplete: mode === "login" ? "current-password" : "new-password" });
  const team = h("input", { class: "input", placeholder: "e.g. Acme SOC" });
  const code = h("input", { class: "input mono", placeholder: "XXXX-XXXX-XXXX" });
  const teamField = h("div", { class: "field hidden" }, h("label", null, "Team name"), team, h("div", { class: "hint" }, "You'll get an invite code to share with teammates."));
  const codeField = h("div", { class: "field hidden" }, h("label", null, "Invite code"), code, h("div", { class: "hint" }, "Ask your team owner for the code from the Team page."));
  const choices = [
    ["personal", "user", "Just me", "Personal workspace"],
    ["team", "users", "New team", "Create & invite"],
    ["join", "link", "Join a team", "Use invite code"],
  ].map(([k, ic, t, s]) => h("button", { type: "button", class: `choice${k === "personal" ? " on" : ""}`, onclick: (e) => {
    accountType = k; choicesEl.querySelectorAll(".choice").forEach((c) => c.classList.remove("on")); e.currentTarget.classList.add("on");
    teamField.classList.toggle("hidden", k !== "team"); codeField.classList.toggle("hidden", k !== "join");
  } }, icon(ic), h("b", null, t), h("span", null, s)));
  const choicesEl = h("div", { class: "choice-grid" }, choices);
  const submit = h("button", { class: "btn primary lg", type: "submit", style: { width: "100%" } }, mode === "login" ? "Sign in" : "Create account");

  const form = h("form", { class: "col gap-16", onsubmit: async (e) => {
    e.preventDefault(); err.classList.add("hidden"); busy(submit, true);
    try {
      const r = mode === "login"
        ? await api("POST", "/auth/login", { email: email.value, password: pw.value }, { noAuthRedirect: true })
        : await api("POST", "/auth/register", { name: name.value, email: email.value, password: pw.value, account_type: accountType,
          team_name: team.value, invite_code: code.value }, { noAuthRedirect: true });
      setUser(r.user);
      if (accountType === "team" || accountType === "join") { const t = r.user.workspaces.find((w) => w.kind === "team"); if (t) setWorkspace(t.id); }
      go(mode === "register" || !r.user.onboarded ? "/setup" : "/");
    } catch (ex) { err.textContent = ex.message; err.classList.remove("hidden"); busy(submit, false); }
  } },
  mode === "register" ? h("div", { class: "field" }, h("label", null, "How will you use S.T.A.R.K?"), choicesEl) : null,
  mode === "register" ? h("div", { class: "field" }, h("label", null, "Full name"), name) : null,
  h("div", { class: "field" }, h("label", null, "Email"), email),
  h("div", { class: "field" }, h("label", null, "Password"), pw),
  teamField, codeField, err, submit);

  const canSignup = state.meta && state.meta.allow_signup;
  const feats = [
    ["layers", "Log Arranger", "Drop in messy exports from Sentinel, Defender, Splunk, QRadar, CrowdStrike, firewalls & WAFs and get one clean timeline."],
    ["zap", "19 reputation sources", "VirusTotal, AbuseIPDB, urlscan, ANY.RUN, OTX, abuse.ch, Shodan and more, checked in one click."],
    ["grid", "MITRE ATT&CK mapping", "Suggested techniques straight from the evidence."],
    ["file", "Incident report writer", "An executive summary, technical analysis and recommendations, drafted for you."],
    ["lock", "Client data stays private", "Raw logs are processed in memory and never saved."],
  ];
  mount(app, h("div", { class: "auth" },
    h("div", { class: "auth-hero" },
      h("div", null,
        h("div", { class: "brand", style: { padding: 0 } }, h("div", { class: "brand-mark" }, icon("shield")),
          h("div", null, h("div", { class: "brand-name" }, "S.T.A.R.K"), h("div", { class: "brand-sub" }, "Security Threat Assessment & Reputation Kit"))),
        h("h1", null, "From messy logs to a clear incident report."),
        h("p", { class: "lead" }, "A case workspace for analysts and the people they report to. Triage evidence, check every indicator and share the story with your team."),
        h("div", { class: "auth-feats" }, feats.map(([ic, t, s]) => h("div", { class: "auth-feat" }, h("div", { class: "i" }, icon(ic)), h("div", null, h("b", null, t), h("span", null, s)))))),
      h("div", { class: "tiny", style: { color: "#6b7896" } }, `Open source · v${state.meta ? state.meta.version : ""}`)),
    h("div", { class: "auth-panel" }, h("div", { class: "auth-card" },
      h("h2", null, mode === "login" ? "Welcome back" : (state.meta && !state.meta.has_users ? "Set up your workspace" : "Create your account")),
      h("div", { class: "muted" }, mode === "login" ? "Sign in to continue your investigations." : "It takes less than a minute."),
      canSignup ? h("div", { class: "seg" },
        h("button", { class: mode === "login" ? "on" : "", onclick: () => go("/login") }, "Sign in"),
        h("button", { class: mode === "register" ? "on" : "", onclick: () => go("/register") }, "Create account")) : h("div", { class: "mt-16" }),
      form))));
}

// ----------------------------------------------------------------- shell
const NAV = [
  ["/", "home", "Dashboard"], ["/cases", "folder", "Cases"], ["/search", "zap", "IOC lookup & search"], ["/assets", "server", "Assets"],
];
const NAV2 = [["/team", "users", "Team & workspace"], ["/settings", "key", "API keys & settings"], ["/setup", "sparkle", "Setup guide"]];

export function shell(title, crumbs, content, { actions } = {}) {
  const u = state.user; const ws = state.ws;
  const path = location.pathname;
  const navLink = ([href, ic, label]) => link(href, { class: (href === "/" ? path === "/" : path.startsWith(href)) ? "active" : "" }, icon(ic), label);
  const sidebar = h("aside", { class: "sidebar" },
    h("div", { class: "brand" }, h("div", { class: "brand-mark" }, icon("shield")),
      h("div", null, h("div", { class: "brand-name" }, "S.T.A.R.K"), h("div", { class: "brand-sub" }, "Threat Assessment Kit"))),
    h("button", { class: "ws-switch", onclick: (e) => wsMenu(e.currentTarget) },
      h("div", { class: "ws-avatar", style: { background: colorFor(ws.name) } }, initials(ws.name)),
      h("div", { class: "ws-meta" }, h("b", { class: "ellipsis" }, ws.name), h("span", null, ws.kind === "team" ? `Team · ${ws.members} member${ws.members !== 1 ? "s" : ""}` : "Personal")),
      icon("chevdown")),
    h("div", { class: "nav-label" }, "Investigate"), h("nav", { class: "nav" }, NAV.map(navLink)),
    h("div", { class: "nav-label" }, "Workspace"), h("nav", { class: "nav" }, NAV2.map(navLink)),
    h("div", { class: "side-foot" }, avatar(u.name), h("div", { class: "who" }, h("b", { class: "ellipsis" }, u.name), h("span", { class: "ellipsis" }, u.email)),
      h("button", { class: "btn ghost icon sm", title: "Account", onclick: (e) => userMenu(e.currentTarget) }, icon("settings"))));
  const search = h("input", { class: "input", placeholder: "Paste an IOC or search hosts, IPs, cases…", title: "Fanged or defanged IOCs get a quick reputation summary",
    onkeydown: (e) => { if (e.key === "Enter" && e.target.value.trim()) go(`/search?q=${encodeURIComponent(e.target.value.trim())}`); } });
  mount(app, h("div", { class: "shell" }, sidebar,
    h("div", { class: "main" },
      h("header", { class: "topbar" },
        h("button", { class: "btn ghost icon menu-toggle", onclick: () => sidebar.classList.toggle("open") }, icon("menu")),
        h("div", { class: "crumbs grow" }, crumbs),
        h("div", { class: "search" }, icon("search"), search),
        actions || null),
      h("main", { class: "content" }, h("div", { class: "page" }, content)))));
  document.title = `${title} · S.T.A.R.K`;
}

function wsMenu(anchor) {
  popMenu(anchor, [
    ...state.user.workspaces.map((w) => ({ icon: w.kind === "team" ? "users" : "user", label: w.name, hint: w.id === state.ws.id ? "current" : w.kind,
      onclick: () => { setWorkspace(w.id); go("/"); } })),
    "-",
    { icon: "plus", label: "Create a team workspace", onclick: createTeamDialog },
    { icon: "link", label: "Join a team with a code", onclick: joinTeamDialog },
  ]);
}
function userMenu(anchor) {
  const setTheme = async (t) => { try { const r = await api("PATCH", "/me", { theme: t }); setUser(r.user); dispatch(); } catch (e) { fail(e); } };
  popMenu(anchor, [
    { icon: "sun", label: "Light theme", onclick: () => setTheme("light") },
    { icon: "moon", label: "Dark theme", onclick: () => setTheme("dark") },
    { icon: "settings", label: "Match system", onclick: () => setTheme("system") },
    "-",
    { icon: "user", label: "Account settings", onclick: () => go("/settings#account") },
    { icon: "logout", label: "Sign out", onclick: async () => { await api("POST", "/auth/logout").catch(() => {}); state.user = null; go("/login"); } },
  ]);
}
export function createTeamDialog() {
  const name = h("input", { class: "input", placeholder: "e.g. Acme SOC" });
  const m = modal({ title: "Create a team workspace", subtitle: "Team members share cases, observables, API keys and reports, and see each other's changes live.",
    body: h("div", { class: "field" }, h("label", null, "Team name"), name),
    foot: [h("button", { class: "btn", onclick: () => m.close() }, "Cancel"), h("button", { class: "btn primary", onclick: async (e) => {
      const btn = e.currentTarget; busy(btn, true);
      try { const r = await api("POST", "/workspaces", { name: name.value }); setUser(r.user); setWorkspace(r.id); m.close(); toast("Team created. Share the invite code with teammates."); go("/team"); }
      catch (ex) { fail(ex); busy(btn, false); }
    } }, "Create team")] });
}
export function joinTeamDialog() {
  const code = h("input", { class: "input mono", placeholder: "XXXX-XXXX-XXXX" });
  const m = modal({ title: "Join a team", body: h("div", { class: "field" }, h("label", null, "Invite code"), code, h("div", { class: "hint" }, "The team owner can find it on the Team page.")),
    foot: [h("button", { class: "btn", onclick: () => m.close() }, "Cancel"), h("button", { class: "btn primary", onclick: async (e) => {
      const btn = e.currentTarget; busy(btn, true);
      try { const r = await api("POST", "/workspaces/join", { code: code.value }); setUser(r.user); setWorkspace(r.id); m.close(); toast("You joined the team"); go("/"); }
      catch (ex) { fail(ex); busy(btn, false); }
    } }, "Join team")] });
}

// ------------------------------------------------------------- new case
export function newCaseDialog(prefill = {}) {
  const title = h("input", { class: "input", placeholder: "e.g. Suspicious PowerShell on FIN-WS-014", value: prefill.title || "" });
  const sev = h("select", { class: "input" }, ["low", "medium", "high", "critical"].map((s) => h("option", { value: s, selected: s === "medium" }, s[0].toUpperCase() + s.slice(1))));
  const cls = h("select", { class: "input" }, ["", "Malware", "Phishing", "Ransomware", "Unauthorized access", "Account compromise", "Data exfiltration",
    "Web application attack", "Denial of service", "Insider threat", "Policy violation", "Other"].map((c) => h("option", { value: c }, c || "Not sure yet")));
  const tlp = h("select", { class: "input" }, ["clear", "green", "amber", "amber+strict", "red"].map((t) => h("option", { value: t, selected: t === "amber" }, `TLP:${t.toUpperCase()}`)));
  const desc = h("textarea", { class: "input", rows: 4, placeholder: "What was reported, by whom, and what do you know so far? (optional)" });
  const fld = (ph, v = "") => h("input", { class: "input", placeholder: ph, value: v });
  const alertName = fld("e.g. Password spray against Entra ID", prefill.alert_name), customer = fld("Client name", prefill.customer || ""),
    findingId = fld("Finding ID from the SIEM / Fusion"), alertUrl = fld("https://security.microsoft.com/…"), siem = fld("e.g. Microsoft Sentinel, Splunk, QRadar");
  const submit = h("button", { class: "btn primary" }, icon("plus"), "Open case");
  const noKeys = state.ws && !state.ws.keys_configured;
  const m = modal({ title: "Open a new case", subtitle: `In ${state.ws.name}. You can change everything later.`,
    body: h("div", { class: "form-grid" },
      h("div", { class: "field full" }, h("label", null, "Case title"), title),
      h("div", { class: "field" }, h("label", null, "Severity"), sev), h("div", { class: "field" }, h("label", null, "Type of incident"), cls),
      h("div", { class: "field" }, h("label", null, "Sharing (TLP)"), tlp, h("div", { class: "hint" }, "Controls how widely the report may be shared.")),
      h("div", { class: "field full" }, h("label", null, "Initial notes"), desc),
      h("details", { class: "full" }, h("summary", { class: "small", style: { cursor: "pointer" } }, "Alert details (MSSP / SOC triage, optional)"),
        h("div", { class: "form-grid mt-8" },
          h("div", { class: "field" }, h("label", null, "Alert name"), alertName), h("div", { class: "field" }, h("label", null, "Customer"), customer),
          h("div", { class: "field" }, h("label", null, "Finding ID"), findingId), h("div", { class: "field" }, h("label", null, "Log source / SIEM"), siem),
          h("div", { class: "field full" }, h("label", null, "Alert link"), alertUrl),
          h("div", { class: "hint full" }, "With an alert name and customer, the report writer checks past tickets, closures and pentest notes for the same alert and decides whether to append, close or raise an incident."))),
      noKeys ? h("div", { class: "full notice warn" }, icon("key"), h("div", { class: "small" }, h("b", null, "No intelligence sources connected yet"),
        "Indicators can only be checked against keyless sources. ", h("a", { href: "/setup", "data-link": true, onclick: () => m.close() }, "Connect API keys first"), " (takes a minute).")) : null),
    foot: [h("button", { class: "btn", onclick: () => m.close() }, "Cancel"), submit] });
  submit.onclick = async () => {
    busy(submit, true);
    try {
      const c = await api("POST", `/workspaces/${state.ws.id}/cases`, { title: title.value, severity: sev.value, classification: cls.value, tlp: tlp.value, description: desc.value,
        alert_name: alertName.value, customer: customer.value, finding_id: findingId.value, alert_url: alertUrl.value, siem: siem.value });
      m.close(); toast(`${c.ref} opened`); go(`/cases/${c.id}?tab=logs`);
    } catch (e) { fail(e); busy(submit, false); }
  };
  title.addEventListener("keydown", (e) => { if (e.key === "Enter") submit.click(); });
}

// ------------------------------------------------------------- dashboard
async function renderDashboard() {
  const content = h("div", null, h("div", { class: "empty" }, h("span", { class: "spinner" })));
  shell("Dashboard", [h("b", null, "Dashboard")], content, { actions: h("button", { class: "btn primary", onclick: () => newCaseDialog() }, icon("plus"), "New case") });
  const wsId = state.ws.id;
  const load = async () => {
    const [d, act] = await Promise.all([api("GET", `/workspaces/${wsId}/dashboard`), api("GET", `/workspaces/${wsId}/activity`)]);
    const s = d.stats;
    const hour = new Date().getHours();
    const greet = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
    const stat = (ic, color, n, label) => h("div", { class: "card stat" }, h("div", { class: "stat-icon", style: { background: `color-mix(in srgb, ${color} 14%, transparent)`, color } }, icon(ic)), h("div", null, h("b", null, n), h("span", null, label)));
    mount(content,
      h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, `${greet}, ${state.user.name.split(" ")[0]}`),
        h("div", { class: "sub" }, state.ws.kind === "team" ? `You're working in the ${state.ws.name} team workspace. Changes sync live with teammates.` : "Your personal workspace. Only you can see these cases."))),
      !state.ws.keys_configured ? h("div", { class: "notice warn mb-16" }, icon("key"), h("div", { class: "grow" }, h("b", null, "Connect your threat-intelligence sources"),
        h("span", { class: "small" }, "Add API keys for VirusTotal, AbuseIPDB, abuse.ch and others so indicators in your cases get checked automatically.")),
        link("/setup", { class: "btn sm primary" }, "Set up now")) : null,
      (() => { const inp = h("input", { class: "input mono", placeholder: "Paste an IOC for a quick reputation check: 185.220.101[.]1, hxxps://evil[.]com/x, a hash, an email…",
        onkeydown: (e) => { if (e.key === "Enter" && inp.value.trim()) go(`/search?q=${encodeURIComponent(inp.value.trim())}`); } });
        return h("div", { class: "card card-pad mb-16 row" }, icon("zap"), h("div", { class: "grow" }, inp), h("button", { class: "btn primary", onclick: () => inp.value.trim() && go(`/search?q=${encodeURIComponent(inp.value.trim())}`) }, "Check")); })(),
      h("div", { class: "grid grid-4 mb-16" },
        stat("folder", "var(--accent)", s.open, "Active cases"), stat("alert", "var(--mal)", s.urgent, "High / critical"),
        stat("bug", "var(--sus)", s.flagged_iocs, "Flagged indicators"), stat("check", "var(--ok)", s.closed, "Closed cases")),
      h("div", { class: "grid grid-main" },
        h("div", { class: "card" }, h("div", { class: "card-head" }, h("h3", null, "Recent cases"), link("/cases", { class: "small" }, "View all")),
          d.recent.length ? h("div", { class: "table-wrap" }, caseTable(d.recent, true)) :
            empty("folder", "No cases yet", "A case holds everything about one incident: logs, indicators, ATT&CK techniques and the report.",
              h("button", { class: "btn primary", onclick: () => newCaseDialog() }, icon("plus"), "Open your first case"))),
        h("div", { class: "col gap-16" },
          h("div", { class: "card" }, h("div", { class: "card-head" }, h("h3", null, "How it works")),
            h("div", { class: "card-body col gap-12" }, [
              ["1", "Open a case", "Give the incident a name and severity."],
              ["2", "Arrange the logs", "Drop in exports from any SIEM, EDR, firewall or WAF."],
              ["3", "Check indicators", "IOCs are pulled out for you. Check their reputation in one click."],
              ["4", "Write the report", "Generate the initial analysis, review it, then share or print it."],
            ].map(([n, t, d2]) => h("div", { class: "row top gap-12" }, h("div", { class: "step-n", style: { width: "24px", height: "24px", borderRadius: "50%", background: "var(--accent-soft)", color: "var(--accent)", display: "grid", placeItems: "center", fontWeight: 700, fontSize: "12px", flex: "none" } }, n),
              h("div", null, h("b", null, t), h("div", { class: "muted small" }, d2)))))),
          h("div", { class: "card" }, h("div", { class: "card-head" }, h("h3", null, "Activity"), state.ws.kind === "team" ? h("span", { class: "row small muted" }, h("span", { class: "sync-dot" }), "Live") : null),
            h("div", { class: "card-body" }, act.length ? activityFeed(act.slice(0, 12)) : h("div", { class: "muted small" }, "Nothing yet."))))));
  };
  try { await load(); } catch (e) { fail(e); }
  const t = setInterval(() => load().catch(() => {}), 15000); onLeave(() => clearInterval(t));
}

export function activityFeed(items) {
  return h("div", { class: "feed" }, items.map((a) => h("div", { class: "feed-item" }, avatar(a.user_name || "?"),
    h("div", { class: "grow" }, h("div", null, h("b", null, a.user_name || "Someone"), " ", a.text), h("time", null, timeAgo(a.created_at))))));
}

function caseTable(rows, compact) {
  return h("table", { class: "table" },
    h("thead", null, h("tr", null, h("th", null, "Case"), h("th", null, "Severity"), h("th", null, "Status"), compact ? null : h("th", null, "Indicators"), h("th", null, "Assignee"), h("th", null, "Updated"))),
    h("tbody", null, rows.map((c) => h("tr", { class: "clickable", onclick: () => go(`/cases/${c.id}`) },
      h("td", null, h("div", { class: "case-title" }, c.title), h("div", { class: "case-ref" }, c.ref, c.classification ? ` · ${c.classification}` : "")),
      h("td", null, sevPill(c.severity)), h("td", null, statusPill(c.status)),
      compact ? null : h("td", null, c.ioc_count ? h("span", null, c.ioc_count, c.malicious_count ? h("span", { class: "pill malicious", style: { marginLeft: "8px" } }, `${c.malicious_count} malicious`) : null) : h("span", { class: "faint" }, "-")),
      h("td", null, c.assignee_name ? h("span", { class: "row" }, avatar(c.assignee_name, "avatar"), h("span", { class: "small" }, c.assignee_name)) : h("span", { class: "faint" }, "Unassigned")),
      h("td", { class: "muted small" }, timeAgo(c.updated_at))))));
}

// ------------------------------------------------------------- case list
async function renderCases(r) {
  const q = r.query.get("q") || "";
  let status = r.query.get("status") || "active";
  const list = h("div");
  const search = h("input", { class: "input", placeholder: "Search by title, reference or indicator", value: q, style: { maxWidth: "360px" } });
  const filters = h("div", { class: "row gap-4" });
  const load = async () => {
    try {
      const rows = await api("GET", `/workspaces/${state.ws.id}/cases?status=${status}&q=${encodeURIComponent(search.value.trim())}`);
      mount(filters, [["active", "Active"], ["open", "Open"], ["in_progress", "In progress"], ["on_hold", "On hold"], ["contained", "Contained"], ["resolved", "Resolved"], ["closed", "Closed"], ["all", "All"]].map(([k, l]) =>
        h("button", { class: `chip-btn${status === k ? " on" : ""}`, onclick: () => { status = k; load(); } }, l)));
      mount(list, rows.length ? h("div", { class: "card table-wrap" }, caseTable(rows)) :
        h("div", { class: "card" }, search.value ? empty("search", "No matching cases", "Try another search or filter.") :
          empty("folder", "No cases here yet", "Open a case to start triaging an incident.", h("button", { class: "btn primary", onclick: () => newCaseDialog() }, icon("plus"), "New case"))));
    } catch (e) { fail(e); }
  };
  search.addEventListener("input", debounce(load, 300));
  shell("Cases", [h("b", null, "Cases")], h("div", null,
    h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, "Cases"), h("div", { class: "sub" }, `All investigations in ${state.ws.name}.`)),
      h("button", { class: "btn primary", onclick: () => newCaseDialog() }, icon("plus"), "New case")),
    h("div", { class: "row wrap gap-12 mb-16" }, search, filters), list));
  load();
}

// ----------------------------------------------------------- quick lookup
function renderLookup() {
  const ta = h("textarea", { class: "input mono", rows: 4, placeholder: "Paste one or more IPs, domains, URLs, hashes or emails, one per line. Defanged values like hxxp://evil[.]com work too." });
  const out = h("div", { class: "col gap-12 mt-16" });
  const btn = h("button", { class: "btn primary lg" }, icon("zap"), "Check reputation");
  btn.onclick = async () => {
    busy(btn, true, "Checking…"); out.replaceChildren();
    try {
      const r = await api("POST", "/lookup", { workspace_id: state.ws.id, text: ta.value });
      mount(out, r.results.map((x) => reputationCard(x)));
    } catch (e) { fail(e); }
    busy(btn, false);
  };
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) btn.click(); });
  shell("Quick lookup", [h("b", null, "Quick lookup")], h("div", null,
    h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, "Quick lookup"),
      h("div", { class: "sub" }, "Check indicators against every configured reputation source without opening a case. Results aren't saved."))),
    h("div", { class: "card card-pad" }, ta, h("div", { class: "row mt-8" }, h("span", { class: "hint grow" }, "Tip: press ", h("span", { class: "kbd" }, "Ctrl"), " + ", h("span", { class: "kbd" }, "Enter"), " to run."), btn)),
    out));
}
export function resultCard(rep) {
  return h("div", { class: "card card-pad" },
    h("div", { class: "row wrap mb-8" }, ioc(rep.observable, rep.verdict), h("span", { class: "tag" }, TYPE_LABEL[rep.type] || rep.type), verdictPill(rep.verdict),
      h("span", { class: "spacer" }), h("span", { class: "small muted" }, `${rep.malicious} malicious · ${rep.suspicious} suspicious · ${rep.results.length} sources`)),
    rep.malware_families && rep.malware_families.length ? h("div", { class: "small mb-8" }, h("b", null, "Families: "), rep.malware_families.join(", ")) : null,
    providerRows(rep.results));
}
export function providerRows(results) {
  return h("div", null, results.map((p) => h("div", { class: "provider-row" },
    h("b", null, p.provider), h("div", null, verdictPill(p.verdict)),
    h("div", { class: "small" }, p.error ? h("span", { style: { color: "var(--err)" } }, p.error) : p.summary,
      p.link ? h("div", null, h("a", { href: p.link, target: "_blank", rel: "noopener noreferrer", class: "tiny" }, "Open report ↗")) : null))));
}

// ------------------------------------------------------------------ team
async function renderTeam() {
  const content = h("div");
  shell("Team", [h("b", null, "Team & workspace")], content);
  const load = async () => {
    const ws = await api("GET", `/workspaces/${state.ws.id}`);
    const admin = ws.role === "owner" || ws.role === "admin";
    const nameInput = h("input", { class: "input", value: ws.name, disabled: !admin });
    mount(content,
      h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, ws.name),
        h("div", { class: "sub" }, ws.kind === "team" ? "Team workspace. Members share cases, API keys and reports." : "Personal workspace. Only you have access.")),
        h("button", { class: "btn", onclick: joinTeamDialog }, icon("link"), "Join a team"), h("button", { class: "btn primary", onclick: createTeamDialog }, icon("plus"), "Create team")),
      h("div", { class: "grid grid-main" },
        h("div", { class: "card" }, h("div", { class: "card-head" }, h("h3", null, `Members (${ws.members.length})`)),
          h("div", { class: "card-body" }, ws.members.map((m) => h("div", { class: "list-row" }, avatar(m.name),
            h("div", { class: "grow" }, h("b", null, m.name, m.id === state.user.id ? h("span", { class: "faint" }, " (you)") : null), h("div", { class: "small muted" }, m.email)),
            admin && m.role !== "owner" ? h("select", { class: "meta-select", onchange: async (e) => { try { await api("PATCH", `/workspaces/${ws.id}/members/${m.id}`, { role: e.target.value }); toast("Role updated"); } catch (ex) { fail(ex); } } },
              ["member", "admin"].map((r) => h("option", { value: r, selected: m.role === r }, r[0].toUpperCase() + r.slice(1)))) : h("span", { class: "tag" }, m.role),
            (admin && m.role !== "owner") || (m.id === state.user.id && m.role !== "owner") ? h("button", { class: "btn ghost sm danger", onclick: async () => {
              if (!await confirmDialog(m.id === state.user.id ? "Leave team?" : `Remove ${m.name}?`, m.id === state.user.id ? "You'll lose access to this team's cases." : "They'll lose access to this team's cases.", { ok: m.id === state.user.id ? "Leave" : "Remove" })) return;
              try { await api("DELETE", `/workspaces/${ws.id}/members/${m.id}`); if (m.id === state.user.id) { const r = await api("GET", "/me"); setUser(r.user); go("/"); } else load(); } catch (ex) { fail(ex); }
            } }, m.id === state.user.id ? "Leave" : "Remove") : null)))),
        h("div", { class: "col gap-16" },
          ws.kind === "team" && ws.invite_code ? h("div", { class: "card card-pad" }, h("h3", { class: "mb-8" }, "Invite teammates"),
            h("p", { class: "muted small" }, "Teammates create an account on this S.T.A.R.K server and choose “Join a team” with this code."),
            h("div", { class: "row mt-8" }, h("code", { class: "ioc", style: { fontSize: "16px", padding: "6px 12px" } }, ws.invite_code), h("button", { class: "btn sm", onclick: () => copy(ws.invite_code) }, icon("copy"), "Copy")),
            h("div", { class: "row mt-8" }, h("button", { class: "link-btn small", onclick: async () => { if (await confirmDialog("Generate a new code?", "The old code will stop working.", { ok: "Regenerate", danger: false })) { await api("PATCH", `/workspaces/${ws.id}`, { regenerate_invite: true }); load(); } } }, "Generate a new code"))) :
            ws.kind === "personal" ? h("div", { class: "notice info" }, icon("info"), h("div", null, h("b", null, "Working with others?"), h("span", { class: "small" }, "Create a team workspace and share its invite code. Cases in the team workspace sync live between members."))) : null,
          h("div", { class: "card card-pad" }, h("h3", { class: "mb-8" }, "Workspace name"), h("div", { class: "row" }, nameInput,
            admin ? h("button", { class: "btn", onclick: async () => { try { await api("PATCH", `/workspaces/${ws.id}`, { name: nameInput.value }); const r = await api("GET", "/me"); setUser(r.user); toast("Saved"); renderTeam(); } catch (e) { fail(e); } } }, "Save") : null)),
          h("div", { class: "card card-pad" }, h("h3", { class: "mb-8" }, "Hosting for a team"),
            h("p", { class: "small muted" }, "For a shared team server, run S.T.A.R.K on a host everyone can reach, behind HTTPS:"),
            h("pre", { class: "raw" }, "stark serve --host 0.0.0.0 --port 8765 --no-signup --secure-cookies"),
            h("p", { class: "small muted mt-8" }, "Or use the Docker image. See docs/workspace.md.")))));
  };
  try { await load(); } catch (e) { fail(e); }
}

// -------------------------------------------------------------- settings
async function renderSettings() {
  const content = h("div");
  shell("Settings", [h("b", null, "API keys & settings")], content);
  try {
    const ed = await keysEditor(state.ws.id, { onSaved: async () => { const r = await api("GET", "/me"); setUser(r.user); renderSettings(); } });
    const pwCur = h("input", { class: "input", type: "password", autocomplete: "current-password" });
    const pwNew = h("input", { class: "input", type: "password", autocomplete: "new-password" });
    const nameIn = h("input", { class: "input", value: state.user.name });
    mount(content,
      h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, "API keys & settings"),
        h("div", { class: "sub" }, state.ws.kind === "team" ? `Keys are shared with everyone in ${state.ws.name}. Only owners and admins can change them.` : "Keys are stored in your local S.T.A.R.K database."))),
      h("div", { class: "card mb-16" }, h("div", { class: "card-head" }, h("h3", null, `Reputation sources (${ed.configured} connected)`), ed.canEdit ? ed.save : h("span", { class: "small muted" }, "Read-only: ask an admin to change keys")),
        h("div", { class: "card-body" }, h("div", { class: "notice info mb-16" }, icon("lock"), h("div", { class: "small" }, "Keys are never shown again after saving, and are only sent to their own service. Use Test to check a key before saving.")), ed.el)),
      h("div", { class: "card", id: "account" }, h("div", { class: "card-head" }, h("h3", null, "Your account")),
        h("div", { class: "card-body form-grid" },
          h("div", { class: "field" }, h("label", null, "Display name"), nameIn),
          h("div", { class: "field" }, h("label", null, "Email"), h("input", { class: "input", value: state.user.email, disabled: true })),
          h("div", { class: "field" }, h("label", null, "Current password"), pwCur),
          h("div", { class: "field" }, h("label", null, "New password"), pwNew),
          h("div", { class: "full row" }, h("span", { class: "spacer" }), h("button", { class: "btn", onclick: async () => {
            try { const r = await api("PATCH", "/me", { name: nameIn.value, ...(pwNew.value ? { current_password: pwCur.value, new_password: pwNew.value } : {}) }); setUser(r.user); toast("Account updated"); renderSettings(); } catch (e) { fail(e); }
          } }, "Update account")))));
    if (location.hash === "#account") document.getElementById("account").scrollIntoView();
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------- routes
route("/login", () => { if (state.user) go("/", true); else renderAuth("login"); });
route("/register", () => { if (state.user) go("/", true); else if (state.meta.allow_signup) renderAuth("register"); else go("/login", true); });
route("/", guard(renderDashboard));
route("/cases", guard(renderCases));
route("/cases/:id", guard((r) => renderCase(Number(r.params.id), r.query)));
route("/lookup", guard(renderLookup));
route("/search", guard(renderSearch));
route("/assets", guard(renderAssets));
route("/setup", guard(renderSetup));
route("/team", guard(renderTeam));
route("/settings", guard(renderSettings));

// First visit to an empty server goes straight to the setup screen.
boot().then(() => {
  if (!state.user && state.meta && !state.meta.has_users && location.pathname !== "/register") go("/register", true);
  else if (state.user && !state.user.onboarded && location.pathname === "/") go("/setup", true);
});
