// Core helpers: DOM builder, icons, API client, toasts, modals, router, formatting.

export const state = { user: null, ws: null, meta: null, route: null };

// ------------------------------------------------------------------ DOM
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === "html") el.innerHTML = v; // only ever used with trusted, static markup (icons, rendered md)
      else if (k === "value") el.value = v;
      else if (k === "checked") el.checked = !!v;
      else if (v === true) el.setAttribute(k, "");
      else el.setAttribute(k, v);
    }
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}
export const frag = (...c) => { const f = document.createDocumentFragment(); append(f, c); return f; };
export function mount(target, ...children) { target.replaceChildren(); append(target, children); return target; }

// ---------------------------------------------------------------- icons
const P = {
  shield: '<path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M9 12l2 2 4-4"/>',
  home: '<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/>',
  folder: '<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0113 0"/><path d="M16 4.5a3.5 3.5 0 010 7M21.5 20a6.5 6.5 0 00-4-6"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0116 0"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M15 8l2 2"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.6 1.6 0 00-1.8-.3 1.6 1.6 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.6 1.6 0 00-1-1.5 1.6 1.6 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.6 1.6 0 00.3-1.8 1.6 1.6 0 00-1.5-1H3a2 2 0 110-4h.1a1.6 1.6 0 001.5-1 1.6 1.6 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.6 1.6 0 001.8.3H9a1.6 1.6 0 001-1.5V3a2 2 0 114 0v.1a1.6 1.6 0 001 1.5 1.6 1.6 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.6 1.6 0 00-.3 1.8V9a1.6 1.6 0 001.5 1H21a2 2 0 110 4h-.1a1.6 1.6 0 00-1.5 1z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>', x: '<path d="M6 6l12 12M18 6L6 18"/>', check: '<path d="M5 12l5 5L20 7"/>',
  logs: '<path d="M4 6h16M4 12h10M4 18h13"/><circle cx="19" cy="12" r="1.5"/>',
  layers: '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  file: '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>', activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  upload: '<path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 16v3a2 2 0 002 2h12a2 2 0 002-2v-3"/>',
  download: '<path d="M12 4v12M7 11l5 5 5-5"/><path d="M4 18v1a2 2 0 002 2h12a2 2 0 002-2v-1"/>',
  zap: '<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>', trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 012-2h10"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M14 6l4 4"/>', pin: '<path d="M12 17v5M8 3h8l-1 6 3 4H6l3-4z"/>',
  alert: '<path d="M12 3l10 18H2z"/><path d="M12 10v4M12 18h.01"/>', info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
  bug: '<rect x="7" y="7" width="10" height="13" rx="5"/><path d="M12 7V4M8 4l2 3M16 4l-2 3M3 13h4M17 13h4M4 19l3-2M20 19l-3-2M4 7l3 2M20 7l-3 2"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/>',
  hash: '<path d="M5 9h14M5 15h14M10 3L8 21M16 3l-2 18"/>', mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  link: '<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
  logout: '<path d="M15 4h3a2 2 0 012 2v12a2 2 0 01-2 2h-3"/><path d="M10 17l-5-5 5-5M5 12h11"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M21 13A9 9 0 1111 3a7 7 0 0010 10z"/>', chevron: '<path d="M9 6l6 6-6 6"/>', chevdown: '<path d="M6 9l6 6 6-6"/>',
  refresh: '<path d="M20 11a8 8 0 00-14.7-4M4 4v4h4M4 13a8 8 0 0014.7 4M20 20v-4h-4"/>', filter: '<path d="M3 5h18l-7 8v6l-4 2v-8z"/>',
  sparkle: '<path d="M12 3l2 6 6 2-6 2-2 6-2-6-6-2 6-2z"/>', printer: '<path d="M6 9V3h12v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v7H7z"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>', message: '<path d="M4 5h16v11H9l-5 4z"/>', flag: '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
  external: '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V7a1 1 0 011-1h5"/>',
};
export function icon(name, cls) {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("fill", "none"); s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "1.9"); s.setAttribute("stroke-linecap", "round"); s.setAttribute("stroke-linejoin", "round");
  s.setAttribute("aria-hidden", "true"); if (cls) s.setAttribute("class", cls);
  s.innerHTML = P[name] || P.info;
  return s;
}

// ------------------------------------------------------------------ API
export class ApiError extends Error { constructor(msg, status) { super(msg); this.status = status; } }
export async function api(method, path, data, opts = {}) {
  const init = { method, headers: { "X-Stark": "1" }, credentials: "same-origin" };
  if (data instanceof FormData) init.body = data;
  else if (data !== undefined) { init.body = JSON.stringify(data); init.headers["Content-Type"] = "application/json"; }
  let res;
  try { res = await fetch("/api" + path, init); } catch { throw new ApiError("Can't reach the S.T.A.R.K server. Is it still running?", 0); }
  if (opts.raw) return res;
  let body = null;
  try { body = await res.json(); } catch { /* empty */ }
  if (!res.ok) {
    if (res.status === 401 && !opts.noAuthRedirect) { state.user = null; go("/login"); }
    throw new ApiError((body && body.error) || `Request failed (${res.status})`, res.status);
  }
  return body;
}

// --------------------------------------------------------------- toasts
export function toast(msg, kind = "ok", ms = 3200) {
  const t = h("div", { class: `toast ${kind}`, role: "status" },
    icon(kind === "err" ? "alert" : kind === "info" ? "info" : "check"), h("div", null, msg));
  document.getElementById("toasts").appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .3s"; setTimeout(() => t.remove(), 320); }, ms);
}
export const fail = (e) => toast(e.message || String(e), "err", 5200);

// ---------------------------------------------------------------- modal
export function modal({ title, body, foot, wide, drawer, onClose, subtitle }) {
  const close = () => { bd.remove(); document.removeEventListener("keydown", onKey); onClose && onClose(); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  const box = h("div", { class: drawer ? "drawer" : `modal${wide ? " wide" : ""}`, role: "dialog", "aria-modal": "true" },
    h("div", { class: "modal-head" }, h("div", { class: "grow" }, h("h2", null, title), subtitle ? h("div", { class: "muted small mt-8" }, subtitle) : null),
      h("button", { class: "btn ghost icon", onclick: close, "aria-label": "Close" }, icon("x"))),
    h("div", { class: "modal-body" }, body), foot ? h("div", { class: "modal-foot" }, foot) : null);
  const bd = h("div", { class: "backdrop", onmousedown: (e) => { if (e.target === bd) close(); } }, box);
  document.body.appendChild(bd); document.addEventListener("keydown", onKey);
  setTimeout(() => { const f = box.querySelector("input:not([type=checkbox]), textarea, select"); f && f.focus(); }, 30);
  return { close, el: box };
}
export function confirmDialog(title, text, { danger = true, ok = "Delete" } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const m = modal({
      title, body: h("p", { class: "muted" }, text),
      foot: [h("button", { class: "btn", onclick: () => { done = true; m.close(); resolve(false); } }, "Cancel"),
        h("button", { class: `btn ${danger ? "danger" : "primary"}`, onclick: () => { done = true; m.close(); resolve(true); } }, ok)],
      onClose: () => { if (!done) resolve(false); },
    });
  });
}
export function popMenu(anchor, items) {
  document.querySelectorAll(".menu").forEach((m) => m.remove());
  const r = anchor.getBoundingClientRect();
  const m = h("div", { class: "menu" }, items.map((it) => it === "-" ? h("hr") :
    h("button", { onclick: () => { m.remove(); it.onclick(); } }, it.icon ? icon(it.icon) : null, h("span", { class: "grow" }, it.label),
      it.hint ? h("span", { class: "faint tiny" }, it.hint) : null)));
  document.body.appendChild(m);
  const top = Math.min(r.bottom + 6, window.innerHeight - m.offsetHeight - 10);
  m.style.top = `${top}px`; m.style.left = `${Math.min(r.left, window.innerWidth - m.offsetWidth - 10)}px`;
  setTimeout(() => document.addEventListener("mousedown", function off(e) { if (!m.contains(e.target)) { m.remove(); document.removeEventListener("mousedown", off); } }), 0);
}

// --------------------------------------------------------------- router
const routes = [];
export function route(pattern, handler) { routes.push({ re: new RegExp("^" + pattern.replace(/:(\w+)/g, "(?<$1>[^/]+)") + "/?$"), handler }); }
export function go(path, replace = false) {
  if (location.pathname + location.search === path) { dispatch(); return; }
  replace ? history.replaceState(null, "", path) : history.pushState(null, "", path);
  dispatch();
}
let cleanup = [];
export function onLeave(fn) { cleanup.push(fn); }
export function dispatch() {
  const leaving = cleanup; cleanup = [];
  for (const fn of leaving) { try { fn(); } catch { /* ignore */ } }
  const path = location.pathname;
  for (const r of routes) {
    const m = path.match(r.re);
    if (m) { state.route = { path, params: m.groups || {}, query: new URLSearchParams(location.search) }; r.handler(state.route); return; }
  }
  go("/", true);
}
window.addEventListener("popstate", dispatch);
document.addEventListener("click", (e) => {
  const a = e.target.closest("a[data-link]");
  if (a && !e.metaKey && !e.ctrlKey && !e.shiftKey && e.button === 0) { e.preventDefault(); go(a.getAttribute("href")); }
});
export const link = (href, attrs, ...c) => h("a", { href, "data-link": true, ...(attrs || {}) }, ...c);

// ----------------------------------------------------------- formatting
export function timeAgo(ts) {
  if (!ts) return "";
  const s = (Date.now() / 1000) - ts;
  if (s < 45) return "just now"; if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`; if (s < 86400 * 7) return `${Math.round(s / 86400)} d ago`;
  return new Date(ts * 1000).toLocaleDateString();
}
export function fmtTime(iso) { return iso ? iso.replace("T", " ").replace(/\.\d+Z$|Z$/, "") : ""; }
export function fmtDate(ts) { return ts ? new Date(ts * 1000).toLocaleString() : ""; }
const PALETTE = ["#2563eb", "#7c3aed", "#db2777", "#ea580c", "#059669", "#0891b2", "#4f46e5", "#ca8a04"];
export function colorFor(s) { let n = 0; for (const c of String(s || "")) n = (n * 31 + c.charCodeAt(0)) >>> 0; return PALETTE[n % PALETTE.length]; }
export const initials = (name) => String(name || "?").split(/\s+/).map((p) => p[0]).join("").slice(0, 2).toUpperCase();
export const avatar = (name, cls = "avatar") => h("div", { class: cls, style: { background: colorFor(name) }, title: name }, initials(name));

export const VERDICT_LABEL = { malicious: "Malicious", suspicious: "Suspicious", harmless: "Clean", unknown: "No data", error: "Error", pending: "Not checked" };
export function verdictPill(v) { v = v || "pending"; return h("span", { class: `pill ${v}` }, h("span", { class: "dot" }), VERDICT_LABEL[v] || v); }
export const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
export const sevPill = (s) => h("span", { class: `pill sev-${s}` }, SEV_LABEL[s] || s);
export const STATUS_LABEL = { open: "Open", in_progress: "In progress", on_hold: "On hold", contained: "Contained", resolved: "Resolved", closed: "Closed", cancelled: "Cancelled" };
export const statusPill = (s) => h("span", { class: `pill st-${s}` }, STATUS_LABEL[s] || s);
export const TYPE_LABEL = { ipv4: "IPv4", ipv6: "IPv6", domain: "Domain", url: "URL", md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", email: "Email" };
export const TYPE_ICON = { ipv4: "server", ipv6: "server", domain: "globe", url: "link", md5: "hash", sha1: "hash", sha256: "hash", email: "mail" };
export function ioc(value, verdict, extra = "") {
  const cls = ["ioc", verdict === "malicious" || verdict === "suspicious" ? verdict : "", extra].filter(Boolean).join(" ");
  return h("code", { class: cls, title: "Click to copy", style: { cursor: "copy" }, onclick: (e) => { e.stopPropagation(); copy(value); } }, value);
}
export async function copy(text, msg = "Copied to clipboard") {
  try { await navigator.clipboard.writeText(text); toast(msg, "info", 1600); }
  catch { const t = h("textarea", { style: { position: "fixed", opacity: "0" } }); t.value = text; document.body.appendChild(t); t.select(); document.execCommand("copy"); t.remove(); toast(msg, "info", 1600); }
}
export function download(name, text, mime = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = h("a", { href: url, download: name }); document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
export function debounce(fn, ms = 250) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
export function empty(iconName, title, text, action) {
  return h("div", { class: "empty" }, h("div", { class: "ill" }, icon(iconName)), h("h3", null, title), text ? h("p", null, text) : null, action || null);
}
export function busy(btn, on, label) {
  if (on) { btn.dataset.label = btn.innerHTML; btn.disabled = true; btn.replaceChildren(h("span", { class: "spinner" }), label ? " " + label : ""); }
  else { btn.disabled = false; if (btn.dataset.label !== undefined) btn.innerHTML = btn.dataset.label; }
}
export function applyTheme(theme) {
  const t = theme || (state.user && state.user.theme) || "system";
  if (t === "system") document.documentElement.removeAttribute("data-theme"); else document.documentElement.setAttribute("data-theme", t);
}
