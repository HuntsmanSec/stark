"""Generate docs/assets/stark-infographic.svg (features and limitations).

Usage: python scripts/make_infographic.py . <version>
"""
import re
import sys
import textwrap
from html import escape
from pathlib import Path

root = Path(sys.argv[1])
core = (root / "stark/web/static/js/core.js").read_text()
ICONS = dict(re.findall(r"\b(\w+): '(<[^']+)'", core))
mark = (root / "docs/assets/logo-mark.svg").read_text()
mark_inner = mark.split(">", 1)[1].rsplit("</svg>", 1)[0].replace('id="sk-bg"', 'id="mk"').replace("url(#sk-bg)", "url(#mk)")

VERSION = sys.argv[2]
W = 1200
FONT = "Inter, 'Segoe UI', Helvetica, Arial, sans-serif"

FEATURES = [
    ("zap", "20 reputation sources", "VirusTotal, AbuseIPDB, urlscan, abuse.ch, OTX, Shodan, GreyNoise, sandboxes and your own MISP, merged into one verdict per indicator."),
    ("logs", "Log Arranger", "Sentinel, Defender, Splunk, Elastic, CrowdStrike, firewalls, WAFs, Zeek and more become one UTC timeline. Logs are never stored."),
    ("bug", "Finding analysis", "Brute force, password spraying, MFA fatigue, impossible travel, LOLBins, encoded PowerShell, C2 beaconing and typosquats."),
    ("target", "Automatic ATT&CK mapping", "Techniques mapped from logs, indicators and threat intel, each with the evidence behind it."),
    ("file", "SOC report writer", "Correlates past tickets, closures and pentest notes, then appends, closes or raises an incident with a defanged customer report."),
    ("user", "Team workspace", "Cases with severity, TLP, assignees and live updates, plus pentest notes, asset lookup and an activity log."),
    ("layers", "Share and export", "STIX 2.1, send to MISP or MISP JSON, CSV, IRFlow Timeline, VESTIGEX sweeps and known-bad hash sets."),
    ("terminal", "CLI and automation", "Bulk lookups, IOC extraction, timeline enrichment, JSON or JSONL output and exit codes for SOAR pipelines."),
    ("refresh", "Safe updates", "Data lives outside the app, with automatic backups before upgrades, stark update, and backup and restore."),
]
LIMITS = [
    ("Verdicts depend on your sources", "Free tiers are slow (VirusTotal public: 4 lookups/min) and coverage varies. Unknown does not mean safe."),
    ("Passive lookups only", "Never detonates files or submits URLs. It finds existing sandbox and scan reports only."),
    ("No live SIEM or EDR connection", "Logs are pasted or uploaded as exports. There is no streaming ingestion or alert polling."),
    ("Analysis needs an analyst", "Findings and ATT&CK mapping are rule-based. Review them before a report goes to a customer."),
    ("Built for small teams", "One SQLite database on one server. No SSO or LDAP, and no high availability."),
    ("Lookups reach third parties", "Every enabled source sees the indicators you check. Turn sources off for sensitive cases."),
    ("Unsigned binaries for now", "Windows SmartScreen and macOS Gatekeeper may warn until code signing is in place."),
    ("MISP: one server per workspace", "Events are sent unpublished for review. Sightings and feed sync aren't supported yet."),
]

out = []
add = out.append


def text(x, y, s, size, weight=400, fill="#e2e8f0", anchor="start", spacing=0, opacity=1):
    add(f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" font-weight="{weight}" fill="{fill}" '
        f'text-anchor="{anchor}" letter-spacing="{spacing}" opacity="{opacity}">{escape(s)}</text>')


def para(x, y, s, size, width_chars, fill, lh):
    lines = textwrap.wrap(s, width_chars)
    for i, ln in enumerate(lines):
        text(x, y + i * lh, ln, size, fill=fill)
    return len(lines)


def icon(name, x, y, size, color):
    sc = size / 24
    add(f'<g transform="translate({x} {y}) scale({sc})" fill="none" stroke="{color}" stroke-width="1.9" '
        f'stroke-linecap="round" stroke-linejoin="round">{ICONS[name].replace("currentColor", color)}</g>')


# ---------------------------------------------------------------- layout
pad = 56
col_gap = 22
cols = 3
tile_w = (W - 2 * pad - (cols - 1) * col_gap) / cols
tile_h = 164
feat_top = 300
feat_rows = (len(FEATURES) + cols - 1) // cols
lim_head = feat_top + feat_rows * (tile_h + col_gap) + 34
lim_top = lim_head + 70
lim_cols = 2
lim_w = (W - 2 * pad - col_gap) / lim_cols
lim_h = 88
lim_rows = (len(LIMITS) + 1) // 2
H = lim_top + lim_rows * (lim_h + 16) + 84

add(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
    f'aria-label="S.T.A.R.K features and limitations">')
add('<defs>'
    '<linearGradient id="bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0b1222"/><stop offset="1" stop-color="#0a0f1c"/></linearGradient>'
    '<linearGradient id="acc" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#3b82f6"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient>'
    '<radialGradient id="glow" cx="0.85" cy="0" r="0.7"><stop offset="0" stop-color="#7c3aed" stop-opacity=".28"/><stop offset="1" stop-color="#7c3aed" stop-opacity="0"/></radialGradient>'
    '<linearGradient id="mk" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#1d4ed8"/><stop offset="1" stop-color="#7c3aed"/></linearGradient>'
    '</defs>')
add(f'<rect width="{W}" height="{H}" rx="28" fill="url(#bg)"/>')
add(f'<rect width="{W}" height="520" rx="28" fill="url(#glow)"/>')

# header
add(f'<g transform="translate({pad} 54) scale(1.35)">{mark_inner}</g>')
text(pad + 108, 98, "S.T.A.R.K", 52, 800, "#f8fafc", spacing=8)
text(pad + 110, 130, "Security Threat Assessment and Reputation Kit", 18, 500, "#94a3b8", spacing=1)
pill_w = 132
add(f'<rect x="{W - pad - pill_w}" y="70" width="{pill_w}" height="34" rx="17" fill="#1e293b" stroke="#334155"/>')
text(W - pad - pill_w / 2, 92, f"v{VERSION} · MIT", 14, 600, "#cbd5e1", anchor="middle")
para(pad, 196, "An open-source OSINT case workspace and command-line toolkit for SOC and MSSP analysts: arrange "
               "messy logs, check indicators, map ATT&CK and write the report, on Windows, macOS and Linux.",
     19, 100, "#cbd5e1", 28)

# features
text(pad, feat_top - 22, "WHAT IT DOES", 14, 700, "#93c5fd", spacing=3)
add(f'<rect x="{pad + 128}" y="{feat_top - 28}" width="{W - 2 * pad - 128}" height="1.5" fill="#1e293b"/>')
for i, (ic, title, body) in enumerate(FEATURES):
    r, c = divmod(i, cols)
    x = pad + c * (tile_w + col_gap)
    y = feat_top + r * (tile_h + col_gap)
    add(f'<rect x="{x}" y="{y}" width="{tile_w}" height="{tile_h}" rx="18" fill="#111a2e" stroke="#1f2a44"/>')
    add(f'<rect x="{x}" y="{y}" width="{tile_w}" height="4" rx="2" fill="url(#acc)"/>')
    add(f'<rect x="{x + 22}" y="{y + 24}" width="42" height="42" rx="11" fill="#1d2b4f"/>')
    icon(ic, x + 31, y + 33, 24, "#93c5fd")
    text(x + 78, y + 52, title, 18, 700, "#f1f5f9")
    para(x + 22, y + 96, body, 14.5, 44, "#a8b3c7", 21)

# limitations
add(f'<rect x="{pad}" y="{lim_head - 30}" width="{W - 2 * pad}" height="{H - lim_head - 70}" rx="22" fill="#141210" stroke="#3a2a12"/>')
icon("alert", pad + 28, lim_head - 4, 26, "#fbbf24")
text(pad + 66, lim_head + 16, "KNOW ITS LIMITS", 14, 700, "#fbbf24", spacing=3)
text(pad + 236, lim_head + 16, "What S.T.A.R.K doesn't do (yet), so nobody is surprised.", 15, 400, "#a8a29e")
for i, (title, body) in enumerate(LIMITS):
    r, c = divmod(i, lim_cols)
    x = pad + 28 + c * (lim_w + col_gap - 28)
    y = lim_top + r * (lim_h + 16) - 14
    add(f'<circle cx="{x + 9}" cy="{y + 9}" r="9" fill="#3b2a0c"/>')
    text(x + 9, y + 14, str(i + 1), 12, 700, "#fbbf24", anchor="middle")
    text(x + 30, y + 15, title, 17, 700, "#fde68a")
    para(x + 30, y + 42, body, 14.5, 64, "#bfb5a8", 21)

text(W / 2, H - 30, "github.com/HuntsmanSec/stark", 14, 500, "#64748b", anchor="middle", spacing=1)
add("</svg>")
(root / "docs/assets/stark-infographic.svg").write_text("\n".join(out) + "\n")
print("height", H)
