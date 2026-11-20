"""Incident report writer.

Builds an initial technical incident analysis (Markdown) from a case: executive
summary, technical analysis, MITRE ATT&CK mapping, recommendations, actions taken
and the artifact list. Every observable/IOC is rendered as inline code.

The draft is deterministic, built from case data with rules. No external service is
involved, and the analyst is expected to review and edit it before sharing.
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List

from .mitre import TACTIC_ORDER
from .observables import defang as _defang

SEVERITY_TEXT = {
    "critical": "Critical: confirmed compromise with significant business impact, or impact in progress",
    "high": "High: confirmed malicious activity affecting one or more assets",
    "medium": "Medium: suspicious activity that needs further investigation",
    "low": "Low: limited or unconfirmed malicious activity",
    "info": "Informational",
}

TYPE_LABEL = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "Domain", "url": "URL", "md5": "MD5",
              "sha1": "SHA-1", "sha256": "SHA-256", "email": "Email"}

ARTIFACT_LABEL = OrderedDict([
    ("host", "Affected hosts"), ("user", "Accounts involved"), ("process", "Processes"),
    ("command_line", "Command lines"), ("file", "Files"), ("registry", "Registry keys"),
    ("email", "Email messages"), ("other", "Other artifacts"),
])

# Recommendation library keyed by tactic -> (phase, text)
TACTIC_RECS = {
    "Initial Access": [
        ("containment", "Block the initial access vector (sender, URL, exposed service or VPN account) and search for the same vector across the environment."),
        ("hardening", "Patch or restrict exposed services, enforce MFA on all external access, and review email filtering and attachment policies."),
    ],
    "Execution": [
        ("hardening", "Enable PowerShell Script Block and Module logging, consider Constrained Language Mode, and turn on Attack Surface Reduction rules for Office and script interpreters."),
    ],
    "Persistence": [
        ("eradication", "Remove the persistence mechanisms identified (scheduled tasks, services, Run keys, WMI subscriptions, new accounts) and confirm they don't come back after reboot."),
    ],
    "Privilege Escalation": [
        ("eradication", "Review privileged group membership and revert unauthorised changes. Audit recently granted rights."),
    ],
    "Defense Evasion": [
        ("recovery", "Re-enable and verify endpoint protection, logging and firewall policies on affected hosts. Alert on future tampering and log clearing."),
    ],
    "Credential Access": [
        ("containment", "Reset credentials for every account that was used on or exposed by affected hosts, starting with privileged and service accounts."),
        ("hardening", "Enable LSA protection / Credential Guard, deploy LAPS for local admin passwords, and remove plaintext credentials from scripts and shares."),
    ],
    "Discovery": [
        ("monitoring", "Monitor for further reconnaissance commands (net, nltest, AdFind, BloodHound) from the same accounts or hosts."),
    ],
    "Lateral Movement": [
        ("containment", "Restrict lateral movement paths: block SMB/RDP/WinRM between workstations, require jump hosts for administration, and review remote logons from affected accounts."),
    ],
    "Collection": [
        ("recovery", "Identify the data that was staged or accessed and assess its sensitivity."),
    ],
    "Command and Control": [
        ("containment", "Block the command-and-control infrastructure at the firewall, proxy and DNS, and hunt for other hosts talking to it."),
    ],
    "Exfiltration": [
        ("recovery", "Assess what data may have left the environment and engage legal/privacy teams on notification obligations."),
    ],
    "Impact": [
        ("containment", "Isolate affected systems immediately and activate the ransomware/destructive-attack playbook."),
        ("recovery", "Restore from known-good offline backups after confirming the threat actor no longer has access, and verify backup integrity."),
    ],
}

TECH_RECS = {
    "T1003.003": ("containment", "NTDS access was observed. Plan a double reset of the `krbtgt` account and reset all domain credentials."),
    "T1003.006": ("containment", "DCSync activity was observed. Reset `krbtgt` twice and review accounts holding replication rights."),
    "T1490": ("recovery", "Shadow copies or backups were deleted. Check that backups are intact and stored offline/immutable."),
    "T1110": ("hardening", "Brute-force activity was observed. Enforce account lockout, MFA and conditional access, and block the offending sources."),
    "T1110.003": ("hardening", "Password spraying was observed. Enforce MFA, block legacy authentication and review sign-ins from the spraying sources."),
    "T1190": ("hardening", "Patch the exploited application, review WAF rules and check the web server for web shells."),
    "T1505.003": ("eradication", "Remove web shells and rebuild the affected web server from a trusted image."),
    "T1219": ("eradication", "Remove unauthorised remote access software and block it with application control."),
    "T1566.001": ("containment", "Purge the phishing message from all mailboxes and block the sender and attachment hashes."),
    "T1566.002": ("containment", "Purge the phishing message, block the URL, and reset credentials of users who clicked."),
    "T1078": ("containment", "Valid accounts were used. Reset passwords, revoke active sessions/tokens and review MFA registrations for affected users."),
    "T1078.004": ("containment", "Cloud accounts were used. Revoke refresh tokens, review OAuth consents and inbox rules, and enforce conditional access."),
}

PHASES = [("containment", "Immediate containment"), ("eradication", "Eradication"),
          ("recovery", "Recovery"), ("hardening", "Hardening & prevention"), ("monitoring", "Monitoring")]


def code(value: Any, defang: bool = False) -> str:
    """Render an observable as Markdown inline code (safe for any backtick content)."""
    s = str(value if value is not None else "").replace("\n", " ").strip()
    if defang:
        s = _defang(s)
    if not s:
        return ""
    if "`" in s:
        return f"`` {s} ``"
    return f"`{s}`"


def _cell(s: Any) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", " ").strip()


def _join(items: List[str], limit: int = 6) -> str:
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) > limit:
        return ", ".join(items[:limit]) + f" and {len(items) - limit} more"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _fmt_time(t: Any) -> str:
    if t is None or t == "":
        return ""
    if isinstance(t, (int, float)):
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    t = str(t)
    return t.replace("T", " ").replace(".000Z", " UTC").replace("Z", " UTC")


def generate(case: Dict[str, Any], author: str = "", defang: bool = False) -> str:
    """Return a Markdown report for a case dict (as returned by the web API)."""
    c = lambda v: code(v, defang)  # noqa: E731
    obs: List[Dict] = case.get("observables") or []
    arts: List[Dict] = case.get("artifacts") or []
    techs: List[Dict] = sorted(case.get("techniques") or [],
                               key=lambda t: (TACTIC_ORDER.get(t.get("tactic"), 99), t.get("technique_id", "")))
    events: List[Dict] = sorted(case.get("events") or [], key=lambda e: e.get("time") or "")
    actions: List[Dict] = case.get("actions") or []

    bad = [o for o in obs if o.get("verdict") == "malicious"]
    sus = [o for o in obs if o.get("verdict") == "suspicious"]
    by_kind: Dict[str, List[Dict]] = {}
    for a in arts:
        by_kind.setdefault(a.get("kind") or "other", []).append(a)
    hosts = [a["value"] for a in by_kind.get("host", [])]
    users = [a["value"] for a in by_kind.get("user", [])]
    families: List[str] = []
    for o in bad + sus:
        for f in o.get("families") or []:
            if f and f.lower() not in (x.lower() for x in families):
                families.append(f)
    tactics = list(OrderedDict((t.get("tactic"), None) for t in techs if t.get("tactic")))
    sev = (case.get("severity") or "medium").lower()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    first = events[0]["time"] if events else case.get("incident_start")
    last = events[-1]["time"] if events else case.get("incident_end")

    L: List[str] = []
    L += [f"# Incident Report: {case.get('title') or 'Untitled case'}", ""]
    L += ["| | |", "|---|---|",
          f"| **Case** | {_cell(case.get('ref'))} |",
          f"| **Severity** | {sev.capitalize()} |",
          f"| **Status** | {_cell((case.get('status') or 'open').replace('_', ' ').capitalize())} |",
          f"| **Classification** | {_cell(case.get('classification') or 'Under investigation')} |",
          f"| **TLP** | TLP:{_cell((case.get('tlp') or 'amber').upper())} |"]
    if first or last:
        L.append(f"| **Incident window** | {_fmt_time(first)}{' to ' + _fmt_time(last) if last and last != first else ''} |")
    L += [f"| **Prepared by** | {_cell(author) or '-'} |", f"| **Report date** | {now} |", ""]

    # ------------------------------------------------------------- 1. summary
    L += ["## 1. Executive Summary", ""]
    if case.get("description"):
        L += [case["description"].strip(), ""]
    sentence = [f"This incident is rated **{sev}** ({SEVERITY_TEXT.get(sev, sev)})."]
    scope = []
    if hosts:
        scope.append(f"{len(hosts)} host{'s' if len(hosts) != 1 else ''} ({_join([c(h) for h in hosts], 4)})")
    if users:
        scope.append(f"{len(users)} account{'s' if len(users) != 1 else ''} ({_join([c(u) for u in users], 4)})")
    if scope:
        sentence.append(f"The investigation so far involves {_join(scope)}.")
    if obs:
        sentence.append(
            f"Of {len(obs)} indicator{'s' if len(obs) != 1 else ''} analysed, **{len(bad)} {'were' if len(bad) != 1 else 'was'} "
            f"rated malicious** and {len(sus)} suspicious by threat-intelligence reputation sources.")
    if families:
        sentence.append(f"Threat intelligence links the activity to {_join(families, 4)}.")
    if tactics:
        sentence.append(f"Observed attacker behaviour covers {len(tactics)} MITRE ATT&CK "
                        f"tactic{'s' if len(tactics) != 1 else ''}: {_join(tactics, 8)}.")
    if "Impact" in tactics:
        sentence.append("Activity in the **Impact** tactic means business disruption is likely or already happening.")
    if actions:
        sentence.append(f"{len(actions)} response action{'s have' if len(actions) != 1 else ' has'} been taken so far (section 4).")
    L += [" ".join(sentence), ""]
    L += ["**Key points for leadership**", ""]
    kp = []
    if bad:
        kp.append(f"Malicious infrastructure or files were confirmed: {_join([c(o['value']) for o in bad], 5)}.")
    if hosts:
        kp.append(f"Affected systems: {_join([c(h) for h in hosts], 6)}.")
    if "Credential Access" in tactics or any(t.get("technique_id", "").startswith("T1078") for t in techs):
        kp.append("Credentials may be compromised, so a password and session reset for the affected accounts is required.")
    if "Exfiltration" in tactics or "Collection" in tactics:
        kp.append("Data exposure is possible. Legal and privacy teams should be informed.")
    status = (case.get("status") or "open").replace("_", " ")
    kp.append(f"Current status: **{status}**. See section 3 for the recommended next steps.")
    L += [f"- {k}" for k in kp] + [""]

    # ---------------------------------------------------- 2. technical analysis
    L += ["## 2. Technical Analysis", ""]
    L += ["### 2.1 Timeline of key events", ""]
    if events:
        L += ["| Time (UTC) | Event |", "|---|---|"]
        for e in events:
            L.append(f"| {_cell(_fmt_time(e.get('time')))} | {_cell(_with_code(e.get('text', ''), obs, defang))} |")
    else:
        L.append("_No key events have been pinned to the case timeline yet. Pin events from the Log Arranger._")
    L.append("")

    L += ["### 2.2 Indicator analysis", ""]
    if bad or sus:
        L += ["| Indicator | Type | Verdict | Score | Flagged by | Malware / context |", "|---|---|---|---|---|---|"]
        for o in bad + sus:
            L.append(f"| {c(o['value'])} | {TYPE_LABEL.get(o.get('type'), o.get('type'))} | **{o.get('verdict')}** | "
                     f"{'' if o.get('score') is None else o.get('score')} | {_cell(', '.join(o.get('flagged_by') or []))} | "
                     f"{_cell(', '.join((o.get('families') or [])[:4]))} |")
        L.append("")
        for o in bad[:10]:
            details = [r for r in (o.get("results") or []) if r.get("verdict") in ("malicious", "suspicious")]
            if details:
                L.append(f"- {c(o['value'])}: " + "; ".join(f"{r['provider']}: {_cell(r.get('summary'))}" for r in details[:4]))
        L.append("")
    elif obs:
        L += [f"{len(obs)} indicator(s) were checked. None was rated malicious or suspicious by the configured reputation "
              "sources. This does not rule out malicious use (new or targeted infrastructure is often unrated).", ""]
    else:
        L += ["_No indicators have been added to the case yet._", ""]
    unrated = [o for o in obs if o.get("verdict") in (None, "", "unknown", "pending")]
    if unrated:
        L += [f"Indicators without a reputation verdict ({len(unrated)}): " + _join([c(o["value"]) for o in unrated], 15) + ".", ""]

    L += ["### 2.3 Affected assets and accounts", ""]
    if hosts or users:
        if hosts:
            L.append(f"- **Hosts:** {', '.join(c(h) for h in hosts)}")
        if users:
            L.append(f"- **Accounts:** {', '.join(c(u) for u in users)}")
        procs = by_kind.get("process", []) + by_kind.get("command_line", [])
        if procs:
            L.append(f"- **Processes / commands of interest:** {len(procs)} (see section 5)")
    else:
        L.append("_No affected hosts or accounts recorded yet._")
    L.append("")

    L += ["### 2.4 MITRE ATT&CK mapping", ""]
    if techs:
        L += ["| Tactic | Technique | Evidence / notes |", "|---|---|---|"]
        for t in techs:
            tid = t.get("technique_id", "")
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            L.append(f"| {_cell(t.get('tactic'))} | [{tid}]({url}) {_cell(t.get('name'))} | "
                     f"{_cell(_with_code(t.get('note') or '', obs, defang)) or '-'} |")
        L.append("")
        if len(tactics) > 1:
            L += [f"The activity follows the ATT&CK sequence {' → '.join(tactics)}.", ""]
    else:
        L += ["_No ATT&CK techniques mapped yet._", ""]

    # --------------------------------------------------------- 3. recommendations
    L += ["## 3. Recommendations", ""]
    recs: Dict[str, List[str]] = OrderedDict((p, []) for p, _ in PHASES)

    def add(phase: str, text: str):
        if text not in recs[phase]:
            recs[phase].append(text)

    if hosts:
        add("containment", f"Isolate the affected hosts ({_join([c(h) for h in hosts], 6)}) with EDR network "
                           "containment and preserve volatile evidence before you remediate.")
    net = [o for o in bad + sus if o.get("type") in ("ipv4", "ipv6", "domain", "url")]
    if net:
        add("containment", "Block the malicious network indicators at the firewall, web proxy and DNS: "
                           + _join([c(o["value"]) for o in net], 10) + ".")
    files = [o for o in bad + sus if o.get("type") in ("md5", "sha1", "sha256")]
    if files:
        add("containment", "Add the malicious file hashes to the EDR/AV blocklist and sweep all endpoints for them: "
                           + _join([c(o["value"]) for o in files], 6) + ".")
    emails = [o for o in obs if o.get("type") == "email" and o.get("verdict") in ("suspicious", "malicious")]
    if emails:
        add("containment", "Reset passwords and enforce MFA for accounts exposed in breaches: "
                           + _join([c(o["value"]) for o in emails], 6) + ".")
    if users:
        add("containment", f"Reset credentials and revoke active sessions for the involved accounts "
                           f"({_join([c(u) for u in users], 6)}).")
    for t in techs:
        if t.get("technique_id") in TECH_RECS:
            add(*TECH_RECS[t["technique_id"]])
    for tac in tactics:
        for phase, text in TACTIC_RECS.get(tac, []):
            add(phase, text)
    add("eradication", "Reimage or fully remediate the affected hosts once the scope is confirmed, and verify that no "
                       "persistence remains.")
    add("monitoring", "Continue to monitor for the indicators and techniques in this report for at least 30 days, and "
                      "share the IOCs (STIX export) with security tooling and partners as TLP allows.")
    add("monitoring", "Hold a lessons-learned review and update detection rules and playbooks.")
    for phase, label in PHASES:
        if recs[phase]:
            L += [f"**{label}**", ""] + [f"1. {r}" for r in recs[phase]] + [""]

    # ---------------------------------------------------------- 4. actions taken
    L += ["## 4. Actions Taken", ""]
    if actions:
        L += ["| Time (UTC) | Action | By |", "|---|---|---|"]
        for a in sorted(actions, key=lambda x: x.get("done_at") or x.get("created_at") or ""):
            L.append(f"| {_cell(_fmt_time(a.get('done_at') or a.get('created_at')))} | "
                     f"{_cell(_with_code(a.get('text', ''), obs, defang))} | {_cell(a.get('added_by_name'))} |")
    else:
        L.append("_No response actions have been recorded yet._")
    L.append("")

    # -------------------------------------------------------------- 5. artifacts
    L += ["## 5. Artifacts", "", "### 5.1 Indicators of compromise", ""]
    if obs:
        L += ["| Indicator | Type | Verdict | Sources | First added |", "|---|---|---|---|---|"]
        order = {"malicious": 0, "suspicious": 1, "unknown": 2, "harmless": 3}
        for o in sorted(obs, key=lambda x: (order.get(x.get("verdict"), 2), x.get("type", ""), x.get("value", ""))):
            L.append(f"| {c(o['value'])} | {TYPE_LABEL.get(o.get('type'), o.get('type'))} | {o.get('verdict') or 'not checked'} | "
                     f"{_cell(', '.join(o.get('flagged_by') or [])) or '-'} | {_cell(_fmt_time(o.get('created_at'))[:16])} |")
    else:
        L.append("_None._")
    L.append("")
    n = 2
    for kind, label in ARTIFACT_LABEL.items():
        items = by_kind.get(kind) or []
        if not items:
            continue
        L += [f"### 5.{n} {label}", ""]
        n += 1
        if kind == "command_line":
            for a in items:
                L += ["```", str(a["value"]).replace("```", "'''"), "```"]
                if a.get("note"):
                    L.append(f"_{_cell(a['note'])}_")
                L.append("")
        else:
            L += [f"- {c(a['value'])}" + (f" ({_cell(a['note'])})" if a.get("note") else "") for a in items] + [""]

    if techs:
        L += [f"### 5.{n} ATT&CK techniques", ""]
        L += [f"- {code(t.get('technique_id'))} {t.get('name')} ({t.get('tactic')})" for t in techs] + [""]

    L += ["---", "",
          f"_Initial analysis generated with S.T.A.R.K from case data on {now}. Reputation verdicts reflect third-party "
          "sources at the time of lookup. Validate findings before acting on them._", ""]
    return "\n".join(L)


def _with_code(text: str, obs: List[Dict], defang: bool) -> str:
    """Wrap any known observable that appears in free text with inline code."""
    if not text:
        return ""
    values = sorted({o["value"] for o in obs if o.get("value") and len(o["value"]) >= 4}, key=len, reverse=True)
    out = text
    placeholders = {}
    for i, v in enumerate(values):
        if v in out:
            key = f"\x00{i}\x00"
            placeholders[key] = code(v, defang)
            out = out.replace(v, key)
    for k, v in placeholders.items():
        out = out.replace(k, v)
    return out


def summary_counts(case: Dict[str, Any]) -> Dict[str, int]:  # used by the dashboard
    c = Counter(o.get("verdict") or "unknown" for o in case.get("observables") or [])
    return dict(c)
