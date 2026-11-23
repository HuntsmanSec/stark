"""Incident report writer.

Builds a structured technical incident report (Markdown) from a case:

* Quick verdict (with confidence level)
* 1. Executive summary
* 2. Timeline
* 3. Event details
* 4. Analysis (security findings, indicator analysis, MITRE ATT&CK)
* 5. Interpretation
* 6. Confidence level
* 7. Recommendations
* 8. Actions taken
* 9. IOCs & artifacts

Indicators are **always defanged** by bracketing the final dot (``185.220.101[.]1``,
``hxxps://bad.example[.]com``; IPv6 and internal addresses are left as they are) and
rendered as Markdown inline code. The report is built deterministically from
case data. Analysts review and edit it before sharing.
"""

from __future__ import annotations

import re
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List

from .mitre import TACTIC_ORDER
from .observables import defang_final as _defang
from .observables import defang_text as _defang_text
from .observables import detect_type


def defang_text(text: str, keep=()) -> str:
    return _defang_text(text, keep=keep, style="final")

SEVERITY_TEXT = {
    "critical": "Critical: confirmed compromise with significant business impact, or impact in progress",
    "high": "High: confirmed malicious activity affecting one or more assets",
    "medium": "Medium: suspicious activity that needs further investigation",
    "low": "Low: limited or unconfirmed malicious activity",
    "info": "Informational",
}
VERDICT_TEXT = {
    "true_positive": "True positive: malicious activity confirmed",
    "likely_malicious": "Likely malicious: true positive suspected",
    "suspicious": "Suspicious: needs further investigation",
    "benign": "Benign: authorised or expected activity",
    "false_positive": "False positive",
    "inconclusive": "Inconclusive: not enough evidence yet",
}
TYPE_LABEL = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "Domain", "url": "URL", "md5": "MD5",
              "sha1": "SHA-1", "sha256": "SHA-256", "email": "Email"}
ARTIFACT_LABEL = OrderedDict([
    ("host", "Affected hosts"), ("user", "Accounts involved"), ("process", "Processes"),
    ("command_line", "Command lines"), ("file", "Files"), ("registry", "Registry keys"),
    ("email", "Email messages"), ("other", "Other artifacts"),
])
SEV_W = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
CONF_W = {"high": 1.0, "medium": 0.7, "low": 0.4}
CATEGORY_LABEL = {"auth": "Authentication anomalies", "process": "Process & command-line activity",
                  "malware": "Malware & file findings", "network": "Network & C2 communication"}

TACTIC_RECS = {
    "Initial Access": [("containment", "Block the initial access vector (sender, URL, exposed service or VPN account) and search for the same vector across the environment."),
                       ("hardening", "Patch or restrict exposed services, enforce MFA on all external access, and review email filtering and attachment policies.")],
    "Execution": [("hardening", "Enable PowerShell Script Block and Module logging, consider Constrained Language Mode, and turn on Attack Surface Reduction rules for Office and script interpreters.")],
    "Persistence": [("eradication", "Remove the persistence mechanisms identified (scheduled tasks, services, Run keys, WMI subscriptions, new accounts) and confirm they don't come back after reboot.")],
    "Privilege Escalation": [("eradication", "Review privileged group membership and revert unauthorised changes. Audit recently granted rights.")],
    "Defense Evasion": [("recovery", "Re-enable and verify endpoint protection, logging and firewall policies on affected hosts. Alert on future tampering and log clearing.")],
    "Credential Access": [("containment", "Reset credentials for every account that was used on or exposed by affected hosts, starting with privileged and service accounts."),
                          ("hardening", "Enable LSA protection / Credential Guard, deploy LAPS for local admin passwords, and remove plaintext credentials from scripts and shares.")],
    "Discovery": [("monitoring", "Monitor for further reconnaissance commands (net, nltest, AdFind, BloodHound) from the same accounts or hosts.")],
    "Lateral Movement": [("containment", "Restrict lateral movement paths: block SMB/RDP/WinRM between workstations, require jump hosts for administration, and review remote logons from affected accounts.")],
    "Collection": [("recovery", "Identify the data that was staged or accessed and assess its sensitivity.")],
    "Command and Control": [("containment", "Block the command-and-control infrastructure at the firewall, proxy and DNS, and hunt for other hosts talking to it.")],
    "Exfiltration": [("recovery", "Assess what data may have left the environment and engage legal/privacy teams on notification obligations.")],
    "Impact": [("containment", "Isolate affected systems immediately and activate the ransomware/destructive-attack playbook."),
               ("recovery", "Restore from known-good offline backups after confirming the threat actor no longer has access, and verify backup integrity.")],
}
TECH_RECS = {
    "T1003.003": ("containment", "NTDS access was observed. Plan a double reset of the `krbtgt` account and reset all domain credentials."),
    "T1003.006": ("containment", "DCSync activity was observed. Reset `krbtgt` twice and review accounts holding replication rights."),
    "T1490": ("recovery", "Shadow copies or backups were deleted. Check that backups are intact and stored offline/immutable."),
    "T1110": ("hardening", "Brute-force activity was observed. Enforce account lockout, MFA and conditional access, and block the offending sources."),
    "T1110.003": ("hardening", "Password spraying was observed. Enforce MFA, block legacy authentication and review sign-ins from the spraying sources."),
    "T1621": ("hardening", "MFA fatigue was observed. Enable number matching / phishing-resistant MFA and alert on repeated MFA denials."),
    "T1190": ("hardening", "Patch the exploited application, review WAF rules and check the web server for web shells."),
    "T1505.003": ("eradication", "Remove web shells and rebuild the affected web server from a trusted image."),
    "T1219": ("eradication", "Remove unauthorised remote access software and block it with application control."),
    "T1566.001": ("containment", "Purge the phishing message from all mailboxes and block the sender and attachment hashes."),
    "T1566.002": ("containment", "Purge the phishing message, block the URL, and reset credentials of users who clicked."),
    "T1078": ("containment", "Valid accounts were used. Reset passwords, revoke active sessions/tokens and review MFA registrations for affected users."),
    "T1583.001": ("containment", "Look-alike domains were seen. Block them at DNS, proxy and email gateway, and consider takedown requests."),
    "T1071.001": ("containment", "Possible C2 traffic was seen. Block the destination and identify the process generating it on each source host."),
}
PHASES = [("containment", "Immediate containment"), ("eradication", "Eradication"),
          ("recovery", "Recovery"), ("hardening", "Hardening & prevention"), ("monitoring", "Monitoring")]


# ----------------------------------------------------------------- helpers


def code(value: Any, defang: bool = True) -> str:
    """Render an indicator as Markdown inline code. Network indicators are defanged."""
    s = str(value if value is not None else "").replace("\n", " ").strip()
    if not s:
        return ""
    if defang and detect_type(s.replace("[.]", ".")) is not None:
        s = _defang(s)
    elif defang:
        s = defang_text(s)
    if "`" in s:
        return f"`` {s} ``"
    return f"`{s}`"


_MD_LINK = re.compile(r"\]\((https?://[^)\s]+)\)")
_SAFE_LINKS = re.compile(r"https?://attack\.mitre\.org/[^\s)|]*")


_ALERT_LINE = re.compile(r"(?im)^\s*[-*]?\s*\**(alert|incident) (url|link)\**:?\**\s*(https?://\S+)")


def defang_markdown(md: str, keep=()) -> str:
    """Defang every indicator in a Markdown document (final dot only), keeping link targets,
    MITRE references and the alert link (which must stay live) intact."""
    keep = set(keep) | set(_MD_LINK.findall(md)) | set(_SAFE_LINKS.findall(md)) | \
        {m.group(3) for m in _ALERT_LINE.finditer(md)}
    return defang_text(md, keep=keep)


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


def _codeify(text: str) -> str:
    """Defang and code-format every indicator inside free text."""
    from .observables import find_iocs
    if not text:
        return ""
    out, last = [], 0
    for start, end, _o in find_iocs(text):
        out.append(text[last:start])
        out.append(code(text[start:end]))
        last = end
    out.append(text[last:])
    return "".join(out)


# --------------------------------------------------------------- assessment


def assess(case: Dict[str, Any]) -> Dict[str, Any]:
    """Compute a quick verdict and confidence level from the evidence in a case.

    Analyst overrides (``case['verdict']`` / ``case['confidence']``) always win."""
    obs = case.get("observables") or []
    findings = [f for f in case.get("findings") or [] if f.get("status") != "dismissed"]
    techs = case.get("techniques") or []
    bad = [o for o in obs if o.get("verdict") == "malicious"]
    sus = [o for o in obs if o.get("verdict") == "suspicious"]
    score = 0.0
    factors: List[str] = []
    for f in findings:
        w = SEV_W.get(f.get("severity"), 5) * CONF_W.get(f.get("confidence"), 0.6)
        if f.get("status") == "confirmed":
            w *= 1.5
        score += w
    if findings:
        cats = sorted({f.get("category") for f in findings})
        factors.append(f"{len(findings)} security finding(s) across {len(cats)} categor{'ies' if len(cats) != 1 else 'y'} "
                       f"({', '.join(CATEGORY_LABEL.get(c, c) for c in cats)})")
    multi_source_bad = [o for o in bad if len(o.get("flagged_by") or []) >= 2]
    score += 25 * len(bad) + 6 * len(sus)
    if bad:
        factors.append(f"{len(bad)} indicator(s) rated malicious by threat intelligence"
                       + (f", {len(multi_source_bad)} by two or more independent sources" if multi_source_bad else ""))
    if sus:
        factors.append(f"{len(sus)} indicator(s) rated suspicious")
    tactics = {t.get("tactic") for t in techs}
    if "Impact" in tactics:
        score += 20
        factors.append("activity in the Impact tactic")
    if len(tactics) >= 3:
        score += 10
        factors.append(f"behaviour spans {len(tactics)} ATT&CK tactics (a multi-stage attack chain)")
    if case.get("actions"):
        factors.append(f"{len(case['actions'])} response action(s) recorded")
    harmless = [o for o in obs if o.get("verdict") == "harmless"]

    if score >= 60:
        verdict = "true_positive"
    elif score >= 30:
        verdict = "likely_malicious"
    elif score >= 10:
        verdict = "suspicious"
    elif obs and len(harmless) == len(obs) and not findings:
        verdict = "benign"
    else:
        verdict = "inconclusive"

    # Confidence = corroboration between independent kinds of evidence.
    evidence_types = sum([bool(findings), bool(bad), bool(multi_source_bad), len({f.get("category") for f in findings}) >= 2,
                          any(f.get("confidence") == "high" for f in findings), bool(case.get("events"))])
    confidence = "high" if evidence_types >= 4 else "medium" if evidence_types >= 2 else "low"
    if verdict == "inconclusive":
        confidence = "low"
    final_verdict = case.get("verdict") or verdict
    return {
        "score": round(score),
        "verdict": final_verdict,
        "confidence": case.get("confidence") or confidence,
        "auto": {"verdict": verdict, "confidence": confidence},
        "overridden": bool(case.get("verdict") or case.get("confidence")),
        "factors": factors or ["no findings, malicious indicators or mapped techniques yet"],
        "label": VERDICT_TEXT.get(final_verdict, final_verdict),
    }


# ----------------------------------------------------------------- generate


def generate(case: Dict[str, Any], author: str = "", defang: bool = True) -> str:  # noqa: C901 - report layout
    """Return the Markdown incident report for a case dict (as returned by the web API)."""
    c = code
    obs: List[Dict] = case.get("observables") or []
    arts: List[Dict] = case.get("artifacts") or []
    techs: List[Dict] = sorted(case.get("techniques") or [],
                               key=lambda t: (TACTIC_ORDER.get(t.get("tactic"), 99), t.get("technique_id", "")))
    events: List[Dict] = sorted(case.get("events") or [], key=lambda e: e.get("time") or "")
    actions: List[Dict] = case.get("actions") or []
    findings: List[Dict] = [f for f in case.get("findings") or [] if f.get("status") != "dismissed"]
    a = assess(case)

    bad = [o for o in obs if o.get("verdict") == "malicious"]
    sus = [o for o in obs if o.get("verdict") == "suspicious"]
    by_kind: Dict[str, List[Dict]] = {}
    for art in arts:
        by_kind.setdefault(art.get("kind") or "other", []).append(art)
    hosts = [x["value"] for x in by_kind.get("host", [])]
    users = [x["value"] for x in by_kind.get("user", [])]
    for f in findings:  # assets named by findings count as involved too
        for hst in (f.get("entities") or {}).get("hosts", []):
            if hst not in hosts:
                hosts.append(hst)
        for u in (f.get("entities") or {}).get("users", []):
            if u not in users:
                users.append(u)
    families: List[str] = []
    for o in bad + sus:
        for fam in o.get("families") or []:
            if fam and fam.lower() not in (x.lower() for x in families):
                families.append(fam)
    tactics = list(OrderedDict((t.get("tactic"), None) for t in techs if t.get("tactic")))
    sev = (case.get("severity") or "medium").lower()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    times = [e.get("time") for e in events if e.get("time")] + [f.get("first") for f in findings if f.get("first")] \
        + [f.get("last") for f in findings if f.get("last")]
    first, last = (min(times), max(times)) if times else (case.get("incident_start"), case.get("incident_end"))

    L: List[str] = [f"# Incident Report: {case.get('title') or 'Untitled case'}", ""]
    L += ["| | |", "|---|---|",
          f"| **Case** | {_cell(case.get('ref'))} |",
          f"| **Severity** | {sev.capitalize()} |",
          f"| **Status** | {_cell((case.get('status') or 'open').replace('_', ' ').capitalize())} |",
          f"| **Classification** | {_cell(case.get('classification') or 'Under investigation')} |",
          f"| **TLP** | TLP:{_cell((case.get('tlp') or 'amber').upper())} |"]
    if first or last:
        L.append(f"| **Incident window** | {_fmt_time(first)}{' to ' + _fmt_time(last) if last and last != first else ''} |")
    L += [f"| **Prepared by** | {_cell(author) or '-'} |", f"| **Report date** | {now} |", ""]

    # ------------------------------------------------------------ quick verdict
    L += ["## Quick Verdict", "",
          f"> **{VERDICT_TEXT.get(a['verdict'], a['verdict'])}**. Confidence: **{a['confidence'].upper()}**.",
          ">",
          f"> Basis: {'; '.join(a['factors'])}."
          + (" (Verdict set by the analyst.)" if a["overridden"] else " (Assessed automatically from the case evidence; the analyst should confirm.)"),
          ""]

    # ------------------------------------------------------------ 1. summary
    L += ["## 1. Executive Summary", ""]
    if case.get("description"):
        L += [_codeify(case["description"].strip()), ""]
    sentence = [f"This incident is rated **{sev}** ({SEVERITY_TEXT.get(sev, sev)})."]
    scope = []
    if hosts:
        scope.append(f"{len(hosts)} host{'s' if len(hosts) != 1 else ''} ({_join([c(x) for x in hosts], 4)})")
    if users:
        scope.append(f"{len(users)} account{'s' if len(users) != 1 else ''} ({_join([c(u) for u in users], 4)})")
    if scope:
        sentence.append(f"It involves {_join(scope)}.")
    if findings:
        top = findings[0]
        sentence.append(f"Analysis produced {len(findings)} security finding{'s' if len(findings) != 1 else ''}; the most "
                        f"serious is *{_codeify(top['title'])}* ({top['severity']} severity).")
    if obs:
        sentence.append(f"Of {len(obs)} indicator{'s' if len(obs) != 1 else ''} checked against threat intelligence, "
                        f"**{len(bad)} {'were' if len(bad) != 1 else 'was'} malicious** and {len(sus)} suspicious.")
    if families:
        sentence.append(f"Threat intelligence associates the activity with {_join(families, 4)}.")
    if tactics:
        sentence.append(f"Attacker behaviour covers {len(tactics)} MITRE ATT&CK tactic{'s' if len(tactics) != 1 else ''}: "
                        f"{_join(tactics, 8)}.")
    if actions:
        sentence.append(f"{len(actions)} response action{'s have' if len(actions) != 1 else ' has'} been taken (section 8).")
    L += [" ".join(sentence), "", "**Key points for leadership**", ""]
    kp = [f"Verdict: **{VERDICT_TEXT.get(a['verdict'], a['verdict'])}** ({a['confidence']} confidence)."]
    if hosts:
        kp.append(f"Affected systems: {_join([c(x) for x in hosts], 6)}.")
    if any(f.get("category") == "auth" for f in findings) or "Credential Access" in tactics \
            or any(t.get("technique_id", "").startswith("T1078") for t in techs):
        kp.append("Account credentials may be compromised, so password and session resets are required for the accounts involved.")
    if "Impact" in tactics:
        kp.append("Activity in the **Impact** tactic means business disruption is likely or already happening.")
    if "Exfiltration" in tactics or "Collection" in tactics or any("dns-tunnel" in f.get("key", "") for f in findings):
        kp.append("Data exposure is possible. Legal and privacy teams should be informed.")
    kp.append(f"Current status: **{(case.get('status') or 'open').replace('_', ' ')}**. See section 7 for the next steps.")
    L += [f"- {k}" for k in kp] + [""]

    # ------------------------------------------------------------ 2. timeline
    L += ["## 2. Timeline", ""]
    tl = [(e.get("time") or "", _codeify(e.get("text", ""))) for e in events]
    for f in findings:
        if f.get("first"):
            tl.append((f["first"], f"**Finding:** {_codeify(f['title'])}"))
    for act in actions:
        tl.append((act.get("done_at") or "", f"**Action:** {_codeify(act.get('text', ''))}"))
    tl.sort(key=lambda x: x[0] or "9999")
    if tl:
        L += ["| Time (UTC) | What happened |", "|---|---|"]
        L += [f"| {_cell(_fmt_time(t)) or '-'} | {_cell(txt)} |" for t, txt in tl]
    else:
        L.append("_No events have been pinned to the case timeline yet._")
    L.append("")

    # ------------------------------------------------------------ 3. event details
    L += ["## 3. Event Details", ""]
    if findings:
        for i, f in enumerate(findings, 1):
            L += [f"### 3.{i} {_codeify(f['title'])}", "",
                  f"- **Category:** {CATEGORY_LABEL.get(f.get('category'), f.get('category'))}",
                  f"- **Severity / confidence:** {f.get('severity', '').capitalize()} / {f.get('confidence', '').capitalize()}"
                  + (f" · analyst status: {f.get('status')}" if f.get("status") not in (None, "", "open") else ""),
                  f"- **Observed:** {f.get('count') or 0} event(s)"
                  + (f", {_fmt_time(f.get('first'))} to {_fmt_time(f.get('last'))}" if f.get("first") else "")]
            ent = f.get("entities") or {}
            for k, label in (("hosts", "Hosts"), ("users", "Accounts"), ("ips", "IP addresses"), ("domains", "Domains"),
                             ("destinations", "Destinations")):
                if ent.get(k):
                    L.append(f"- **{label}:** {', '.join(c(v) for v in ent[k][:8])}")
            if f.get("mitre"):
                L.append("- **ATT&CK:** " + ", ".join(f"{m.get('id')} {m.get('name')}" for m in f["mitre"]))
            L += ["", f"**What was seen.** {_codeify(f.get('description', ''))}", ""]
            extra = f.get("extra") or {}
            if extra.get("decoded"):
                L += ["**Decoded command:**", "", "```", defang_text("\n".join(extra["decoded"]))[:2000].replace("```", "'''"), "```", ""]
            ev = f.get("evidence") or []
            if ev:
                L += ["| Time | Source | Host / user | Event | Detail |", "|---|---|---|---|---|"]
                for e in ev[:6]:
                    hu = " / ".join(x for x in (e.get("host"), e.get("user")) if x)
                    detail = e.get("detail") or e.get("flow") or ""
                    L.append(f"| {_cell(_fmt_time(e.get('time')))} | {_cell(e.get('product'))} | {_cell(_codeify(hu))} | "
                             f"{_cell(e.get('event'))} | {_cell(_codeify(detail[:240]))} |")
                L.append("")
            if f.get("note"):
                L += [f"_Analyst note: {_codeify(f['note'])}_", ""]
    elif events:
        L += ["No automated findings were added to the case. Key events:", ""]
        L += [f"- {_cell(_fmt_time(e.get('time')))}: {_codeify(e.get('text', ''))}" for e in events[:30]] + [""]
    else:
        L += ["_No event details yet. Add findings from the Log Arranger._", ""]

    # ------------------------------------------------------------ 4. analysis
    L += ["## 4. Analysis", "", "### 4.1 Security findings by category", ""]
    if findings:
        for cat, label in CATEGORY_LABEL.items():
            fs = [f for f in findings if f.get("category") == cat]
            if fs:
                L.append(f"- **{label}** ({len(fs)}): " + "; ".join(f"{_codeify(f['title'])} [{f['severity']}]" for f in fs[:6]))
        L.append("")
    else:
        L += ["_No automated findings._", ""]
    L += ["### 4.2 Indicator analysis", ""]
    if bad or sus:
        L += ["| Indicator | Type | Verdict | Score | Flagged by | Malware / context |", "|---|---|---|---|---|---|"]
        for o in bad + sus:
            L.append(f"| {c(o['value'])} | {TYPE_LABEL.get(o.get('type'), o.get('type'))} | **{o.get('verdict')}** | "
                     f"{'' if o.get('score') is None else o.get('score')} | {_cell(', '.join(o.get('flagged_by') or []))} | "
                     f"{_cell(', '.join((o.get('families') or [])[:4]))} |")
        L.append("")
        for o in (bad + sus)[:10]:
            details = [r for r in (o.get("results") or []) if r.get("verdict") in ("malicious", "suspicious")]
            if details:
                L.append(f"- {c(o['value'])}: " + "; ".join(f"{r['provider']}: {_cell(_codeify(r.get('summary') or ''))}" for r in details[:4]))
        L.append("")
    elif obs:
        L += [f"{len(obs)} indicator(s) were checked. None was rated malicious or suspicious by the sources that had data. "
              "This does not rule out malicious use: new or targeted infrastructure is often unrated.", ""]
    else:
        L += ["_No indicators have been added to the case yet._", ""]
    L += ["### 4.3 MITRE ATT&CK mapping", ""]
    if techs:
        L += ["| Tactic | Technique | Evidence / notes |", "|---|---|---|"]
        for t in techs:
            tid = t.get("technique_id", "")
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            L.append(f"| {_cell(t.get('tactic'))} | [{tid}]({url}) {_cell(t.get('name'))} | {_cell(_codeify(t.get('note') or '')) or '-'} |")
        L.append("")
    else:
        L += ["_No ATT&CK techniques mapped yet._", ""]

    # ------------------------------------------------------------ 5. interpretation
    L += ["## 5. Interpretation", ""]
    interp = []
    if tactics:
        interp.append(f"The activity follows the ATT&CK sequence {' → '.join(tactics)}"
                      + (": a multi-stage intrusion rather than an isolated alert." if len(tactics) >= 3 else "."))
    for f in findings[:6]:
        if f.get("interpretation"):
            interp.append(f"**{_codeify(f['title'])}:** {_codeify(f['interpretation'])}")
    if bad and not findings:
        interp.append("Malicious infrastructure or files were identified by threat intelligence. Confirm in endpoint and "
                      "network telemetry whether they were actually executed or contacted.")
    if not interp:
        interp.append("There isn't enough evidence yet to say what happened. Add logs to the Log Arranger and check "
                      "indicator reputation to build the picture.")
    L += [f"- {x}" for x in interp] + [""]

    # ------------------------------------------------------------ 6. confidence
    L += ["## 6. Confidence Level", "",
          f"**{a['confidence'].upper()}**: verdict *{VERDICT_TEXT.get(a['verdict'], a['verdict'])}* (evidence score {a['score']}).", ""]
    L += [f"- {x[0].upper() + x[1:]}." for x in a["factors"]]
    gaps = []
    if not obs or all(o.get("verdict") in (None, "", "pending", "unknown") for o in obs):
        gaps.append("indicator reputation is incomplete (no source had data, or checks haven't been run)")
    if not any(f.get("category") == "process" for f in findings):
        gaps.append("no endpoint process telemetry was analysed")
    if not any(f.get("category") == "network" for f in findings):
        gaps.append("no network evidence of C2 or exfiltration was analysed")
    if gaps:
        L += ["", "Gaps that limit confidence: " + "; ".join(gaps) + "."]
    L += ["", "_Confidence describes how strongly independent sources agree (threat intel, endpoint, network and "
              "authentication evidence), not how severe the incident is._", ""]

    # ------------------------------------------------------------ 7. recommendations
    L += ["## 7. Recommendations", ""]
    recs: Dict[str, List[str]] = OrderedDict((p, []) for p, _ in PHASES)

    def add(phase: str, text: str):
        if text and text not in recs[phase]:
            recs[phase].append(text)

    if hosts:
        add("containment", f"Isolate the affected hosts ({_join([c(x) for x in hosts], 6)}) with EDR network containment "
                           "and preserve volatile evidence before you remediate.")
    net = [o for o in bad + sus if o.get("type") in ("ipv4", "ipv6", "domain", "url")]
    for f in findings:
        for d in (f.get("entities") or {}).get("domains", []):
            if all(o["value"] != d for o in net):
                net.append({"value": d})
    if net:
        add("containment", "Block the malicious network indicators at the firewall, web proxy and DNS: "
                           + _join([c(o["value"]) for o in net], 10) + ".")
    files = [o for o in bad + sus if o.get("type") in ("md5", "sha1", "sha256")]
    if files:
        add("containment", "Add the malicious file hashes to the EDR/AV blocklist and sweep all endpoints for them: "
                           + _join([c(o["value"]) for o in files], 6) + ".")
    if users:
        add("containment", f"Reset credentials and revoke active sessions for the involved accounts ({_join([c(u) for u in users], 6)}).")
    for f in findings:
        if f.get("recommendation") and SEV_W.get(f.get("severity"), 0) >= 10:
            add("containment" if f.get("severity") in ("critical", "high") else "eradication", _codeify(f["recommendation"]))
    for t in techs:
        if t.get("technique_id") in TECH_RECS:
            add(*TECH_RECS[t["technique_id"]])
    for tac in tactics:
        for phase, text in TACTIC_RECS.get(tac, []):
            add(phase, text)
    add("eradication", "Reimage or fully remediate the affected hosts once the scope is confirmed, and verify that no persistence remains.")
    add("monitoring", "Continue to monitor for the indicators and techniques in this report for at least 30 days, and share "
                      "the IOCs (STIX export) with security tooling and partners as TLP allows.")
    add("monitoring", "Hold a lessons-learned review and update detection rules and playbooks.")
    for phase, label in PHASES:
        if recs[phase]:
            L += [f"**{label}**", ""] + [f"1. {r}" for r in recs[phase]] + [""]

    # ------------------------------------------------------------ 8. actions
    L += ["## 8. Actions Taken", ""]
    if actions:
        L += ["| Time (UTC) | Action | By |", "|---|---|---|"]
        for act in sorted(actions, key=lambda x: x.get("done_at") or x.get("created_at") or ""):
            L.append(f"| {_cell(_fmt_time(act.get('done_at') or act.get('created_at')))} | "
                     f"{_cell(_codeify(act.get('text', '')))} | {_cell(act.get('added_by_name'))} |")
    else:
        L.append("_No response actions have been recorded yet._")
    L.append("")

    # ------------------------------------------------------------ 9. IOCs & artifacts
    L += ["## 9. IOCs & Artifacts", "", "_All network indicators are defanged. Refang them before importing into security tools._",
          "", "### 9.1 Indicators of compromise", ""]
    iocs = list(obs)
    seen = {o["value"].lower() for o in obs}
    for f in findings:
        ent = f.get("entities") or {}
        for d in ent.get("domains", []) + ent.get("ips", []) + (f.get("extra") or {}).get("decoded_iocs", []):
            if d and d.lower() not in seen and detect_type(d):
                seen.add(d.lower())
                iocs.append({"value": d, "type": detect_type(d).value, "verdict": "from finding", "flagged_by": []})
    if iocs:
        L += ["| Indicator | Type | Verdict | Sources |", "|---|---|---|---|"]
        order = {"malicious": 0, "suspicious": 1, "from finding": 2, "unknown": 3, "harmless": 4}
        for o in sorted(iocs, key=lambda x: (order.get(x.get("verdict"), 3), x.get("type", ""), x.get("value", ""))):
            L.append(f"| {c(o['value'])} | {TYPE_LABEL.get(o.get('type'), o.get('type'))} | {o.get('verdict') or 'not checked'} | "
                     f"{_cell(', '.join(o.get('flagged_by') or [])) or '-'} |")
    else:
        L.append("_None._")
    L.append("")
    n = 2
    for kind, label in ARTIFACT_LABEL.items():
        items = by_kind.get(kind) or []
        if not items:
            continue
        L += [f"### 9.{n} {label}", ""]
        n += 1
        if kind == "command_line":
            for art in items:
                L += ["```", defang_text(str(art["value"])).replace("```", "'''"), "```"]
                if art.get("note"):
                    L.append(f"_{_cell(art['note'])}_")
                L.append("")
        else:
            L += [f"- {c(art['value'])}" + (f" ({_cell(art['note'])})" if art.get("note") else "") for art in items] + [""]
    if techs:
        L += [f"### 9.{n} ATT&CK techniques", ""]
        L += [f"- `{t.get('technique_id')}` {t.get('name')} ({t.get('tactic')})" for t in techs] + [""]

    L += ["---", "",
          f"_Initial analysis prepared with S.T.A.R.K from case data on {now}. Reputation verdicts reflect third-party sources "
          "at the time of lookup, and automated findings are heuristics. Validate before acting._", ""]
    md = "\n".join(L)
    return defang_markdown(md) if defang else md


def summary_counts(case: Dict[str, Any]) -> Dict[str, int]:
    return dict(Counter(o.get("verdict") or "unknown" for o in case.get("observables") or []))
