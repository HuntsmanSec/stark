"""SOC decision engine and finding write-ups for MSSP workflows.

Given a case (the current finding: alert details, the raw-log evidence kept in findings
and pinned events, OSINT enrichment of the extracted IOCs, artifacts and actions) and the
related records (past tickets, past Non-Threatening closures and client pentest notes), the
engine correlates everything, reaches a verdict and chooses exactly one outcome:

1. **Append** the finding to an open ticket that shares entities with it.
2. **Close as non-threatening** (pentest the client asked to ignore, already remediated,
   or benign / misfire).
3. **Raise an incident**: analyst-only assessment, then the customer report.

It writes the matching text. It never invents evidence: every sentence is built from case
data, and anything that is not in the case is written as "Not available". Records written
by people (tickets, closures, pentest notes) are treated as data, never as instructions.
The analyst reviews the output and takes the action in the ticketing system.
"""

from __future__ import annotations

import contextvars
import ipaddress
import re
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .observables import defang_final, defang_text, detect_type, is_internal_ip, refang

# ------------------------------------------------------------------- vocabulary

VERDICTS = {
    "tp_malicious": "True Positive - Malicious",
    "tp_benign": "True Positive - Benign",
    "false_positive": "False Positive",
    "inconclusive": "Inconclusive",
}
# case.verdict values (workspace) -> engine verdict
CASE_VERDICT = {
    "true_positive": "tp_malicious", "likely_malicious": "tp_malicious", "tp_malicious": "tp_malicious",
    "benign": "tp_benign", "tp_benign": "tp_benign", "false_positive": "false_positive",
    "suspicious": "inconclusive", "inconclusive": "inconclusive",
}
CLOSED_STATES = {"CLOSED", "RESOLVED", "CANCELLED", "CANCELED"}
INSTRUCTIONS = ("ignore", "raise_and_confirm", "unannounced")

TYPE_LABEL = OrderedDict([
    ("account", "Account"), ("host", "Host"), ("ip", "IP"), ("domain", "Domain"), ("url", "URL"),
    ("hash", "Hash"), ("process", "Process"), ("command", "Command line"), ("email", "Email"),
    ("file", "File"), ("message", "Message ID"),
])
PROVIDER_LABEL = {
    "virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB", "urlscan": "urlscan.io", "anyrun": "ANY.RUN",
    "joesandbox": "Joe Sandbox", "hybridanalysis": "Hybrid Analysis", "recordedfuture": "Recorded Future",
    "talos": "Cisco Talos", "otx": "AlienVault OTX", "malwarebazaar": "MalwareBazaar", "threatfox": "ThreatFox",
    "urlhaus": "URLhaus", "hibp": "Have I Been Pwned", "mxtoolbox": "MXToolbox", "shodan": "Shodan",
    "greynoise": "GreyNoise", "pulsedive": "Pulsedive", "ipinfo": "IPinfo", "crtsh": "crt.sh",
}
MICROSOFT = re.compile(r"microsoft|defender|sentinel|entra|azure|m365|office ?365|mde|mdi|mdo|xdr", re.I)

_BLOCK = re.compile(r"\b(block(ed)?|den(y|ied)|drop(ped)?|reject(ed)?|quarantin\w*|prevent(ed)?|fail(ed|ure)?|"
                    r"sinkhol\w*|remediated|terminated|reset-?(both|client|server)|interrupt(ed)?|4625|4771)\b", re.I)
_ALLOW = re.compile(r"\b(allow(ed)?|accept(ed)?|permit(ted)?|success(ful|fully)?|succeeded|pass(ed)?|connected|"
                    r"established|execut(ed|ion)|launched|process ?created|logged on|4624|sign-?in succeeded|"
                    r"downloaded|200 ok)\b", re.I)
_CONTAIN = re.compile(r"\b(block(ed)?|den(y|ied)|drop(ped)?|quarantin\w*|prevent(ed)?|sinkhol\w*|isolat\w*|"
                      r"remediated|terminated|reset-?(both|client|server))\b", re.I)
_INVESTIGATION = re.compile(r"\b(review(ed)?|investigat\w*|notif\w*|escalat\w*|analys\w*|informed|emailed|called|"
                            r"triag\w*|checked|looked|raised|opened)\b", re.I)
_STRONG_FIX = [
    (re.compile(r"\bblock(ed|ing)?\b|\bblacklist(ed)?\b|\bdeny rule\b|\bgeo-?block", re.I), "blocked"),
    (re.compile(r"password(s)? (was |were |has been |have been )?reset|reset (the )?(user'?s? )?password|"
                r"credentials? (were |was )?(reset|rotated)", re.I), "password reset"),
    (re.compile(r"session(s)? (were |was |have been )?revoked|revoke[sd]? (all )?(active )?sessions|"
                r"refresh tokens? (were )?revoked|sign(ed)? out of all sessions", re.I), "sessions revoked"),
    (re.compile(r"\bisolat(ed|ion)\b|\bcontained the (host|device)\b", re.I), "host isolated"),
    (re.compile(r"\b(rebuilt|re-?imaged|reinstalled|wiped)\b", re.I), "host rebuilt"),
    (re.compile(r"\b(patched|closed the port|disabled the (service|port)|removed public access|fixed the "
                r"(exposed|misconfigured))", re.I), "exposed service fixed"),
    (re.compile(r"\b(account (was |has been )?disabled|disabled the account)\b", re.I), "account disabled"),
    (re.compile(r"\bquarantin(ed|e)\b|\bremoved the (file|malware)\b|\bdeleted the (file|malware)\b", re.I),
     "file quarantined"),
]
_VAGUE = re.compile(r"^\W*(resolved|closed|done|fixed|client informed|customer informed|no action( required)?|"
                    r"n/?a|false positive|benign)\W*$", re.I)
_PRIV = re.compile(r"(^|[\\/@])(administrator|admin|root|domain admins?|svc[_-]|sa$|krbtgt|backup)|adm(in)?[-_.]|"
                   r"[-_.]adm(in)?\b", re.I)
_SERVER = re.compile(r"(^|[-_.])(srv|svr|server|dc\d*|sql|db\d*|exch|exchange|ad\d*|fs\d*|file|web\d*|app\d*|"
                     r"esx|vcenter|hyperv|ca\d*|adfs|rds|citrix)([-_.\d]|$)", re.I)
_VPN = re.compile(r"\b(vpn|proxy|anonymi[sz]er|hosting|tor)\b", re.I)
_DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2})?)(Z|[+-]\d{2}:?\d{2})?)?")

PENTEST_ACTIVITY = [
    (re.compile(r"password spray", re.I), "password spraying", ("T1110.003",), ("auth:spray",)),
    (re.compile(r"brute[- ]?forc", re.I), "brute force", ("T1110", "T1110.003"), ("auth:bruteforce",)),
    (re.compile(r"port ?scan|network scan|scanning|nmap|masscan|discovery scan", re.I), "scanning",
     ("T1046", "T1595"), ()),
    (re.compile(r"phish", re.I), "phishing", ("T1566", "T1566.001", "T1566.002"), ()),
    (re.compile(r"kerberoast", re.I), "Kerberoasting", ("T1558.003",), ()),
    (re.compile(r"credential (dump|harvest)|mimikatz|lsass", re.I), "credential dumping",
     ("T1003", "T1003.001", "T1003.002", "T1003.003", "T1003.006"), ()),
    (re.compile(r"lateral movement|pass[- ]the[- ]hash|psexec", re.I), "lateral movement",
     ("T1021", "T1021.001", "T1021.002", "T1021.006", "T1550.002", "T1569.002"), ()),
    (re.compile(r"\bc2\b|command and control|beacon|cobalt ?strike|sliver", re.I), "command and control",
     ("T1071.001", "T1071.004", "T1573"), ("network:beacon",)),
    (re.compile(r"web app|sql ?injection|sqlmap|burp|owasp|exploit", re.I), "web application testing",
     ("T1190",), ()),
    (re.compile(r"privilege escalation|uac bypass", re.I), "privilege escalation", ("T1548.002", "T1068"), ()),
]
PENTEST_TOOLS = ["nmap", "masscan", "mimikatz", "bloodhound", "sharphound", "responder", "impacket", "hydra",
                 "burp", "sqlmap", "metasploit", "cobalt strike", "crackmapexec", "netexec", "nessus", "nikto",
                 "gobuster", "kerbrute", "rubeus", "sliver", "nuclei", "zgrab", "medusa", "evil-winrm"]


# ------------------------------------------------------------------- helpers


def iso(t: Any) -> str:
    """ISO 8601 as stored; epoch numbers are converted to UTC."""
    if t is None or t == "":
        return ""
    if isinstance(t, (int, float)):
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(t).strip()


def _parse_time(t: Any) -> Optional[datetime]:
    if t is None or t == "":
        return None
    if isinstance(t, (int, float)):
        return datetime.fromtimestamp(t, tz=timezone.utc)
    s = str(t).strip().replace(" ", "T", 1)
    if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        s += "T00:00:00"
    s = re.sub(r"\.\d+", "", s).replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


# Accounts and hostnames of the current finding are written exactly (they are pivots, not
# investigated infrastructure), even when they look like an email address or a domain.
_KEEP: contextvars.ContextVar = contextvars.ContextVar("stark_soc_keep", default=frozenset())


def dfg(value: Any) -> str:
    """Defang one investigated value (final dot only) and show it as inline code."""
    s = str(value if value is not None else "").replace("\n", " ").strip()
    if not s:
        return ""
    keep = _KEEP.get()
    if s.lower() not in keep:
        t = detect_type(refang(s))
        s = defang_final(s, t) if t else dtext(s)
    return f"`` {s} ``" if "`" in s else f"`{s}`"


def dtext(text: Any) -> str:
    text = str(text or "")
    keep = _KEEP.get()
    if not keep:
        return defang_text(text, style="final")
    from .observables import find_iocs
    spans = [text[a:b] for a, b, _o in find_iocs(text) if text[a:b].lower() in keep]
    return defang_text(text, keep=spans, style="final")


def _flow(flow: str) -> str:
    src, _, dst = (flow or "").partition(" -> ")
    src, dst = src.strip(), dst.strip()
    if src and src != "?" and (not dst or dst == "?"):
        return f"from {dtext(src)}"
    if dst and dst != "?" and (not src or src == "?"):
        return f"to {dtext(dst)}"
    return f"from {dtext(src)} to {dtext(dst)}" if src and dst else ""


def _join(items: Sequence[str], limit: int = 6) -> str:
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) > limit:
        return ", ".join(items[:limit]) + f" and {len(items) - limit} more"
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _plural(n: int, word: str, plural: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _norm(v: str) -> str:
    return refang(str(v or "")).strip().lower()


def mentions(text: str, value: str) -> bool:
    """Exact (case-insensitive) mention of ``value`` as a whole token in ``text``."""
    v = _norm(value)
    if len(v) < 3:
        return False
    hay = _norm(text)
    return re.search(r"(?<![\w.\-@\\])" + re.escape(v) + r"(?![\w\-@]|\.\w)", hay) is not None


def _ip_in(ip: str, specs: Iterable[str]) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for spec in specs:
        spec = refang(str(spec)).strip()
        if not spec:
            continue
        try:
            if a in ipaddress.ip_network(spec, strict=False):
                return True
        except ValueError:
            continue
    return False


def provider_label(name: str) -> str:
    return PROVIDER_LABEL.get(str(name or "").lower(), str(name or "Unknown source"))


# ------------------------------------------------------------------- evidence model


class Evidence:
    """Everything the engine knows about the current finding, derived from a case dict."""

    def __init__(self, case: Dict[str, Any]):
        self.case = case
        self.findings = [f for f in case.get("findings") or [] if f.get("status") != "dismissed"]
        self.observables = case.get("observables") or []
        self.artifacts = case.get("artifacts") or []
        self.events = sorted(case.get("events") or [], key=lambda e: e.get("time") or "")
        self.actions = case.get("actions") or []
        self.techniques = case.get("techniques") or []
        self.rows: List[Dict[str, Any]] = []
        seen = set()
        for f in self.findings:
            for r in f.get("evidence") or []:
                k = tuple(str(r.get(x) or "") for x in ("time", "event", "user", "host", "flow", "detail"))
                if k in seen:
                    continue
                seen.add(k)
                self.rows.append({**r, "_finding": f.get("title")})
        for e in self.events:
            self.rows.append({"time": e.get("time") or "", "product": "Timeline", "event": "", "detail": e.get("text") or "",
                              "host": "", "user": "", "flow": "", "action": ""})
        self.entities = self._entities()
        self.times = sorted({t for t in self._times() if t})

    # entities -------------------------------------------------------------
    def _entities(self) -> Dict[str, List[str]]:
        ent: Dict[str, "OrderedDict[str, str]"] = {k: OrderedDict() for k in TYPE_LABEL}

        def add(kind: str, value: Any):
            v = str(value or "").strip()
            if not v or v in ("-", "?", "N/A", "SYSTEM") or len(v) > 2000:
                return
            v = refang(v) if kind in ("ip", "domain", "url", "email") else v
            ent[kind].setdefault(v.lower(), v)

        type_map = {"ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url", "md5": "hash", "sha1": "hash",
                    "sha256": "hash", "email": "email"}
        for o in self.observables:
            add(type_map.get(o.get("type"), "domain"), o.get("value"))
        kind_map = {"host": "host", "user": "account", "process": "process", "command_line": "command",
                    "file": "file", "email": "message"}
        for a in self.artifacts:
            if a.get("kind") in kind_map:
                add(kind_map[a["kind"]], a.get("value"))
        for f in self.findings:
            e = f.get("entities") or {}
            for k, kind in (("hosts", "host"), ("users", "account"), ("ips", None), ("domains", None),
                            ("destinations", None)):
                for v in e.get(k) or []:
                    if kind:
                        add(kind, v)
                        continue
                    t = detect_type(refang(str(v)))
                    if t:
                        add(type_map.get(t.value, "domain"), v)
            for v in (f.get("extra") or {}).get("decoded_iocs") or []:
                t = detect_type(refang(str(v)))
                if t:
                    add(type_map.get(t.value, "domain"), v)
        for r in self.rows:
            add("host", r.get("host"))
            add("account", r.get("user"))
            for ip in (r.get("src_ip"), r.get("dst_ip")):
                add("ip", ip)
            for part in re.findall(r"[0-9a-fA-F:.]{7,}", r.get("flow") or ""):
                ip = part.rsplit(":", 1)[0] if part.count(":") == 1 else part
                if detect_type(ip):
                    add("ip", ip)
        if self.case.get("customer_hosts"):
            for h in self.case["customer_hosts"]:
                add("host", h)
        return {k: list(v.values()) for k, v in ent.items() if v}

    def all_entities(self) -> List[Tuple[str, str]]:
        return [(k, v) for k, vals in self.entities.items() for v in vals]

    def external_ips(self) -> List[str]:
        return [ip for ip in self.entities.get("ip", []) if not is_internal_ip(ip)]

    # time -------------------------------------------------------------------
    def _times(self) -> Iterable[str]:
        for f in self.findings:
            yield f.get("first") or ""
            yield f.get("last") or ""
        for r in self.rows:
            yield r.get("time") or ""

    @property
    def first(self) -> str:
        return self.times[0] if self.times else ""

    @property
    def last(self) -> str:
        return self.times[-1] if self.times else ""

    # outcomes -----------------------------------------------------------
    def rows_for(self, value: str) -> List[Dict[str, Any]]:
        out = []
        for r in self.rows:
            blob = " ".join(str(r.get(k) or "") for k in ("host", "user", "flow", "detail", "event", "src_ip", "dst_ip"))
            if mentions(blob, value):
                out.append(r)
        return out

    @staticmethod
    def row_outcome(r: Dict[str, Any]) -> str:
        text = " ".join(str(r.get(k) or "") for k in ("action", "event", "detail"))
        act = str(r.get("action") or "")
        if act:
            if _BLOCK.search(act):
                return "blocked"
            if _ALLOW.search(act):
                return "succeeded"
        if _BLOCK.search(text):
            return "blocked"
        if _ALLOW.search(text):
            return "succeeded"
        return "observed"

    def outcome(self, value: str) -> Tuple[str, List[Dict[str, Any]]]:
        rows = self.rows_for(value)
        if not rows:
            return "absent", []
        kinds = {self.row_outcome(r) for r in rows}
        if "succeeded" in kinds and "blocked" in kinds:
            return "mixed", rows
        if "succeeded" in kinds:
            return "succeeded", rows
        if "blocked" in kinds:
            return "blocked", rows
        return "observed", rows

    def products(self) -> List[str]:
        return sorted({r.get("product") for r in self.rows if r.get("product") and r.get("product") != "Timeline"})

    def text_blob(self) -> str:
        parts = [self.case.get("alert_name") or "", self.case.get("title") or ""]
        parts += [f"{f.get('title')} {f.get('description')}" for f in self.findings]
        parts += [str((f.get("extra") or {}).get("tools") or "") for f in self.findings]
        parts += [a.get("value") or "" for a in self.artifacts]
        parts += [e.get("text") or "" for e in self.events]
        parts += [r.get("detail") or "" for r in self.rows]
        return "\n".join(parts)

    def technique_ids(self) -> set:
        ids = {t.get("technique_id") or t.get("id") for t in self.techniques}
        for f in self.findings:
            ids |= {m.get("id") if isinstance(m, dict) else m for m in f.get("mitre") or []}
        return {i for i in ids if i}

    def tactics(self) -> set:
        return {t.get("tactic") for t in self.techniques if t.get("tactic")}


# ------------------------------------------------------------------- OSINT correlation


def osint(ev: Evidence) -> List[Dict[str, Any]]:
    """Per enriched observable: feeds and verdicts, whether it is in the logs and what happened."""
    out = []
    for o in ev.observables:
        feeds = [r for r in (o.get("results") or []) if r.get("verdict") in ("malicious", "suspicious", "harmless")]
        if not feeds and o.get("verdict") in (None, "", "pending"):
            continue
        outcome, rows = ev.outcome(o["value"])
        verdicts = {r["verdict"] for r in feeds}
        disagreement = "malicious" in verdicts and "harmless" in verdicts or \
            ("suspicious" in verdicts and "harmless" in verdicts)
        bad = [r for r in feeds if r["verdict"] in ("malicious", "suspicious")]
        good = [r for r in feeds if r["verdict"] == "harmless"]
        out.append({"value": o["value"], "type": o.get("type"), "verdict": o.get("verdict") or "unknown",
                    "feeds": feeds, "bad": bad, "good": good, "disagreement": disagreement,
                    "outcome": outcome, "rows": rows, "families": o.get("families") or [], "tags": o.get("tags") or [],
                    "checked": o.get("sources_checked") or 0, "enriched": bool(o.get("enriched_at"))})
    return out


def _type_label(t: Optional[str]) -> str:
    return {"ipv4": "IP", "ipv6": "IP", "domain": "Domain", "url": "URL", "md5": "Hash", "sha1": "Hash",
            "sha256": "Hash", "email": "Email"}.get(t or "", "Indicator")


def _ip_nature(item: Dict[str, Any]) -> str:
    if item["type"] not in ("ipv4", "ipv6"):
        return ""
    if item["verdict"] == "malicious":
        return "malicious"
    if item["verdict"] == "suspicious":
        return "suspicious"
    if item["verdict"] == "harmless":
        return "benign"
    return "no reputation on record"


def osint_bullets(items: List[Dict[str, Any]]) -> List[str]:
    lines = []
    for it in items:
        feeds = "; ".join(
            f"{provider_label(r.get('provider'))}: {r.get('verdict')}"
            + (f" ([report]({r['link']}))" if r.get("link") else "") for r in it["feeds"])
        nature = _ip_nature(it)
        head = f"- **{_type_label(it['type'])}:** {dfg(it['value'])}"
        if nature:
            head += f", assessed {nature}"
        lines.append(head + (f". {feeds}" if feeds else ". No feed holds a record of it"))
    return lines


def osint_sentence(it: Dict[str, Any]) -> str:
    v = dfg(it["value"])
    bad = [f"{provider_label(r['provider'])} ({r['verdict']})" for r in it["bad"]]
    good = [provider_label(r["provider"]) for r in it["good"]]
    if bad and good:
        support = "the malicious rating is better supported" if len(it["bad"]) >= len(it["good"]) else \
            "the clean rating is better supported"
        s = f"{_join(bad)} flag {v}, while {_join(good)} rate{'s' if len(good) == 1 else ''} it clean; {support} " \
            f"({len(it['bad'])} against {len(it['good'])})"
    elif bad:
        s = f"{_join(bad)} flag{'s' if len(bad) == 1 else ''} {v}"
        if it["families"]:
            s += f", associated with {_join(it['families'], 4)}"
    elif good:
        s = f"{_join(good)} rate{'s' if len(good) == 1 else ''} {v} clean"
    else:
        s = f"none of the {it['checked'] or ''} sources checked holds a record of {v}".replace("the  ", "the ")
    return s + "."


def outcome_sentence(it: Dict[str, Any]) -> str:
    v = dfg(it["value"])
    o = it["outcome"]
    rows = it["rows"]
    when = sorted({r.get("time") for r in rows if r.get("time")})
    span = f" between {when[0]} and {when[-1]}" if len(when) > 1 else (f" at {when[0]}" if when else "")
    prods = _join(sorted({r.get("product") for r in rows if r.get("product") and r.get("product") != "Timeline"}))
    src = f" in the {prods} logs" if prods else " in the alert's raw logs"
    if o == "absent":
        return f"{v} was enriched but does not appear in the alert's raw logs, so the enrichment is not tied to logged activity."
    if o == "succeeded":
        return f"The logs show activity involving {v} completing{span}{src} ({_plural(len(rows), 'event')})."
    if o == "blocked":
        return f"Every logged attempt involving {v}{span}{src} was blocked, denied or failed ({_plural(len(rows), 'event')})."
    if o == "mixed":
        ok = sum(1 for r in rows if Evidence.row_outcome(r) == "succeeded")
        bad = len(rows) - ok
        return (f"{v} appears in {_plural(len(rows), 'event')}{span}{src}: {ok} completed and {bad} "
                f"{'was' if bad == 1 else 'were'} blocked or failed.")
    return f"{v} appears in {_plural(len(rows), 'event')}{span}{src}; the logs do not record whether the activity completed."


# ------------------------------------------------------------------- compromise


def compromise_signs(ev: Evidence, intel: List[Dict[str, Any]]) -> List[str]:
    signs = []
    for f in ev.findings:
        key = f.get("key") or ""
        if key.startswith(("auth:bruteforce-success", "auth:travel", "auth:priv-external")):
            signs.append(f"unexpected successful sign-in ({f.get('title')})")
        if key.startswith("network:inbound"):
            signs.append(f"exposed service reachable from the internet ({f.get('title')})")
        if key.startswith(("network:dns-tunnel", "network:exfil")):
            signs.append(f"possible data transfer ({f.get('title')})")
    tac = ev.tactics()
    for t, label in (("Persistence", "new persistence"), ("Lateral Movement", "lateral movement"),
                     ("Exfiltration", "data transfer out of the environment"), ("Impact", "impact on systems or data")):
        if t in tac:
            techs = [x.get("technique_id") for x in ev.techniques if x.get("tactic") == t]
            signs.append(f"{label} ({_join(techs, 4)})")
    for it in intel:
        if it["verdict"] in ("malicious",) and it["outcome"] in ("succeeded", "mixed"):
            signs.append(f"completed activity with flagged observable {dfg(it['value'])}")
    return list(dict.fromkeys(signs))


SIGN_KINDS = [("sign-in", "an unexpected successful sign-in"), ("persistence", "new persistence"),
              ("lateral", "lateral movement"), ("data transfer", "data transfer")]


def absence_sentence(signs: List[str], expected: bool = False) -> str:
    """What was looked for and not found; signs that were found are named instead."""
    found = [label for key, label in SIGN_KINDS if any(key in sg for sg in signs)]
    missing = [label for key, label in SIGN_KINDS if label not in found]
    out = ""
    if signs and expected:
        out = ("We observed " + "; ".join(signs) + ". These come from the tester address(es) inside the test window and "
               "are expected for this test. ")
    elif signs:
        out = "We identified " + "; ".join(signs) + ". "
    if missing:
        out += f"We looked for {_join(missing)} from any other source and found none." if expected and signs else \
            f"We looked for {_join(missing)} and found none."
    return out.strip()


# ------------------------------------------------------------------- past records


def normalise_record(d: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Map an imported record (ticket / fusion-closure / pentest-note) to the engine's shape."""
    r = {re.sub(r"[\s\-]+", "_", str(k).strip().lower()): v for k, v in (d or {}).items()}
    t = str(r.get("_type") or r.get("type") or "").lower()
    if "pentest" in t:
        ips = r.get("tester_ips") or []
        if isinstance(ips, str):
            ips = [x for x in re.split(r"[\s,;]+", ips) if x]
        hosts = r.get("hosts") or r.get("machines") or []
        if isinstance(hosts, str):
            hosts = [x for x in re.split(r"[\s,;]+", hosts) if x]
        instr = str(r.get("client_instruction") or "raise_and_confirm").lower().replace(" ", "_").replace("-", "_")
        return "pentest", {"title": str(r.get("title") or "Untitled pentest note"), "details": str(r.get("details") or ""),
                           "tester_ips": [str(x) for x in ips], "hosts": [str(x) for x in hosts],
                           "starts_on": str(r.get("starts_on") or ""), "ends_on": str(r.get("ends_on") or ""),
                           "window_status": str(r.get("window_status") or ""),
                           "client_instruction": instr if instr in INSTRUCTIONS else "raise_and_confirm",
                           "tester_ips_seen_in_evidence": r.get("tester_ips_seen_in_evidence") or []}
    if "closure" in t:
        return "closure", {"finding_id": str(r.get("finding_id") or r.get("id") or ""), "detail": str(r.get("detail") or ""),
                           "closure_note": str(r.get("closure_note") or ""), "closed_by": str(r.get("closed_by") or ""),
                           "closed_on": iso(r.get("closed_on")), "reference_for": str(r.get("reference_for") or ""),
                           "artifacts": [], "source": "imported"}
    findings = r.get("findings") or []
    if isinstance(findings, str):
        findings = [x for x in re.split(r"[\s,;]+", findings) if x]
    notes = r.get("notes") or ""
    if isinstance(notes, list):
        notes = "\n".join(str(n.get("text") if isinstance(n, dict) else n) for n in notes)
    return "ticket", {"case_number": str(r.get("case_number") or r.get("number") or r.get("ticket") or ""),
                      "status": str(r.get("status") or "").upper().replace(" ", "_"),
                      "subject": str(r.get("subject") or r.get("title") or ""),
                      "description": str(r.get("description") or ""), "notes": str(notes),
                      "close_notes": str(r.get("close_notes") or ""), "created_on": iso(r.get("created_on")),
                      "updated_on": iso(r.get("updated_on")), "findings": [str(x) for x in findings],
                      "involves_current_finding": bool(r.get("involves_current_finding")),
                      "reference_for": str(r.get("reference_for") or ""), "artifacts": [], "source": "imported"}


def _record_fields(rec: Dict[str, Any], kind: str) -> List[Tuple[str, str]]:
    if kind == "ticket":
        return [("subject", rec.get("subject") or ""), ("description", rec.get("description") or ""),
                ("notes", rec.get("notes") or ""), ("close notes", rec.get("close_notes") or ""),
                ("recorded indicators", " \n ".join(rec.get("artifacts") or []))]
    return [("detail", rec.get("detail") or ""), ("closure note", rec.get("closure_note") or ""),
            ("recorded indicators", " \n ".join(rec.get("artifacts") or []))]


def entity_matches(ev: Evidence, rec: Dict[str, Any], kind: str) -> List[Dict[str, str]]:
    out = []
    fields = _record_fields(rec, kind)
    for etype, value in ev.all_entities():
        if etype in ("command",) and len(value) > 300:
            continue
        where = [name for name, text in fields if text and mentions(text, value)]
        if where:
            out.append({"type": etype, "value": value, "where": _join(where)})
    return out


def remediation_check(ev: Evidence, ticket: Dict[str, Any], matches: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    notes = (ticket.get("close_notes") or "").strip()
    if not notes or _VAGUE.match(notes):
        return None
    done = [label for rx, label in _STRONG_FIX if rx.search(notes)]
    if not done:
        return None
    covered = [m for m in matches if "close notes" in m["where"]]
    if not covered:
        return None
    rem_time = None
    for m in _DATE.finditer(notes):
        rem_time = _parse_time(m.group(1) + ("T" + m.group(2) if m.group(2) else "") + (m.group(3) or ""))
    rem_time = rem_time or _parse_time(ticket.get("updated_on"))
    covered_vals = {m["value"].lower() for m in covered}
    key_types = ("account", "host", "ip", "domain", "url", "hash")
    uncovered = [v for t, v in ev.all_entities() if t in key_types and v.lower() not in covered_vals
                 and not (t == "ip" and is_internal_ip(v))]
    succeeded_after, worked = [], []
    seen_rows = set()
    for m in covered:
        for r in ev.rows_for(m["value"]):
            if id(r) in seen_rows:
                continue
            seen_rows.add(id(r))
            t = _parse_time(r.get("time"))
            oc = Evidence.row_outcome(r)
            if oc == "blocked":
                worked.append(r)
            elif oc == "succeeded" and (rem_time is None or (t and t > rem_time)):
                succeeded_after.append(r)
    last = _parse_time(ev.last)
    before = bool(rem_time and last and last <= rem_time)
    can_close = not succeeded_after and not uncovered and (before or bool(worked))
    if succeeded_after:
        reason = (f"the current logs show the same activity completing after the remediation "
                  f"({_plural(len(succeeded_after), 'event')}, latest {max(r.get('time') or '' for r in succeeded_after)})")
    elif uncovered:
        reason = f"the finding also involves entities the remediation did not cover ({_join([dfg(v) for v in uncovered], 5)})"
    elif before:
        reason = (f"all of the current activity ({ev.first or 'Not available'} to {ev.last or 'Not available'}) "
                  f"took place before the remediation ({iso(rem_time.isoformat()) if rem_time else 'Not available'})")
    elif worked:
        reason = f"the current logs show the remediation working: {_plural(len(worked), 'attempt')} were blocked, denied or failed"
    else:
        reason = "the current logs do not place the activity before the remediation, nor show it being blocked"
    return {"case_number": ticket.get("case_number"), "done": done, "notes": notes, "can_close": can_close,
            "reason": reason, "covered": covered, "remediated_at": iso(rem_time.strftime("%Y-%m-%dT%H:%M:%SZ")) if rem_time else ""}


# ------------------------------------------------------------------- pentest


def pentest_match(ev: Evidence, note: Dict[str, Any]) -> Dict[str, Any]:
    matched: List[str] = []
    testers = note.get("tester_ips") or []
    tester_hits = [ip for ip in ev.entities.get("ip", []) if _ip_in(ip, testers)]
    for ip in tester_hits:
        matched.append(f"tester address {dfg(ip)}")
    note_text = f"{note.get('title', '')}\n{note.get('details', '')}\n" + " ".join(note.get("hosts") or [])
    host_hits = [hst for hst in ev.entities.get("host", []) if mentions(note_text, hst)
                 or any(hst.lower().split(".")[0] == x.lower().split(".")[0] for x in note.get("hosts") or [])]
    for hst in host_hits:
        matched.append(f"machine {dfg(hst)}")
    techs = ev.technique_ids()
    keys = " ".join(f.get("key") or "" for f in ev.findings)
    blob = ev.text_blob().lower()
    activity_hits = []
    for rx, label, tids, fkeys in PENTEST_ACTIVITY:
        if rx.search(note_text) and (techs & set(tids) or any(k in keys for k in fkeys) or rx.search(blob)):
            activity_hits.append(label)
    for tool in PENTEST_TOOLS:
        if tool in note_text.lower() and tool in blob:
            activity_hits.append(f"the {tool} tool")
    activity_hits = list(dict.fromkeys(activity_hits))
    for a in activity_hits:
        matched.append(f"activity ({a})")
    related = bool(tester_hits or host_hits or activity_hits)

    start, end = _parse_time(note.get("starts_on")), _parse_time(note.get("ends_on"))
    if end and re.match(r"^\d{4}-\d{2}-\d{2}$", str(note.get("ends_on")).strip()):
        end = end.replace(hour=23, minute=59, second=59)
    times = [t for t in (_parse_time(x) for x in ev.times) if t] or \
        [t for t in [_parse_time(ev.case.get("alert_created"))] if t]
    if times:
        in_window = all((not start or t >= start) and (not end or t <= end) for t in times)
        window_text = "inside" if in_window else "outside"
    else:
        in_window = False
        window_text = "not placed in"
    others = [ip for ip in ev.external_ips() if not _ip_in(ip, testers)]
    covered = related and bool(tester_hits) and in_window and not others
    gaps = []
    if not tester_hits:
        gaps.append("none of the tester addresses appears in the logs")
    if others:
        gaps.append(f"the logs also show other external addresses ({_join([dfg(i) for i in others], 4)})")
    if not in_window:
        gaps.append("the activity falls outside the test window" if times else "the activity has no timestamps to place in the test window")
    return {"note": note, "related": related, "matched": matched, "tester_hits": tester_hits, "host_hits": host_hits,
            "activity_hits": activity_hits, "in_window": in_window, "window_text": window_text, "covered": covered,
            "gaps": gaps, "instruction": note.get("client_instruction") or "raise_and_confirm", "others": others}


def _window(note: Dict[str, Any]) -> str:
    s, e = note.get("starts_on") or "", note.get("ends_on") or ""
    if s and e:
        return f"{s} to {e}"
    if s:
        return f"from {s} (open-ended)"
    if e:
        return f"until {e}"
    return "open-ended"


# ------------------------------------------------------------------- verdict


def reach_verdict(case: Dict[str, Any], ev: Evidence, intel, signs, pentests, closures) -> Dict[str, Any]:
    from .report import assess
    a = assess(case)
    auto = a["auto"]["verdict"]
    conf = (case.get("confidence") or a["auto"]["confidence"] or "low").capitalize()
    override = CASE_VERDICT.get(case.get("verdict") or "")
    flagged_done = [i for i in intel if i["verdict"] in ("malicious", "suspicious") and i["outcome"] in ("succeeded", "mixed")]
    ignore_cover = [p for p in pentests if p["covered"] and p["instruction"] == "ignore"]
    reason = ""
    if override:
        v = override
        reason = "set by the analyst after review"
    elif ignore_cover:
        v, conf = "tp_benign", "High"
        p = ignore_cover[0]
        reason = (f"the activity comes from tester address(es) {_join([dfg(i) for i in p['tester_hits']])} inside the "
                  f"window of the authorized test \"{p['note']['title']}\"")
    elif auto in ("true_positive", "likely_malicious"):
        v = "tp_malicious"
        if auto == "likely_malicious" and conf == "High":
            conf = "Medium"
        reason = "; ".join(a["factors"][:3])
    elif auto == "suspicious":
        v = "inconclusive"
        reason = "suspicious indicators without corroborating evidence that the activity succeeded: " + "; ".join(a["factors"][:2])
    else:
        v = "inconclusive"
        reason = "the evidence in the case does not establish whether the activity is malicious or expected"
        same = [c for c in closures if c["matches"]]
        if same and not flagged_done and not signs and a["score"] < 30:
            v, conf = "tp_benign", "Medium"
            c = same[0]
            reason = (f"the same entities were reviewed and closed as non-threatening by {c['rec'].get('closed_by') or 'an analyst'} "
                      f"on {c['rec'].get('closed_on') or 'Not available'}, and nothing in this finding differs in kind")
    if v == "inconclusive":
        conf = "Low" if conf == "High" else conf
    missing = []
    if v == "inconclusive":
        if not intel:
            missing.append("OSINT enrichment of the observables")
        if not ev.rows:
            missing.append("raw log evidence")
        if not ev.entities.get("account") and not ev.entities.get("host"):
            missing.append("the account or host involved")
    return {"key": v, "label": VERDICTS[v], "confidence": conf, "reason": reason, "missing": missing,
            "score": a["score"], "factors": a["factors"]}


# ------------------------------------------------------------------- decision


def analyse(case: Dict[str, Any], tickets: List[Dict[str, Any]], closures: List[Dict[str, Any]],
            pentest_notes: List[Dict[str, Any]]) -> Dict[str, Any]:
    ev = Evidence(case)
    intel = osint(ev)
    signs = compromise_signs(ev, intel)
    fid = str(case.get("finding_id") or "").strip()

    t_info = []
    for t in tickets:
        m = entity_matches(ev, t, "ticket")
        involves = bool(t.get("involves_current_finding")) or (fid and fid in (t.get("findings") or []))
        status = (t.get("status") or "").upper()
        t_info.append({"rec": t, "matches": m, "open": status not in CLOSED_STATES, "involves": involves,
                       "remediation": remediation_check(ev, t, m) if m else None})
    c_info = [{"rec": c, "matches": entity_matches(ev, c, "closure")} for c in closures]
    p_info = [pentest_match(ev, n) for n in pentest_notes]
    p_rel = [p for p in p_info if p["related"]]
    verdict = reach_verdict(case, ev, intel, signs, p_rel, c_info)

    covered = [p for p in p_rel if p["covered"]]
    ignore = [p for p in covered if p["instruction"] == "ignore"]
    unannounced_cover = [p for p in covered if p["instruction"] == "unannounced"]
    flagged_done = [i for i in intel if i["verdict"] in ("malicious", "suspicious") and i["outcome"] in ("succeeded", "mixed")]
    no_finding = not fid and not case.get("alert_name")

    outcome, target, reason = 3, None, ""
    appendable = [t for t in t_info if t["matches"] and t["open"] and not t["involves"]]
    appendable.sort(key=lambda t: (len(t["matches"]), t["rec"].get("updated_on") or t["rec"].get("created_on") or ""),
                    reverse=True)
    remediated = [t for t in t_info if t["remediation"] and t["remediation"]["can_close"]]
    not_remediated = [t for t in t_info if t["remediation"] and not t["remediation"]["can_close"]]
    already_in = [t for t in t_info if t["involves"] and t["open"]]
    benign = verdict["key"] in ("false_positive", "tp_benign") and verdict["confidence"] in ("High", "Medium")
    escalated_same = [t for t in t_info if t["matches"] and not t["open"] and not t["remediation"]]

    if no_finding:
        outcome, reason = 3, "IOC / CSV analysis without a finding"
    elif ignore and not [p for p in p_rel if p["instruction"] != "ignore" and p["covered"]]:
        outcome, reason = 2, "pentest the client asked the SOC to ignore"
    elif appendable:
        outcome, target, reason = 1, appendable[0], "open ticket with similar entities"
    elif unannounced_cover:
        outcome, reason = 3, "activity covered by an unannounced pentest"
    elif remediated and not signs:
        outcome, target, reason = 2, remediated[0], "already remediated"
    elif benign and not flagged_done and not signs:
        outcome, reason = 2, "benign or misfire"
        if escalated_same and not [c for c in c_info if c["matches"]]:
            outcome, reason = 3, "a past ticket for the same entities was escalated"
    if outcome == 2 and reason == "benign or misfire" and any(p["covered"] and p["instruction"] != "ignore" for p in p_rel):
        outcome, reason = 3, "pentest note requires the standard workflow"

    return {"ev": ev, "intel": intel, "signs": signs, "tickets": t_info, "closures": c_info, "pentests": p_info,
            "related_pentests": p_rel, "verdict": verdict, "outcome": outcome, "target": target, "reason": reason,
            "remediated": remediated, "not_remediated": not_remediated, "already_in": already_in, "no_finding": no_finding,
            "flagged_done": flagged_done, "finding_id": fid}


# ------------------------------------------------------------------- shared text


def _tl(kind: str) -> str:
    label = TYPE_LABEL.get(kind, kind)
    return label if label.isupper() or label.startswith(("IP", "URL")) else label.lower()


def _who(ev: Evidence, limit: int = 4) -> str:
    acc = ev.entities.get("account", [])
    hosts = ev.entities.get("host", [])
    parts = []
    if acc:
        parts.append(("the account " if len(acc) == 1 else "the accounts ") + _join([dfg(a) for a in acc], limit))
    if hosts:
        parts.append(("the host " if len(hosts) == 1 else "the hosts ") + _join([dfg(x) for x in hosts], limit))
    return _join(parts) or "the observables in this finding"


def _activity_phrase(ev: Evidence) -> str:
    cats = [f.get("category") for f in ev.findings]
    if "auth" in cats:
        return "suspicious sign-in activity"
    if "malware" in cats:
        return "suspicious file and process activity"
    if "process" in cats:
        return "suspicious command execution"
    if "network" in cats:
        return "suspicious network activity"
    if any(o.get("verdict") in ("malicious", "suspicious") for o in ev.observables):
        return "communication with flagged infrastructure"
    return "the alerted activity"


def _event_lines(ev: Evidence, limit: int = 8) -> List[str]:
    rows = sorted((r for r in ev.rows if r.get("time")), key=lambda r: r["time"])
    out = []
    for r in rows[:limit]:
        bits = []
        if r.get("user"):
            bits.append(f"the account {dfg(r['user'])}")
        if r.get("host"):
            bits.append(f"on {dfg(r['host'])}")
        flow = r.get("flow") or ""
        what = (r.get("event") or "").strip()
        detail = (r.get("detail") or "").strip()
        act = (r.get("action") or "").strip()
        s = f"At {r['time']}"
        if r.get("product") and r["product"] != "Timeline":
            s += f" the {r['product']} logs record"
        else:
            s += " we recorded"
        s += f" {what or 'an event'}" + (f" for {' '.join(bits)}" if bits else "")
        if _flow(flow):
            s += f", {_flow(flow)}"
        if act:
            s += f" (action: {act})"
        if detail and detail != what:
            s += f": {dfg(detail[:220]) if len(detail) < 220 else dfg(detail[:220] + '...')}"
        out.append(s + ".")
    return out


def _past_paragraph(an: Dict[str, Any], include_pentest: bool = True) -> str:
    bits = []
    rel = [t for t in an["tickets"] if t["matches"]]
    for t in rel[:3]:
        r = t["rec"]
        vals = _join([dfg(m["value"]) for m in t["matches"]], 4)
        bits.append(f"Similar activity involving {vals} was previously raised as {r.get('case_number') or 'a past ticket'}"
                    f" (status {r.get('status') or 'Not available'}, last updated {r.get('updated_on') or 'Not available'})"
                    + (f"; its close notes record: {dtext(r['close_notes'][:300])}" if r.get("close_notes") else ""))
    for c in [c for c in an["closures"] if c["matches"]][:2]:
        r = c["rec"]
        bits.append(f"the same entities ({_join([dfg(m['value']) for m in c['matches']], 4)}) were reviewed and closed as "
                    f"non-threatening by {r.get('closed_by') or 'an analyst'} on {r.get('closed_on') or 'Not available'}")
    if not bits:
        if an["tickets"] or an["closures"]:
            return ("None of the past tickets or closures for this alert shares an account, host, IP or other entity with "
                    "this finding, so this activity has not been seen before for these accounts or hosts.")
        return "This activity has not been seen before for these accounts or hosts in the records available to us."
    diffs = []
    ev = an["ev"]
    seen = {m["value"].lower() for t in rel for m in t["matches"]} | \
        {m["value"].lower() for c in an["closures"] for m in c["matches"]}
    new = [v for t, v in ev.all_entities() if v.lower() not in seen and t in ("account", "host", "ip", "domain", "url", "hash")]
    if new:
        diffs.append(f"this time the activity also involves {_join([dfg(v) for v in new], 5)}")
    if ev.last:
        diffs.append(f"the latest activity is at {ev.last}")
    text = ". ".join(b[0].upper() + b[1:] for b in bits) + "."
    if diffs:
        text += " What differs: " + "; ".join(diffs) + "."
    return text


# ------------------------------------------------------------------- outcome 1


def render_append(case: Dict[str, Any], an: Dict[str, Any]) -> str:
    ev, t = an["ev"], an["target"]
    r = t["rec"]
    fid = an["finding_id"] or case.get("ref") or "Not available"
    inc = r.get("case_number") or "Not available"
    p1 = (f"the finding records {_activity_phrase(ev)} involving {_who(ev)}"
          + (f", with external addresses {_join([dfg(i) for i in ev.external_ips()], 5)}" if ev.external_ips() else "")
          + (f", from {ev.first} to {ev.last}" if ev.first and ev.last and ev.first != ev.last else
             (f", at {ev.first}" if ev.first else "")) + ".")
    if ev.findings:
        p1 += " " + " ".join(f"{dtext(f.get('description') or f.get('title'))}" for f in ev.findings[:2])
    same = _join([f"{_tl(m['type'])} {dfg(m['value'])}" for m in t["matches"]], 6)
    p2 = (f"We observed the same {same} in {inc} ({dtext(r.get('subject') or 'no subject')}), which this finding "
          f"{'continues' if ev.first and r.get('updated_on') and ev.first > r.get('updated_on', '') else 'repeats'}.")
    intel = an["intel"]
    p3_bits = []
    for it in intel[:4]:
        p3_bits.append(outcome_sentence(it))
    flagged = [i for i in intel if i["verdict"] in ("malicious", "suspicious")]
    if intel:
        p3_bits.append(f"Across the OSINT enrichment, {_plural(len(flagged), 'observable')} of {len(intel)} "
                       f"{'is' if len(flagged) == 1 else 'are'} flagged by at least one feed.")
    p3_bits.append(absence_sentence(an["signs"]))
    p3 = " ".join(p3_bits)
    matched_vals = {m["value"].lower() for m in t["matches"]}
    new_ents = [(k, v) for k, v in ev.all_entities() if v.lower() not in matched_vals]
    p4_bits = []
    if new_ents:
        p4_bits.append(f"New in this finding: {_join([f'{_tl(k)} {dfg(v)}' for k, v in new_ents], 6)}.")
    if ev.last and r.get("updated_on") and ev.last > r["updated_on"]:
        p4_bits.append(f"The activity continues after the ticket was last updated ({r['updated_on']}).")
    for p in an["related_pentests"]:
        if p["instruction"] == "unannounced":
            continue
        n = p["note"]
        s = (f"The client's penetration test \"{dtext(n['title'])}\" ({_window(n)}) is related: we matched "
             f"{_join(p['matched'])}, and the activity falls {p['window_text']} the test window.")
        if not p["covered"] and p["gaps"]:
            s += " The test does not explain all of it: " + "; ".join(p["gaps"]) + "."
        if p["instruction"] == "raise_and_confirm" and p["covered"]:
            s += " Please confirm whether this activity is within the scope of that test."
        p4_bits.append(s)
    new_hosts = [v for k, v in new_ents if k == "host"]
    if new_hosts and (an["signs"] or an["flagged_done"]):
        p4_bits.append(f"In addition to the ticket's recommendations, the newly involved host(s) {_join([dfg(h) for h in new_hosts])} "
                       "should be isolated and reviewed.")
    paras = [p2, p3] + ([" ".join(p4_bits)] if p4_bits else [])
    L = [f"Appending finding \"{fid}\" to \"{inc}\" as similar entities have been observed. Our analysis shows that {p1}",
         ""]
    for p in paras:
        L += [p, ""]
    L += ["## OSINT Info", ""] + (osint_bullets(intel) or ["- Not available"]) + [""]
    L += ["## Similar Entities Found", ""]
    L += [f"- **{TYPE_LABEL[m['type']]}:** {dfg(m['value'])} (in the ticket's {m['where']})" for m in t["matches"]] + [""]
    L += ["## New Entities Found", ""]
    L += ([f"- **{TYPE_LABEL[k]}:** {dfg(v)}" for k, v in new_ents[:30]] or ["- None"]) + [""]
    L += ["Kindly follow initial recommendations. Thank you.", ""]
    return "\n".join(L)


# ------------------------------------------------------------------- outcome 2


def render_close(case: Dict[str, Any], an: Dict[str, Any]) -> str:
    ev = an["ev"]
    alert = case.get("alert_name") or case.get("title") or "the alert"
    p1 = f"the alert {dtext(alert)} fired on {_activity_phrase(ev)} involving {_who(ev)}"
    if ev.first:
        p1 += f", from {ev.first} to {ev.last}" if ev.last and ev.last != ev.first else f", at {ev.first}"
    p1 += "."
    lines = _event_lines(ev, 5)
    if lines:
        p1 += " " + " ".join(lines)
    intel = an["intel"]
    p2 = " ".join(osint_sentence(i)[0].upper() + osint_sentence(i)[1:] + " " + outcome_sentence(i) for i in intel[:6]) or \
        "No OSINT enrichment is available for the observables in this finding."
    reason = an["reason"]
    if reason == "pentest the client asked the SOC to ignore":
        p = [x for x in an["related_pentests"] if x["covered"] and x["instruction"] == "ignore"][0]
        p3 = ("The activity is authorized testing: every external source in the logs is a listed tester address and the "
              "activity falls inside the test window, so the detection fired correctly on expected activity.")
    elif reason == "already remediated":
        rem = an["target"]["remediation"]
        p3 = (f"The activity was already remediated under {rem['case_number']}, so this finding does not need a new "
              "incident.")
    else:
        p3 = f"We assess the activity as {an['verdict']['label'].lower()}: {dtext(an['verdict']['reason'])}."
    p3 += " " + absence_sentence(an["signs"], expected=reason == "pentest the client asked the SOC to ignore")
    p4 = ""
    if reason == "already remediated":
        t = an["target"]
        rem = t["remediation"]
        p4 = (f"We relied on {rem['case_number']}: its close notes record that the issue was addressed "
              f"({_join(rem['done'])}) for {_join([dfg(m['value']) for m in rem['covered']], 5)}, and {rem['reason']}.")
    else:
        rel = [c for c in an["closures"] if c["matches"]]
        if rel:
            c = rel[0]["rec"]
            p4 = (f"We relied on the past closure by {c.get('closed_by') or 'an analyst'} on {c.get('closed_on') or 'Not available'}, "
                  f"which covered the same {_join([dfg(m['value']) for m in rel[0]['matches']], 5)}"
                  + (f" ({dtext(c['closure_note'][:250])})" if c.get("closure_note") else "") + ".")
            seen = {m["value"].lower() for m in rel[0]["matches"]}
            new = [v for k, v in ev.all_entities() if v.lower() not in seen and k in ("account", "host", "ip", "domain")]
            p4 += (f" What differs this time: {_join([dfg(v) for v in new], 5)}." if new else
                   " The entities and pattern match that closure.")
    others = [t for t in an["tickets"] if t["matches"] and t is not an.get("target")]
    if others:
        o = others[0]["rec"]
        p4 += (f" {o.get('case_number')} covered similar activity but was not relied on, because "
               + ("its close notes do not record a remediation that settles this finding." if o.get("close_notes")
                  else "it records no remediation for these entities."))
    p5 = ""
    for p in an["related_pentests"]:
        if p["instruction"] == "unannounced":
            continue
        n = p["note"]
        p5 += (f"The client's penetration test \"{dtext(n['title'])}\" ({_window(n)}) is related: we matched "
               f"{_join(p['matched'])}, and the activity falls {p['window_text']} the test window. ")
        if p["covered"] and p["instruction"] == "ignore":
            p5 += "The client asked the SOC to ignore alerts related to this test, and that instruction is the reason for closing. "
        elif not p["covered"]:
            p5 += "It does not explain all of the activity: " + "; ".join(p["gaps"]) + ". "
    paras = [p2, p3] + [x for x in (p4.strip(), p5.strip()) if x]
    L = [f"Closing as non-threatening. Our analysis shows that {p1}", ""]
    for p in paras:
        L += [p, ""]
    L += ["## Artifacts", ""]
    if intel:
        L += osint_bullets(intel)
    else:
        L.append("- OSINT: Not available")
    for k in ("account", "host", "file", "hash", "process"):
        for v in ev.entities.get(k, [])[:10]:
            if k == "hash" and any(i["value"].lower() == v.lower() for i in intel):
                continue
            L.append(f"- **{TYPE_LABEL[k]}:** {dfg(v)}")
    rel = [c for c in an["closures"] if c["matches"]]
    if rel and reason != "already remediated":
        c = rel[0]["rec"]
        L.append(f"- **Related Closures:** {c.get('finding_id') or 'past finding'} closed by {c.get('closed_by') or 'Not available'} "
                 f"on {c.get('closed_on') or 'Not available'}")
    if reason == "already remediated":
        L.append(f"- **Related Tickets:** {an['target']['rec'].get('case_number')}")
    L.append("")
    return "\n".join(L)


# ------------------------------------------------------------------- outcome 3


WEIGHTS = OrderedDict([("id", 15), ("device", 20), ("timeline", 20), ("ioc", 15), ("impact", 20), ("telemetry", 10)])


def completeness(case: Dict[str, Any], an: Dict[str, Any]) -> Tuple[int, Dict[str, str]]:
    ev, intel = an["ev"], an["intel"]
    score: Dict[str, Optional[float]] = {}
    na: Dict[str, str] = {}
    cats = {f.get("category") for f in ev.findings}
    acc = bool(ev.entities.get("account"))
    if acc and ("auth" in cats or any(r.get("user") for r in ev.rows)):
        score["id"] = 1.0
    elif acc or "auth" in cats:
        score["id"] = 0.5
    elif cats and cats <= {"network"} and not acc:
        score["id"] = None
        na["id"] = "the activity is network traffic with no account attached to it"
    else:
        score["id"] = 0.0
    dev = 0.0
    if ev.entities.get("host"):
        dev += 0.4
    if ev.entities.get("ip"):
        dev += 0.3
    if cats & {"process", "malware"} or any(a.get("kind") in ("process", "command_line") for a in ev.artifacts) \
            or case.get("assets_matched"):
        dev += 0.3
    score["device"] = min(dev, 1.0)
    tl = 0.0
    if ev.first and ev.last:
        tl += 0.5
    if len(ev.times) >= 3 or ev.events:
        tl += 0.5
    score["timeline"] = tl
    if not ev.observables:
        score["ioc"] = 0.0
    else:
        done = sum(1 for o in ev.observables if o.get("enriched_at"))
        score["ioc"] = 1.0 if done == len(ev.observables) else (0.5 if done else 0.0)
    imp = 0.0
    if ev.actions:
        imp += 0.4
    if ev.techniques:
        imp += 0.3
    if any(i["outcome"] != "absent" for i in intel) or any(r.get("action") for r in ev.rows):
        imp += 0.3
    score["impact"] = min(imp, 1.0)
    prods = ev.products()
    score["telemetry"] = 1.0 if len(prods) >= 2 else (0.5 if prods else 0.0)
    total_w = sum(w for k, w in WEIGHTS.items() if score.get(k) is not None)
    got = sum(w * score[k] for k, w in WEIGHTS.items() if score.get(k) is not None)
    return (round(100 * got / total_w) if total_w else 0), na


def missing_work(case: Dict[str, Any], an: Dict[str, Any], pct: int, na: Dict[str, str]) -> List[str]:
    ev, intel = an["ev"], an["intel"]
    out: List[str] = []
    if not case.get("alert_url"):
        out.append("**No alert link provided.**")
    items: List[str] = []
    siem = f"{case.get('siem') or ''} {' '.join(ev.products())} {case.get('alert_name') or ''}"
    if MICROSOFT.search(siem):
        acted = [a.get("text") for a in ev.actions if not _INVESTIGATION.search(a.get("text") or "")]
        auto = [r for r in ev.rows if _CONTAIN.search(str(r.get("action") or ""))]
        if acted or auto:
            items.append("**Response Action Check:** the evidence shows containment ("
                         + _join([dtext(a) for a in acted][:3] + ([f"{len(auto)} event(s) blocked by the product"] if auto else []))
                         + "). Confirm the customer is MXDR and that we are authorized, and if so confirm nothing further is "
                           "pending; otherwise route the remaining actions to the customer.")
        else:
            items.append("**Response Action Check:** no response or containment action appears in the evidence. Confirm whether "
                         "the customer is MXDR and we are authorized to act: if so, take the containment the evidence supports "
                         "(for example isolating the device or revoking sessions); otherwise route it to the customer.")
    if an["tickets"] or an["closures"]:
        rel = [t for t in an["tickets"] if t["matches"]]
        rc = [c for c in an["closures"] if c["matches"]]
        bits = []
        if rel:
            bits.append(_join([f"{t['rec'].get('case_number')} ({t['rec'].get('status') or 'status Not available'})" for t in rel], 4)
                        + " share entities with this finding")
        if rc:
            bits.append(f"{len(rc)} past closure(s) cover the same entities")
        if not bits:
            bits.append(f"{len(an['tickets'])} past ticket(s) and {len(an['closures'])} closure(s) for this alert share no entities")
        unresolved = [t for t in rel if t["open"]] + [t for t in an["not_remediated"]]
        items.append("**Previous Incident/Ticket Check:** " + "; ".join(bits) + "."
                     + (" Unresolved risk remains in " + _join([t['rec'].get('case_number') for t in unresolved], 4) + "."
                        if unresolved else ""))
    else:
        items.append("**Previous Incident/Ticket Check:** earlier tickets and closures for the same alert, accounts and hosts "
                     "still need to be checked.")
    gaps: List[str] = []
    pending = [o for o in ev.observables if not o.get("enriched_at")]
    if pending:
        gaps.append(f"**Enrichment:** {_plural(len(pending), 'observable')} {'has' if len(pending) == 1 else 'have'} not been "
                    f"enriched ({_join([dfg(o['value']) for o in pending], 4)}).")
    if not ev.observables:
        gaps.append("**IOC extraction:** no observables were extracted from the alert or logs for OSINT enrichment.")
    if an["signs"] or an["flagged_done"]:
        if not ev.actions:
            gaps.append("**Containment status:** confirm whether the affected accounts and hosts have been contained.")
    cats = {f.get("category") for f in ev.findings}
    if an["signs"] and ev.entities.get("account") and ev.last:
        gaps.append("**Post-compromise activity:** review what " + _join([dfg(a) for a in ev.entities["account"]], 3)
                    + f" did after {ev.last} (audit, mailbox, file access and MFA changes).")
    if ev.entities.get("account") and "auth" not in cats:
        gaps.append("**Sign-in logs:** review the sign-in history of " + _join([dfg(a) for a in ev.entities["account"]], 3)
                    + " around the activity for successful or unusual sign-ins.")
    if ev.entities.get("host") and not cats & {"process", "malware"}:
        gaps.append("**Endpoint telemetry:** review process and file activity on " + _join([dfg(h) for h in ev.entities["host"]], 3)
                    + " for execution, persistence or lateral movement.")
    if not ev.first:
        gaps.append("**Timeline:** the evidence has no timestamps; build the timeline of the activity from the raw logs.")
    elif len(ev.times) < 3 and not ev.events:
        gaps.append("**Timeline:** only the first and last event times are in the case; pin the key events in order.")
    for it in intel:
        if it["outcome"] == "absent":
            gaps.append(f"**Log correlation:** {dfg(it['value'])} is enriched but not found in the logs; confirm where it was observed.")
            break
    for it in intel:
        if it["verdict"] in ("malicious", "suspicious") and it["outcome"] in ("observed",):
            gaps.append(f"**Outcome:** the logs do not record whether activity with {dfg(it['value'])} succeeded; check firewall, "
                        "proxy or EDR records for the result.")
            break
    if len(ev.products()) < 2:
        gaps.append("**Telemetry coverage:** only " + (ev.products()[0] if ev.products() else "no") + " log source was reviewed; "
                    "correlate with a second source (firewall, proxy, EDR or identity logs).")
    for k, why in na.items():
        out_label = {"id": "Identity/authentication"}.get(k, k)
        gaps.append(f"**{out_label}:** N/A, {why}.")
    if pct < 80:
        items += gaps
        items = items[:5]
    else:
        items = [i for i in items if not i.startswith("**Previous Incident/Ticket Check:** earlier")] + \
            [g for g in gaps if g.startswith(("**Enrichment", "**Containment", "**Outcome"))]
    if not items:
        out.append("None")
    else:
        out += [f"{i}. {x}" for i, x in enumerate(items, 1)]
    return out


def _priority(an: Dict[str, Any], case: Dict[str, Any]) -> Tuple[str, str]:
    ev, v = an["ev"], an["verdict"]["key"]
    priv = [a for a in ev.entities.get("account", []) if _PRIV.search(a)]
    servers = [h for h in ev.entities.get("host", []) if _SERVER.search(h)]
    crit_assets = case.get("critical_assets") or []
    tac = ev.tactics()
    reasons = []
    if "Impact" in tac or (v == "tp_malicious" and an["signs"] and (priv or servers or crit_assets)):
        level = "Critical"
    elif v == "tp_malicious":
        level = "High"
    elif v == "inconclusive" and (an["flagged_done"] or [i for i in an["intel"] if i["verdict"] == "malicious"]):
        level = "Medium"
    elif v == "inconclusive":
        level = "Medium" if ev.findings and any(f.get("severity") in ("high", "critical") for f in ev.findings) else "Low"
    else:
        level = "Low"
    if (priv or servers or crit_assets) and level in ("Medium", "Low") and v != "false_positive":
        level = {"Low": "Medium", "Medium": "High"}[level]
        reasons.append("elevated for " + _join([f"privileged account {dfg(a)}" for a in priv[:2]] +
                                               [f"server {dfg(s)}" for s in servers[:2]] +
                                               [f"high-value asset {dfg(s)}" for s in crit_assets[:2]]))
    families = sorted({f for i in an["intel"] for f in i["families"]})
    techs = sorted(ev.technique_ids())
    basis = [f"verdict {VERDICTS[v]}"]
    if an["signs"]:
        basis.append("signs of compromise: " + "; ".join(an["signs"][:3]))
    if families:
        basis.append("associated malware " + _join(families, 3))
    if techs:
        basis.append(_plural(len(techs), "mapped ATT&CK technique") + f" ({_join(techs, 5)})")
    return level, "; ".join(basis + reasons) + "."


def _exec_summary(case: Dict[str, Any], an: Dict[str, Any], scope_confirm: Optional[Dict[str, Any]]) -> str:
    ev, v = an["ev"], an["verdict"]["key"]
    who = _who(ev, 3)
    s1 = f"We are raising this incident regarding {who} following confirmed {_activity_phrase(ev)}."
    if scope_confirm:
        n = scope_confirm["note"]
        s2 = (f"The activity originated from {_join([dfg(i) for i in scope_confirm['tester_hits']], 3)}, which is listed for your "
              f"penetration test {dtext(n['title'])}; please confirm whether it is within the scope of that test, and treat it "
              "as unauthorized if it is not.")
    elif v == "tp_malicious":
        action = "containing the affected accounts and hosts" if an["signs"] else "blocking the flagged indicators"
        if an["signs"] and ev.entities.get("account"):
            action = "resetting the affected credentials and revoking active sessions"
        elif an["signs"] and ev.entities.get("host"):
            action = "isolating the affected host"
        s2 = f"The activity is assessed as malicious, and we recommend {action} as soon as possible."
    elif v == "false_positive":
        s2 = ("Our review found no indicators of malicious activity; no action is required, but please let us know if this "
              "differs from your expectations.")
    elif v == "tp_benign":
        unannounced = any(p["instruction"] == "unannounced" for p in an["related_pentests"])
        if not unannounced and case.get("verdict") not in ("benign", "tp_benign"):
            s2 = ("The activity appears consistent with expected administrative or testing activity, with no indicators of "
                  "malicious activity identified; however, please confirm whether it was authorized and expected.")
        else:
            s2 = ("Our review found no indicators of malicious activity; no action is required, but please let us know if this "
                  "differs from your expectations.")
    else:
        leaning_benign = not an["flagged_done"] and not an["signs"] and not [i for i in an["intel"] if i["verdict"] == "malicious"]
        if leaning_benign:
            s2 = ("The activity appears consistent with legitimate use, with no indicators of malicious activity identified; "
                  "however, please confirm whether it was authorized and expected.")
        else:
            s2 = ("Confirming legitimacy requires business context only your team holds; we recommend validating the activity "
                  "with the account owner to confirm authorization.")
    return f"{s1} {s2}"


def _recommendations(case: Dict[str, Any], an: Dict[str, Any], scope_confirm: Optional[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    ev, v = an["ev"], an["verdict"]["key"]
    imm: List[str] = []
    lt: List[str] = []
    if scope_confirm:
        n = scope_confirm["note"]
        hosts = ev.entities.get("host", [])
        imm.append(f"Confirm that the activity from {_join([dfg(i) for i in scope_confirm['tester_hits']], 3)}"
                   + (f" against {_join([dfg(h) for h in hosts], 3)}" if hosts else "")
                   + (f" between {ev.first} and {ev.last}" if ev.first and ev.last else "")
                   + f" is within the scope of the penetration test {dtext(n['title'])} ({_window(n)}).")
        imm.append(f"If it is not in scope, block {_join([dfg(i) for i in scope_confirm['tester_hits']], 3)} at the perimeter and "
                   "treat the activity as unauthorized.")
    compromise = bool(an["signs"]) or v == "tp_malicious" and bool(an["flagged_done"])
    bad_net = [i for i in an["intel"] if i["verdict"] == "malicious" and i["type"] in ("ipv4", "ipv6", "domain", "url")]
    bad_files = [i for i in an["intel"] if i["verdict"] == "malicious" and i["type"] in ("md5", "sha1", "sha256")]
    if not scope_confirm and v in ("tp_malicious", "inconclusive"):
        if bad_net:
            imm.append(f"Block {_join([dfg(i['value']) for i in bad_net], 5)} at the firewall, proxy and DNS layer.")
        cats = {f.get("category") for f in ev.findings}
        hosts = ev.entities.get("host", [])
        if hosts and (cats & {"malware", "process"} or bad_files) and v == "tp_malicious":
            imm.append(f"Isolate {_join([dfg(h) for h in hosts], 3)} and remove the malicious files"
                       + (f" ({_join([dfg(i['value']) for i in bad_files], 3)})" if bad_files else "") + ".")
        accs = ev.entities.get("account", [])
        if compromise and accs:
            imm.append(f"Reset the password of {_join([dfg(a) for a in accs], 3)}, revoke active sessions and refresh tokens, "
                       "and re-register MFA.")
    if not imm:
        imm = []
    if any(_VPN.search(" ".join(i["tags"] + [r.get("summary") or "" for r in i["feeds"]])) for i in an["intel"]
           if i["type"] in ("ipv4", "ipv6")):
        lt.append("Confirm whether VPN or anonymizing proxy use is allowed in your environment, and restrict sign-ins from "
                  "such services if it is not.")
    recurring = [t for t in an["tickets"] if t["matches"]] + [c for c in an["closures"] if c["matches"]]
    if len(recurring) >= 2:
        lt.append("This activity keeps recurring in past tickets; address the root cause, or tune the detection for the "
                  "known-good entities involved.")
    if v in ("tp_benign", "false_positive") or (v == "inconclusive" and not an["signs"]):
        lt.append("Validate the activity with the account or system owner and document it as expected if it is authorized.")
    accs = ev.entities.get("account", [])
    if any(f.get("category") == "auth" for f in ev.findings):
        lt.append(f"Review the sign-in policy for {_join([dfg(a) for a in accs], 3) or 'the affected accounts'}: enforce MFA "
                  "and block legacy authentication.")
    if v == "tp_malicious" and ev.entities.get("account"):
        lt.append("Review the affected accounts' recent activity (mailbox rules, MFA registrations, OAuth consents and file "
                  "access) for changes made after the suspicious activity.")
    lt.append("Continue to monitor the accounts, hosts and indicators in this report for renewed activity.")
    total = imm + lt
    if len(total) > 5:
        keep_lt = max(1, 5 - len(imm))
        imm, lt = imm[:4], lt[:keep_lt]
    return imm, lt


def _analysis_paragraphs(case: Dict[str, Any], an: Dict[str, Any], hide_pentest: bool) -> List[str]:
    ev = an["ev"]
    paras = []
    alert = case.get("alert_name")
    opening = []
    if alert:
        opening.append(f"The alert {dtext(alert)}" + (f" was created at {case['alert_created']}" if case.get("alert_created") else "")
                       + f" for {_who(ev)}.")
    lines = _event_lines(ev, 8)
    if lines:
        opening.append(("We reviewed the alert's raw logs from the earliest relevant event. " if alert else
                        "We reviewed the uploaded logs from the earliest relevant event. ") + " ".join(lines))
    if opening:
        paras.append(" ".join(opening))
    for f in ev.findings[:5]:
        s = f"{dtext(f.get('description') or f.get('title'))}"
        if f.get("interpretation"):
            s += f" {dtext(f['interpretation'])}"
        dec = (f.get("extra") or {}).get("decoded")
        if dec:
            s += f" The decoded command reads {dfg(' '.join(dec)[:300])}."
        paras.append(s)
    intel_bits = []
    for it in an["intel"][:8]:
        intel_bits.append(osint_sentence(it)[0].upper() + osint_sentence(it)[1:] + " " + outcome_sentence(it))
    if intel_bits:
        paras.append("Our review of the OSINT enrichment: " + " ".join(intel_bits))
    techs = [t for t in ev.techniques][:8]
    if techs:
        paras.append("The behaviour maps to MITRE ATT&CK " + _join([f"{t.get('technique_id')} {t.get('name')}"
                                                                      + (f" ({dtext((t.get('basis') or [''])[0])})" if t.get('basis') else "")
                                                                      for t in techs], 8) + ".")
    para = absence_sentence(an["signs"])
    if ev.observables and not an["flagged_done"]:
        para += " We observed no completed connection or execution involving a flagged observable."
    paras.append(para)
    if an["already_in"]:
        t = an["already_in"][0]["rec"]
        paras.append(f"This finding is already part of the open ticket {t.get('case_number')}.")
    for t in an["not_remediated"]:
        rem = t["remediation"]
        paras.append(f"{rem['case_number']} recorded a remediation ({_join(rem['done'])}) for "
                     f"{_join([dfg(m['value']) for m in rem['covered']], 4)}, but it does not settle this finding: {rem['reason']}.")
    paras.append(_past_paragraph(an))
    if not hide_pentest:
        for p in an["related_pentests"]:
            if p["instruction"] == "unannounced":
                continue
            n = p["note"]
            s = (f"The client's penetration test {dtext(n['title'])} ({_window(n)}) is related to this activity: we matched "
                 f"{_join(p['matched'])}, and the activity falls {p['window_text']} the test window.")
            if p["covered"] and p["instruction"] == "raise_and_confirm":
                s += " The activity needs to be confirmed as part of the test's scope."
            elif not p["covered"]:
                s += " The test does not account for all of it: " + "; ".join(p["gaps"]) + "."
            paras.append(s)
    return paras


def _actions_taken(an: Dict[str, Any]) -> List[str]:
    ev = an["ev"]
    out = []
    for a in ev.actions:
        txt = a.get("text") or ""
        if _INVESTIGATION.search(txt) and not re.search(r"\b(block|isolat|disabl|reset|revok|quarantin|remov)\w*", txt, re.I):
            continue
        out.append(f"- {a.get('done_at') or ''} {dtext(txt)}".replace("-  ", "- "))
    auto = [r for r in ev.rows if _CONTAIN.search(str(r.get("action") or ""))]
    if auto:
        prods = _join(sorted({r.get("product") for r in auto if r.get("product")}))
        times = sorted(r.get("time") for r in auto if r.get("time"))
        out.append(f"- {prods or 'The security product'} automatically blocked {_plural(len(auto), 'event')}"
                   + (f" between {times[0]} and {times[-1]}" if len(times) > 1 else (f" at {times[0]}" if times else "")) + ".")
    return out


def render_incident(case: Dict[str, Any], an: Dict[str, Any]) -> str:
    ev, ver = an["ev"], an["verdict"]
    unannounced = [p for p in an["related_pentests"] if p["instruction"] == "unannounced"]
    scope = next((p for p in an["related_pentests"] if p["covered"] and p["instruction"] == "raise_and_confirm"), None)
    L: List[str] = []
    no_finding = an["no_finding"]
    if not no_finding:
        pct, na = completeness(case, an)
        L += ["**ANALYST-ONLY — DO NOT COPY**", "",
              f"**Verdict:** {ver['label']} - **Confidence:** {ver['confidence']}", "",
              f"{dtext(ver['reason'])[0].upper() + dtext(ver['reason'])[1:]}."
              + (f" Missing: {_join(ver['missing'])}." if ver["missing"] else ""), ""]
        L += ["## 1. Investigation Completeness", "", f"{pct}%"]
        if pct < 50:
            L += ["", "**Investigation is incomplete. Reinvestigate the incident, then check and complete the missing investigation work.**"]
        elif pct < 80:
            L += ["", "**Investigation is incomplete. Please check the missing investigation work.**"]
        L += ["", "## 2. Missing Investigation Work", ""] + missing_work(case, an, pct, na) + [""]
        if ver["key"] == "tp_malicious":
            decision, why = "Incident Recommended", "The evidence supports genuine malicious activity that needs remediation."
        elif ver["key"] in ("tp_benign", "false_positive") and ver["confidence"] in ("High", "Medium") and not an["signs"]:
            decision = "Tuning Candidate"
            ents = _join([dfg(v) for v in (ev.entities.get("account", []) + ev.entities.get("host", []))[:3]])
            why = (f"The activity is {'expected' if ver['key'] == 'tp_benign' else 'a detection misfire'} ({dtext(ver['reason'])}), "
                   "so the detection is low-fidelity for it here; excluding "
                   f"{ents or 'the known-good entities'} from the rule would stop it recurring.")
        else:
            decision, why = "Analyst Review Recommended", ("The evidence is incomplete or does not settle whether the activity "
                                                           "is malicious; an analyst should confirm before notifying.")
        if unannounced and ver["key"] != "tp_malicious":
            decision, why = "Incident Recommended", "Covered activity from an unannounced test is handled as a real incident."
        L += ["## 3. Ticket Notification Decision", "", f"**{decision}:** {why}"]
        for p in an["related_pentests"]:
            n = p["note"]
            instr = {"ignore": "ignore alerts related to the test",
                     "raise_and_confirm": "no specific instruction: raise and confirm scope",
                     "unannounced": "unannounced: raise as an incident"}[p["instruction"]]
            L += ["", f"**Pentest note \"{dtext(n['title'])}\":** matched {_join(p['matched'])}; the test "
                      f"{'covers' if p['covered'] else 'does not cover'} the activity"
                      + ("" if p["covered"] else f" ({'; '.join(p['gaps'])})") + f"; client instruction: {instr}."]
            if p["instruction"] == "unannounced":
                L += ["", "**UNANNOUNCED PENTEST — DO NOT INFORM THE CLIENT IT IS A PENTEST.**"]
        level, just = _priority(an, case)
        L += ["", "## 4. Overall Priority Determination", "", f"**{level}:** {just}", "",
              "**END ANALYST-ONLY — CUSTOMER REPORT STARTS BELOW**", ""]
        L += ["## Executive Summary", "", _exec_summary(case, an, scope), ""]
    else:
        L += [f"**Verdict:** {ver['label']} - **Confidence:** {ver['confidence']}", "",
              f"{dtext(ver['reason'])[0].upper() + dtext(ver['reason'])[1:]}.", ""]
    L += ["## Analysis", ""]
    for p in _analysis_paragraphs(case, an, hide_pentest=bool(unannounced)):
        L += [p, ""]
    imm, lt = _recommendations(case, an, None if unannounced else scope)
    L += ["## Recommendation", ""]
    if imm or not no_finding:
        L += ["**Immediate Action Needed**", ""] + ([f"- {x}" for x in imm] or ["- None at this time."]) + [""]
    if lt:
        L += ["**Long-Term Recommendation**", ""] + [f"- {x}" for x in lt] + [""]
    if not no_finding:
        acts = _actions_taken(an)
        L += ["## Action Taken", ""] + (acts or ["**N/A**"]) + [""]
    L += ["## Artifacts", ""]
    if not no_finding:
        L += ["**Incident Details**", "",
              f"- **Alert Name:** {dtext(case.get('alert_name')) or 'Not available'}",
              f"- **Customer:** {case.get('customer') or 'Not available'}",
              f"- **Incident/Threat ID:** {case.get('threat_id') or case.get('finding_id') or 'Not available'}",
              f"- **Creation Time:** {case.get('alert_created') or iso(case.get('created_at')) or 'Not available'}",
              f"- **Alert URL:** {case.get('alert_url') or 'Not available'}", ""]
    groups = [("IPs", "ip"), ("URLs/Domains", "url"), ("Accounts", "account"), ("Devices", "host"),
              ("Files/Hashes", "hash"), ("Processes/Commands", "process"), ("Message IDs", "message")]
    intel_by = {i["value"].lower(): i for i in an["intel"]}
    any_art = False
    for label, k in groups:
        vals = list(ev.entities.get(k, []))
        if k == "url":
            vals += ev.entities.get("domain", []) + ev.entities.get("email", [])
        if k == "hash":
            vals += ev.entities.get("file", [])
        if k == "process":
            vals += ev.entities.get("command", [])
        if not vals:
            continue
        any_art = True
        L += [f"**{label}**", ""]
        for v in vals[:25]:
            it = intel_by.get(v.lower())
            suffix = ""
            if k == "ip":
                nature = _ip_nature(it) if it else ("internal" if is_internal_ip(v) else "not enriched")
                suffix = f" ({nature})"
            L.append(f"- {dfg(v)}{suffix}")
        L.append("")
    if an["intel"]:
        any_art = True
        L += ["**OSINT/Threat Intel**", ""] + osint_bullets(an["intel"]) + [""]
    rel = [t["rec"].get("case_number") for t in an["tickets"] if t["matches"] and t["rec"].get("case_number")]
    if rel:
        L += ["**Related Tickets**", ""] + [f"- {r}" for r in rel] + [""]
    if not any_art:
        L += ["No artifacts recovered.", ""]
    return "\n".join(L)


# ------------------------------------------------------------------- entry point


OUTCOME_LABEL = {1: "Append to existing incident", 2: "Close as non-threatening", 3: "Raise an incident"}


def write(case: Dict[str, Any], tickets: List[Dict[str, Any]] = (), closures: List[Dict[str, Any]] = (),
          pentest_notes: List[Dict[str, Any]] = (), force: Optional[int] = None) -> Dict[str, Any]:
    """Analyse the case against the related records and write the matching output.

    ``force`` (1, 2 or 3) lets the analyst pick a different outcome than the decision;
    an append without a qualifying ticket falls back to an incident."""
    ev0 = Evidence(case)
    token = _KEEP.set(frozenset(v.lower() for k in ("account", "host") for v in ev0.entities.get(k, [])))
    try:
        return _write(case, list(tickets), list(closures), list(pentest_notes), force)
    finally:
        _KEEP.reset(token)


def _write(case, tickets, closures, pentest_notes, force) -> Dict[str, Any]:
    an = analyse(case, tickets, closures, pentest_notes)
    outcome = an["outcome"]
    note = ""
    if force in (1, 2, 3) and force != outcome:
        if force == 1:
            cands = [t for t in an["tickets"] if t["matches"] and t["open"] and not t["involves"]]
            if cands:
                an["target"] = cands[0]
                outcome = 1
            else:
                note = "No open ticket shares entities with this finding, so it cannot be appended."
        elif force == 2:
            if any(p["covered"] and p["instruction"] == "unannounced" for p in an["related_pentests"]):
                note = "Activity covered by an unannounced pentest is never closed: it is raised as an incident."
            else:
                outcome = 2
                if an["reason"] not in ("already remediated", "pentest the client asked the SOC to ignore"):
                    an["reason"] = "benign or misfire"
        else:
            outcome = 3
    if outcome == 1:
        md = render_append(case, an)
    elif outcome == 2:
        md = render_close(case, an)
    else:
        md = render_incident(case, an)
    md = re.sub(r"\n{3,}", "\n\n", md).strip() + "\n"
    return {
        "markdown": md,
        "outcome": outcome, "outcome_label": OUTCOME_LABEL[outcome], "decided": an["outcome"],
        "reason": an["reason"], "note": note,
        "verdict": {k: an["verdict"][k] for k in ("key", "label", "confidence", "reason")},
        "target": (an["target"]["rec"].get("case_number") if an.get("target") else None),
        "related": {
            "tickets": [{"case_number": t["rec"].get("case_number"), "status": t["rec"].get("status"), "open": t["open"],
                         "matches": t["matches"], "involves": t["involves"], "source": t["rec"].get("source"),
                         "case_id": t["rec"].get("case_id"),
                         "remediation": ({k: t["remediation"][k] for k in ("done", "can_close", "reason")}
                                         if t["remediation"] else None)} for t in an["tickets"]],
            "closures": [{"finding_id": c["rec"].get("finding_id"), "closed_by": c["rec"].get("closed_by"),
                          "closed_on": c["rec"].get("closed_on"), "matches": c["matches"], "source": c["rec"].get("source"),
                          "case_id": c["rec"].get("case_id")} for c in an["closures"]],
            "pentests": [{"title": p["note"]["title"], "related": p["related"], "covered": p["covered"],
                          "matched": p["matched"], "instruction": p["instruction"], "gaps": p["gaps"],
                          "id": p["note"].get("id"), "source": p["note"].get("source")} for p in an["pentests"]],
        },
        "signs": an["signs"],
    }
