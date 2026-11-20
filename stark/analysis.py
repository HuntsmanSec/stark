"""Security finding analysis.

Runs detectors over arranged log rows (see :mod:`stark.logarranger`) and returns
*findings*: explained, evidence-backed observations with a severity, a confidence
level, MITRE ATT&CK mapping and a recommendation.

Detector families
-----------------
* ``auth``     authentication anomalies: brute force / password spraying, success after
               failures, MFA failures and fatigue, unusual or multiple countries, impossible
               travel, new / unusual devices and user agents, legacy authentication, external
               logons to privileged accounts
* ``process``  process and command-line activity: PowerShell abuse (encoded commands are
               decoded), mshta, rundll32, regsvr32, certutil, bitsadmin, wmic, msiexec, and other
               LOLBins, Office spawning shells, credential dumping, recovery inhibition, log clearing
* ``malware``  malware and file findings: hacking tools, double extensions, executables in
               user-writable paths, masquerading system binaries, file hashes worth checking
* ``network``  network and C2: beaconing, suspicious ports, direct-to-IP downloads, DGA-like and
               typosquatted domains (homoglyphs, edit distance, brand impersonation, punycode),
               DNS tunnelling, abused TLDs

Everything here is a heuristic. Findings say *why* they fired and how confident the rule is,
and the analyst decides.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .mitre import technique

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CATEGORIES = {
    "auth": "Authentication anomaly",
    "process": "Process & command-line activity",
    "malware": "Malware & file finding",
    "network": "Network & C2 communication",
}

Row = Dict[str, Any]


def _ts(r: Row) -> Optional[float]:
    t = r.get("time")
    if not t:
        return None
    try:
        return datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _text(r: Row, *fields: str) -> str:
    fields = fields or ("event", "process", "parent_process", "command_line", "message", "action", "url", "app")
    return " ".join(str(r.get(f) or "") for f in fields)


class Finding(dict):
    """A dict with a stable key so the same finding is not duplicated in a case."""


def make(key: str, category: str, title: str, severity: str, confidence: str, description: str,
         interpretation: str, recommendation: str, rows: Sequence[Row] = (), mitre: Sequence[str] = (),
         entities: Optional[Dict[str, List[str]]] = None, extra: Optional[Dict[str, Any]] = None) -> Finding:
    rows = list(rows)
    times = sorted(r["time"] for r in rows if r.get("time"))
    ent = {k: sorted({str(v) for v in vals if v})[:20] for k, vals in (entities or {}).items()}
    if not ent:
        ent = {"hosts": sorted({r["host"] for r in rows if r.get("host")})[:20],
               "users": sorted({r["user"] for r in rows if r.get("user")})[:20]}
    f = Finding(
        key=key, category=category, category_label=CATEGORIES[category], title=title, severity=severity,
        confidence=confidence, description=description, interpretation=interpretation,
        recommendation=recommendation,
        mitre=[technique(t) for t in mitre],
        entities={k: v for k, v in ent.items() if v},
        evidence_ids=[r["id"] for r in rows if "id" in r][:500],
        evidence=[_evidence_line(r) for r in rows[:8]],
        count=len(rows), first=times[0] if times else None, last=times[-1] if times else None,
    )
    if extra:
        f.update(extra)
    return f


def _evidence_line(r: Row) -> Dict[str, str]:
    detail = r.get("command_line") or r.get("url") or r.get("domain") or r.get("message") or ""
    flow = ""
    if r.get("src_ip") or r.get("dst_ip"):
        flow = f"{r.get('src_ip') or '?'}{':' + str(r['src_port']) if r.get('src_port') else ''} -> " \
               f"{r.get('dst_ip') or '?'}{':' + str(r['dst_port']) if r.get('dst_port') else ''}"
    return {"time": r.get("time") or "", "product": r.get("product") or "", "event": str(r.get("event") or "")[:120],
            "host": r.get("host") or "", "user": r.get("user") or "", "flow": flow, "detail": str(detail)[:400]}


# =========================================================================== auth

_FAIL = re.compile(r"\b(fail(ed|ure)?|invalid|denied|bad password|wrong password|unsuccessful|rejected|locked|"
                   r"4625|4771|4776|50126|50053|50055|50057|530032)\b|logon failure|authentication failure", re.I)
_SUCCESS = re.compile(r"\b(4624|success(ful)?|accepted|logged on|login ok|sign-?in succeeded)\b", re.I)
_AUTH = re.compile(r"\b(logon|log-on|login|log in|sign-?in|signin|authenticat\w*|4624|4625|4648|4768|4769|4771|4776|"
                   r"sshd|kerberos|ntlm|mfa|vpn|okta|duo|consolelogin|interactive|password)\b", re.I)
_MFA_FAIL = re.compile(r"\b(500121|50074|50076|50158|mfa (denied|fail\w*|rejected|timeout)|push (denied|rejected)|"
                       r"user (denied|rejected) (the )?(mfa|push)|fraud|strong authentication|multi-?factor\s+(denied|fail\w*))\b", re.I)
_LEGACY = re.compile(r"\b(imap4?|pop3?|smtp auth|authenticated smtp|exchange activesync|other clients|"
                     r"basic auth|legacy|bav2ropc|exchange web services)\b", re.I)
_ODD_UA = re.compile(r"\b(curl|wget|python-requests|python-urllib|go-http-client|okhttp|powershell|winhttp|"
                     r"libwww|java/|axios|node-fetch|httpie|bav2ropc|masscan|zgrab|hydra|sqlmap)\b", re.I)
_PRIV = re.compile(r"(^|[\\\\/@])(administrator|admin|root|domain admins?|svc_|sa$|krbtgt|backup)|adm(in)?[-_.]", re.I)


def _is_auth(r: Row) -> bool:
    if r.get("product") == "Microsoft Sentinel" and ("signin" in str(r.get("event", "")).lower()):
        return True
    return bool(_AUTH.search(_text(r, "event", "message", "action", "logon_type", "app")))


def _auth_outcome(r: Row) -> Optional[str]:
    action = str(r.get("action") or "").strip()
    # Entra ID / Sentinel sign-ins expose a numeric ResultType: 0 == success
    if action.isdigit():
        return "success" if action == "0" else "failure"
    text = _text(r, "event", "action", "message")
    if _FAIL.search(text):
        return "failure"
    if _SUCCESS.search(text):
        return "success"
    return None


def detect_auth(rows: List[Row]) -> List[Finding]:
    out: List[Finding] = []
    auth = [r for r in rows if _is_auth(r)]
    if not auth:
        return out
    mfa_rows = {id(r) for r in auth if _MFA_FAIL.search(_text(r, "event", "action", "message", "logon_type"))}
    # MFA denials mean the password was right; they are handled separately, not as password failures.
    fails = [r for r in auth if _auth_outcome(r) == "failure" and id(r) not in mfa_rows]
    succ = [r for r in auth if _auth_outcome(r) == "success"]

    # --- brute force per account / password spraying per source
    by_user: Dict[str, List[Row]] = defaultdict(list)
    by_src: Dict[str, List[Row]] = defaultdict(list)
    for r in fails:
        if r.get("user"):
            by_user[r["user"].lower()].append(r)
        if r.get("src_ip"):
            by_src[r["src_ip"]].append(r)
    for user, fr in by_user.items():
        if len(fr) >= 5:
            later = [s for s in succ if (s.get("user") or "").lower() == user and (_ts(s) or 0) >= (_ts(fr[0]) or 0)]
            srcs = sorted({r.get("src_ip") for r in fr if r.get("src_ip")})
            if later:
                out.append(make(
                    f"auth:bruteforce-success:{user}", "auth", f"Successful login after {len(fr)} failures for {fr[0]['user']}",
                    "high", "high" if len(fr) >= 10 else "medium",
                    f"{len(fr)} failed authentications for this account were followed by a successful login"
                    + (f" (sources: {', '.join(srcs[:5])})." if srcs else "."),
                    "A run of failures followed by a success is the classic sign of a guessed or sprayed password, "
                    "or a credential-stuffing hit. Treat the account as compromised until proven otherwise.",
                    "Reset the password, revoke sessions and tokens, check MFA registrations and review what the "
                    "account did after the successful login.",
                    fr + later[:3], ["T1110", "T1078"], {"users": [fr[0]["user"]], "ips": srcs}))
            else:
                out.append(make(
                    f"auth:bruteforce:{user}", "auth", f"{len(fr)} failed logins for {fr[0]['user']}",
                    "medium", "medium",
                    "Repeated authentication failures against one account" + (f" from {', '.join(srcs[:5])}." if srcs else "."),
                    "Likely a brute-force attempt or a misconfigured service with a stale password. No successful "
                    "login followed in these logs.",
                    "Confirm with the user or service owner, block the source if it is external, and check lockout policy.",
                    fr, ["T1110"], {"users": [fr[0]["user"]], "ips": srcs}))
    for src, fr in by_src.items():
        users = {(r.get("user") or "").lower() for r in fr if r.get("user")}
        if len(users) >= 5:
            out.append(make(
                f"auth:spray:{src}", "auth", f"Password spraying from {src} against {len(users)} accounts",
                "high", "high" if len(users) >= 10 else "medium",
                f"One source failed to authenticate as {len(users)} different accounts ({len(fr)} attempts).",
                "Many accounts with few attempts each from a single source is password spraying. It is designed to "
                "stay under lockout thresholds.",
                "Block the source, check whether any of the targeted accounts later logged in successfully, and enforce "
                "MFA and conditional access.",
                fr, ["T1110.003"], {"ips": [src], "users": sorted(users)}))

    # --- MFA failures / fatigue
    mfa = [r for r in auth if _MFA_FAIL.search(_text(r, "event", "action", "message", "logon_type"))]
    by_user_mfa: Dict[str, List[Row]] = defaultdict(list)
    for r in mfa:
        by_user_mfa[(r.get("user") or "?").lower()].append(r)
    for user, mr in by_user_mfa.items():
        fatigue = len(mr) >= 3
        out.append(make(
            f"auth:mfa:{user}", "auth",
            (f"Possible MFA fatigue: {len(mr)} MFA prompts failed or denied for {mr[0].get('user') or 'an account'}"
             if fatigue else f"MFA failure for {mr[0].get('user') or 'an account'}"),
            "high" if fatigue else "medium", "medium",
            f"{len(mr)} MFA challenge(s) were denied, failed or timed out.",
            ("Repeated MFA prompts mean someone already has the password and is trying to wear the user down "
             "(push bombing)." if fatigue else
             "An MFA failure after a correct password means the first factor may already be known to someone else."),
            "Contact the user out-of-band, reset the password, and enable number matching / phishing-resistant MFA.",
            mr, ["T1621"] if fatigue else ["T1078"], {"users": [mr[0].get("user") or ""]}))

    # --- locations, impossible travel, devices, user agents (successful logins)
    by_u: Dict[str, List[Row]] = defaultdict(list)
    for r in succ:
        if r.get("user"):
            by_u[r["user"].lower()].append(r)
    for user, sr in by_u.items():
        countries = [r for r in sr if r.get("country")]
        cset = Counter(r["country"] for r in countries)
        name = sr[0]["user"]
        if len(cset) >= 2:
            # impossible travel: different countries within 2 hours
            ordered = sorted((r for r in countries if _ts(r)), key=lambda r: _ts(r))
            travel = None
            for a, b in zip(ordered, ordered[1:]):
                if a["country"] != b["country"] and (_ts(b) - _ts(a)) <= 7200:
                    travel = (a, b)
                    break
            if travel:
                a, b = travel
                mins = int((_ts(b) - _ts(a)) / 60)
                out.append(make(
                    f"auth:travel:{user}", "auth", f"Impossible travel for {name}: {a['country']} → {b['country']} in {mins} min",
                    "high", "medium",
                    f"Successful logins from {a['country']} ({a.get('src_ip') or '?'}) and {b['country']} "
                    f"({b.get('src_ip') or '?'}) {mins} minutes apart.",
                    "No one can physically travel that fast. Either the account is in use by someone else, or one "
                    "login came through a VPN/proxy. Check whether either IP is a known corporate egress or VPN.",
                    "Verify with the user. If they don't recognise a location, reset credentials, revoke sessions and review mailbox rules.",
                    [a, b], ["T1078"], {"users": [name], "ips": [a.get("src_ip"), b.get("src_ip")]},
                    {"countries": sorted(cset)}))
            else:
                rare = [c for c, n in cset.items() if n == min(cset.values())]
                out.append(make(
                    f"auth:countries:{user}", "auth", f"{name} signed in from {len(cset)} countries ({', '.join(sorted(cset))})",
                    "medium", "low",
                    f"Successful logins for one account came from several countries. Least common: {', '.join(rare)}.",
                    "This can be travel or VPN use, or account takeover. The least common location deserves a closer look.",
                    "Confirm the user's travel and VPN usage. Compare the IPs with corporate egress ranges.",
                    [r for r in countries if r["country"] in rare] or countries, ["T1078"], {"users": [name]},
                    {"countries": sorted(cset)}))
        devices = Counter(r.get("device") or r.get("user_agent") for r in sr if r.get("device") or r.get("user_agent"))
        if len(devices) >= 3:
            rare = [d for d, n in devices.items() if n == 1]
            out.append(make(
                f"auth:devices:{user}", "auth", f"{name} used {len(devices)} different devices / clients",
                "low", "low",
                f"Distinct devices or user agents for this account: {', '.join(list(devices)[:5])}.",
                "Users normally have one or two devices. Single-use devices can mean an attacker's machine or a "
                "token being replayed.",
                "Review the one-off devices and their source IPs with the user.",
                [r for r in sr if (r.get("device") or r.get("user_agent")) in rare][:20], ["T1078"], {"users": [name]}))

    odd = [r for r in auth if _ODD_UA.search(str(r.get("user_agent") or "")) or _LEGACY.search(_text(r, "logon_type", "app", "user_agent"))]
    if odd:
        users = sorted({r.get("user") for r in odd if r.get("user")})
        out.append(make(
            "auth:legacy-or-scripted", "auth", f"Scripted or legacy-protocol authentication ({len(odd)} event(s))",
            "medium", "medium",
            "Logins used a scripting user agent (curl, python-requests…) or a legacy protocol (IMAP/POP/SMTP auth, "
            "ActiveSync, basic auth).",
            "Legacy protocols skip MFA and are the main target of password spraying. Scripted user agents on "
            "interactive accounts point to automation by someone else.",
            "Block legacy authentication with conditional access and check whether these logins succeeded.",
            odd, ["T1078", "T1110"], {"users": users}))

    priv = [r for r in succ if r.get("user") and _PRIV.search(r["user"]) and r.get("src_ip") and _public(r["src_ip"])]
    if priv:
        out.append(make(
            "auth:priv-external", "auth", f"Privileged account logged in from an external IP ({len(priv)} event(s))",
            "high", "medium",
            "An account that looks administrative logged in successfully from a public IP address.",
            "Admin accounts should normally sign in only from managed internal hosts or a PAW/jump host.",
            "Verify the login. Restrict admin sign-ins to trusted networks and require phishing-resistant MFA.",
            priv, ["T1078", "T1133"]))
    return out


def _public(ip: str) -> bool:
    from .observables import is_public_ip
    return is_public_ip(ip)


# ======================================================================== process

LOLBINS: List[Tuple[str, str, str, str, List[str], str]] = [
    # (key, regex over process+command line, title, severity, mitre, why)
    ("powershell-download", r"(powershell|pwsh).*(downloadstring|downloadfile|invoke-webrequest|\biwr\b|\bwget\b|\bcurl\b|"
     r"net\.webclient|start-bitstransfer|invoke-restmethod|\birm\b)", "PowerShell download cradle", "high",
     ["T1059.001", "T1105"], "PowerShell fetching content from the network is a common first-stage loader pattern."),
    ("powershell-iex", r"(powershell|pwsh).*(\biex\b|invoke-expression|\[scriptblock\]::create)", "PowerShell in-memory execution (IEX)",
     "high", ["T1059.001"], "Invoke-Expression runs code straight from a string or download without touching disk."),
    ("powershell-hidden", r"(powershell|pwsh).*(-w(indowstyle)?\s+h(idden)?|-nop(rofile)?\b.*-ep?\s+bypass|-exec(utionpolicy)?\s+bypass)",
     "PowerShell with hidden window / policy bypass", "medium", ["T1059.001", "T1562.001"],
     "Hiding the window and bypassing execution policy are attempts to avoid the user and controls noticing."),
    ("powershell-amsi", r"amsiutils|amsiinitfailed|amsi\.dll|\[ref\]\.assembly\.gettype|set-mppreference.*disable",
     "AMSI / Defender tampering from PowerShell", "critical", ["T1562.001"],
     "Disabling AMSI or Defender is something only an attacker or a red team needs to do."),
    ("mshta", r"mshta(\.exe)?\s+.*(http|javascript:|vbscript:|\.hta)", "mshta executing remote or inline script", "high",
     ["T1218.005"], "mshta runs HTML applications. With a URL or inline script it is a well-known way to bypass application control."),
    ("rundll32", r"rundll32(\.exe)?\s+.*(javascript:|http|\\\\users\\\\|\\\\temp\\\\|\\\\appdata\\\\|\\\\programdata\\\\|"
     r"comsvcs(\.dll)?.*minidump|url\.dll|shell32\.dll,control_rundll|,\s*#\d+)", "Suspicious rundll32 usage", "high",
     ["T1218.011"], "rundll32 loading DLLs from user-writable paths, remote locations or comsvcs MiniDump is typical of malware and credential theft."),
    ("regsvr32", r"regsvr32(\.exe)?\s+.*(/i:|scrobj|http|\.sct)", "regsvr32 Squiblydoo / remote scriptlet", "high",
     ["T1218.010"], "regsvr32 with /i: and scrobj.dll fetches and runs a remote scriptlet and bypasses application allow-listing."),
    ("certutil", r"certutil(\.exe)?\s+.*(-urlcache|-verifyctl|-decode|-decodehex|-encode)", "certutil used to download or decode files",
     "high", ["T1105", "T1140"], "certutil is a certificate tool. Downloading or decoding files with it is a classic LOLBin abuse."),
    ("bitsadmin", r"bitsadmin(\.exe)?\s+.*(/transfer|/addfile|/setnotifycmdline)", "bitsadmin file transfer", "medium",
     ["T1197", "T1105"], "BITS jobs download files and can persist while staying out of most user-facing tools."),
    ("wmic", r"wmic(\.exe)?\s+.*(process\s+call\s+create|/node:|shadowcopy\s+delete|format:.*http)", "WMIC remote or process execution",
     "high", ["T1047"], "WMIC creating processes, running against remote nodes or deleting shadow copies is often attacker activity."),
    ("msiexec", r"msiexec(\.exe)?\s+.*(/q|/i)\s*.*http", "msiexec installing a package from the internet", "medium",
     ["T1218.007"], "Silent installs straight from a URL are used to drop payloads."),
    ("installutil-etc", r"\b(installutil|regasm|regsvcs|cmstp|odbcconf|msbuild|ieexec|msxsl|forfiles|pcalua|scriptrunner|"
     r"syncappvpublishingserver|control\.exe\s+.*\.cpl)\b", "Signed binary proxy execution (LOLBin)", "medium",
     ["T1218"], "These signed Microsoft binaries can be made to run arbitrary code and are favoured for bypassing application control."),
    ("script-host", r"(wscript|cscript)(\.exe)?\s+.*\.(js|jse|vbs|vbe|wsf)\b", "Windows Script Host running a script", "medium",
     ["T1059.005", "T1059.007"], "JS/VBS scripts run by wscript/cscript are a common phishing payload format."),
    ("lsass-dump", r"(procdump.*lsass|comsvcs(\.dll)?.*minidump|sekurlsa|mimikatz|lsass.*\.dmp|nanodump|pypykatz|"
     r"out-minidump|createdump.*lsass)", "Credential dumping from LSASS", "critical", ["T1003.001"],
     "Dumping LSASS memory gives the attacker every credential cached on the host."),
    ("sam-dump", r"reg(\.exe)?\s+save\s+hklm\\\\(sam|system|security)|ntdsutil.*ifm|ntds\.dit|vssadmin.*create\s+shadow",
     "Registry hive / NTDS credential extraction", "critical", ["T1003.002", "T1003.003"],
     "Copying SAM/SYSTEM hives or NTDS.dit allows offline extraction of password hashes."),
    ("shadow-delete", r"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no|"
     r"wbadmin\s+delete\s+(catalog|systemstatebackup)|delete\s+shadows", "Backups / shadow copies deleted", "critical",
     ["T1490"], "Deleting shadow copies and disabling recovery is a near-certain precursor to ransomware encryption."),
    ("log-clear", r"wevtutil(\.exe)?\s+(cl|clear-log)|clear-eventlog|remove-eventlog|\b1102\b.*audit log", "Event logs cleared",
     "high", ["T1070.001"], "Clearing logs destroys evidence and is rarely legitimate on production systems."),
    ("defender-off", r"set-mppreference.*-disable|disablerealtimemonitoring|sc(\.exe)?\s+(stop|delete|config)\s+(windefend|sense|wdboot)|"
     r"netsh\s+(adv)?firewall.*(off|disable)", "Security tooling disabled", "high", ["T1562.001", "T1562.004"],
     "Attackers disable AV/EDR and firewalls before running their payloads."),
    ("schtasks", r"schtasks(\.exe)?\s+/create.*(/tr\s+.*(powershell|cmd|mshta|rundll32|\\\\appdata\\\\|\\\\temp\\\\|http)|/ru\s+system)",
     "Scheduled task created to run a suspicious command", "high", ["T1053.005"],
     "Scheduled tasks pointing at scripts or user-writable paths are a common persistence mechanism."),
    ("run-key", r"reg(\.exe)?\s+add\s+.*\\\\(currentversion\\\\run|runonce)|set-itemproperty.*currentversion\\\\run",
     "Registry Run key persistence", "high", ["T1547.001"], "Run keys start a program at every logon."),
    ("new-account", r"net(1)?(\.exe)?\s+user\s+\S+\s+\S+\s+/add|net(1)?(\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add",
     "Account created / added to administrators", "high", ["T1136.001", "T1098"],
     "Creating accounts or adding them to Administrators gives the attacker durable access."),
    ("recon-burst", r"\b(whoami\s+/(all|priv|groups)|nltest\s+/(domain_trusts|dclist)|net(1)?\s+group\s+\"?domain admins|"
     r"adfind|sharphound|bloodhound|net(1)?\s+view|quser|systeminfo)\b", "Discovery / reconnaissance commands", "medium",
     ["T1087.002", "T1482", "T1033", "T1018"], "Hands-on-keyboard attackers run these to map users, groups, trusts and hosts."),
    ("remote-tools", r"\b(anydesk|teamviewer|screenconnect|connectwise|atera|splashtop|rustdesk|ngrok|meshagent|"
     r"simplehelp|tacticalrmm|zohoassist|plink|chisel|cloudflared\s+tunnel)\b", "Remote access / tunnelling tool", "medium",
     ["T1219", "T1572"], "Remote admin and tunnelling tools are routinely abused for persistent hands-on access."),
    ("psexec", r"psexe(c|svc)|paexec|\\\\\\\\[\w.-]+\\\\admin\$", "PsExec-style remote execution", "high", ["T1569.002", "T1021.002"],
     "Service-based remote execution over SMB is a staple of lateral movement."),
]
_LOL = [(k, re.compile(rx, re.I), t, s, m, w) for k, rx, t, s, m, w in LOLBINS]
_OFFICE = re.compile(r"\b(winword|excel|powerpnt|outlook|onenote|msaccess|mspub|visio)(\.exe)?\b", re.I)
_SHELL = re.compile(r"\b(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|wmic)(\.exe)?\b", re.I)
_ENC = re.compile(r"(?:^|\s)-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+([A-Za-z0-9+/=]{16,})", re.I)


def decode_powershell(cmd: str) -> Optional[str]:
    """Decode a PowerShell -EncodedCommand (Base64 UTF-16LE) argument, if present."""
    m = _ENC.search(cmd or "")
    if not m:
        return None
    b64 = m.group(1)
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False)
        text = raw.decode("utf-16-le", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(ch.isprintable() for ch in text)
    return text if text and printable / len(text) > 0.9 else None


def detect_process(rows: List[Row]) -> List[Finding]:
    out: List[Finding] = []
    hits: Dict[str, List[Row]] = defaultdict(list)
    decoded: Dict[int, str] = {}
    for r in rows:
        cmd = str(r.get("command_line") or "")
        text = f"{r.get('process') or ''} {cmd} {r.get('message') if not cmd else ''}"
        dec = decode_powershell(cmd) if cmd else None
        if dec:
            decoded[r.get("id", 0)] = dec
            r["decoded_command"] = dec
            text += " " + dec
            hits["encoded"].append(r)
        for key, rx, *_ in _LOL:
            if rx.search(text):
                hits[key].append(r)
        parent = str(r.get("parent_process") or "")
        if parent and _OFFICE.search(parent) and _SHELL.search(f"{r.get('process') or ''} {cmd}"):
            hits["office-child"].append(r)
    meta = {k: (t, s, m, w) for k, _, t, s, m, w in _LOL}
    for key, rs in hits.items():
        if key == "encoded":
            samples = [decoded[r.get("id", 0)][:300] for r in rs[:3]]
            from .observables import extract
            iocs = sorted({o.value for s in decoded.values() for o in extract(s, include_private=True)})
            out.append(make(
                "process:ps-encoded", "process", f"Encoded PowerShell command ({len(rs)} event(s)), decoded",
                "high", "high",
                "PowerShell was started with -EncodedCommand. Decoded content: " + " | ".join(samples),
                "Base64-encoded commands hide what is being run from casual review and simple detections. The decoded "
                "text above shows the real intent." + (" It contains network indicators." if iocs else ""),
                "Review the decoded script, block any indicators it contains, and find how the command was launched "
                "(parent process).",
                rs, ["T1059.001", "T1027", "T1140"], extra={"decoded": samples, "decoded_iocs": iocs}))
            continue
        if key == "office-child":
            out.append(make(
                "process:office-child", "process", f"Office application spawned a shell or script host ({len(rs)} event(s))",
                "high", "high",
                "A process such as cmd, PowerShell, mshta or rundll32 had an Office application as its parent: "
                + ", ".join(sorted({f"{r.get('parent_process')} → {r.get('process')}" for r in rs})[:4]) + ".",
                "Office documents should not launch command interpreters. This is the signature of a malicious macro "
                "or exploit document, usually delivered by phishing.",
                "Find the document and its delivery email, purge it from all mailboxes, block macros from the internet, "
                "and isolate the host.",
                rs, ["T1204.002", "T1566.001", "T1059"]))
            continue
        title, sev, mitre_ids, why = meta[key]
        cmds = sorted({str(r.get("command_line") or r.get("process") or "")[:200] for r in rs})
        conf = "high" if sev in ("critical", "high") and len(rs) >= 1 else "medium"
        out.append(make(
            f"process:{key}", "process", f"{title} ({len(rs)} event(s))", sev, conf,
            "Matched command line(s): " + " | ".join(cmds[:3]),
            why, _PROC_RECS.get(key, "Investigate the process tree, the user who ran it and what it wrote or connected to."),
            rs, mitre_ids))
    return out


_PROC_RECS = {
    "lsass-dump": "Isolate the host, treat every credential used on it as compromised (reset passwords, krbtgt if a DC), "
                  "and enable LSA protection / Credential Guard.",
    "sam-dump": "Isolate the host and reset local and domain credentials. If NTDS.dit was copied, reset krbtgt twice.",
    "shadow-delete": "Isolate affected hosts immediately, check for encryption activity and protect/verify offline backups.",
    "log-clear": "Collect remaining logs from central sources (SIEM/forwarders) and scope what the clearing tried to hide.",
    "defender-off": "Re-enable protections, enable tamper protection, and hunt for what ran while protection was off.",
    "schtasks": "Delete the task, collect its payload and check other hosts for the same task name.",
    "run-key": "Remove the Run key value, collect the referenced binary and check other hosts for it.",
    "new-account": "Disable the account, review who created it and remove unauthorised group memberships.",
    "psexec": "Identify source and target hosts, the account used, and restrict admin shares / remote service creation.",
    "remote-tools": "Confirm whether the tool is sanctioned. If not, remove it and block it with application control.",
}

# ========================================================================= malware

_HACKTOOLS = re.compile(r"\b(mimikatz|rubeus|kekeo|lazagne|sharphound|bloodhound|cobaltstrike|beacon\.(exe|dll)|"
                        r"sliver|havoc|bruteratel|meterpreter|metasploit|psexec\.py|wmiexec|smbexec|secretsdump|crackmapexec|"
                        r"netexec|impacket|nanodump|procdump64?|advanced_ip_scanner|netscan\.exe|rclone)\b", re.I)
_DOUBLE_EXT = re.compile(r"[\w-]+\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip)\.(exe|scr|js|vbs|bat|cmd|hta|lnk|ps1|com|pif)\b", re.I)
_USER_PATH = re.compile(r"(\\users\\[^\\]+\\(appdata|downloads|desktop|documents)|\\windows\\temp|\\programdata|"
                        r"\\users\\public|\\temp\\|/tmp/|/dev/shm/)[^\s\"']*\.(exe|dll|scr|ps1|bat|vbs|js|hta|sys)\b", re.I)
_SYSBIN = re.compile(r"(?:^|[\\/\s\"])(svchost|lsass|csrss|winlogon|services|smss|explorer|spoolsv|taskhostw|dllhost|conhost)\.exe", re.I)
_MASQ = re.compile(r"\b(svch0st|scvhost|svchosts|lsas|lssass|isass|csrsss|expl0rer|explorar|winlogin|spoolsvc)\.exe\b", re.I)


def detect_malware(rows: List[Row]) -> List[Finding]:
    out: List[Finding] = []
    tool, dbl, upath, masq, sysloc = [], [], [], [], []
    for r in rows:
        text = _text(r, "process", "parent_process", "command_line", "message", "url") + " " + str(r.get("decoded_command") or "")
        if _HACKTOOLS.search(text):
            tool.append(r)
        if _DOUBLE_EXT.search(text):
            dbl.append(r)
        if _USER_PATH.search(text):
            upath.append(r)
        if _MASQ.search(text):
            masq.append(r)
        m = _SYSBIN.search(str(r.get("process") or "") + " " + str(r.get("command_line") or "").split(" ")[0])
        p = (str(r.get("command_line") or "").split(" ")[0] or str(r.get("process") or "")).lower().strip('"')
        if m and ("\\" in p or "/" in p) and not any(x in p for x in ("\\windows\\system32\\", "\\windows\\syswow64\\",
                                                                        "\\windows\\explorer.exe", "\\windows\\winsxs\\")):
            sysloc.append(r)
    if tool:
        names = sorted({_HACKTOOLS.search(_text(r, "process", "command_line", "message", "url") + " " +
                                          str(r.get("decoded_command") or "")).group(1).lower() for r in tool})
        out.append(make("malware:hacktool", "malware", f"Known attack tooling observed: {', '.join(names[:5])}",
                        "critical", "high", f"Names of offensive tools appeared in {len(tool)} event(s).",
                        "These tools are rarely legitimate outside authorised testing. Their presence points to an "
                        "active intrusion (credential theft, lateral movement or C2).",
                        "Confirm whether a penetration test is running. If not, isolate affected hosts and start full IR.",
                        tool, ["T1588.002", "T1003"], extra={"tools": names}))
    if dbl:
        out.append(make("malware:double-ext", "malware", f"Double file extension used to disguise an executable ({len(dbl)})",
                        "high", "high", "Files named like document.pdf.exe were executed or referenced.",
                        "Double extensions trick users into running executables that look like documents.",
                        "Collect the file, check its hash reputation and trace how it arrived (email, download, USB).",
                        dbl, ["T1036.007", "T1204.002"]))
    if masq:
        out.append(make("malware:masquerade-name", "malware", f"Look-alike system binary name ({len(masq)})",
                        "high", "high", "Process names misspelled to resemble Windows system binaries were seen.",
                        "Malware often uses names like svch0st.exe to blend in with legitimate processes.",
                        "Collect the binary, check its hash and signature, and hunt for it on other hosts.",
                        masq, ["T1036.005"]))
    if sysloc:
        out.append(make("malware:sysbin-path", "malware", f"System binary running from an unusual location ({len(sysloc)})",
                        "high", "medium", "A process named like a core Windows binary ran outside System32/SysWOW64.",
                        "Legitimate svchost/lsass/csrss only run from System32. A copy elsewhere is almost always masquerading malware.",
                        "Collect the binary and verify its signature and hash.", sysloc, ["T1036.005"]))
    if upath:
        out.append(make("malware:user-path", "malware", f"Executable or script run from a user-writable folder ({len(upath)})",
                        "medium", "medium", "Executables or scripts in AppData, Temp, Downloads, ProgramData or Public were referenced.",
                        "Malware and droppers usually live in user-writable paths because they don't need admin rights.",
                        "Check the file hashes for reputation and see which parent process wrote or launched them.",
                        upath, ["T1204.002"]))
    return out


# ========================================================================= network

SUSPICIOUS_PORTS = {4444: "Metasploit default", 1337: "common backdoor", 31337: "common backdoor", 50050: "Cobalt Strike team server",
                    6667: "IRC (botnet C2)", 6697: "IRC over TLS", 9001: "Tor ORPort", 9030: "Tor DirPort", 9050: "Tor SOCKS",
                    8888: "common C2/alt web", 2222: "alt SSH", 5555: "Android debug / backdoor", 3333: "mining pool",
                    14444: "mining pool", 45700: "mining pool", 23: "Telnet"}
ABUSED_TLDS = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "ga", "work", "buzz", "rest", "country", "kim",
               "loan", "bid", "win", "party", "review", "stream", "download", "racing", "date", "faith", "cricket",
               "science", "accountant", "icu", "cyou", "sbs", "lol", "quest", "monster", "beauty", "hair", "autos"}
BRANDS = {
    "microsoft": "microsoft.com", "office": "office.com", "office365": "office.com", "outlook": "outlook.com",
    "live": "live.com", "onedrive": "onedrive.com", "sharepoint": "sharepoint.com", "azure": "azure.com",
    "windows": "windows.com", "google": "google.com", "gmail": "gmail.com", "youtube": "youtube.com", "apple": "apple.com",
    "icloud": "icloud.com", "paypal": "paypal.com", "amazon": "amazon.com", "aws": "aws.amazon.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com", "linkedin": "linkedin.com",
    "twitter": "twitter.com", "github": "github.com", "gitlab": "gitlab.com", "dropbox": "dropbox.com",
    "docusign": "docusign.com", "adobe": "adobe.com", "okta": "okta.com", "salesforce": "salesforce.com",
    "zoom": "zoom.us", "slack": "slack.com", "netflix": "netflix.com", "steam": "steampowered.com",
    "binance": "binance.com", "coinbase": "coinbase.com", "metamask": "metamask.io", "chase": "chase.com",
    "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com", "citibank": "citi.com", "hsbc": "hsbc.com",
    "dhl": "dhl.com", "fedex": "fedex.com", "ups": "ups.com", "usps": "usps.com", "cloudflare": "cloudflare.com",
    "crowdstrike": "crowdstrike.com", "zscaler": "zscaler.com", "servicenow": "servicenow.com", "atlassian": "atlassian.com",
    "wetransfer": "wetransfer.com", "telegram": "telegram.org", "discord": "discord.com", "ebay": "ebay.com",
}
# Registrable domains that legitimately belong to the brands above (never flagged).
LEGIT_DOMAINS = {
    "microsoftonline.com", "microsoft365.com", "msauth.net", "msftauth.net", "windows.net", "office.net", "office365.com",
    "sharepointonline.com", "azureedge.net", "azurewebsites.net", "msn.com", "bing.com", "skype.com", "msedge.net",
    "outlook.office.com", "onenote.com", "microsoftstore.com", "msocdn.com", "aka.ms", "live.net", "xboxlive.com",
    "googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com", "ggpht.com", "google.co.uk", "withgoogle.com",
    "ytimg.com", "youtu.be", "apple-cloudkit.com", "mzstatic.com", "icloud-content.com", "paypalobjects.com",
    "amazonaws.com", "cloudfront.net", "media-amazon.com", "ssl-images-amazon.com", "fbcdn.net", "fb.com", "cdninstagram.com",
    "licdn.com", "lnkd.in", "twimg.com", "t.co", "x.com", "githubusercontent.com", "githubassets.com", "github.io",
    "dropboxusercontent.com", "dropboxapi.com", "adobelogin.com", "adobe.io", "typekit.net", "oktacdn.com", "okta-emea.com",
    "oktapreview.com", "force.com", "salesforceliveagent.com", "zoom.com", "zoomgov.com", "slack-edge.com", "nflxvideo.net",
    "nflximg.net", "steamstatic.com", "steamcommunity.com", "cloudflare.net", "cloudflare-dns.com", "zscaler.net",
    "zscalertwo.net", "service-now.com", "atlassian.net", "bitbucket.org", "wetransfer.net", "telegram.me", "t.me",
    "discordapp.com", "discord.gg", "ebayimg.com", "dhl.de", "usps.gov", "chase.net", "citi.com", "hsbc.co.uk",
}
_HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "|": "l"})
_MULTI_HOMO = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"), ("ii", "u")]
_SUFFIX2 = {"co.uk", "com.au", "co.jp", "com.br", "co.za", "com.mx", "co.in", "com.sg", "com.ph", "co.nz", "org.uk", "gov.uk"}


def registrable(domain: str) -> Tuple[str, str]:
    """Return (second-level label, registrable domain) with a small multi-part suffix list."""
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _SUFFIX2:
        return parts[-3], ".".join(parts[-3:])
    if len(parts) >= 2:
        return parts[-2], ".".join(parts[-2:])
    return parts[0], parts[0]


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _deconfuse(label: str) -> str:
    s = label.translate(_HOMO)
    for a, b in _MULTI_HOMO:
        s = s.replace(a, b)
    return s


def typosquat(domain: str, protected: Optional[Dict[str, str]] = None) -> Optional[Dict[str, str]]:
    """Detect a domain impersonating a brand or one of ``protected`` (label -> real domain).

    Returns ``{"target": real_domain, "technique": ...}`` or None."""
    d = domain.lower().rstrip(".")
    label, reg = registrable(d)
    targets = dict(BRANDS)
    targets.update(protected or {})
    real_regs = {registrable(v)[1] for v in targets.values()} | LEGIT_DOMAINS
    if reg in real_regs or d in LEGIT_DOMAINS:
        return None
    if d.startswith("xn--") or ".xn--" in d:
        try:
            uni = d.encode().decode("idna")
            ascii_like = _deconfuse("".join(ch for ch in uni if ch.isascii()))
            for brand, real in targets.items():
                if len(brand) >= 4 and brand in ascii_like:
                    return {"target": real, "technique": f"punycode/IDN homograph ({uni})"}
        except UnicodeError:
            pass
        return {"target": "?", "technique": "punycode/IDN domain"}
    plain = label.replace("-", "")
    dec = _deconfuse(plain)
    for brand, real in targets.items():
        if len(brand) < 4:
            continue
        if dec == brand and plain != brand:
            return {"target": real, "technique": "homoglyph substitution"}
        if plain == brand:  # brand label on the wrong TLD (microsoft.support, paypal.xyz)
            return {"target": real, "technique": f"brand on another TLD (.{reg.split('.', 1)[-1]})"}
        if len(brand) >= 5 and abs(len(plain) - len(brand)) <= 2:
            dist = levenshtein(plain, brand)
            if 0 < dist <= (1 if len(brand) <= 6 else 2):
                return {"target": real, "technique": f"typo (edit distance {dist})"}
        if len(brand) >= 5 and brand in dec and dec != brand:
            tokens = re.split(r"[-.]", d)
            lure = {"login", "signin", "secure", "verify", "account", "support", "update", "auth", "portal", "help",
                    "billing", "payment", "office", "mail", "online", "web", "service", "id", "sso", "access", "alert", "docs"}
            if any(t in lure for t in tokens) or "-" in label or len(dec) - len(brand) <= 6:
                return {"target": real, "technique": "brand name combined with lure words (combosquatting)"}
    for sub in d.split(".")[:-2]:  # brand in a subdomain of an unrelated domain: paypal.com.evil.xyz
        if sub in targets and len(sub) >= 4:
            return {"target": targets[sub], "technique": "brand used as subdomain of an unrelated domain"}
    if re.search(r"(^|\.)(" + "|".join(re.escape(registrable(v)[1].split(".")[0]) for v in targets.values()
                                       if len(registrable(v)[1].split(".")[0]) >= 5) + r")\.(com|net|org)\.", d):
        return {"target": "?", "technique": "real-looking domain followed by another domain"}
    return None


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def dga_like(domain: str) -> bool:
    label, _ = registrable(domain)
    if len(label) < 12 or "-" in label:
        return False
    vowels = sum(ch in "aeiou" for ch in label) / len(label)
    digits = sum(ch.isdigit() for ch in label) / len(label)
    return entropy(label) >= 3.6 and (vowels < 0.28 or digits > 0.25)


def detect_network(rows: List[Row], protected: Optional[Dict[str, str]] = None) -> List[Finding]:
    from .observables import ObsType, extract, is_public_ip

    out: List[Finding] = []
    # ---- beaconing: regular intervals between the same src and dst
    flows: Dict[Tuple[str, str], List[Row]] = defaultdict(list)
    for r in rows:
        dst = r.get("domain") or r.get("dst_ip")
        src = r.get("host") or r.get("src_ip")
        if dst and src and _ts(r) and (not r.get("dst_ip") or is_public_ip(r["dst_ip"]) or r.get("domain")):
            flows[(src, dst)].append(r)
    for (src, dst), rs in flows.items():
        if len(rs) < 6:
            continue
        ts = sorted(_ts(r) for r in rs)
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
        if len(gaps) < 5:
            continue
        med = statistics.median(gaps)
        cv = statistics.pstdev(gaps) / statistics.mean(gaps) if statistics.mean(gaps) else 9
        if 10 <= med <= 7200 and cv <= 0.25:
            out.append(make(
                f"network:beacon:{src}:{dst}", "network", f"Beaconing from {src} to {dst} every ~{_human(med)}",
                "high", "high" if cv <= 0.1 and len(rs) >= 10 else "medium",
                f"{len(rs)} connections at a regular interval (median {_human(med)}, jitter {int(cv * 100)}%).",
                "Implants check in with their C2 server on a timer. Very regular connections to one external "
                "destination are a strong C2 indicator. Some legitimate updaters behave the same way, so check the "
                "destination's reputation.",
                "Check the destination's reputation, find the process making the connections on the source host, "
                "and block the destination if it is not a known service.",
                rs, ["T1071.001", "T1573"], {"hosts": [src], "destinations": [dst]},
                {"interval_seconds": round(med, 1), "jitter": round(cv, 3)}))

    # ---- suspicious ports
    port_hits: Dict[int, List[Row]] = defaultdict(list)
    for r in rows:
        try:
            p = int(r.get("dst_port") or 0)
        except ValueError:
            continue
        if p in SUSPICIOUS_PORTS and r.get("dst_ip") and is_public_ip(r["dst_ip"]):
            port_hits[p].append(r)
        elif p in (3389, 445, 22, 5985, 5986) and r.get("src_ip") and is_public_ip(r["src_ip"]) and r.get("dst_ip") \
                and not is_public_ip(r["dst_ip"]) and str(r.get("action") or "").lower() not in ("deny", "denied", "drop", "block", "blocked"):
            port_hits[-p].append(r)
    for p, rs in port_hits.items():
        if p > 0:
            out.append(make(
                f"network:port:{p}", "network", f"Outbound connection to port {p} ({SUSPICIOUS_PORTS[p]})",
                "medium", "medium",
                f"{len(rs)} connection(s) to external hosts on TCP/UDP {p}: {', '.join(sorted({r['dst_ip'] for r in rs})[:5])}.",
                f"Port {p} is commonly associated with {SUSPICIOUS_PORTS[p]}. Business traffic rarely uses it.",
                "Identify the process making the connection and check the destination's reputation.",
                rs, ["T1571"], {"ips": sorted({r["dst_ip"] for r in rs})}))
        else:
            port = -p
            out.append(make(
                f"network:inbound:{port}", "network", f"Inbound {_svc(port)} from the internet allowed ({len(rs)})",
                "high", "medium",
                f"External addresses reached internal hosts on port {port}: "
                f"{', '.join(sorted({r['src_ip'] for r in rs})[:5])} → {', '.join(sorted({r['dst_ip'] for r in rs})[:5])}.",
                f"Exposed {_svc(port)} is a top initial-access vector (brute force, exploitation).",
                f"Close {_svc(port)} to the internet or put it behind VPN/ZTNA, and review authentication logs for the target hosts.",
                rs, ["T1133", "T1021"], {"ips": sorted({r["src_ip"] for r in rs})}))

    # ---- direct-to-IP downloads
    ip_urls = [r for r in rows if re.match(r"(?i)^(https?|ftp)://\d{1,3}(\.\d{1,3}){3}", str(r.get("url") or ""))
               or re.search(r"(?i)(https?|ftp)://\d{1,3}(\.\d{1,3}){3}[:/][^\s\"']*\.(exe|dll|ps1|bin|sh|hta|zip|msi|js|vbs)",
                            str(r.get("command_line") or "") + " " + str(r.get("decoded_command") or ""))]
    if ip_urls:
        out.append(make("network:ip-url", "network", f"File fetched from a bare IP address ({len(ip_urls)})",
                        "high", "medium", "URLs pointing straight at an IP address (no domain name) were requested.",
                        "Legitimate software is almost always served from a domain. Bare-IP downloads are typical of "
                        "droppers and quickly stood-up attacker infrastructure.",
                        "Block the IP, retrieve the downloaded file if possible and check its hash.",
                        ip_urls, ["T1105", "T1071.001"]))

    # ---- domains: typosquatting, DGA, abused TLDs, DNS tunnelling
    domain_rows: Dict[str, List[Row]] = defaultdict(list)
    for r in rows:
        cands = set()
        if r.get("domain"):
            cands.add(str(r["domain"]).lower())
        for o in extract(" ".join(str(r.get(f) or "") for f in ("url", "command_line", "message", "decoded_command")),
                         types={ObsType.DOMAIN, ObsType.URL, ObsType.EMAIL}):
            if o.type is ObsType.DOMAIN:
                cands.add(o.value)
            elif o.type is ObsType.URL:
                from urllib.parse import urlsplit
                h = urlsplit(o.value).hostname
                if h and not re.match(r"^\d+(\.\d+){3}$", h):
                    cands.add(h.lower())
            elif o.type is ObsType.EMAIL:
                cands.add(o.value.split("@")[1])
        for d in cands:
            domain_rows[d].append(r)
    squats, dgas, tlds = [], [], []
    for d, rs in domain_rows.items():
        t = typosquat(d, protected)
        if t:
            squats.append((d, t, rs))
        elif dga_like(d):
            dgas.append((d, rs))
        elif d.rsplit(".", 1)[-1] in ABUSED_TLDS:
            tlds.append((d, rs))
    for d, t, rs in squats:
        out.append(make(
            f"network:typosquat:{d}", "network", f"Look-alike domain {d} impersonating {t['target']}",
            "high", "high" if "homoglyph" in t["technique"] or "typo" in t["technique"] else "medium",
            f"{d} resembles {t['target']} ({t['technique']}). Seen in {len(rs)} event(s).",
            "Typosquatted and look-alike domains are used for phishing pages, credential harvesting and C2 that "
            "blends in with trusted services.",
            "Block the domain at DNS/proxy/email gateway, search mail logs for messages containing it, and reset "
            "credentials of anyone who submitted them to it.",
            rs, ["T1583.001", "T1566.002"], {"domains": [d]}, {"impersonates": t["target"], "technique": t["technique"]}))
    if dgas:
        out.append(make(
            "network:dga", "network", f"Random-looking (DGA-like) domains ({len(dgas)})",
            "medium", "low", "High-entropy domain names: " + ", ".join(d for d, _ in dgas[:6]) + ".",
            "Malware with domain generation algorithms contacts pseudo-random domains to find its C2. CDNs and "
            "cloud services sometimes produce similar names, so confidence is low until reputation confirms it.",
            "Check reputation for these domains and find the process resolving them.",
            [r for _, rs in dgas for r in rs], ["T1568.002"], {"domains": [d for d, _ in dgas]}))
    if tlds:
        out.append(make(
            "network:abused-tld", "network", f"Domains on frequently abused TLDs ({len(tlds)})",
            "low", "low", "Contacted: " + ", ".join(d for d, _ in tlds[:8]) + ".",
            "These top-level domains are cheap and have a high share of malicious registrations. On its own this is "
            "only a weak signal.",
            "Check these domains' reputation in the Observables tab.",
            [r for _, rs in tlds for r in rs], ["T1583.001"], {"domains": [d for d, _ in tlds]}))
    parents: Dict[str, set] = defaultdict(set)
    tunnel_rows: Dict[str, List[Row]] = defaultdict(list)
    for d, rs in domain_rows.items():
        labels = d.split(".")
        _, reg = registrable(d)
        if len(labels) > 2:
            sub = d[: -len(reg) - 1]
            if len(sub) >= 40 or any(len(lbl) >= 30 for lbl in labels[:-2]):
                parents[reg].add(sub)
                tunnel_rows[reg].extend(rs)
    for reg, subs in parents.items():
        out.append(make(
            f"network:dns-tunnel:{reg}", "network", f"Possible DNS tunnelling / exfiltration via {reg}",
            "high", "medium" if len(subs) >= 5 else "low",
            f"{len(subs)} long, encoded-looking subdomain(s) of {reg}, e.g. {next(iter(subs))[:60]}…",
            "Data can be smuggled out (or commands in) by encoding it in DNS query names. Long random labels under "
            "one parent domain are the tell-tale sign.",
            "Block the parent domain, find the querying host/process and assess what data could have been encoded.",
            tunnel_rows[reg], ["T1071.004", "T1048"], {"domains": [reg]}))
    return out


def _human(seconds: float) -> str:
    if seconds < 90:
        return f"{int(round(seconds))}s"
    if seconds < 5400:
        return f"{round(seconds / 60, 1):g} min"
    return f"{round(seconds / 3600, 1):g} h"


def _svc(port: int) -> str:
    return {3389: "RDP", 445: "SMB", 22: "SSH", 5985: "WinRM", 5986: "WinRM/HTTPS"}.get(port, f"port {port}")


# ====================================================================== entry point


def protected_domains(rows: Iterable[Row]) -> Dict[str, str]:
    """Infer the organisation's own domains (from user principal names / emails) so look-alikes can be flagged."""
    c: Counter = Counter()
    for r in rows:
        u = str(r.get("user") or "")
        if "@" in u:
            dom = u.rsplit("@", 1)[1].lower()
            if "." in dom:
                c[dom] += 1
    out = {}
    for dom, n in c.most_common(5):
        label, reg = registrable(dom)
        if len(label) >= 5 and label not in BRANDS:
            out[label] = reg
    return out


def analyze(rows: List[Row]) -> List[Finding]:
    protected = protected_domains(rows)
    findings: List[Finding] = []
    for fn in (detect_auth, detect_process, detect_malware):
        findings += fn(rows)
    findings += detect_network(rows, protected)
    conf_rank = {"high": 2, "medium": 1, "low": 0}
    findings.sort(key=lambda f: (-SEV_RANK.get(f["severity"], 0), -conf_rank.get(f["confidence"], 0), f["category"]))
    return findings
