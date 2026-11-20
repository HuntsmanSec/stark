"""MITRE ATT&CK (Enterprise) reference data and evidence-based technique suggestions.

The catalogue below is a curated subset of the techniques most often seen in
incident response. Suggestions are keyword/behaviour heuristics over log text:
they are a starting point for the analyst and must be reviewed before they go in a report.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

TACTICS = [
    ("TA0043", "Reconnaissance"), ("TA0042", "Resource Development"), ("TA0001", "Initial Access"),
    ("TA0002", "Execution"), ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"), ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"), ("TA0009", "Collection"), ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]
TACTIC_ORDER = {name: i for i, (_, name) in enumerate(TACTICS)}

# (id, name, tactic)
TECHNIQUES = [
    ("T1595", "Active Scanning", "Reconnaissance"),
    ("T1589", "Gather Victim Identity Information", "Reconnaissance"),
    ("T1583", "Acquire Infrastructure", "Resource Development"),
    ("T1566", "Phishing", "Initial Access"),
    ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
    ("T1566.002", "Phishing: Spearphishing Link", "Initial Access"),
    ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("T1133", "External Remote Services", "Initial Access"),
    ("T1078", "Valid Accounts", "Initial Access"),
    ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    ("T1189", "Drive-by Compromise", "Initial Access"),
    ("T1195", "Supply Chain Compromise", "Initial Access"),
    ("T1199", "Trusted Relationship", "Initial Access"),
    ("T1091", "Replication Through Removable Media", "Initial Access"),
    ("T1059", "Command and Scripting Interpreter", "Execution"),
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    ("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution"),
    ("T1059.005", "Command and Scripting Interpreter: Visual Basic", "Execution"),
    ("T1059.006", "Command and Scripting Interpreter: Python", "Execution"),
    ("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution"),
    ("T1047", "Windows Management Instrumentation", "Execution"),
    ("T1053.005", "Scheduled Task/Job: Scheduled Task", "Execution"),
    ("T1053.003", "Scheduled Task/Job: Cron", "Execution"),
    ("T1204.001", "User Execution: Malicious Link", "Execution"),
    ("T1204.002", "User Execution: Malicious File", "Execution"),
    ("T1569.002", "System Services: Service Execution", "Execution"),
    ("T1203", "Exploitation for Client Execution", "Execution"),
    ("T1106", "Native API", "Execution"),
    ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence"),
    ("T1543.003", "Create or Modify System Process: Windows Service", "Persistence"),
    ("T1136.001", "Create Account: Local Account", "Persistence"),
    ("T1136.002", "Create Account: Domain Account", "Persistence"),
    ("T1098", "Account Manipulation", "Persistence"),
    ("T1505.003", "Server Software Component: Web Shell", "Persistence"),
    ("T1546.003", "Event Triggered Execution: WMI Event Subscription", "Persistence"),
    ("T1574.002", "Hijack Execution Flow: DLL Side-Loading", "Persistence"),
    ("T1137", "Office Application Startup", "Persistence"),
    ("T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control", "Privilege Escalation"),
    ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    ("T1134", "Access Token Manipulation", "Privilege Escalation"),
    ("T1055", "Process Injection", "Privilege Escalation"),
    ("T1484.001", "Domain or Tenant Policy Modification: Group Policy Modification", "Privilege Escalation"),
    ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
    ("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    ("T1070.004", "Indicator Removal: File Deletion", "Defense Evasion"),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    ("T1562.004", "Impair Defenses: Disable or Modify System Firewall", "Defense Evasion"),
    ("T1218.005", "System Binary Proxy Execution: Mshta", "Defense Evasion"),
    ("T1218.010", "System Binary Proxy Execution: Regsvr32", "Defense Evasion"),
    ("T1218.011", "System Binary Proxy Execution: Rundll32", "Defense Evasion"),
    ("T1218.007", "System Binary Proxy Execution: Msiexec", "Defense Evasion"),
    ("T1036", "Masquerading", "Defense Evasion"),
    ("T1112", "Modify Registry", "Defense Evasion"),
    ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"),
    ("T1553.005", "Subvert Trust Controls: Mark-of-the-Web Bypass", "Defense Evasion"),
    ("T1003", "OS Credential Dumping", "Credential Access"),
    ("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    ("T1003.002", "OS Credential Dumping: Security Account Manager", "Credential Access"),
    ("T1003.003", "OS Credential Dumping: NTDS", "Credential Access"),
    ("T1003.006", "OS Credential Dumping: DCSync", "Credential Access"),
    ("T1110", "Brute Force", "Credential Access"),
    ("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access"),
    ("T1555", "Credentials from Password Stores", "Credential Access"),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),
    ("T1621", "Multi-Factor Authentication Request Generation", "Credential Access"),
    ("T1557", "Adversary-in-the-Middle", "Credential Access"),
    ("T1087", "Account Discovery", "Discovery"),
    ("T1087.002", "Account Discovery: Domain Account", "Discovery"),
    ("T1482", "Domain Trust Discovery", "Discovery"),
    ("T1033", "System Owner/User Discovery", "Discovery"),
    ("T1082", "System Information Discovery", "Discovery"),
    ("T1016", "System Network Configuration Discovery", "Discovery"),
    ("T1049", "System Network Connections Discovery", "Discovery"),
    ("T1057", "Process Discovery", "Discovery"),
    ("T1018", "Remote System Discovery", "Discovery"),
    ("T1046", "Network Service Discovery", "Discovery"),
    ("T1069", "Permission Groups Discovery", "Discovery"),
    ("T1083", "File and Directory Discovery", "Discovery"),
    ("T1135", "Network Share Discovery", "Discovery"),
    ("T1518.001", "Software Discovery: Security Software Discovery", "Discovery"),
    ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    ("T1021.004", "Remote Services: SSH", "Lateral Movement"),
    ("T1021.006", "Remote Services: Windows Remote Management", "Lateral Movement"),
    ("T1550.002", "Use Alternate Authentication Material: Pass the Hash", "Lateral Movement"),
    ("T1570", "Lateral Tool Transfer", "Lateral Movement"),
    ("T1560.001", "Archive Collected Data: Archive via Utility", "Collection"),
    ("T1005", "Data from Local System", "Collection"),
    ("T1039", "Data from Network Shared Drive", "Collection"),
    ("T1114", "Email Collection", "Collection"),
    ("T1113", "Screen Capture", "Collection"),
    ("T1056.001", "Input Capture: Keylogging", "Collection"),
    ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    ("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
    ("T1105", "Ingress Tool Transfer", "Command and Control"),
    ("T1219", "Remote Access Software", "Command and Control"),
    ("T1090", "Proxy", "Command and Control"),
    ("T1090.003", "Proxy: Multi-hop Proxy", "Command and Control"),
    ("T1572", "Protocol Tunneling", "Command and Control"),
    ("T1573", "Encrypted Channel", "Command and Control"),
    ("T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "Command and Control"),
    ("T1571", "Non-Standard Port", "Command and Control"),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
    ("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration"),
    ("T1486", "Data Encrypted for Impact", "Impact"),
    ("T1490", "Inhibit System Recovery", "Impact"),
    ("T1489", "Service Stop", "Impact"),
    ("T1485", "Data Destruction", "Impact"),
    ("T1498", "Network Denial of Service", "Impact"),
    ("T1499", "Endpoint Denial of Service", "Impact"),
    ("T1531", "Account Access Removal", "Impact"),
    ("T1496", "Resource Hijacking", "Impact"),
]

CATALOGUE: Dict[str, Dict[str, str]] = {
    tid: {"id": tid, "name": name, "tactic": tactic,
          "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}
    for tid, name, tactic in TECHNIQUES
}

# (technique id, regex) - evaluated case-insensitively over event/process/command line/message text
RULES = [
    ("T1059.001", r"powershell(\.exe)?|pwsh|\bIEX\b|Invoke-Expression|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}"),
    ("T1027", r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|FromBase64String|\bchar\]\s*\d+"),
    ("T1059.003", r"\bcmd(\.exe)?\s+/[ck]\b"),
    ("T1059.005", r"wscript|cscript|\.vbs\b|\.vbe\b"),
    ("T1059.004", r"/bin/(ba)?sh\s+-c|bash -i|\bsh -c\b"),
    ("T1059.006", r"python(3)?(\.exe)?\s+-c"),
    ("T1047", r"wmic(\.exe)?\s|Win32_Process|wmiprvse"),
    ("T1053.005", r"schtasks(\.exe)?\s+/create|\bEventID\D{0,5}4698\b|ScheduledTask"),
    ("T1053.003", r"crontab\s|/etc/cron"),
    ("T1569.002", r"psexe(c|svc)|sc(\.exe)?\s+(\\\\\S+\s+)?(create|start)|\b7045\b"),
    ("T1021.002", r"psexe(c|svc)|\\\\[\w.\-]+\\(admin|c|ipc)\$|\bADMIN\$"),
    ("T1021.001", r"\bmstsc\b|\bRDP\b|logon\s*type\D{0,5}10\b|TerminalServices|3389"),
    ("T1021.004", r"\bsshd?\b.*(Accepted|session opened)|port 22\b"),
    ("T1021.006", r"winrm|wsmprovhost|Enter-PSSession|Invoke-Command\s+-ComputerName|5985|5986"),
    ("T1003.001", r"lsass|mimikatz|sekurlsa|procdump.*lsass|comsvcs(\.dll)?.*minidump|MiniDump"),
    ("T1003.002", r"reg(\.exe)?\s+save\s+hklm\\(sam|system|security)"),
    ("T1003.003", r"ntdsutil|ntds\.dit|vssadmin.*create\s+shadow"),
    ("T1003.006", r"dcsync|lsadump::dcsync|DS-Replication-Get-Changes|\b4662\b.*1131f6a"),
    ("T1558.003", r"kerberoast|Invoke-Kerberoast|Rubeus|\b4769\b.*0x17"),
    ("T1110", r"\b4625\b|failed password|authentication fail|login fail|invalid user|logon failure|brute"),
    ("T1110.003", r"password spray|spray"),
    ("T1621", r"mfa (fatigue|push)|MFA denied|50074|500121"),
    ("T1078", r"\b4624\b|successful logon|Accepted password|sign-?in success"),
    ("T1136.001", r"net(1)?(\.exe)?\s+user\s+\S+\s+\S*\s*/add|\b4720\b|useradd"),
    ("T1136.002", r"net(1)?(\.exe)?\s+user\s+.*/add\s+/domain"),
    ("T1098", r"net(1)?(\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add|\b4732\b|\b4728\b|Add member to role"),
    ("T1547.001", r"CurrentVersion\\Run(Once)?\b|\\Startup\\|reg(\.exe)?\s+add.*\\Run\b"),
    ("T1543.003", r"sc(\.exe)?\s+create|New-Service|\b7045\b|\b4697\b"),
    ("T1546.003", r"__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer"),
    ("T1505.003", r"webshell|web shell|w3wp\.exe.*(cmd|powershell)|\.(aspx|jsp|php)\?cmd="),
    ("T1548.002", r"fodhelper|eventvwr\.exe|computerdefaults|sdclt|UAC bypass"),
    ("T1070.001", r"wevtutil(\.exe)?\s+(cl|clear-log)|Clear-EventLog|\b1102\b|\b104\b.*cleared"),
    ("T1070.004", r"\bdel\s+/[fqs]|Remove-Item.*-Force|rm\s+-rf|sdelete"),
    ("T1562.001", r"Set-MpPreference.*Disable|DisableRealtimeMonitoring|tamper|sc(\.exe)?\s+(stop|delete)\s+(windefend|sense)|Defender.*disabled"),
    ("T1562.004", r"netsh\s+(adv)?firewall\s+.*(off|disable|delete)|ufw disable|iptables -F"),
    ("T1218.005", r"mshta(\.exe)?"),
    ("T1218.010", r"regsvr32(\.exe)?.*(/i:|scrobj|http)"),
    ("T1218.011", r"rundll32(\.exe)?\s+\S+,\s*\w+|rundll32.*javascript"),
    ("T1218.007", r"msiexec(\.exe)?\s+.*(/q|http)"),
    ("T1140", r"certutil(\.exe)?\s+-decode|base64\s+-d"),
    ("T1105", r"certutil(\.exe)?\s+.*-urlcache|bitsadmin.*/transfer|Invoke-WebRequest|iwr\s|wget\s|curl\s.*-o|DownloadFile|DownloadString|Start-BitsTransfer"),
    ("T1112", r"reg(\.exe)?\s+(add|delete)|Set-ItemProperty.*HK(LM|CU)"),
    ("T1036", r"svch0st|scvhost|lsas\.exe|explorer\.exe.*\\(temp|appdata)\\"),
    ("T1055", r"CreateRemoteThread|process (hollowing|injection)|VirtualAllocEx|\bEventID\D{0,5}8\b"),
    ("T1134", r"token (impersonation|manipulation)|SeDebugPrivilege|Invoke-TokenManipulation"),
    ("T1033", r"\bwhoami(\.exe)?\b|query user|\bquser\b"),
    ("T1082", r"systeminfo|hostname(\.exe)?\b|uname -a"),
    ("T1016", r"ipconfig|ifconfig|route print|arp -a"),
    ("T1049", r"netstat"),
    ("T1057", r"tasklist|Get-Process|\bps aux\b"),
    ("T1018", r"net(\.exe)?\s+view|ping\s+-n|nltest\s+/dclist|Get-ADComputer"),
    ("T1482", r"nltest(\.exe)?\s+/(domain_trusts|trusted_domains)|Get-ADTrust"),
    ("T1087.002", r"net(1)?(\.exe)?\s+(user|group)\s+.*/domain|Get-ADUser|AdFind|BloodHound|SharpHound"),
    ("T1069", r"net(1)?(\.exe)?\s+(local)?group\b|Get-ADGroupMember"),
    ("T1046", r"\bnmap\b|masscan|port ?scan|Advanced IP Scanner|angry ?ip"),
    ("T1135", r"net(\.exe)?\s+share|Get-SmbShare|ShareFinder"),
    ("T1518.001", r"Get-MpComputerStatus|AntiVirusProduct|wmic.*antivirus"),
    ("T1560.001", r"\b7z(a)?(\.exe)?\s+a\b|rar(\.exe)?\s+a\b|Compress-Archive|tar\s+-c"),
    ("T1567.002", r"rclone|mega(\.nz|sync)|dropbox|drive\.google|transfer\.sh|anonfiles|wetransfer"),
    ("T1048", r"\bftp\b.*(put|stor)|scp\s+\S+\s+\S+@|exfil"),
    ("T1219", r"anydesk|teamviewer|screenconnect|connectwise|atera|splashtop|ngrok|rustdesk|meshagent"),
    ("T1572", r"ngrok|plink|chisel|ssh\s+-[RLD]\s|cloudflared|iodine|dnscat"),
    ("T1090.003", r"\btor\b|\.onion\b|tor exit"),
    ("T1071.004", r"dns tunnel|TXT record.*long|dnscat|iodine"),
    ("T1071.001", r"beacon|c2 |command and control|cobalt ?strike|sliver|havoc|brute ?ratel"),
    ("T1486", r"ransom|\.lock(ed)?\b|encrypt(ed|ion) files|readme.*\.txt|DECRYPT"),
    ("T1490", r"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no|wbadmin\s+delete"),
    ("T1489", r"net(\.exe)?\s+stop|sc(\.exe)?\s+stop|taskkill\s+/f"),
    ("T1190", r"sql ?injection|\bunion\s+select\b|\.\./\.\./|/etc/passwd|\$\{jndi:|cmd=|exploit|CVE-\d{4}-\d+|WAF.*(block|deny)"),
    ("T1566.001", r"\.(docm|xlsm|iso|img|lnk|hta)\b.*(attach|outlook)|outlook\.exe.*\\(temp|content\.outlook)"),
    ("T1566.002", r"phish|safelinks|clicked url|urlclick"),
    ("T1204.002", r"(winword|excel|powerpnt|outlook)(\.exe)?.*(cmd|powershell|wscript|mshta|rundll32)"),
    ("T1595", r"scan(ner|ning)?\b.*(detected|probe)|nikto|sqlmap|zgrab|masscan|nuclei"),
    ("T1498", r"\bddos\b|syn flood|udp flood|flood attack"),
    ("T1496", r"xmrig|cryptominer|stratum\+tcp|coinhive|monero"),
    ("T1056.001", r"keylog"),
    ("T1113", r"screenshot|screen ?capture"),
    ("T1114", r"New-MailboxExportRequest|MailItemsAccessed|inbox rule|New-InboxRule"),
    ("T1078.004", r"(azure|entra|aad|okta|o365|aws).*sign-?in|ConsoleLogin|risky sign-?in|impossible travel"),
]
_COMPILED = [(tid, re.compile(rx, re.I)) for tid, rx in RULES]


def technique(tid: str) -> Dict[str, str]:
    t = CATALOGUE.get(tid.upper())
    if t:
        return dict(t)
    return {"id": tid.upper(), "name": tid.upper(), "tactic": "Unknown",
            "url": f"https://attack.mitre.org/techniques/{tid.upper().replace('.', '/')}/"}


def search(q: str, limit: int = 30) -> List[Dict[str, str]]:
    q = q.strip().lower()
    out = [t for t in CATALOGUE.values()
           if not q or q in t["id"].lower() or q in t["name"].lower() or q in t["tactic"].lower()]
    return out[:limit]


def suggest_techniques(texts: Iterable[str], max_evidence: int = 3) -> List[Dict]:
    hits: Dict[str, Dict] = {}
    for text in texts:
        if not text:
            continue
        for tid, rx in _COMPILED:
            m = rx.search(text)
            if not m:
                continue
            h = hits.setdefault(tid, {**technique(tid), "count": 0, "evidence": []})
            h["count"] += 1
            if len(h["evidence"]) < max_evidence:
                start = max(0, m.start() - 60)
                h["evidence"].append(text[start:m.end() + 60].strip()[:220])
    return sorted(hits.values(), key=lambda h: (TACTIC_ORDER.get(h["tactic"], 99), -h["count"]))
