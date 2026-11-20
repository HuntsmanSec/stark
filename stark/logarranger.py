"""Log Arranger: turn messy exports from SIEM / EDR / network tools into one tidy timeline.

Everything here is pure, in-memory processing. Nothing is written to disk or a
database. Callers (CLI or web workspace) get the arranged result back and
decide what, if anything, to keep. Raw client logs are never persisted.

Recognised inputs (auto-detected, mixed input is fine):

* JSON / JSONL / concatenated JSON, including wrappers: Splunk (``result``/``_raw``),
  Elastic (``_source``, ``hits.hits``), Microsoft Sentinel / Log Analytics API
  (``tables[].columns/rows``), Defender XDR advanced hunting (``Results``/``Schema``),
  SentinelOne (``data``), CrowdStrike (FDR / Event Search), Suricata EVE, AWS WAF,
  Cloudflare, Azure WAF
* CSV / TSV with a header row (Sentinel, Defender, LogRhythm, QRadar, Splunk, Palo Alto
  exports...), Zeek ``#fields`` logs
* Syslog RFC 3164 / RFC 5424 lines, CEF, LEEF (QRadar), Cisco ASA/FTD ``%ASA-``,
  Palo Alto PAN-OS CSV syslog, Fortinet / generic ``key=value``
* Windows Event XML (``<Event>`` blocks)
* Anything else is kept as a raw line and still mined for IOCs
"""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from .observables import ObsType, extract, is_public_ip

MAX_ROWS = 100_000

FIELDS = ["time", "product", "event", "severity", "action", "host", "user", "src_ip", "src_port",
          "dst_ip", "dst_port", "protocol", "process", "parent_process", "command_line", "hash",
          "url", "domain", "message", "country", "user_agent", "device", "mac", "logon_type", "app"]

# Field aliases (lower-cased, dotted paths after flattening). First non-empty wins.
ALIASES: Dict[str, List[str]] = {
    "time": ["@timestamp", "timestamp", "timegenerated", "_time", "eventtime", "event_time", "time",
             "devtime", "starttime", "start", "log date", "normal msg date", "receive time", "receive_time",
             "generated time", "time_generated", "createdat", "created_at", "eventcreationtime", "ts",
             "datetime", "date_time", "timecreated", "timecreated.systemtime", "systemtime", "rt",
             "event.created", "eventdate", "date", "timestamp_utc", "processstarttime", "contextTimeStamp"],
    "host": ["devicename", "computername", "computer", "host.name", "srcname", "hostname", "agentname", "agent.name",
             "endpoint.name", "endpointname", "devname", "dvchost", "origin host", "impacted host",
             "host", "device.name", "machinename", "workstationname", "_resourceid", "observer.name",
             "src.endpoint.name", "deviceinfo.name"],
    "user": ["username", "user.name", "accountname", "account name", "userprincipalname", "targetusername",
             "subjectusername", "initiatingprocessaccountname", "suser", "duser", "usrname", "src_user",
             "srcuser", "user", "login", "account", "user_name", "actor.user.name", "src.process.user",
             "user.email", "identity", "upn", "callername", "impacted user", "origin user"],
    "src_ip": ["src_ip", "srcip", "sourceip", "source ip", "source.ip", "source address", "source_address",
               "src", "sip", "clientip", "client_ip", "c-ip", "httprequest.clientip", "ipaddress",
               "callipaddress", "localip", "id.orig_h", "src_endpoint.ip", "origin ip", "sourceaddress",
               "properties.clientip", "transaction.client_ip", "client.ip", "aip", "remote_addr"],
    "dst_ip": ["dst_ip", "dstip", "dest_ip", "destinationip", "destination ip", "destination.ip",
               "destination address", "destination_address", "dst", "dip", "remoteip", "remoteaddressip4",
               "remoteaddressip6", "id.resp_h", "dst_endpoint.ip", "impacted ip", "destinationaddress",
               "server.ip", "dst.ip.address"],
    "src_port": ["src_port", "srcport", "spt", "sourceport", "source port", "source.port", "localport",
                 "id.orig_p", "sport", "client.port"],
    "dst_port": ["dst_port", "dstport", "dpt", "dest_port", "destinationport", "destination port",
                 "destination.port", "remoteport", "id.resp_p", "dport", "server.port", "dst.port.number"],
    "protocol": ["protocol", "proto", "network.transport", "transport", "ipprotocol", "protocol name"],
    "action": ["action", "act", "actiontype", "event.action", "deviceaction", "disposition", "wafaction",
               "securityaction", "terminatingruleaction", "outcome", "event.outcome", "result",
               "resulttype", "verdict", "alert.action", "status"],
    "event": ["event_simplename", "eventname", "event name", "event.code", "eventid", "event id",
              "operationname", "activity", "activitydisplayname", "rulename", "rule.name", "alert.signature",
              "signature", "mpe rule name", "common event", "threatname", "threat name", "alertname",
              "title", "name", "event.type", "event_type", "event.category", "type", "subtype", "logid",
              "classification", "category", "qid", "msgid", "terminatingruleid", "event.dataset", "actiontype",
              "event"],
    "severity": ["severity", "sev", "level", "alertseverity", "priority", "risk", "risklevel",
                 "event.severity", "alert.severity", "severity_name", "magnitude", "pri"],
    "process": ["image", "processname", "process.name", "process.executable", "filename",
                "initiatingprocessfilename", "src.process.name", "newprocessname", "imagefilename",
                "process", "tgt.process.name", "process_name", "exe"],
    "parent_process": ["parentimage", "parentprocessname", "initiatingprocessfilename", "initiatingprocessparentfilename",
                       "parentbasefilename", "src.process.parent.name", "process.parent.name",
                       "parent_process_name", "parentprocess"],
    "command_line": ["commandline", "command_line", "cmdline", "processcommandline",
                     "initiatingprocesscommandline", "src.process.cmdline", "process.command_line",
                     "srcproccmdline", "tgt.process.cmdline", "process_command_line", "scriptblocktext"],
    "hash": ["sha256", "sha256hashdata", "sha256hash", "process.hash.sha256", "file.hash.sha256",
             "initiatingprocesssha256", "src.process.image.sha256", "tgt.file.sha256", "sha1",
             "initiatingprocesssha1", "md5", "md5hashdata", "hash", "filehash", "hashes", "fileshash"],
    "url": ["url", "url.full", "request", "requesturl", "request_url", "remoteurl", "httprequest.uri",
            "clientrequesturi", "uri", "cs-uri-stem", "http.url", "properties.requesturi", "fileurl"],
    "domain": ["domain", "query", "queryname", "dns.question.name", "dns.rrname", "clientrequesthost",
               "httprequest.host", "dest_host", "destinationhostname", "domainname", "http.hostname",
               "server.domain", "url.domain", "tls.sni", "sni"],
    "country": ["country", "countrycode", "country_code", "location", "location.countryorregion",
                "locationdetails.countryorregion", "geo.country_name", "geo.country_iso_code", "source.geo.country_iso_code",
                "client.geo.country_iso_code", "srccountry", "src_country", "httprequest.country", "clientcountry",
                "country_name", "ipcountry", "sourcecountry", "loc.country"],
    "user_agent": ["useragent", "user_agent", "user_agent.original", "http.user_agent", "clientrequestuseragent",
                   "cs(user-agent)", "requestuseragent", "httprequest.headers.user-agent", "devicedetail.browser",
                   "browser", "ua"],
    "device": ["deviceid", "devicedetail.deviceid", "devicedetail.displayname", "devicedetail.operatingsystem",
               "device.id", "workstation", "workstationname", "clientdevice", "devicetype", "client_name",
               "devicedetail.os", "operatingsystem"],
    "mac": ["mac", "macaddress", "mac_address", "src_mac", "srcmac", "client_mac", "clientmac", "host.mac",
            "source.mac", "smac", "dhcp.mac", "physicaladdress", "macaddresses"],
    "logon_type": ["logontype", "logon_type", "logon.type", "authenticationprotocol", "authmethod",
                   "authenticationrequirement", "clientappused", "authentication_method"],
    "app": ["appdisplayname", "app", "application", "applicationname", "resourcedisplayname", "service",
            "client_app", "clientappused", "app_name"],
    "message": ["message", "msg", "_raw", "description", "details", "normal message", "alert.category",
                "summary", "renderedmessage", "log"],
}

# Signatures used to label the product a record came from.
PRODUCT_RULES: List[Tuple[str, List[str]]] = [
    ("Microsoft Sentinel", ["timegenerated", "tenantid", "_resourceid", "sourcesystem", "type"]),
    ("Microsoft Defender", ["devicename", "actiontype", "reportid", "initiatingprocessfilename", "deviceid"]),
    ("CrowdStrike Falcon", ["event_simplename", "aid", "cid", "contextprocessid", "sha256hashdata",
                            "composite_id", "falcon_host_link"]),
    ("SentinelOne", ["agentname", "src.process.cmdline", "endpoint.name", "srcproccmdline", "agentuuid",
                     "storyline", "s1"]),
    ("Splunk", ["_raw", "_time", "sourcetype", "splunk_server", "_indextime"]),
    ("Elastic / ELK", ["@timestamp", "ecs.version", "event.dataset", "agent.type", "_index", "log.file.path"]),
    ("IBM QRadar", ["qid", "magnitude", "log source", "logsourceid", "event name", "sourceip", "leef"]),
    ("LogRhythm", ["mpe rule name", "log source entity", "common event", "normal msg date", "classification",
                   "origin host", "impacted host"]),
    ("Palo Alto Networks", ["panos", "serial", "virtual system", "source zone", "from_zone", "app", "rule",
                            "threat/content type"]),
    ("Fortinet FortiGate", ["devname", "devid", "logid", "vd", "srcintf", "policyid"]),
    ("Cisco ASA / FTD", ["asa", "ftd"]),
    ("AWS WAF", ["webaclid", "terminatingruleid", "httprequest.clientip", "httpsourcename"]),
    ("Cloudflare", ["clientip", "clientrequesthost", "rayid", "edgeresponsestatus", "securityaction"]),
    ("Azure WAF / Front Door", ["properties.clientip", "properties.rulename", "properties.policy",
                                "properties.requesturi"]),
    ("ModSecurity", ["transaction.client_ip", "transaction.unique_id", "audit_data"]),
    ("Suricata", ["event_type", "flow_id", "alert.signature", "in_iface"]),
    ("Zeek", ["id.orig_h", "id.resp_h", "uid"]),
    ("Windows Event Log", ["eventid", "computer", "channel", "provider.name", "eventrecordid"]),
]

_SYSLOG_5424 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[[^\]]*\])+) ?(?P<msg>.*)$")
_SYSLOG_3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)?|"
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (?P<host>[\w.\-:]+) "
    r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:? ?(?P<msg>.*)$")
_KV = re.compile(r'([A-Za-z_][\w.\-/]*)=("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s,;]+)')
_CEF_EXT = re.compile(r"(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)")
_ASA = re.compile(r"%(?P<kind>ASA|FTD|PIX|FWSM)-(?P<sev>\d)-(?P<id>\d{6}): (?P<msg>.*)")
_ASA_CONN = re.compile(
    r"(?P<proto>TCP|UDP|ICMP|tcp|udp|icmp).*?(?:for|from|src)\s+\S*?:(?P<sip>[\d.:a-f]+)/(?P<sport>\d+)"
    r".*?(?:to|dst)\s+\S*?:(?P<dip>[\d.:a-f]+)/(?P<dport>\d+)")
_ASA_ACT = re.compile(r"\b(Built|Teardown|Deny|Denied|denied|permitted|Permitted|dropped|Dropped)\b")
_WIN_NS = re.compile(r"\{[^}]+\}")
_MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")

_SEVERITY_WORDS = {"0": "info", "1": "low", "2": "low", "3": "medium", "4": "medium", "5": "medium",
                   "6": "high", "7": "high", "8": "high", "9": "critical", "10": "critical"}
_SYSLOG_SEV = ["critical", "critical", "critical", "high", "medium", "low", "info", "info"]


# --------------------------------------------------------------------------- utils


def flatten(obj: Any, prefix: str = "", out: Optional[Dict[str, str]] = None, depth: int = 0) -> Dict[str, str]:
    out = {} if out is None else out
    if isinstance(obj, dict) and depth < 8:
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            flatten(v, key, out, depth + 1)
    elif isinstance(obj, list) and depth < 8:
        if all(not isinstance(x, (dict, list)) for x in obj):
            out[prefix.lower()] = ", ".join("" if x is None else str(x) for x in obj)
        else:
            for i, v in enumerate(obj[:50]):
                flatten(v, f"{prefix}.{i}" if prefix else str(i), out, depth + 1)
    else:
        if obj is not None and obj != "":
            out[prefix.lower()] = obj if isinstance(obj, str) else json.dumps(obj) if not isinstance(
                obj, (int, float, bool)) else str(obj)
    return out


_TS_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M:%S.%f %p", "%d/%m/%Y %H:%M:%S", "%b %d %Y %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S", "%b %d, %Y %I:%M:%S %p", "%b %d, %Y %H:%M:%S",
    "%a %b %d %H:%M:%S %Y", "%Y%m%d%H%M%S", "%m/%d/%Y, %I:%M:%S.%f %p", "%m/%d/%Y, %I:%M:%S %p",
    "%d/%m/%Y, %H:%M:%S", "%b %d %Y %H:%M:%S.%f",
]


def parse_time(value: Any, default_year: Optional[int] = None) -> Optional[str]:
    """Best-effort conversion of any timestamp to ISO-8601 UTC (``...Z``)."""
    if value is None:
        return None
    s = str(value).strip().strip('"')
    if not s:
        return None
    try:
        if re.fullmatch(r"\d{9,19}(\.\d+)?", s):
            n = float(s)
            if n > 1e17:      # nanoseconds
                n /= 1e9
            elif n > 1e14:    # microseconds
                n /= 1e6
            elif n > 1e11:    # milliseconds
                n /= 1e3
            return _iso(datetime.fromtimestamp(n, tz=timezone.utc))
    except (ValueError, OverflowError, OSError):
        return None
    iso = s.replace(" UTC", "Z").replace(" GMT", "Z")
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)              # trim nanoseconds
    iso = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", iso)
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(iso.replace(" +", "+"))
        return _iso(dt)
    except ValueError:
        pass
    m = re.fullmatch(r"([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}:\d{2}:\d{2})(\.\d+)?", s)
    if m:
        year = default_year or datetime.now(timezone.utc).year
        try:
            dt = datetime.strptime(f"{year} {m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d %H:%M:%S")
            return _iso(dt)
        except ValueError:
            return None
    for fmt in _TS_FORMATS:
        try:
            return _iso(datetime.strptime(s, fmt))
        except ValueError:
            continue
    return None


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def detect_product(keys: Iterable[str], hint: Optional[str] = None) -> str:
    if hint:
        return hint
    ks = set(keys)
    best, best_score = "Generic", 0
    for name, sig in PRODUCT_RULES:
        score = sum(1 for s in sig if s in ks)
        if score > best_score:
            best, best_score = name, score
    return best if best_score >= 2 or (best_score == 1 and best in ("Zeek", "Suricata")) else "Generic"


_SUFFIX_OK = {"command_line", "process", "parent_process", "hash", "user"}


def _first(flat: Dict[str, str], aliases: List[str], field: str = "") -> str:
    for a in aliases:
        v = flat.get(a)
        if v not in (None, "", "-", "null", "None", "N/A", "n/a"):
            return str(v)
    # fall back to a suffix match (e.g. "event.data.commandline")
    if field not in _SUFFIX_OK:
        return ""
    for a in aliases:
        if "." in a or " " in a:
            continue
        for k, v in flat.items():
            if k.endswith("." + a) and v not in (None, "", "-"):
                return str(v)
    return ""


def _norm_severity(v: str) -> str:
    s = str(v).strip().lower()
    if not s:
        return ""
    if s in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[s]
    for word in ("critical", "high", "medium", "low", "info"):
        if word in s:
            return word
    if s in ("informational", "information", "notice", "debug", "verbose"):
        return "info"
    if s in ("warning", "warn", "moderate", "med"):
        return "medium"
    if s in ("error", "err", "severe", "alert", "emergency", "crit", "very malicious", "malicious"):
        return "high"
    return s[:12]


def normalise(flat: Dict[str, str], product: Optional[str] = None, raw: Optional[str] = None,
              default_year: Optional[int] = None, raw_is_message: bool = False) -> Dict[str, Any]:
    # Fortinet style separate date= time= fields
    if flat.get("date") and re.fullmatch(r"\d{1,2}:\d{2}:\d{2}(\.\d+)?", str(flat.get("time", ""))):
        flat = {**flat, "time": f"{flat['date']} {flat['time']}"}
    row: Dict[str, Any] = {f: _first(flat, ALIASES[f], f) if f in ALIASES else "" for f in FIELDS}
    if flat.get("devid") and flat.get("logid"):
        # FortiGate: "hostname" is the destination web host, the client is srcname/srcip
        if flat.get("hostname"):
            row["domain"] = row["domain"] or flat["hostname"]
            row["host"] = flat.get("srcname") or ""
    row["time"] = parse_time(row["time"], default_year) or ""
    row["product"] = detect_product(flat.keys(), product)
    row["severity"] = _norm_severity(row["severity"])
    for f in ("src_ip", "dst_ip"):
        row[f] = row[f].split(",")[0].strip()
    if row["mac"]:
        m = _MAC.search(row["mac"])
        row["mac"] = m.group(0).lower().replace("-", ":") if m else ""
    elif raw:
        m = _MAC.search(raw)
        row["mac"] = m.group(0).lower().replace("-", ":") if m else ""
    if row["country"] and len(row["country"]) > 60:
        row["country"] = ""
    # Combine Cloudflare/AWS WAF host + uri into a URL
    if row["url"] and row["url"].startswith("/") and row["domain"]:
        row["url"] = f"https://{row['domain']}{row['url']}"
    # Hashes field like "MD5=..,SHA256=.."
    if row["hash"] and "=" in row["hash"]:
        m = re.search(r"SHA256=([0-9A-Fa-f]{64})", row["hash"]) or re.search(r"MD5=([0-9A-Fa-f]{32})", row["hash"])
        row["hash"] = m.group(1).lower() if m else ""
    if not row["message"] and raw_is_message:
        row["message"] = raw if raw and len(raw) < 2000 else ""
    row["raw"] = raw if raw is not None else json.dumps(flat, ensure_ascii=False)[:20000]
    row["fields"] = flat
    return row


# ------------------------------------------------------------------------ parsers


def _unwrap_json(obj: Any) -> Iterator[Tuple[Dict[str, Any], Optional[str]]]:
    """Yield (record, product-hint) from known API/export wrappers."""
    if isinstance(obj, list):
        for x in obj:
            yield from _unwrap_json(x)
        return
    if not isinstance(obj, dict):
        return
    # Log Analytics / Sentinel API: {"tables":[{"columns":[{"name":..}], "rows":[[..]]}]}
    if isinstance(obj.get("tables"), list):
        for t in obj["tables"]:
            cols = [c.get("name") or c.get("ColumnName") for c in t.get("columns") or []]
            for r in t.get("rows") or []:
                yield dict(zip(cols, r)), "Microsoft Sentinel"
        return
    # Defender advanced hunting API: {"Schema": [...], "Results": [...]}
    if isinstance(obj.get("Results"), list) and ("Schema" in obj or "Stats" in obj):
        for r in obj["Results"]:
            yield r, "Microsoft Defender"
        return
    # Elastic search response
    hits = obj.get("hits")
    if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
        for h in hits["hits"]:
            yield (h.get("_source") or h), "Elastic / ELK"
        return
    if isinstance(obj.get("_source"), dict):
        yield obj["_source"], "Elastic / ELK"
        return
    # Splunk export: {"preview":false,"result":{...}}
    if isinstance(obj.get("result"), dict) and ("preview" in obj or "_raw" in obj["result"]):
        yield obj["result"], "Splunk"
        return
    if isinstance(obj.get("results"), list) and obj.get("results") and isinstance(obj["results"][0], dict):
        for r in obj["results"]:
            yield r, None
        return
    # SentinelOne API {"data":[...], "pagination":{...}}
    if isinstance(obj.get("data"), list) and ("pagination" in obj or "nextCursor" in str(obj.get("pagination"))):
        for r in obj["data"]:
            yield r, "SentinelOne"
        return
    # CrowdStrike API {"resources":[...]}
    if isinstance(obj.get("resources"), list) and "meta" in obj:
        for r in obj["resources"]:
            yield r, "CrowdStrike Falcon"
        return
    # Generic {"value":[...]} (Graph API) / {"events":[...]} / {"records":[...]} (Azure diagnostic)
    for key in ("value", "events", "records", "Records", "logs", "alerts", "items"):
        if isinstance(obj.get(key), list) and obj[key] and isinstance(obj[key][0], dict):
            for r in obj[key]:
                yield r, None
            return
    yield obj, None


def _iter_json_text(text: str) -> Optional[List[Any]]:
    s = text.lstrip()
    if not s or s[0] not in "[{":
        return None
    try:
        return [json.loads(s)]
    except json.JSONDecodeError:
        pass
    out, dec, i, n = [], json.JSONDecoder(), 0, len(s)
    try:
        while i < n:
            while i < n and s[i] in " \r\n\t,":
                i += 1
            if i >= n:
                break
            obj, i = dec.raw_decode(s, i)
            out.append(obj)
    except json.JSONDecodeError:
        return out if len(out) > 5 else None
    return out


def parse_cef(line: str) -> Optional[Dict[str, str]]:
    idx = line.find("CEF:")
    if idx < 0:
        return None
    parts = re.split(r"(?<!\\)\|", line[idx + 4:], maxsplit=7)
    if len(parts) < 7:
        return None
    ver, vendor, product, pver, sig, name, sev = parts[:7]
    ext = parts[7] if len(parts) > 7 else ""
    flat = {"cef.vendor": vendor, "cef.product": product, "signature": sig, "name": name, "severity": sev}
    for k, v in _CEF_EXT.findall(ext):
        flat[k.lower()] = v.replace("\\=", "=").replace("\\\\", "\\").strip()
    flat["_product_hint"] = f"{vendor} {product}".strip()
    return flat


def parse_leef(line: str) -> Optional[Dict[str, str]]:
    idx = line.find("LEEF:")
    if idx < 0:
        return None
    body = line[idx + 5:]
    parts = body.split("|")
    if len(parts) < 5:
        return None
    ver = parts[0]
    vendor, product, _pver, event_id = parts[1:5]
    rest = "|".join(parts[5:])
    delim = "\t"
    if ver.startswith("2") and len(parts) > 6:
        d = parts[5]
        delim = bytes.fromhex(d[2:]).decode() if d.lower().startswith("0x") else (d or "\t")
        rest = "|".join(parts[6:])
    flat = {"leef": "1", "vendor": vendor, "leef.product": product, "eventid": event_id}
    for pair in rest.split(delim):
        if "=" in pair:
            k, v = pair.split("=", 1)
            flat[k.strip().lower()] = v.strip()
    if "src" in flat and "sourceip" not in flat:
        flat["sourceip"] = flat["src"]
    if "devtime" in flat:
        flat["time"] = flat.pop("devtime")
    flat["_product_hint"] = "IBM QRadar" if "qradar" in product.lower() or vendor.lower() == "ibm" else \
        f"{vendor} {product} (LEEF)"
    return flat


_PAN_TRAFFIC = ["future_use1", "receive_time", "serial", "type", "subtype", "future_use2", "generated_time",
                "src", "dst", "natsrc", "natdst", "rule", "srcuser", "dstuser", "app", "vsys", "from_zone",
                "to_zone", "inbound_if", "outbound_if", "log_action", "future_use3", "sessionid", "repeatcnt",
                "sport", "dport", "natsport", "natdport", "flags", "proto", "action"]
_PAN_THREAT_EXTRA = {31: "url_or_filename", 32: "threatname", 33: "category", 34: "severity", 35: "direction"}


def parse_panos(msg: str) -> Optional[Dict[str, str]]:
    if msg.count(",") < 25:
        return None
    cols = next(csv.reader([msg]))
    if len(cols) < 30 or cols[3] not in ("TRAFFIC", "THREAT", "URL", "SYSTEM", "CONFIG", "GLOBALPROTECT",
                                          "DECRYPTION", "AUTHENTICATION"):
        return None
    flat = {k: v for k, v in zip(_PAN_TRAFFIC, cols) if v}
    if cols[3] == "THREAT":
        for i, k in _PAN_THREAT_EXTRA.items():
            if i < len(cols) and cols[i]:
                flat[k] = cols[i]
        if flat.get("url_or_filename"):
            v = flat["url_or_filename"].strip('"')
            flat["url" if "/" in v or "." in v.split("/")[0] else "filename"] = v
    flat["event"] = f"{cols[3]}/{cols[4]}"
    flat["_product_hint"] = "Palo Alto Networks"
    flat["panos"] = "1"
    return flat


def parse_asa(msg: str) -> Optional[Dict[str, str]]:
    m = _ASA.search(msg)
    if not m:
        return None
    flat = {"asa": "1", "severity": m.group("sev"), "event": f"%{m.group('kind')}-{m.group('sev')}-{m.group('id')}",
            "message": m.group("msg")}
    c = _ASA_CONN.search(m.group("msg"))
    if c:
        flat.update({"protocol": c.group("proto").upper(), "src_ip": c.group("sip"), "src_port": c.group("sport"),
                     "dst_ip": c.group("dip"), "dst_port": c.group("dport")})
    a = _ASA_ACT.search(m.group("msg"))
    if a:
        word = a.group(1).lower()
        flat["action"] = "deny" if word.startswith("den") or word == "dropped" else "allow"
    flat["_product_hint"] = "Cisco ASA / FTD"
    return flat


def parse_kv(msg: str) -> Optional[Dict[str, str]]:
    pairs = _KV.findall(msg)
    if len(pairs) < 3:
        return None
    flat = {}
    for k, v in pairs:
        if v[:1] in "\"'":
            v = v[1:-1]
        flat[k.lower()] = v
    return flat


def parse_syslog(line: str) -> Tuple[Dict[str, str], str]:
    """Return (header fields, message body)."""
    m = _SYSLOG_5424.match(line)
    if m:
        hdr = {"time": m.group("ts"), "hostname": m.group("host"), "syslog_app": m.group("app"),
               "msgid": m.group("msgid") if m.group("msgid") != "-" else ""}
        if m.group("pri"):
            hdr["pri"] = _SYSLOG_SEV[int(m.group("pri")) % 8]
        sd = m.group("sd")
        if sd and sd != "-":
            for k, v in re.findall(r'(\w[\w.\-]*)="((?:[^"\\]|\\.)*)"', sd):
                hdr[k.lower()] = v
        return hdr, m.group("msg")
    m = _SYSLOG_3164.match(line)
    if m:
        hdr = {"time": m.group("ts"), "hostname": m.group("host"), "syslog_app": m.group("tag")}
        if m.group("pri"):
            hdr["pri"] = _SYSLOG_SEV[int(m.group("pri")) % 8]
        msg = m.group("msg")
        if "," in m.group("tag") or m.group("tag").startswith(("CEF", "LEEF", "%")):
            # PAN-OS CSV, CEF/LEEF or Cisco "%ASA-" bodies: the "tag" is part of the message
            hdr.pop("syslog_app")
            msg = line[m.start("tag"):]
        return hdr, msg
    return {}, line


def parse_line(line: str, default_year: Optional[int] = None) -> Dict[str, Any]:
    line = line.rstrip("\r\n")
    hdr, msg = parse_syslog(line)
    flat: Optional[Dict[str, str]] = None
    s = msg.lstrip()
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            recs = list(_unwrap_json(obj))
            if recs:
                rec, hint = recs[0]
                flat = flatten(rec)
                if hint:
                    flat["_product_hint"] = hint
        except json.JSONDecodeError:
            flat = None
    if flat is None:
        flat = parse_cef(line) or parse_leef(line) or parse_asa(line) or parse_panos(msg) or parse_kv(msg)
    if flat is None:
        flat = {"message": msg}
    for k, v in hdr.items():
        flat.setdefault(k, v)
    if "pri" in flat and "severity" not in flat:
        flat["severity"] = flat["pri"]
    hint = flat.pop("_product_hint", None)
    if not hint and flat.get("devname") and flat.get("logid"):
        hint = "Fortinet FortiGate"
    return normalise(flat, hint, raw=line, default_year=default_year, raw_is_message=True)


def _parse_csv(text: str, delim: str) -> List[Dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text), delimiter=delim)
    rows = []
    for rec in reader:
        rec = {k: v for k, v in rec.items() if k is not None}
        flat = {re.sub(r"\s*[\[(].*?[\])]$", "", str(k).strip().lower()): (v or "").strip()
                for k, v in rec.items()}
        flat = {k: v for k, v in flat.items() if v}
        # nested JSON in a cell (e.g. Sentinel AdditionalFields)
        for k, v in list(flat.items()):
            if v[:1] in "{[" and len(v) < 100_000:
                try:
                    flatten(json.loads(v), k, flat)
                except ValueError:
                    pass
        rows.append(normalise(flat, raw=delim.join(str(v or "") for v in rec.values())))
        if len(rows) >= MAX_ROWS:
            break
    return rows


def _parse_zeek(text: str) -> List[Dict[str, Any]]:
    fields: List[str] = []
    path = ""
    rows = []
    for line in text.splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#path"):
            path = line.split("\t", 1)[-1]
        elif line.startswith("#") or not line.strip():
            continue
        elif fields:
            flat = {k.lower(): v for k, v in zip(fields, line.split("\t")) if v not in ("-", "(empty)", "")}
            flat["event"] = f"zeek.{path}" if path else "zeek"
            rows.append(normalise(flat, "Zeek", raw=line))
    return rows


def _parse_windows_xml(text: str) -> List[Dict[str, Any]]:
    rows = []
    for block in re.findall(r"<Event[\s>].*?</Event>", text, flags=re.S):
        try:
            root = ET.fromstring(block)
        except ET.ParseError:
            continue
        flat: Dict[str, str] = {}
        for el in root.iter():
            tag = _WIN_NS.sub("", el.tag)
            if tag == "Data" and el.get("Name"):
                flat[el.get("Name").lower()] = (el.text or "").strip()
            elif tag == "TimeCreated" and el.get("SystemTime"):
                flat["timecreated"] = el.get("SystemTime")
            elif tag == "Provider" and el.get("Name"):
                flat["provider.name"] = el.get("Name")
            elif tag in ("EventID", "Computer", "Channel", "EventRecordID", "Level", "Keywords") and el.text:
                flat[tag.lower()] = el.text.strip()
        if flat.get("level"):
            flat["severity"] = {"1": "critical", "2": "high", "3": "medium", "4": "info", "0": "info"}.get(
                flat["level"], flat["level"])
        rows.append(normalise(flat, "Windows Event Log", raw=block[:20000]))
    return rows


def _looks_like_csv(lines: List[str]) -> Optional[str]:
    if len(lines) < 2:
        return None
    head = lines[0]
    for d in ("\t", ",", ";", "|"):
        n = head.count(d)
        if n >= 2 and not head.lstrip().startswith(("<", "{", "CEF:", "LEEF:")):
            sample = lines[1: min(len(lines), 6)]
            try:
                counts = [len(next(csv.reader([s], delimiter=d))) for s in sample if s.strip()]
            except (csv.Error, StopIteration):
                continue
            hdr_n = len(next(csv.reader([head], delimiter=d)))
            if counts and all(abs(c - hdr_n) <= 1 for c in counts) and not _SYSLOG_3164.match(head) \
                    and not re.search(r"\w=\S", head.split(d)[0]):
                return d
    return None


def arrange_text(text: str, name: str = "pasted", default_year: Optional[int] = None) -> List[Dict[str, Any]]:
    text = text.lstrip("﻿")
    if not text.strip():
        return []
    rows: List[Dict[str, Any]]
    if "<Event" in text[:2000] and "</Event>" in text:
        rows = _parse_windows_xml(text)
    elif text.lstrip().startswith("#separator") or "\n#fields\t" in text[:5000]:
        rows = _parse_zeek(text)
    else:
        docs = _iter_json_text(text)
        if docs is not None:
            rows = []
            for d in docs:
                for rec, hint in _unwrap_json(d):
                    flat = flatten(rec)
                    raw_text = rec.get("_raw") if isinstance(rec, dict) and isinstance(rec.get("_raw"), str) else None
                    if raw_text and len(flat) <= 8:
                        # Splunk event with only _raw: parse the raw line, keep Splunk metadata
                        r = parse_line(raw_text, default_year)
                        if r["product"] == "Generic":
                            r["product"] = "Splunk"
                        for f in ("host", "time"):
                            if not r[f]:
                                r[f] = normalise(flat, "Splunk")[f]
                        rows.append(r)
                    else:
                        rows.append(normalise(flat, hint, raw=json.dumps(rec, ensure_ascii=False)[:20000]))
                    if len(rows) >= MAX_ROWS:
                        break
        else:
            lines = text.splitlines()
            delim = _looks_like_csv(lines[:10])
            if delim:
                rows = _parse_csv(text, delim)
            else:
                rows = [parse_line(ln, default_year) for ln in lines[:MAX_ROWS] if ln.strip()]
    for r in rows:
        r["source_file"] = name
    return rows


# ----------------------------------------------------------------------- analysis


def _row_text(r: Dict[str, Any]) -> str:
    parts = [str(r.get(f) or "") for f in FIELDS if f not in ("time", "product", "severity")]
    parts.append(" ".join(str(v) for v in (r.get("fields") or {}).values())[:20000])
    return " ¦ ".join(parts)


def arrange(sources: List[Tuple[str, str]], include_fields: bool = False) -> Dict[str, Any]:
    """Arrange several (name, text) inputs into one sorted timeline with IOC/entity summaries."""
    from .mitre import suggest_techniques

    rows: List[Dict[str, Any]] = []
    for name, text in sources:
        rows.extend(arrange_text(text, name))
        if len(rows) >= MAX_ROWS:
            rows = rows[:MAX_ROWS]
            break
    rows.sort(key=lambda r: (r["time"] == "", r["time"]))

    ioc_counter: Counter = Counter()
    ioc_type: Dict[str, str] = {}
    hosts: Counter = Counter()
    users: Counter = Counter()
    procs: Counter = Counter()
    cmdlines: Counter = Counter()
    products: Counter = Counter()
    severities: Counter = Counter()
    texts: List[str] = []
    for i, r in enumerate(rows):
        r["id"] = i + 1
        products[r["product"]] += 1
        if r["severity"]:
            severities[r["severity"]] += 1
        text = _row_text(r)
        texts.append(" ".join(str(r.get(f) or "") for f in ("event", "process", "parent_process",
                                                              "command_line", "message", "url", "action")))
        found = list(extract(text, include_private=True, include_noise=False))
        r["iocs"] = [o.value for o in found]
        for o in found:
            ioc_counter[o.value] += 1
            ioc_type[o.value] = o.type.value
        for f, counter in (("host", hosts), ("user", users), ("process", procs), ("command_line", cmdlines)):
            v = (r.get(f) or "").strip()
            if v and v not in ("-", "SYSTEM", "N/A"):
                counter[v[:500]] += 1

    from .analysis import analyze
    findings = analyze(rows)
    for r in rows:
        if not include_fields:
            r.pop("fields", None)

    iocs = []
    for value, count in ioc_counter.most_common():
        t = ioc_type[value]
        internal = t in (ObsType.IPV4.value, ObsType.IPV6.value) and not is_public_ip(value)
        iocs.append({"value": value, "type": t, "count": count, "internal": internal})

    times = [r["time"] for r in rows if r["time"]]
    return {
        "rows": rows,
        "stats": {
            "rows": len(rows),
            "sources": len(sources),
            "products": dict(products.most_common()),
            "severities": dict(severities.most_common()),
            "first": times[0] if times else None,
            "last": times[-1] if times else None,
            "truncated": len(rows) >= MAX_ROWS,
        },
        "iocs": iocs,
        "entities": {
            "hosts": [{"value": v, "count": c} for v, c in hosts.most_common(200)],
            "users": [{"value": v, "count": c} for v, c in users.most_common(200)],
            "processes": [{"value": v, "count": c} for v, c in procs.most_common(200)],
            "command_lines": [{"value": v, "count": c} for v, c in cmdlines.most_common(100)],
        },
        "mitre": suggest_techniques(texts),
        "findings": findings,
        "assets": asset_map(rows),
    }


def asset_map(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Correlate hostnames, IP addresses and MAC addresses seen together in the logs."""
    from .observables import is_public_ip

    assets: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        host = (r.get("host") or "").strip()
        if not host or host in ("-", "localhost"):
            continue
        key = host.lower().split(".")[0]
        a = assets.setdefault(key, {"hostname": host, "names": set(), "ips": set(), "macs": set(), "users": set(),
                                    "products": set(), "events": 0, "first": None, "last": None})
        a["names"].add(host)
        a["events"] += 1
        if r.get("product"):
            a["products"].add(r["product"])
        if r.get("user"):
            a["users"].add(r["user"])
        if r.get("mac"):
            a["macs"].add(r["mac"])
        ip = r.get("src_ip")
        # Endpoint telemetry reports the host's own (internal) address as the source.
        if ip and not is_public_ip(ip) and r.get("product") not in ("Cisco ASA / FTD", "Palo Alto Networks",
                                                                     "IBM QRadar", "Generic"):
            a["ips"].add(ip)
        t = r.get("time")
        if t:
            a["first"] = min(a["first"] or t, t)
            a["last"] = max(a["last"] or t, t)
    out = []
    for a in assets.values():
        out.append({k: (sorted(v) if isinstance(v, set) else v) for k, v in a.items()})
    out.sort(key=lambda a: -a["events"])
    return out[:500]

