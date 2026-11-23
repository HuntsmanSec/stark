"""Build MISP events from STARK results, and send them to a MISP server.

The event is MISP's standard JSON format, so the file can also be loaded by hand in MISP
(*Events -> Import from -> MISP JSON*). Event and attribute UUIDs are derived from the case,
so sending the same case again updates the existing event instead of creating a copy.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import requests

from ..models import ObservableReport, Verdict
from ..observables import ObsType
from ..providers.base import USER_AGENT
from ..providers.misp import base_url, misp_headers

NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/HuntsmanSec/stark/misp")

# STARK type -> (MISP attribute type, category)
ATTR_TYPE = {
    ObsType.IPV4: ("ip-dst", "Network activity"),
    ObsType.IPV6: ("ip-dst", "Network activity"),
    ObsType.DOMAIN: ("domain", "Network activity"),
    ObsType.URL: ("url", "Network activity"),
    ObsType.MD5: ("md5", "Payload delivery"),
    ObsType.SHA1: ("sha1", "Payload delivery"),
    ObsType.SHA256: ("sha256", "Payload delivery"),
    ObsType.EMAIL: ("email-src", "Payload delivery"),
}
THREAT_LEVEL = {"critical": "1", "high": "1", "medium": "2", "low": "3", "info": "4"}
DONE = {"resolved", "closed", "cancelled"}


def _tlp(tlp: str) -> str:
    t = (tlp or "amber").lower()
    return "tlp:clear" if t in ("clear", "white") else f"tlp:{t}"


def build_event(
    reports: Iterable[ObservableReport],
    *,
    info: str,
    key: str,
    severity: str = "medium",
    status: str = "open",
    tlp: str = "amber",
    techniques: Optional[List[Dict[str, Any]]] = None,
    all_indicators: bool = False,
    date: Optional[str] = None,
) -> Dict[str, Any]:
    """A MISP event (``{"Event": {...}}``).

    ``key`` makes the UUIDs stable (use the workspace + case reference). Indicators rated
    malicious/suspicious are marked *for IDS*; others are added as context unless
    ``all_indicators`` is False and they are harmless (benign infrastructure is left out)."""
    ev_uuid = str(uuid.uuid5(NAMESPACE, f"event:{key}"))
    attrs = []
    for r in reports:
        v = r.verdict
        if v is Verdict.HARMLESS and not all_indicators:
            continue
        mtype, cat = ATTR_TYPE[r.observable.type]
        flagged = v in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
        parts = [f"STARK verdict: {v.value}"]
        if r.score is not None:
            parts.append(f"score {r.score}")
        if r.flagged_by:
            parts.append("flagged by " + ", ".join(r.flagged_by))
        if r.malware_families:
            parts.append("families: " + ", ".join(r.malware_families))
        a_tags = [{"name": f'stark:verdict="{v.value}"'}]
        a_tags += [{"name": f'stark:family="{f}"'} for f in r.malware_families[:5]]
        attrs.append({
            "uuid": str(uuid.uuid5(NAMESPACE, f"attr:{key}:{r.observable.type.value}:{r.observable.value}")),
            "type": mtype, "category": cat, "value": r.observable.value, "to_ids": flagged,
            "comment": "; ".join(parts)[:255], "distribution": "5", "Tag": a_tags,
        })
    tags = [{"name": _tlp(tlp)}, {"name": "stark:source=\"S.T.A.R.K\""}]
    for t in techniques or []:
        if t.get("technique_id") and t.get("name"):
            tags.append({"name": f'misp-galaxy:mitre-attack-pattern="{t["name"]} - {t["technique_id"]}"'})
    return {"Event": {
        "uuid": ev_uuid, "info": info[:255],
        "date": date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "threat_level_id": THREAT_LEVEL.get((severity or "medium").lower(), "2"),
        "analysis": "2" if (status or "").lower() in DONE else "1",
        "distribution": "0", "published": False, "Tag": tags, "Attribute": attrs,
    }}


def event_json(reports, **kw) -> str:
    kw.setdefault("info", "S.T.A.R.K indicators")
    kw.setdefault("key", "cli:" + ",".join(sorted(r.observable.value for r in reports)))
    return json.dumps(build_event(reports, **kw), indent=2)


def push_event(event: Dict[str, Any], url: str, key: str, verify: bool = True, timeout: float = 30) -> Dict[str, Any]:
    """Create the event on the MISP server, or update it if it was sent before.

    Returns ``{"id", "uuid", "url", "created"}``. Raises ``RuntimeError`` with a readable message."""
    url = base_url(url)
    ev_uuid = event["Event"]["uuid"]
    s = requests.Session()
    s.headers.update({**misp_headers(key), "User-Agent": USER_AGENT})
    s.verify = verify
    try:
        existing = s.get(f"{url}/events/view/{ev_uuid}", timeout=timeout)
        created = existing.status_code != 200
        resp = s.post(f"{url}/events/add" if created else f"{url}/events/edit/{ev_uuid}",
                      data=json.dumps(event), timeout=timeout)
    except requests.exceptions.SSLError:
        raise RuntimeError("MISP's TLS certificate isn't trusted. Fix the certificate, or set "
                           "STARK_MISP_VERIFY_TLS=0 for a server with a self-signed certificate.") from None
    except requests.RequestException as exc:
        raise RuntimeError(f"Could not reach MISP at {url}: {exc.__class__.__name__}") from None
    if resp.status_code in (401, 403):
        raise RuntimeError("MISP refused the key: check the automation key and that its user may create events.")
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if resp.status_code >= 300 or "Event" not in data:
        msg = data.get("message") or data.get("errors") or resp.text[:200]
        raise RuntimeError(f"MISP returned HTTP {resp.status_code}: {msg}")
    ev = data["Event"]
    return {"id": ev.get("id"), "uuid": ev.get("uuid", ev_uuid), "url": f"{url}/events/view/{ev.get('id')}",
            "created": created}
