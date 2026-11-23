"""MISP: look indicators up in your own (or a community) MISP instance.

Needs two settings: the server address (``misp_url``) and an automation key (``misp``).
Both can be set in the workspace (Settings -> API keys), with ``stark config set``, or with
the ``STARK_MISP_URL_API_KEY`` / ``STARK_MISP_API_KEY`` environment variables.

Verdict rules (conservative, so context-only data never raises an alarm):

* attribute marked *for IDS* in an event with threat level High or Medium -> malicious
* attribute marked *for IDS* in a Low / Undefined event                    -> suspicious
* tagged ``false-positive`` or every hit is on a MISP warninglist           -> harmless
* only context attributes (not for IDS)                                     -> unknown, with the events listed
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from ..models import Verdict
from ..observables import ALL_TYPES
from .base import NotFound, Provider, ProviderError, score_to_verdict

THREAT_LEVEL = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}
_LEVEL_SCORE = {"1": 95, "2": 80, "3": 50, "4": 30}
_GALAXY = re.compile(r'^misp-galaxy:([\w-]+)="(.+)"$')
_FAMILY_GALAXIES = {"malpedia", "ransomware", "rat", "botnet", "banker", "stealer", "backdoor", "exploit-kit",
                    "tool", "android", "mitre-malware", "mitre-tool"}


def misp_headers(key: str) -> Dict[str, str]:
    return {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}


def verify_tls(options: Dict[str, Any]) -> bool:
    env = os.environ.get("STARK_MISP_VERIFY_TLS", "").strip().lower()
    if env in ("0", "false", "no", "off"):
        return False
    return bool(options.get("verify_tls", True))


def base_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not re.match(r"^https?://[^\s/]+", url):
        raise ProviderError("MISP server address must start with https:// (e.g. https://misp.example.org)")
    return url


class MISP(Provider):
    name = "misp"
    display = "MISP"
    homepage = "https://www.misp-project.org"
    supported = ALL_TYPES
    rate_limit = None
    extra_keys = {"misp_url": "MISP server address"}
    description = "Your MISP threat-sharing platform: events, IDS attributes, tags and galaxies."

    def query(self, obs):
        url = base_url(self.extra.get("misp_url", ""))
        payload = {"returnFormat": "json", "value": obs.value, "limit": 50, "page": 1,
                   "includeContext": True, "includeEventTags": True, "includeWarninglistHits": True}
        data = self.post_json(f"{url}/attributes/restSearch", json=payload, headers=misp_headers(self.api_key),
                              verify=verify_tls(self.options))
        attrs = ((data or {}).get("response") or {}).get("Attribute") or []
        attrs = [a for a in attrs if str(a.get("value", "")).lower() == obs.value.lower()] or attrs
        if not attrs:
            raise NotFound("Not in MISP")
        return self._summarise(obs, url, attrs)

    def _summarise(self, obs, url: str, attrs: List[Dict[str, Any]]):
        events: Dict[str, Dict[str, Any]] = {}
        tags: List[str] = []
        families: List[str] = []
        ids_levels: List[str] = []
        fp = False
        warn = 0
        for a in attrs:
            ev = a.get("Event") or {}
            eid = str(ev.get("id") or a.get("event_id") or "")
            if eid and eid not in events:
                events[eid] = {"id": eid, "info": ev.get("info") or "", "date": ev.get("date") or "",
                               "threat_level": THREAT_LEVEL.get(str(ev.get("threat_level_id")), "Undefined"),
                               "org": (ev.get("Orgc") or {}).get("name") or ""}
            names = [t.get("name", "") for t in (a.get("Tag") or []) + (ev.get("Tag") or []) if isinstance(t, dict)]
            for n in names:
                low = n.lower()
                if "false-positive" in low:
                    fp = True
                m = _GALAXY.match(n)
                if m and m.group(1) in _FAMILY_GALAXIES:
                    families.append(m.group(2).split(" - ")[0])
                elif m and m.group(1) == "threat-actor":
                    tags.append(f"actor:{m.group(2)}")
                elif not low.startswith(("tlp:", "misp-galaxy:mitre-attack-pattern", "workflow:")):
                    tags.append(n)
            if a.get("warnings"):
                warn += 1
            if a.get("to_ids") in (True, 1, "1", "true"):
                ids_levels.append(str(ev.get("threat_level_id") or "4"))

        score = max((_LEVEL_SCORE.get(level, 30) for level in ids_levels), default=None)
        if fp or (warn and warn == len(attrs)):
            verdict, score = Verdict.HARMLESS, 0
        elif score is not None:
            verdict = score_to_verdict(score)
        else:
            verdict = Verdict.UNKNOWN
        ev_list = sorted(events.values(), key=lambda e: e["date"], reverse=True)
        latest = ev_list[0] if ev_list else {}
        summary = f"{len(attrs)} attribute(s) in {len(events)} event(s)"
        if ids_levels:
            summary += f", {len(ids_levels)} marked for IDS"
        elif verdict is Verdict.UNKNOWN:
            summary += ", context only (not marked for IDS)"
        if warn:
            summary += f", {warn} on a warninglist"
        if latest:
            summary += f" | latest: {latest['info'][:80]} ({latest['date']}, threat level {latest['threat_level']})"
        link = f"{url}/events/view/{latest['id']}" if latest.get("id") else f"{url}/attributes/index"
        return self.result(
            obs, verdict, score=score, summary=summary,
            tags=list(dict.fromkeys(tags))[:10], malware_families=list(dict.fromkeys(families))[:5], link=link,
            details={"events": ev_list[:10], "attributes": len(attrs), "ids": len(ids_levels), "warninglist_hits": warn},
        )
