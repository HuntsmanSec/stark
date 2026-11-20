"""STIX 2.1 import / export.

Export produces a STIX 2.1 bundle containing, per observable:

* the Cyber-observable object (``ipv4-addr``, ``ipv6-addr``, ``domain-name``,
  ``url``, ``email-addr`` or ``file``) with a deterministic id (UUIDv5, spec §2.9)
* an ``indicator`` (when the consolidated verdict is malicious/suspicious, or
  always with ``all_indicators=True``) linked to the SCO with ``based-on``
* ``malware`` (family) SDOs linked from the indicator with ``indicates``
* a ``note`` holding every provider's result, with ``x_stark_results``
* a STARK ``identity`` used as ``created_by_ref``

Import accepts any STIX 2.x bundle (or list of objects) and pulls observables
out of indicator patterns and SCOs.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, Iterable, Iterator, List, Optional

from . import __version__
from .models import ObservableReport, Verdict, utcnow
from .observables import Observable, ObsType, parse_observable

SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
STARK_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/HuntsmanSec/stark")
IDENTITY_ID = f"identity--{uuid.uuid5(STARK_NAMESPACE, 'identity:stark')}"
TLP_CLEAR = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
TLP_GREEN = "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb"
TLP_AMBER = "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421"
TLP_RED = "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1"
TLP = {"clear": TLP_CLEAR, "white": TLP_CLEAR, "green": TLP_GREEN, "amber": TLP_AMBER, "red": TLP_RED}
_TLP_DEFS = {
    TLP_CLEAR: "clear", TLP_GREEN: "green", TLP_AMBER: "amber", TLP_RED: "red",
}

_HASH_KEY = {ObsType.MD5: "MD5", ObsType.SHA1: "SHA-1", ObsType.SHA256: "SHA-256"}
_SCO_TYPE = {
    ObsType.IPV4: "ipv4-addr", ObsType.IPV6: "ipv6-addr", ObsType.DOMAIN: "domain-name",
    ObsType.URL: "url", ObsType.EMAIL: "email-addr",
}


def _canonical(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _det_id(prefix: str, *parts: str) -> str:
    return f"{prefix}--{uuid.uuid5(STARK_NAMESPACE, '|'.join(parts))}"


def sco_for(obs: Observable) -> Dict[str, Any]:
    if obs.type.is_hash:
        contrib = {"hashes": {_HASH_KEY[obs.type]: obs.value}}
        sco = {"type": "file", "spec_version": "2.1", **contrib}
    else:
        contrib = {"value": obs.value}
        sco = {"type": _SCO_TYPE[obs.type], "spec_version": "2.1", **contrib}
    sco["id"] = f"{sco['type']}--{uuid.uuid5(SCO_NAMESPACE, _canonical(contrib))}"
    return sco


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def pattern_for(obs: Observable) -> str:
    if obs.type.is_hash:
        return f"[file:hashes.'{_HASH_KEY[obs.type]}' = '{_esc(obs.value)}']"
    return f"[{_SCO_TYPE[obs.type]}:value = '{_esc(obs.value)}']"


def identity(now: str) -> Dict[str, Any]:
    return {
        "type": "identity", "spec_version": "2.1", "id": IDENTITY_ID,
        "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
        "name": "S.T.A.R.K", "identity_class": "system",
        "description": "Security Threat Assessment and Reputation Kit - consolidated OSINT reputation lookups.",
    }


def _tlp_definition(ref: str) -> Dict[str, Any]:
    name = _TLP_DEFS[ref]
    return {
        "type": "marking-definition", "spec_version": "2.1", "id": ref,
        "created": "2022-10-01T00:00:00.000Z", "name": f"TLP:{name.upper()}",
        "extensions": {"extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d":
                       {"extension_type": "property-extension", "tlp_2_0": name}},
    }


def to_bundle(
    reports: Iterable[ObservableReport],
    all_indicators: bool = False,
    tlp: str = "clear",
    include_notes: bool = True,
) -> Dict[str, Any]:
    now = utcnow()
    tlp_ref = TLP.get(tlp.lower(), TLP_CLEAR)
    marking = [tlp_ref]
    objects: List[Dict[str, Any]] = [identity(now), _tlp_definition(tlp_ref)]
    malware_ids: Dict[str, str] = {}

    for rep in reports:
        obs = rep.observable
        sco = sco_for(obs)
        sco["object_marking_refs"] = marking
        objects.append(sco)
        verdict = rep.verdict
        ext_refs = [
            {"source_name": r.provider, "url": r.link, "description": r.summary[:500]}
            for r in rep.results if r.link
        ]
        indicator_id = None
        if all_indicators or verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            indicator_id = _det_id("indicator", obs.type.value, obs.value, now)
            itypes = {Verdict.MALICIOUS: ["malicious-activity"],
                      Verdict.SUSPICIOUS: ["anomalous-activity"]}.get(verdict, ["unknown"])
            ind = {
                "type": "indicator", "spec_version": "2.1", "id": indicator_id,
                "created": now, "modified": now, "created_by_ref": IDENTITY_ID,
                "name": f"{obs.type.value}: {obs.value}",
                "description": f"S.T.A.R.K consolidated verdict: {verdict.value}. Flagged by: "
                               f"{', '.join(rep.flagged_by) or 'none'}.",
                "indicator_types": itypes,
                "pattern": pattern_for(obs), "pattern_type": "stix", "pattern_version": "2.1",
                "valid_from": now,
                "labels": [verdict.value] + rep.tags[:10],
                "object_marking_refs": marking,
                "x_stark_verdict": verdict.value,
            }
            if rep.score is not None:
                ind["confidence"] = max(0, min(100, int(rep.score)))
            if ext_refs:
                ind["external_references"] = ext_refs
            objects.append(ind)
            objects.append(_rel(indicator_id, "based-on", sco["id"], now, marking))
            for fam in rep.malware_families:
                key = fam.lower()
                if key not in malware_ids:
                    malware_ids[key] = _det_id("malware", key)
                    objects.append({
                        "type": "malware", "spec_version": "2.1", "id": malware_ids[key],
                        "created": now, "modified": now, "created_by_ref": IDENTITY_ID,
                        "name": fam, "is_family": True, "object_marking_refs": marking,
                    })
                objects.append(_rel(indicator_id, "indicates", malware_ids[key], now, marking))

        if include_notes and rep.results:
            refs = [sco["id"]] + ([indicator_id] if indicator_id else [])
            lines = [f"{r.provider}: {r.verdict.value}" + (f" - {r.summary}" if r.summary else "")
                     + (f" (error: {r.error})" if r.error else "") for r in rep.results]
            objects.append({
                "type": "note", "spec_version": "2.1", "id": _det_id("note", obs.type.value, obs.value, now),
                "created": now, "modified": now, "created_by_ref": IDENTITY_ID,
                "abstract": f"S.T.A.R.K reputation results for {obs.value}: {verdict.value}",
                "content": "\n".join(lines), "authors": ["S.T.A.R.K"], "object_refs": refs,
                "object_marking_refs": marking,
                "x_stark_results": [r.to_dict() for r in rep.results],
            })

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects,
            "x_stark_version": __version__}


def _rel(src: str, rtype: str, tgt: str, now: str, marking: List[str]) -> Dict[str, Any]:
    return {
        "type": "relationship", "spec_version": "2.1", "id": _det_id("relationship", src, rtype, tgt),
        "created": now, "modified": now, "created_by_ref": IDENTITY_ID,
        "relationship_type": rtype, "source_ref": src, "target_ref": tgt, "object_marking_refs": marking,
    }


# --------------------------------------------------------------------------- #
# Import
# --------------------------------------------------------------------------- #

_PATTERN_TERM = re.compile(
    r"(?P<obj>ipv4-addr|ipv6-addr|domain-name|url|email-addr|email-message|file|network-traffic)"
    r":(?P<path>[\w.'\-\[\]*]+)\s*(?:=|LIKE)\s*'(?P<val>(?:[^'\\]|\\.)*)'",
    re.I,
)
_HASH_PATH = re.compile(r"hashes\.'?(md5|sha-?1|sha-?256)'?", re.I)


def observables_from_pattern(pattern: str) -> Iterator[Observable]:
    for m in _PATTERN_TERM.finditer(pattern):
        val = m.group("val").replace("\\'", "'").replace("\\\\", "\\")
        obj, path = m.group("obj").lower(), m.group("path")
        forced = None
        if obj == "file":
            hm = _HASH_PATH.search(path)
            if not hm:
                continue
        elif obj == "url":
            forced = ObsType.URL
        o = parse_observable(val, forced=forced, source="stix")
        if o:
            yield o


def observables_from_bundle(data: Any) -> List[Observable]:
    if isinstance(data, dict) and data.get("type") == "bundle":
        objects = data.get("objects") or []
    elif isinstance(data, dict) and "objects" in data:  # TAXII envelope
        objects = data["objects"]
    elif isinstance(data, list):
        objects = data
    else:
        objects = [data]
    out: List[Observable] = []

    def add(o: Optional[Observable]):
        if o and o not in out:
            out.append(o)

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        t = obj.get("type")
        if t == "indicator" and obj.get("pattern_type", "stix") == "stix" and obj.get("pattern"):
            for o in observables_from_pattern(obj["pattern"]):
                add(o)
        elif t in ("ipv4-addr", "ipv6-addr", "domain-name", "email-addr"):
            add(parse_observable(str(obj.get("value", "")), source="stix"))
        elif t == "url":
            add(parse_observable(str(obj.get("value", "")), forced=ObsType.URL, source="stix"))
        elif t == "file":
            hashes = obj.get("hashes") or {}
            for k in ("SHA-256", "SHA256", "SHA-1", "SHA1", "MD5"):
                if hashes.get(k):
                    add(parse_observable(hashes[k], source="stix"))
                    break
    return out


def load_bundle(path: str) -> List[Observable]:
    with open(path, "r", encoding="utf-8-sig") as fh:
        return observables_from_bundle(json.load(fh))
