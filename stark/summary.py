"""Relevance filtering and one-paragraph reputation summaries for investigations.

In an investigation only sources that actually have an opinion matter. Results from
sources that errored (missing or rejected key, quota, timeout), that don't cover the
observable, or that simply have no record are dropped, so they never clutter a case
or a report with error messages.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .observables import defang

RELEVANT = ("malicious", "suspicious", "harmless")
TYPE_LABEL = {"ipv4": "IP address", "ipv6": "IPv6 address", "domain": "domain", "url": "URL", "md5": "file hash (MD5)",
              "sha1": "file hash (SHA-1)", "sha256": "file hash (SHA-256)", "email": "email address"}


def relevant(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep only results that carry a verdict (no errors, no 'no data')."""
    return [r for r in results if r.get("verdict") in RELEVANT]


def filter_report(rep: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of an ObservableReport.to_dict() with non-relevant sources removed and counters fixed."""
    out = dict(rep)
    rel = relevant(rep.get("results") or [])
    out["sources_checked"] = len(rep.get("results") or [])
    out["results"] = rel
    out["errors"] = 0
    out["unknown"] = 0
    if rep.get("verdict") in ("error", "unknown") or not rel:
        out["verdict"] = "unknown"
    out["summary"] = quick_summary(out)
    return out


def quick_summary(rep: Dict[str, Any]) -> str:
    """Plain-language verdict sentence, e.g. for a pasted IOC. Indicators are defanged."""
    value = defang(rep["observable"])
    kind = TYPE_LABEL.get(rep.get("type"), rep.get("type", "indicator"))
    res = relevant(rep.get("results") or [])
    if not res:
        return (f"No reputation source has data on the {kind} {value}. That isn't proof it's safe: new or targeted "
                f"infrastructure is often unrated. Judge it by where it appeared in your logs.")
    bad = [r for r in res if r["verdict"] == "malicious"]
    sus = [r for r in res if r["verdict"] == "suspicious"]
    ok = [r for r in res if r["verdict"] == "harmless"]
    verdict = rep.get("verdict", "unknown")
    lead = {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS", "harmless": "likely clean"}.get(verdict, "unrated")
    parts = [f"The {kind} {value} is {lead}: "]
    counts = []
    if bad:
        counts.append(f"{len(bad)} source{'s' if len(bad) != 1 else ''} rate it malicious ({', '.join(r['provider'] for r in bad)})")
    if sus:
        counts.append(f"{len(sus)} suspicious ({', '.join(r['provider'] for r in sus)})")
    if ok:
        counts.append(f"{len(ok)} clean ({', '.join(r['provider'] for r in ok)})")
    parts.append("; ".join(counts) + ".")
    fams = rep.get("malware_families") or []
    if fams:
        parts.append(f" Associated with {', '.join(fams[:4])}.")
    top = (bad or sus or ok)[0]
    if top.get("summary"):
        parts.append(f" {top['provider']}: {defang_summary(top['summary'], rep['observable'])}.")
    parts.append({"malicious": " Recommended: block it and search your logs for any contact with it.",
                  "suspicious": " Recommended: investigate where it was seen before blocking.",
                  "harmless": " No action needed unless other evidence says otherwise."}.get(verdict, ""))
    return "".join(parts)


def defang_summary(text: str, value: str) -> str:
    from .observables import defang_text
    return defang_text(str(text).rstrip(".")).replace(value, defang(value))
