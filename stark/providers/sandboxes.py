"""Malware sandboxes: ANY.RUN, Joe Sandbox, Hybrid Analysis."""

import json
from urllib.parse import quote

from ..models import Verdict
from ..observables import ALL_TYPES, HASH_TYPES, IP_TYPES, ObsType
from .base import NotFound, Provider

# ---------------------------------------------------------------------------- ANY.RUN


class AnyRun(Provider):
    name = "anyrun"
    display = "ANY.RUN"
    homepage = "https://any.run"
    supported = ALL_TYPES - {ObsType.EMAIL}
    rate_limit = 30
    description = "ANY.RUN Threat Intelligence Lookup (requires a TI Lookup API key)."

    _FIELD = {
        ObsType.IPV4: "destinationIP", ObsType.IPV6: "destinationIP",
        ObsType.DOMAIN: "domainName", ObsType.URL: "url",
        ObsType.MD5: "md5", ObsType.SHA1: "sha1", ObsType.SHA256: "sha256",
    }

    def query(self, obs):
        q = f'{self._FIELD[obs.type]}:"{obs.value}"'
        data = self.post_json(
            "https://api.any.run/v1/intelligence/api/search",
            json={"query": q, "lookupDepth": int(self.settings.get("max_age_days", 90))},
            headers={"Authorization": f"API-Key {self.api_key}"},
        )
        summary = data.get("summary") or {}
        tasks = data.get("sourceTasks") or data.get("relatedTasks") or []
        if not summary and not tasks:
            raise NotFound("No ANY.RUN data")
        level = summary.get("threatLevel")
        verdict = {2: Verdict.MALICIOUS, 1: Verdict.SUSPICIOUS, 0: Verdict.HARMLESS}.get(level, Verdict.UNKNOWN)
        tags = [t.get("tag") if isinstance(t, dict) else str(t) for t in summary.get("tags") or []]
        families = [t for t in tags if t]
        text = f"threat level {level if level is not None else '?'}, {len(tasks)} related task(s)"
        if summary.get("lastSeen"):
            text += f", last seen {str(summary['lastSeen'])[:10]}"
        return self.result(
            obs, verdict, score={2: 100, 1: 50, 0: 0}.get(level),
            summary=text, tags=tags[:10], malware_families=families[:5],
            link="https://intelligence.any.run/analysis/lookup#" + quote(json.dumps({"query": q})),
            details={"summary": summary},
        )


# ------------------------------------------------------------------------- Joe Sandbox


class JoeSandbox(Provider):
    name = "joesandbox"
    display = "Joe Sandbox"
    homepage = "https://www.joesandbox.com"
    supported = ALL_TYPES - {ObsType.EMAIL}
    rate_limit = 30
    description = "Search existing Joe Sandbox Cloud analyses (set providers.joesandbox.base_url for on-prem)."

    def query(self, obs):
        base = self.options.get("base_url", "https://jbxcloud.joesecurity.org/api").rstrip("/")
        data = self.post_json(f"{base}/v2/analysis/search", data={"apikey": self.api_key, "q": obs.value})
        items = data.get("data") or []
        if not items:
            raise NotFound("No analyses")
        order = {"malicious": 4, "suspicious": 3, "clean": 2, "unknown": 1}
        best = max(items, key=lambda i: order.get(str(i.get("detection", "")).lower(), 0))
        det = str(best.get("detection", "unknown")).lower()
        verdict = {"malicious": Verdict.MALICIOUS, "suspicious": Verdict.SUSPICIOUS,
                   "clean": Verdict.HARMLESS}.get(det, Verdict.UNKNOWN)
        score = best.get("score")
        try:
            score = int(score) if score is not None else None
            if score is not None and score <= 10:  # Joe uses a 0-10 scale in some APIs
                score *= 10
        except (TypeError, ValueError):
            score = None
        webid = best.get("webid")
        families = [c for c in (best.get("classification") or "").split(",") if c.strip()]
        return self.result(
            obs, verdict, score=score,
            summary=f"{len(items)} analysis/analyses, worst: {det}"
                    + (f" ({best.get('filename')})" if best.get("filename") else ""),
            malware_families=[f.strip() for f in families][:5],
            link=f"https://www.joesandbox.com/analysis/{webid}" if webid else "https://www.joesandbox.com",
            details={"analyses": len(items), "best": {k: best.get(k) for k in ("webid", "detection", "score", "time")}},
        )


# --------------------------------------------------------------------- Hybrid Analysis


class HybridAnalysis(Provider):
    name = "hybridanalysis"
    display = "Hybrid Analysis"
    homepage = "https://www.hybrid-analysis.com"
    supported = HASH_TYPES | IP_TYPES | {ObsType.DOMAIN, ObsType.URL}
    rate_limit = 60
    description = "CrowdStrike Falcon Sandbox public reports."

    BASE = "https://www.hybrid-analysis.com/api/v2"

    def _headers(self):
        return {"api-key": self.api_key, "User-Agent": "Falcon Sandbox", "accept": "application/json"}

    def query(self, obs):
        if obs.type in HASH_TYPES:
            data = self.get_json(f"{self.BASE}/search/hash", params={"hash": obs.value}, headers=self._headers())
            if isinstance(data, dict):
                items = data.get("reports") or data.get("result") or []
            else:
                items = data or []
        else:
            field = {ObsType.DOMAIN: "domain", ObsType.URL: "url"}.get(obs.type, "host")
            data = self.post_json(f"{self.BASE}/search/terms", data={field: obs.value}, headers=self._headers())
            items = data.get("result") or []
        if not items:
            raise NotFound("No reports")
        order = {"malicious": 4, "suspicious": 3, "no specific threat": 2, "whitelisted": 2}
        best = max(items, key=lambda i: (order.get(str(i.get("verdict", "")).lower(), 0), i.get("threat_score") or 0))
        v = str(best.get("verdict") or "").lower()
        verdict = {"malicious": Verdict.MALICIOUS, "suspicious": Verdict.SUSPICIOUS,
                   "no specific threat": Verdict.HARMLESS, "whitelisted": Verdict.HARMLESS}.get(v, Verdict.UNKNOWN)
        fam = best.get("vx_family")
        sha = best.get("sha256")
        return self.result(
            obs, verdict, score=best.get("threat_score"),
            summary=f"{len(items)} report(s), worst: {v or 'n/a'}"
                    + (f", threat score {best['threat_score']}" if best.get("threat_score") is not None else ""),
            malware_families=[fam] if fam else [],
            tags=list(best.get("tags") or [])[:10],
            link=f"https://www.hybrid-analysis.com/sample/{sha}" if sha
                 else f"https://www.hybrid-analysis.com/search?query={obs.value}",
            details={"reports": len(items)},
        )
