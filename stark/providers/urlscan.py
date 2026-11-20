from ..models import Verdict
from ..observables import IP_TYPES, ObsType
from .base import NotFound, Provider


def _q(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class URLScan(Provider):
    name = "urlscan"
    display = "urlscan.io"
    homepage = "https://urlscan.io"
    supported = IP_TYPES | {ObsType.DOMAIN, ObsType.URL, ObsType.SHA256}
    rate_limit = 30
    description = "Passive search of existing public scans (no new scan is submitted)."

    def _headers(self):
        return {"API-Key": self.api_key} if self.api_key else {}

    def query(self, obs):
        if obs.type in IP_TYPES:
            q = f"ip:{_q(obs.value)}"
        elif obs.type is ObsType.DOMAIN:
            q = f"domain:{obs.value}"
        elif obs.type is ObsType.URL:
            q = f"page.url:{_q(obs.value)}"
        else:
            q = f"hash:{obs.value}"
        data = self.get_json("https://urlscan.io/api/v1/search/", params={"q": q, "size": 10},
                             headers=self._headers())
        hits = data.get("results") or []
        if not hits:
            raise NotFound("No public scans")
        total = data.get("total", len(hits))
        latest = hits[0]
        uuid = latest.get("_id") or latest.get("task", {}).get("uuid")
        verdicts = latest.get("verdicts") or {}
        if not verdicts and uuid:
            try:
                full = self.get_json(f"https://urlscan.io/api/v1/result/{uuid}/", headers=self._headers())
                verdicts = full.get("verdicts") or {}
            except NotFound:
                verdicts = {}
        overall = verdicts.get("overall") or {}
        score = overall.get("score")
        if overall.get("malicious"):
            verdict = Verdict.MALICIOUS
        elif score is not None and score > 0:
            verdict = Verdict.SUSPICIOUS
        elif overall:
            verdict = Verdict.HARMLESS
        else:
            verdict = Verdict.UNKNOWN
        tags = list(dict.fromkeys((overall.get("categories") or []) + (overall.get("tags") or [])))
        families = list(overall.get("brands") or [])
        page = latest.get("page") or {}
        summary = f"{total} public scan(s); latest {latest.get('task', {}).get('time', '?')[:10]}"
        if page.get("domain"):
            summary += f" {page['domain']}"
        if page.get("ip"):
            summary += f" ({page['ip']}, {page.get('asnname', '')})"
        if score is not None:
            summary += f", urlscan score {score}"
        return self.result(
            obs, verdict,
            score=max(0, min(100, int(score))) if isinstance(score, (int, float)) else None,
            summary=summary, tags=tags[:10], malware_families=[str(b) for b in families][:5],
            link=f"https://urlscan.io/result/{uuid}/" if uuid else f"https://urlscan.io/search/#{q}",
            details={"total": total, "verdicts": overall, "latest_uuid": uuid},
        )
