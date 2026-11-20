import base64
from urllib.parse import quote

from ..models import Verdict
from ..observables import ALL_TYPES, ObsType
from .base import Provider

_KIND = {
    ObsType.IPV4: ("ip_addresses", "ip-address"),
    ObsType.IPV6: ("ip_addresses", "ip-address"),
    ObsType.DOMAIN: ("domains", "domain"),
    ObsType.URL: ("urls", "url"),
    ObsType.MD5: ("files", "file"),
    ObsType.SHA1: ("files", "file"),
    ObsType.SHA256: ("files", "file"),
}


class VirusTotal(Provider):
    name = "virustotal"
    display = "VirusTotal"
    homepage = "https://www.virustotal.com"
    supported = ALL_TYPES - {ObsType.EMAIL}
    rate_limit = 4  # public API: 4 requests / minute
    description = "Multi-engine AV / URL scanner verdicts (API v3)."

    BASE = "https://www.virustotal.com/api/v3"

    def query(self, obs):
        api, gui = _KIND[obs.type]
        ident = obs.value
        if obs.type is ObsType.URL:
            ident = base64.urlsafe_b64encode(obs.value.encode()).decode().rstrip("=")
        data = self.get_json(f"{self.BASE}/{api}/{quote(ident, safe='')}",
                             headers={"x-apikey": self.api_key})
        attr = data["data"]["attributes"]
        stats = attr.get("last_analysis_stats") or {}
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int))
        if mal >= 3:
            verdict = Verdict.MALICIOUS
        elif mal or sus:
            verdict = Verdict.SUSPICIOUS
        elif total:
            verdict = Verdict.HARMLESS
        else:
            verdict = Verdict.UNKNOWN
        families = []
        ptc = attr.get("popular_threat_classification") or {}
        if ptc.get("suggested_threat_label"):
            families.append(ptc["suggested_threat_label"])
        for item in ptc.get("popular_threat_name") or []:
            if item.get("value") and item["value"] not in families:
                families.append(item["value"])
        parts = [f"{mal}/{total} engines malicious"]
        if sus:
            parts.append(f"{sus} suspicious")
        if attr.get("reputation") is not None:
            parts.append(f"reputation {attr['reputation']}")
        if attr.get("meaningful_name"):
            parts.append(attr["meaningful_name"])
        if attr.get("as_owner"):
            parts.append(attr["as_owner"])
        gui_id = data["data"].get("id", ident)
        return self.result(
            obs, verdict,
            score=round(100 * mal / total) if total else None,
            summary=", ".join(parts),
            tags=list(attr.get("tags") or [])[:10],
            malware_families=families[:5],
            link=f"https://www.virustotal.com/gui/{gui}/{gui_id}",
            details={"last_analysis_stats": stats, "reputation": attr.get("reputation"),
                     "country": attr.get("country"), "type_description": attr.get("type_description")},
        )
