from ..models import Verdict
from ..observables import IP_TYPES
from .base import Provider, score_to_verdict


class AbuseIPDB(Provider):
    name = "abuseipdb"
    display = "AbuseIPDB"
    homepage = "https://www.abuseipdb.com"
    supported = IP_TYPES
    rate_limit = 60
    description = "Crowd-sourced IP abuse reports and confidence score."

    def query(self, obs):
        data = self.get_json(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": obs.value, "maxAgeInDays": self.settings.get("max_age_days", 90)},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )["data"]
        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        verdict = score_to_verdict(score, 75, 25)
        if data.get("isWhitelisted"):
            verdict = Verdict.HARMLESS
        tags = [t for t, on in (("tor", data.get("isTor")), ("whitelisted", data.get("isWhitelisted"))) if on]
        if data.get("usageType"):
            tags.append(data["usageType"])
        return self.result(
            obs, verdict, score=score,
            summary=f"confidence {score}%, {reports} reports from {data.get('numDistinctUsers', 0)} users"
                    f" | {data.get('isp') or '?'} ({data.get('countryCode') or '?'})",
            tags=tags,
            link=f"https://www.abuseipdb.com/check/{obs.value}",
            details={k: data.get(k) for k in ("countryCode", "isp", "domain", "usageType",
                                              "totalReports", "lastReportedAt", "isTor")},
        )
