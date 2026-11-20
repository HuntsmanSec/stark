from urllib.parse import quote

from ..models import Verdict
from ..observables import ObsType
from .base import NotFound, Provider


class HaveIBeenPwned(Provider):
    name = "hibp"
    display = "Have I Been Pwned"
    homepage = "https://haveibeenpwned.com"
    supported = frozenset({ObsType.EMAIL})
    rate_limit = 10  # Pwned 1 plan; raise via [providers.hibp] rate_limit
    description = "Breaches an email address appears in (API v3)."

    def query(self, obs):
        try:
            breaches = self.get_json(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(obs.value, safe='')}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": self.api_key},
            )
        except NotFound:
            return self.result(obs, Verdict.HARMLESS, score=0, summary="Not found in any breach",
                               link=f"https://haveibeenpwned.com/account/{quote(obs.value)}")
        names = [b.get("Name") for b in breaches]
        classes = sorted({c for b in breaches for c in b.get("DataClasses") or []})
        verified = sum(1 for b in breaches if b.get("IsVerified"))
        latest = max((b.get("BreachDate") or "") for b in breaches) if breaches else ""
        if not breaches:
            raise NotFound("Not found in any breach")
        return self.result(
            obs, Verdict.SUSPICIOUS, score=min(100, 20 * len(breaches)),
            summary=f"exposed in {len(breaches)} breach(es) ({verified} verified), latest {latest}: "
                    + ", ".join(names[:5]),
            tags=classes[:10],
            link=f"https://haveibeenpwned.com/account/{quote(obs.value)}",
            details={"breaches": names, "data_classes": classes},
        )
