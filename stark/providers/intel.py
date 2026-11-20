"""Threat-intelligence platforms: Recorded Future, AlienVault OTX, Pulsedive, GreyNoise."""

from urllib.parse import quote

from ..models import Verdict
from ..observables import ALL_TYPES, ObsType
from .base import NotFound, Provider

# ------------------------------------------------------------------- Recorded Future


class RecordedFuture(Provider):
    name = "recordedfuture"
    display = "Recorded Future"
    homepage = "https://www.recordedfuture.com"
    supported = ALL_TYPES - {ObsType.EMAIL}
    rate_limit = 60
    description = "Recorded Future Connect API v2 risk score and triggered risk rules."

    _ENTITY = {ObsType.IPV4: "ip", ObsType.IPV6: "ip", ObsType.DOMAIN: "domain",
               ObsType.URL: "url", ObsType.MD5: "hash", ObsType.SHA1: "hash", ObsType.SHA256: "hash"}

    def query(self, obs):
        ent = self._ENTITY[obs.type]
        data = self.get_json(
            f"https://api.recordedfuture.com/v2/{ent}/{quote(obs.value, safe='')}",
            params={"fields": "risk,intelCard,entity,sightings"},
            headers={"X-RFToken": self.api_key},
        ).get("data") or {}
        risk = data.get("risk") or {}
        score = risk.get("score")
        crit = risk.get("criticality")
        if crit is None:
            verdict = Verdict.UNKNOWN
        elif crit >= 3 or (score or 0) >= 65:
            verdict = Verdict.MALICIOUS
        elif crit >= 2 or (score or 0) >= 25:
            verdict = Verdict.SUSPICIOUS
        elif (score or 0) == 0 and crit == 0:
            verdict = Verdict.HARMLESS
        else:
            verdict = Verdict.SUSPICIOUS if (score or 0) >= 5 else Verdict.HARMLESS
        rules = [e.get("rule") for e in risk.get("evidenceDetails") or [] if e.get("rule")]
        return self.result(
            obs, verdict, score=score,
            summary=f"risk {score if score is not None else '?'}/99 ({risk.get('criticalityLabel', 'n/a')})"
                    + (f" - {risk['riskSummary']}" if risk.get("riskSummary") else ""),
            tags=rules[:10],
            link=data.get("intelCard") or "https://app.recordedfuture.com",
            details={"criticality": crit, "rules": rules},
        )


# ------------------------------------------------------------------------------ OTX

# OTX "validation" sources that mean the indicator is known-good infrastructure.
_OTX_ALLOWLISTS = frozenset({"whitelist", "false_positive", "alexa", "majestic", "akamai", "cloud",
                             "major_cdn", "umbrella", "tranco"})


class OTX(Provider):
    name = "otx"
    display = "AlienVault OTX"
    homepage = "https://otx.alienvault.com"
    supported = ALL_TYPES - {ObsType.EMAIL}
    requires_key = False  # general endpoint works without a key; a key raises limits
    rate_limit = 60
    description = "LevelBlue/AlienVault Open Threat Exchange pulses."

    def query(self, obs):
        section = {ObsType.IPV4: "IPv4", ObsType.IPV6: "IPv6", ObsType.DOMAIN: "domain",
                   ObsType.URL: "url"}.get(obs.type, "file")
        ident = quote(obs.value, safe="") if obs.type is ObsType.URL else obs.value
        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        data = self.get_json(f"https://otx.alienvault.com/api/v1/indicators/{section}/{ident}/general",
                             headers=headers)
        pulses = (data.get("pulse_info") or {}).get("pulses") or []
        count = (data.get("pulse_info") or {}).get("count", len(pulses))
        # Pulses are community-curated and noisy (popular infrastructure appears in many),
        # so OTX alone never escalates beyond "suspicious".
        validation = [v.get("source") for v in data.get("validation") or [] if v.get("source")]
        allow = [v for v in validation if v in _OTX_ALLOWLISTS]
        whitelisted = bool(allow)
        if whitelisted:
            verdict = Verdict.HARMLESS
        elif count > 0:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.UNKNOWN
        tags, families = [], []
        for p in pulses[:25]:
            for t in p.get("tags") or []:
                if t not in tags:
                    tags.append(t)
            for m in p.get("malware_families") or []:
                n = m.get("display_name") if isinstance(m, dict) else m
                if n and n not in families:
                    families.append(n)
        gui = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "url": "url", "file": "file"}[section]
        return self.result(
            obs, verdict, score=0 if whitelisted else (min(70, count * 5) if count else None),
            summary=f"{count} pulse(s)" + (f": {pulses[0].get('name')}" if pulses else "")
                    + (f" [allow-listed: {', '.join(allow)}]" if whitelisted else ""),
            # OTX pulse "malware_families" are free-form community labels (often pulse or author
            # names), so they are reported as tags, never as malware families.
            tags=[v for v in validation if v not in allow] + families[:5] + tags[:10],
            link=f"https://otx.alienvault.com/indicator/{gui}/{ident}",
            details={"pulse_count": count, "validation": validation},
        )


# ------------------------------------------------------------------------ Pulsedive


class Pulsedive(Provider):
    name = "pulsedive"
    display = "Pulsedive"
    homepage = "https://pulsedive.com"
    supported = ALL_TYPES - {ObsType.EMAIL}
    requires_key = False
    rate_limit = 30
    description = "Community threat intelligence risk rating."

    def query(self, obs):
        params = {"indicator": obs.value}
        if self.api_key:
            params["key"] = self.api_key
        data = self.get_json("https://pulsedive.com/api/info.php", params=params)
        if data.get("error"):
            if "not found" in str(data["error"]).lower():
                raise NotFound("Indicator not found")
            raise ValueError(data["error"])
        risk = str(data.get("risk") or "unknown").lower()
        verdict = {"critical": Verdict.MALICIOUS, "high": Verdict.MALICIOUS, "medium": Verdict.SUSPICIOUS,
                   "low": Verdict.SUSPICIOUS, "none": Verdict.HARMLESS}.get(risk, Verdict.UNKNOWN)
        threats = [t.get("name") for t in data.get("threats") or [] if t.get("name")]
        return self.result(
            obs, verdict, score={"critical": 100, "high": 80, "medium": 50, "low": 25, "none": 0}.get(risk),
            summary=f"risk {risk}" + (f", threats: {', '.join(threats[:3])}" if threats else ""),
            malware_families=threats[:5],
            link=f"https://pulsedive.com/indicator/?iid={data['iid']}" if data.get("iid") else "https://pulsedive.com",
            details={"risk": risk, "risk_factors": [f.get("description") for f in data.get("riskfactors") or []]},
        )


# ------------------------------------------------------------------------ GreyNoise


class GreyNoise(Provider):
    name = "greynoise"
    display = "GreyNoise"
    homepage = "https://www.greynoise.io"
    supported = frozenset({ObsType.IPV4})
    requires_key = False  # community API works without a key at low volume
    rate_limit = 10
    description = "Internet background noise / benign scanner classification (Community API)."

    def query(self, obs):
        headers = {"key": self.api_key} if self.api_key else {}
        data = self.get_json(f"https://api.greynoise.io/v3/community/{obs.value}", headers=headers)
        cls = str(data.get("classification") or "unknown").lower()
        if data.get("riot") or cls == "benign":
            verdict = Verdict.HARMLESS
        elif cls == "malicious":
            verdict = Verdict.MALICIOUS
        elif data.get("noise"):
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.UNKNOWN
        tags = [t for t, on in (("noise", data.get("noise")), ("riot", data.get("riot"))) if on]
        return self.result(
            obs, verdict,
            summary=f"{cls}" + (f" - {data['name']}" if data.get("name") and data["name"] != "unknown" else "")
                    + (f", last seen {data['last_seen']}" if data.get("last_seen") else ""),
            tags=tags,
            link=data.get("link") or f"https://viz.greynoise.io/ip/{obs.value}",
            details={k: data.get(k) for k in ("noise", "riot", "classification", "name", "last_seen")},
        )
