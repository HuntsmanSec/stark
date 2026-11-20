"""abuse.ch services: MalwareBazaar, ThreatFox, URLhaus (one shared Auth-Key)."""

from ..models import Verdict
from ..observables import HASH_TYPES, IP_TYPES, ObsType
from .base import NotFound, Provider, ProviderError


class _AbuseCh(Provider):
    key_name = "abusech"
    rate_limit = 60

    def _headers(self):
        return {"Auth-Key": self.api_key}

    @staticmethod
    def _status(data):
        status = data.get("query_status")
        if status in ("ok",):
            return
        if status in ("hash_not_found", "no_result", "no_results", "illegal_search_term", "not_found"):
            raise NotFound("Not in database")
        if status in ("unknown_auth_key", "wrong_auth_key"):
            raise ProviderError("abuse.ch Auth-Key rejected")
        raise ProviderError(f"abuse.ch: {status}")


class MalwareBazaar(_AbuseCh):
    name = "malwarebazaar"
    display = "MalwareBazaar"
    homepage = "https://bazaar.abuse.ch"
    supported = HASH_TYPES
    description = "abuse.ch malware sample repository (hash lookups)."

    def query(self, obs):
        data = self.post_json("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": obs.value},
                              headers=self._headers())
        self._status(data)
        s = (data.get("data") or [{}])[0]
        sig = s.get("signature")
        return self.result(
            obs, Verdict.MALICIOUS, score=100,
            summary=f"{sig or 'unclassified'} sample, {s.get('file_type', '?')}, first seen {s.get('first_seen', '?')}"
                    + (f" ({s['file_name']})" if s.get("file_name") else ""),
            tags=list(s.get("tags") or [])[:10],
            malware_families=[sig] if sig else [],
            link=f"https://bazaar.abuse.ch/sample/{s.get('sha256_hash', obs.value)}/",
            details={k: s.get(k) for k in ("sha256_hash", "md5_hash", "sha1_hash", "file_name", "file_type",
                                           "first_seen", "last_seen", "reporter", "delivery_method")},
        )


class ThreatFox(_AbuseCh):
    name = "threatfox"
    display = "ThreatFox"
    homepage = "https://threatfox.abuse.ch"
    supported = HASH_TYPES | IP_TYPES | {ObsType.DOMAIN, ObsType.URL}
    description = "abuse.ch IOC database (C2, payload delivery, botnets)."

    def query(self, obs):
        if obs.type in HASH_TYPES:
            body = {"query": "search_hash", "hash": obs.value}
        else:
            body = {"query": "search_ioc", "search_term": obs.value, "exact_match": True}
        data = self.post_json("https://threatfox-api.abuse.ch/api/v1/", json=body, headers=self._headers())
        self._status(data)
        items = data.get("data") or []
        if not items or not isinstance(items, list):
            raise NotFound("Not in database")
        top = max(items, key=lambda i: i.get("confidence_level") or 0)
        fams = list(dict.fromkeys(i.get("malware_printable") for i in items if i.get("malware_printable")))
        conf = top.get("confidence_level") or 0
        return self.result(
            obs, Verdict.MALICIOUS if conf >= 50 else Verdict.SUSPICIOUS, score=conf,
            summary=f"{len(items)} IOC record(s): {top.get('threat_type_desc') or top.get('threat_type')}"
                    f" / {top.get('malware_printable', '?')} (confidence {conf}%)",
            tags=list(dict.fromkeys(t for i in items for t in (i.get("tags") or [])))[:10],
            malware_families=fams[:5],
            link=f"https://threatfox.abuse.ch/ioc/{top['id']}/" if top.get("id") else "https://threatfox.abuse.ch",
            details={"records": len(items), "first_seen": top.get("first_seen"), "threat_type": top.get("threat_type")},
        )


class URLhaus(_AbuseCh):
    name = "urlhaus"
    display = "URLhaus"
    homepage = "https://urlhaus.abuse.ch"
    supported = HASH_TYPES - {ObsType.SHA1} | IP_TYPES | {ObsType.DOMAIN, ObsType.URL}
    description = "abuse.ch malware distribution URL database."

    API = "https://urlhaus-api.abuse.ch/v1"

    def query(self, obs):
        h = self._headers()
        if obs.type is ObsType.URL:
            d = self.post_json(f"{self.API}/url/", data={"url": obs.value}, headers=h)
            self._status(d)
            online = d.get("url_status") == "online"
            return self.result(
                obs, Verdict.MALICIOUS, score=100,
                summary=f"malware URL ({d.get('url_status')}), threat {d.get('threat')}, added {d.get('date_added')}",
                tags=list(d.get("tags") or [])[:10],
                link=d.get("urlhaus_reference"), details={"online": online, "threat": d.get("threat")},
            )
        if obs.type in HASH_TYPES:
            key = "md5_hash" if obs.type is ObsType.MD5 else "sha256_hash"
            d = self.post_json(f"{self.API}/payload/", data={key: obs.value}, headers=h)
            self._status(d)
            sig = d.get("signature")
            return self.result(
                obs, Verdict.MALICIOUS, score=100,
                summary=f"payload seen on {d.get('url_count', '?')} URL(s), {d.get('file_type', '?')}",
                malware_families=[sig] if sig else [],
                link=f"https://urlhaus.abuse.ch/browse.php?search={obs.value}",
                details={"url_count": d.get("url_count"), "firstseen": d.get("firstseen")},
            )
        d = self.post_json(f"{self.API}/host/", data={"host": obs.value}, headers=h)
        self._status(d)
        urls = d.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        bl = {k: v for k, v in (d.get("blacklists") or {}).items() if v and v != "not listed"}
        return self.result(
            obs, Verdict.MALICIOUS if urls else Verdict.SUSPICIOUS, score=100 if online else 80,
            summary=f"hosted {d.get('url_count', len(urls))} malware URL(s), {online} online"
                    + (f"; blocklists: {', '.join(bl)}" if bl else ""),
            tags=list(dict.fromkeys(t for u in urls for t in (u.get("tags") or [])))[:10],
            link=d.get("urlhaus_reference"), details={"url_count": d.get("url_count"), "blacklists": bl},
        )
