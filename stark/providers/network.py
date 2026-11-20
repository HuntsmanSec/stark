"""Network / infrastructure sources: Shodan, MXToolbox, Cisco Talos, IPinfo, crt.sh."""

import ipaddress
import threading
import time

from ..models import Verdict
from ..observables import IP_TYPES, ObsType
from .base import NotFound, Provider, ProviderError

# --------------------------------------------------------------------------- Shodan


class Shodan(Provider):
    name = "shodan"
    display = "Shodan"
    homepage = "https://www.shodan.io"
    supported = IP_TYPES | {ObsType.DOMAIN}
    rate_limit = 60
    description = "Exposed services, banners, CVEs and tags for an IP (domains are resolved first)."

    BAD_TAGS = {"malware", "c2", "compromised", "botnet", "honeypot", "tor", "scanner", "proxy", "vpn"}

    def query(self, obs):
        ip = obs.value
        if obs.type is ObsType.DOMAIN:
            res = self.get_json("https://api.shodan.io/dns/resolve",
                                params={"hostnames": obs.value, "key": self.api_key})
            ip = res.get(obs.value)
            if not ip:
                raise NotFound("Domain does not resolve")
        try:
            d = self.get_json(f"https://api.shodan.io/shodan/host/{ip}", params={"key": self.api_key, "minify": "true"})
        except NotFound:
            raise NotFound(f"No Shodan data for {ip}")
        tags = list(d.get("tags") or [])
        vulns = list(d.get("vulns") or [])
        ports = sorted(d.get("ports") or [])
        flagged = {t.lower() for t in tags} & {"malware", "c2", "compromised", "botnet"}
        verdict = Verdict.MALICIOUS if flagged else (Verdict.SUSPICIOUS if vulns else Verdict.UNKNOWN)
        summary = f"{ip}: {d.get('org') or '?'} ({d.get('country_code') or '?'}), ports {ports[:12]}"
        if vulns:
            summary += f", {len(vulns)} CVE(s)"
        return self.result(
            obs, verdict, summary=summary, tags=tags + vulns[:5],
            link=f"https://www.shodan.io/host/{ip}",
            details={"ip": ip, "ports": ports, "vulns": vulns, "os": d.get("os"), "hostnames": d.get("hostnames"),
                     "asn": d.get("asn"), "isp": d.get("isp")},
        )


# ------------------------------------------------------------------------ MXToolbox


class MXToolbox(Provider):
    name = "mxtoolbox"
    display = "MXToolbox"
    homepage = "https://mxtoolbox.com"
    supported = frozenset({ObsType.IPV4, ObsType.DOMAIN})
    rate_limit = 30
    description = "Checks the IP/domain against ~100 DNS blocklists (RBL/DNSBL)."

    def query(self, obs):
        d = self.get_json(f"https://api.mxtoolbox.com/api/v1/Lookup/blacklist/{obs.value}",
                          headers={"Authorization": self.api_key})
        if d.get("Errors"):
            raise ProviderError("; ".join(str(e.get("Name", e)) if isinstance(e, dict) else str(e)
                                          for e in d["Errors"])[:200])
        failed = [f.get("Name") for f in d.get("Failed") or []]
        passed = len(d.get("Passed") or [])
        total = passed + len(failed) + len(d.get("Warnings") or [])
        if len(failed) >= 3:
            verdict = Verdict.MALICIOUS
        elif failed:
            verdict = Verdict.SUSPICIOUS
        elif passed:
            verdict = Verdict.HARMLESS
        else:
            verdict = Verdict.UNKNOWN
        return self.result(
            obs, verdict, score=round(100 * len(failed) / total) if total else None,
            summary=f"listed on {len(failed)}/{total} blocklists" + (f": {', '.join(failed[:4])}" if failed else ""),
            tags=failed[:10],
            link=f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{obs.value}",
            details={"listed": failed, "checked": total},
        )


# ---------------------------------------------------------------------- Cisco Talos


class Talos(Provider):
    """Cisco Talos has no public reputation API.

    STARK checks the IP against the Talos public IP blocklist feed (downloaded once per
    run) and always returns a pivot link to the Talos Reputation Center.
    """

    name = "talos"
    display = "Cisco Talos"
    homepage = "https://talosintelligence.com"
    supported = IP_TYPES | {ObsType.DOMAIN, ObsType.URL}
    requires_key = False
    description = "Talos IP blocklist feed check + Reputation Center pivot link (no public API)."

    FEED = "https://www.talosintelligence.com/documents/ip-blacklist"
    _feed = None
    _feed_lock = threading.Lock()
    _feed_ts = 0.0

    def _blocklist(self):
        cls = type(self)
        with cls._feed_lock:
            if cls._feed is None or time.time() - cls._feed_ts > 3600:
                try:
                    resp = self.request("GET", self.options.get("feed_url", self.FEED))
                    cls._feed = {
                        ln.strip() for ln in resp.text.splitlines()
                        if ln.strip() and not ln.startswith("#") and _is_ip(ln.strip())
                    }
                except Exception:
                    cls._feed = set()
                cls._feed_ts = time.time()
            return cls._feed

    def query(self, obs):
        target = obs.value
        link = f"https://talosintelligence.com/reputation_center/lookup?search={target}"
        if obs.type in IP_TYPES:
            feed = self._blocklist()
            if target in feed:
                return self.result(obs, Verdict.MALICIOUS, score=100,
                                   summary="Listed on the Talos IP blocklist", link=link)
            if feed:
                return self.result(obs, Verdict.UNKNOWN, summary="Not on the Talos IP blocklist; see link for "
                                   "web/email reputation", link=link)
        return self.result(obs, Verdict.UNKNOWN, summary="No public API - open the Reputation Center link",
                           link=link)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- IPinfo


class IPinfo(Provider):
    name = "ipinfo"
    display = "IPinfo"
    homepage = "https://ipinfo.io"
    supported = IP_TYPES
    requires_key = False
    informational = True
    rate_limit = 60
    description = "Geolocation / ASN / hosting context (informational, no verdict)."

    def query(self, obs):
        params = {"token": self.api_key} if self.api_key else {}
        d = self.get_json(f"https://ipinfo.io/{obs.value}/json", params=params)
        if d.get("bogon"):
            return self.result(obs, Verdict.UNKNOWN, summary="bogon / private address")
        loc = ", ".join(x for x in (d.get("city"), d.get("region"), d.get("country")) if x)
        return self.result(
            obs, Verdict.UNKNOWN, summary=f"{d.get('org') or '?'} - {loc or '?'}"
            + (f" ({d['hostname']})" if d.get("hostname") else ""),
            link=f"https://ipinfo.io/{obs.value}",
            details={k: d.get(k) for k in ("hostname", "city", "region", "country", "org", "asn", "privacy")},
        )


# --------------------------------------------------------------------------- crt.sh


class CrtSh(Provider):
    name = "crtsh"
    display = "crt.sh"
    homepage = "https://crt.sh"
    supported = frozenset({ObsType.DOMAIN})
    requires_key = False
    informational = True
    rate_limit = 20
    description = "Certificate Transparency: certificates and subdomains (informational)."

    def query(self, obs):
        d = self.get_json("https://crt.sh/", params={"q": f"%.{obs.value}", "output": "json"},
                          timeout=max(self.timeout, 45))
        if not d:
            raise NotFound("No certificates logged")
        names = set()
        for c in d:
            for n in str(c.get("name_value", "")).splitlines():
                names.add(n.strip().lower().lstrip("*."))
        first = min((c.get("not_before") or "9999") for c in d)
        return self.result(
            obs, Verdict.UNKNOWN,
            summary=f"{len(d)} certificate(s), {len(names)} unique name(s), first logged {first[:10]}",
            link=f"https://crt.sh/?q={obs.value}",
            details={"certificates": len(d), "names": sorted(names)[:200]},
        )
