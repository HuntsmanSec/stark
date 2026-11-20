"""Provider registry."""

from typing import Dict, List, Type

from .abusech import MalwareBazaar, ThreatFox, URLhaus
from .abuseipdb import AbuseIPDB
from .base import Provider, ProviderError
from .hibp import HaveIBeenPwned
from .intel import OTX, GreyNoise, Pulsedive, RecordedFuture
from .network import CrtSh, IPinfo, MXToolbox, Shodan, Talos
from .sandboxes import AnyRun, HybridAnalysis, JoeSandbox
from .urlscan import URLScan
from .virustotal import VirusTotal

PROVIDERS: List[Type[Provider]] = [
    VirusTotal,
    AbuseIPDB,
    URLScan,
    AnyRun,
    JoeSandbox,
    HybridAnalysis,
    RecordedFuture,
    Talos,
    OTX,
    MalwareBazaar,
    ThreatFox,
    URLhaus,
    HaveIBeenPwned,
    MXToolbox,
    Shodan,
    GreyNoise,
    Pulsedive,
    IPinfo,
    CrtSh,
]

REGISTRY: Dict[str, Type[Provider]] = {p.name: p for p in PROVIDERS}

# Friendly aliases accepted on the command line
ALIASES = {
    "vt": "virustotal", "abuse": "abuseipdb", "urlscanio": "urlscan", "any.run": "anyrun",
    "joe": "joesandbox", "ha": "hybridanalysis", "hybrid": "hybridanalysis", "rf": "recordedfuture",
    "alienvault": "otx", "bazaar": "malwarebazaar", "mb": "malwarebazaar", "haveibeenpwned": "hibp",
    "mxtoolbox": "mxtoolbox", "mx": "mxtoolbox", "gn": "greynoise",
}


def resolve(name: str) -> str:
    n = name.strip().lower()
    n = ALIASES.get(n, n)
    if n not in REGISTRY:
        raise KeyError(f"Unknown provider '{name}'. Run 'stark providers' for the list.")
    return n


def key_names() -> List[str]:
    return sorted({p.config_key() for p in PROVIDERS})


__all__ = ["PROVIDERS", "REGISTRY", "Provider", "ProviderError", "resolve", "key_names"]
