"""Observable (IOC) detection, normalisation, refanging and extraction."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit


class ObsType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"

    @property
    def is_ip(self) -> bool:
        return self in (ObsType.IPV4, ObsType.IPV6)

    @property
    def is_hash(self) -> bool:
        return self in (ObsType.MD5, ObsType.SHA1, ObsType.SHA256)


IP_TYPES = frozenset({ObsType.IPV4, ObsType.IPV6})
HASH_TYPES = frozenset({ObsType.MD5, ObsType.SHA1, ObsType.SHA256})
ALL_TYPES = frozenset(ObsType)


@dataclass(frozen=True)
class Observable:
    value: str
    type: ObsType
    # Free-form origin information (e.g. "hayabusa:row 42"); not part of identity.
    source: Optional[str] = field(default=None, compare=False, hash=False)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value

    @property
    def defanged(self) -> str:
        return defang(self.value)

    def to_dict(self) -> dict:
        return {"value": self.value, "type": self.type.value}


# --------------------------------------------------------------------------- #
# Refang / defang
# --------------------------------------------------------------------------- #

_REFANG_RULES = [
    (re.compile(r"^h[x]{2}p(s?)", re.I), r"http\1"),
    (re.compile(r"^fxp", re.I), "ftp"),
    (re.compile(r"\[\s*:\s*/\s*/\s*\]"), "://"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]|\(\s*dot\s*\)", re.I), "."),
    (re.compile(r"\[\s*@\s*\]|\(\s*@\s*\)|\[\s*at\s*\]", re.I), "@"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
]


def refang(text: str) -> str:
    """Undo common IOC defanging (hxxp, [.], [dot], [@], [:]...)."""
    s = text.strip().strip("'\"<>")
    for rx, repl in _REFANG_RULES:
        s = rx.sub(repl, s)
    return s


def defang(value: str, otype: Optional["ObsType"] = None) -> str:
    """Make an IOC safe to paste into tickets, chat and reports.

    ``185.220.101.1`` -> ``185[.]220[.]101[.]1``; ``https://evil.com/a.php`` ->
    ``hxxps[://]evil[.]com/a.php``; ``bob@evil.com`` -> ``bob[@]evil[.]com``. Hashes are
    returned unchanged. Already-defanged input is normalised first, so this is idempotent.
    """
    v = refang(value)
    t = otype or detect_type(v)
    if t is None or t in (ObsType.MD5, ObsType.SHA1, ObsType.SHA256):
        return value if t is None else v
    if t is ObsType.URL:
        parts = urlsplit(v)
        scheme = re.sub(r"^http", "hxxp", parts.scheme, flags=re.I)
        scheme = re.sub(r"^ftp", "fxp", scheme, flags=re.I)
        rest = v[len(parts.scheme) + 3:]
        host_end = len(rest)
        for ch in "/?#":
            i = rest.find(ch)
            if i != -1:
                host_end = min(host_end, i)
        host, tail = rest[:host_end], rest[host_end:]
        if "@" in host:
            cred, host = host.rsplit("@", 1)
            host = cred + "[@]" + host
        return f"{scheme}[://]{host.replace('.', '[.]')}{tail}"
    if t is ObsType.EMAIL:
        local, domain = v.rsplit("@", 1)
        return f"{local}[@]{domain.replace('.', '[.]')}"
    if t is ObsType.IPV6:
        return v.replace(":", "[:]")
    return v.replace(".", "[.]")


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN = re.compile(
    r"^(?=.{4,253}$)(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$",
    re.I,
)
_EMAIL = re.compile(r"^[a-z0-9._%+\-]{1,64}@([a-z0-9.\-]+\.[a-z]{2,63})$", re.I)
_URL_SCHEME = re.compile(r"^(https?|ftp)://", re.I)

# Extensions that are never (or almost never) TLDs – used to avoid treating
# "invoice.exe" or "Security.evtx" as domain names when extracting from logs.
FILE_EXTENSIONS = frozenset(
    """exe dll sys scr ps1 psm1 psd1 bat cmd vbs vbe js jse wsf wsh hta msi msp
    lnk inf ini reg evtx etl log txt csv tsv json xml yml yaml dat db sqlite tmp
    doc docx docm xls xlsx xlsm ppt pptx pptm pdf rtf one zip rar 7z gz tgz tar
    iso img vhd vhdx cab jar class py pyc sh elf so dylib bin pf lock bak old
    png jpg jpeg gif bmp ico svg mp3 mp4 avi mov htm html aspx asp php jsp cs
    config manifest mui cat drv ocx cpl efi pdb local tlb nls ttf otf dmp hiv msc ldf mdf bak1 cfg conf
    vmdk ova key pem crt cer pfx p12 sql lck pst ost eml msg rdp vhdx wim esd job""".split()
)


# Dotted tokens common in log field names/values that are not real TLDs.
PSEUDO_TLDS = frozenset(
    """dns conn http https ssl tls log type cmdline process user users event events name_ value
    local localdomain internal intranet lan corp home arpa domain workgroup ad dataset action
    category code module provider kind outcome severity client server source destination
    id uid path file hash parent pid data""".split()
)


def _is_hash(s: str) -> Optional[ObsType]:
    if not _HEX.match(s):
        return None
    return {32: ObsType.MD5, 40: ObsType.SHA1, 64: ObsType.SHA256}.get(len(s))


def detect_type(value: str) -> Optional[ObsType]:
    """Return the ObsType for an already refanged value, or None."""
    s = value.strip()
    if not s:
        return None
    h = _is_hash(s)
    if h:
        return h
    if _URL_SCHEME.match(s):
        host = urlsplit(s).hostname
        return ObsType.URL if host else None
    try:
        ip = ipaddress.ip_address(s.strip("[]"))
        return ObsType.IPV4 if ip.version == 4 else ObsType.IPV6
    except ValueError:
        pass
    if _EMAIL.match(s):
        return ObsType.EMAIL
    if _DOMAIN.match(s.rstrip(".")):
        tld = s.rstrip(".").rsplit(".", 1)[-1].lower()
        if tld in FILE_EXTENSIONS or tld in PSEUDO_TLDS:
            return None
        return ObsType.DOMAIN
    return None


def normalise(value: str, otype: ObsType) -> str:
    if otype.is_hash:
        return value.lower()
    if otype is ObsType.DOMAIN:
        return value.rstrip(".").lower()
    if otype is ObsType.EMAIL:
        return value.lower()
    if otype is ObsType.IPV6:
        return str(ipaddress.ip_address(value.strip("[]")))
    return value


def parse_observable(raw: str, forced: Optional[ObsType] = None, source: Optional[str] = None) -> Optional[Observable]:
    """Parse one user supplied string into an Observable (refanging first)."""
    s = refang(raw)
    otype = forced or detect_type(s)
    if otype is None:
        return None
    return Observable(normalise(s, otype), otype, source)


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


# --------------------------------------------------------------------------- #
# Extraction from free text / logs
# --------------------------------------------------------------------------- #

_X_URL = re.compile(r"\b(?:h[tx]{2}ps?|ftp)(?:://|\[://\]|\[:\]//)[^\s\"'<>|¦,;]+", re.I)
_X_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|\[\.\])){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_X_IPV6 = re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])", re.I)
_X_HASH = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])", re.I)
_X_EMAIL = re.compile(r"\b[a-z0-9._%+\-]{1,64}(?:@|\[@\])[a-z0-9.\-]+(?:\.|\[\.\])[a-z]{2,63}\b", re.I)
_X_DOMAIN = re.compile(
    r"(?<![@\w.\-\\/])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.|\[\.\]))+[a-z]{2,63}(?![\w\-]|\.[a-z0-9])",
    re.I,
)
# Common IOC-looking strings that are noise in Windows telemetry.
_NOISE_DOMAINS = frozenset(
    {"microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com", "live.com",
     "office.com", "office365.com", "msn.com", "bing.com", "azure.com", "msedge.net",
     "digicert.com", "verisign.com", "symantec.com", "w3.org", "schemas.microsoft.com",
     "localhost", "local", "example.com", "example.org", "example.net"}
)


def _domain_is_noise(d: str) -> bool:
    d = d.lower()
    return any(d == n or d.endswith("." + n) for n in _NOISE_DOMAINS)


def extract(
    text: str,
    types: Iterable[ObsType] = ALL_TYPES,
    include_private: bool = False,
    include_noise: bool = False,
    source: Optional[str] = None,
) -> Iterator[Observable]:
    """Yield unique observables found in arbitrary text (logs, reports, CSV cells)."""
    wanted = set(types)
    seen = set()

    def emit(raw: str, forced: Optional[ObsType] = None):
        obs = parse_observable(raw, forced=forced, source=source)
        if obs is None or obs.type not in wanted:
            return None
        if obs.type.is_ip and not include_private and not is_public_ip(obs.value):
            return None
        if obs.type is ObsType.DOMAIN and not include_noise and _domain_is_noise(obs.value):
            return None
        key = (obs.type, obs.value)
        if key in seen:
            return None
        seen.add(key)
        return obs

    consumed: List[str] = []
    for m in _X_URL.finditer(text):
        url = m.group(0)
        while url and url[-1] in ".)]}" and url.count(url[-1]) > url.count({")": "(", "]": "[", "}": "{"}.get(url[-1], "\0")):
            url = url[:-1]
        consumed.append(url)
        o = emit(url, ObsType.URL)
        if o:
            yield o
    for m in _X_EMAIL.finditer(text):
        consumed.append(m.group(0))
        o = emit(m.group(0))
        if o:
            yield o
    for m in _X_HASH.finditer(text):
        o = emit(m.group(0))
        if o:
            yield o
    for m in _X_IPV4.finditer(text):
        o = emit(m.group(0), ObsType.IPV4)
        if o:
            yield o
    if ObsType.IPV6 in wanted:
        for m in _X_IPV6.finditer(text):
            cand = m.group(0)
            if cand.count(":") < 2 or len(cand) < 6:
                continue
            o = emit(cand)
            if o and o.type is ObsType.IPV6:
                yield o
    if ObsType.DOMAIN in wanted:
        scrubbed = text
        for c in consumed:
            scrubbed = scrubbed.replace(c, " ")
        for m in _X_DOMAIN.finditer(scrubbed):
            o = emit(m.group(0))
            if o and o.type is ObsType.DOMAIN:
                yield o


def iter_lines(lines: Iterable[str], forced: Optional[ObsType] = None) -> Iterator[Observable]:
    """Parse a list of observables, one per line; ``#`` comments are ignored."""
    seen = set()
    for line in lines:
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        obs = parse_observable(line, forced=forced)
        if obs is None:
            # Fall back to extraction (e.g. CSV rows, sentences)
            for o in extract(line, include_private=True, include_noise=True):
                if (o.type, o.value) not in seen:
                    seen.add((o.type, o.value))
                    yield o
            continue
        if (obs.type, obs.value) not in seen:
            seen.add((obs.type, obs.value))
            yield obs


def find_iocs(text: str, include_private: bool = True) -> List[Tuple[int, int, Observable]]:
    """Return non-overlapping (start, end, observable) spans for every IOC in ``text``.

    Unlike :func:`extract` this keeps positions, so callers can rewrite the text
    (for example to defang it) without touching anything else."""
    spans: List[Tuple[int, int, Observable]] = []

    def taken(a: int, b: int) -> bool:
        return any(a < e and b > s0 for s0, e, _ in spans)

    def add(m_start: int, raw: str, forced: Optional[ObsType] = None, want: Optional[ObsType] = None):
        end = m_start + len(raw)
        if taken(m_start, end):
            return
        o = parse_observable(raw, forced=forced)
        if o is None or (want and o.type is not want):
            return
        if o.type.is_ip and not include_private and not is_public_ip(o.value):
            return
        spans.append((m_start, end, o))

    for m in _X_URL.finditer(text):
        url = m.group(0)
        while url and url[-1] in ".,)]}'\"" and url.count(url[-1]) > url.count({")": "(", "]": "[", "}": "{"}.get(url[-1], "\0")):
            url = url[:-1]
        add(m.start(), url, ObsType.URL)
    for m in _X_EMAIL.finditer(text):
        add(m.start(), m.group(0))
    for m in _X_HASH.finditer(text):
        add(m.start(), m.group(0))
    for m in _X_IPV4.finditer(text):
        add(m.start(), m.group(0), ObsType.IPV4)
    for m in _X_IPV6.finditer(text):
        if m.group(0).count(":") >= 2 and len(m.group(0)) >= 6:
            add(m.start(), m.group(0), want=ObsType.IPV6)
    for m in _X_DOMAIN.finditer(text):
        add(m.start(), m.group(0), want=ObsType.DOMAIN)
    spans.sort(key=lambda x: x[0])
    return spans


def defang_text(text: str, keep: Iterable[str] = ()) -> str:
    """Defang every IP, domain, URL and email address inside free text.

    Values listed in ``keep`` (for example reference links) are left untouched."""
    if not text:
        return text
    keep = set(keep)
    out, last = [], 0
    for start, end, o in find_iocs(text):
        raw = text[start:end]
        if raw in keep or o.type.is_hash:
            continue
        out.append(text[last:start])
        out.append(defang(raw, o.type))
        last = end
    out.append(text[last:])
    return "".join(out)

