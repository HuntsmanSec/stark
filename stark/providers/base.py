"""Base class shared by every reputation source."""

from __future__ import annotations

import threading
import time
from typing import Any, ClassVar, Dict, FrozenSet, Optional

import requests

from .. import __version__
from ..models import ProviderResult, Verdict
from ..observables import Observable, ObsType

USER_AGENT = f"STARK/{__version__} (+https://github.com/HuntsmanSec/stark)"


class ProviderError(Exception):
    """Raised by providers for expected, user-facing failures."""


class NotFound(Exception):
    """The source has no record of the observable."""


class RateLimiter:
    """Enforce a minimum interval between calls (thread safe)."""

    def __init__(self, per_minute: Optional[float]):
        self.interval = 60.0 / per_minute if per_minute else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            time.sleep(delay)


class Provider:
    #: short identifier used on the CLI and as the config key name
    name: ClassVar[str] = ""
    #: human readable name
    display: ClassVar[str] = ""
    homepage: ClassVar[str] = ""
    supported: ClassVar[FrozenSet[ObsType]] = frozenset()
    #: True = cannot run without a key; False = keyless or key optional
    requires_key: ClassVar[bool] = True
    #: name of the config key (several abuse.ch services share one key)
    key_name: ClassVar[Optional[str]] = None
    #: default requests/minute (None = unlimited). Free-tier friendly defaults.
    rate_limit: ClassVar[Optional[float]] = None
    #: informational sources (no verdict) are only queried with --all or -p
    informational: ClassVar[bool] = False
    description: ClassVar[str] = ""
    #: extra settings stored next to the key (e.g. a server address), name -> label
    extra_keys: ClassVar[Dict[str, str]] = {}

    def __init__(
        self,
        api_key: Optional[str] = None,
        session: Optional[requests.Session] = None,
        timeout: float = 20,
        options: Optional[Dict[str, Any]] = None,
        settings: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Optional[str]]] = None,
    ):
        self.api_key = api_key
        self.session = session or make_session()
        self.timeout = timeout
        self.options = options or {}
        self.settings = settings or {}
        self.extra = {k: v for k, v in (extra or {}).items() if v}
        self.limiter = RateLimiter(self.options.get("rate_limit", self.rate_limit))

    @classmethod
    def config_key(cls) -> str:
        return cls.key_name or cls.name

    def supports(self, obs: Observable) -> bool:
        return obs.type in self.supported

    @property
    def available(self) -> bool:
        if any(k not in self.extra for k in self.extra_keys):
            return False
        return bool(self.api_key) or not self.requires_key

    # ------------------------------------------------------------------ api
    def lookup(self, obs: Observable) -> ProviderResult:
        start = time.monotonic()
        try:
            res = self.query(obs)
        except NotFound as exc:
            res = self.result(obs, Verdict.UNKNOWN, summary=str(exc) or "No record found")
        except ProviderError as exc:
            res = self.result(obs, Verdict.ERROR, error=str(exc))
        except requests.RequestException as exc:
            res = self.result(obs, Verdict.ERROR, error=_describe_request_error(exc))
        except (ValueError, KeyError, TypeError) as exc:
            res = self.result(obs, Verdict.ERROR, error=f"Unexpected response: {exc!r}")
        res.elapsed = round(time.monotonic() - start, 3)
        return res

    def query(self, obs: Observable) -> ProviderResult:  # pragma: no cover - abstract
        raise NotImplementedError

    # -------------------------------------------------------------- helpers
    def result(self, obs: Observable, verdict: Verdict = Verdict.UNKNOWN, **kw) -> ProviderResult:
        return ProviderResult(provider=self.name, observable=obs, verdict=verdict, **kw)

    def request(self, method: str, url: str, *, ok=(200,), not_found=(404,), **kw) -> requests.Response:
        self.limiter.wait()
        kw.setdefault("timeout", self.timeout)
        resp = self.session.request(method, url, **kw)
        if resp.status_code in not_found:
            raise NotFound("Not found")
        if resp.status_code in (401, 403):
            raise ProviderError(f"HTTP {resp.status_code}: authentication failed or plan does not allow this lookup")
        if resp.status_code == 429:
            raise ProviderError("HTTP 429: rate limit / quota exceeded")
        if resp.status_code not in ok:
            raise ProviderError(f"HTTP {resp.status_code}: {resp.text[:200].strip()}")
        return resp

    def get_json(self, url: str, **kw) -> Any:
        return self.request("GET", url, **kw).json()

    def post_json(self, url: str, **kw) -> Any:
        return self.request("POST", url, **kw).json()


def _describe_request_error(exc: requests.RequestException) -> str:
    if isinstance(exc, requests.Timeout):
        return "Request timed out"
    if isinstance(exc, requests.ConnectionError):
        return "Connection error"
    return exc.__class__.__name__


def make_session(proxy: str = "", verify: bool = True) -> requests.Session:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    # One quick retry for transient connection/5xx errors; never retry read timeouts, so a
    # source that is down can't stall a whole investigation.
    retry = Retry(total=1, connect=1, read=0, status=1, backoff_factor=0.5, status_forcelist=(500, 502, 503, 504),
                  allowed_methods=frozenset({"GET", "POST"}))
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.verify = verify
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def score_to_verdict(score: Optional[float], malicious: float = 75, suspicious: float = 25) -> Verdict:
    if score is None:
        return Verdict.UNKNOWN
    if score >= malicious:
        return Verdict.MALICIOUS
    if score >= suspicious:
        return Verdict.SUSPICIOUS
    return Verdict.HARMLESS
