"""Query orchestration: fan observables out to providers concurrently."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Union

from .cache import ResultCache
from .config import Config, cache_dir
from .models import ObservableReport, ProviderResult
from .observables import Observable, parse_observable
from .providers import REGISTRY, Provider, resolve
from .providers.base import make_session

ProgressFn = Callable[[int, int, ProviderResult], None]


class Stark:
    def __init__(
        self,
        config: Optional[Config] = None,
        providers: Optional[Sequence[str]] = None,
        exclude: Optional[Sequence[str]] = None,
        include_informational: bool = False,
        use_cache: bool = True,
        timeout: Optional[float] = None,
        workers: Optional[int] = None,
    ):
        self.config = config or Config()
        s = self.config.settings
        self.timeout = float(timeout or s.get("timeout", 20))
        self.workers = int(workers or s.get("workers", 8))
        session = make_session(proxy=s.get("proxy", ""), verify=bool(s.get("verify_tls", True)))

        explicit = [resolve(p) for p in providers] if providers else None
        excluded = {resolve(p) for p in exclude or []}
        excluded |= set(self.config.disabled) if not explicit else set()

        self.providers: List[Provider] = []
        self.skipped: Dict[str, str] = {}
        for name, cls in REGISTRY.items():
            if explicit is not None and name not in explicit:
                continue
            if name in excluded:
                self.skipped[name] = "disabled"
                continue
            if cls.informational and explicit is None and not include_informational:
                self.skipped[name] = "informational (use --all)"
                continue
            p = cls(
                api_key=self.config.get_key(cls.config_key()),
                session=session,
                timeout=self.timeout,
                options=self.config.provider_options.get(name, {}),
                settings=s,
            )
            if not p.available:
                self.skipped[name] = "no API key"
                continue
            self.providers.append(p)

        ttl = int(s.get("cache_ttl", 86400))
        self.cache = ResultCache(cache_dir() / "results.sqlite", ttl) if use_cache and ttl > 0 else None

    # ------------------------------------------------------------------ api
    def query(self, observable: Union[str, Observable]) -> ObservableReport:
        return self.query_many([observable])[0]

    def query_many(
        self, observables: Iterable[Union[str, Observable]], progress: Optional[ProgressFn] = None
    ) -> List[ObservableReport]:
        obs_list: List[Observable] = []
        for o in observables:
            if isinstance(o, str):
                parsed = parse_observable(o)
                if parsed is None:
                    raise ValueError(f"Cannot determine observable type of {o!r}")
                o = parsed
            if o not in obs_list:
                obs_list.append(o)

        reports = {o: ObservableReport(o) for o in obs_list}
        jobs = [(o, p) for o in obs_list for p in self.providers if p.supports(o)]
        total = len(jobs)
        done = 0

        def run(o: Observable, p: Provider) -> ProviderResult:
            if self.cache:
                hit = self.cache.get(p.name, o)
                if hit:
                    return hit
            res = p.lookup(o)
            if self.cache:
                self.cache.put(res)
            return res

        # One pool per provider so a slow, rate-limited source (e.g. VirusTotal's
        # 4 req/min public tier) never starves the others of worker threads.
        pools = {}
        futs = []
        try:
            for o, p in jobs:
                if p.name not in pools:
                    n = 1 if p.limiter.interval >= 1 else max(1, self.workers)
                    pools[p.name] = ThreadPoolExecutor(max_workers=n, thread_name_prefix=f"stark-{p.name}")
                futs.append(pools[p.name].submit(run, o, p))
            for fut in as_completed(futs):
                res = fut.result()
                reports[res.observable].results.append(res)
                done += 1
                if progress:
                    progress(done, total, res)
        finally:
            for pool in pools.values():
                pool.shutdown(wait=False, cancel_futures=True)

        order = {p.name: i for i, p in enumerate(self.providers)}
        for r in reports.values():
            r.results.sort(key=lambda x: order.get(x.provider, 99))
        return [reports[o] for o in obs_list]
