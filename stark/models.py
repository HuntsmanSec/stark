"""Result data structures and verdict aggregation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from .observables import Observable


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    HARMLESS = "harmless"
    UNKNOWN = "unknown"   # source answered but has no opinion / no data
    ERROR = "error"       # source failed (network, auth, quota...)

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {
    Verdict.MALICIOUS: 4,
    Verdict.SUSPICIOUS: 3,
    Verdict.HARMLESS: 2,
    Verdict.UNKNOWN: 1,
    Verdict.ERROR: 0,
}


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class ProviderResult:
    provider: str
    observable: Observable
    verdict: Verdict = Verdict.UNKNOWN
    score: Optional[int] = None          # normalised 0-100 risk score, if the source has one
    summary: str = ""
    tags: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    link: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    cached: bool = False
    elapsed: float = 0.0
    queried_at: str = field(default_factory=utcnow)

    def to_dict(self, include_raw: bool = False) -> dict:
        d = {
            "provider": self.provider,
            "verdict": self.verdict.value,
            "score": self.score,
            "summary": self.summary,
            "tags": self.tags,
            "malware_families": self.malware_families,
            "link": self.link,
            "error": self.error,
            "cached": self.cached,
            "queried_at": self.queried_at,
        }
        if include_raw:
            d["details"] = self.details
        return d

    @classmethod
    def from_dict(cls, observable: Observable, d: dict) -> "ProviderResult":
        return cls(
            provider=d["provider"],
            observable=observable,
            verdict=Verdict(d.get("verdict", "unknown")),
            score=d.get("score"),
            summary=d.get("summary", ""),
            tags=list(d.get("tags") or []),
            malware_families=list(d.get("malware_families") or []),
            link=d.get("link"),
            details=d.get("details") or {},
            error=d.get("error"),
            queried_at=d.get("queried_at") or utcnow(),
        )


@dataclass
class ObservableReport:
    observable: Observable
    results: List[ProviderResult] = field(default_factory=list)

    @property
    def verdict(self) -> Verdict:
        answered = [r.verdict for r in self.results if r.verdict is not Verdict.ERROR]
        if not answered:
            return Verdict.ERROR if self.results else Verdict.UNKNOWN
        return max(answered, key=lambda v: v.rank)

    def count(self, verdict: Verdict) -> int:
        return sum(1 for r in self.results if r.verdict is verdict)

    @property
    def score(self) -> Optional[int]:
        scores = [r.score for r in self.results if r.score is not None]
        return max(scores) if scores else None

    @property
    def tags(self) -> List[str]:
        out: List[str] = []
        for r in self.results:
            for t in r.tags:
                if t and t not in out:
                    out.append(t)
        return out

    @property
    def malware_families(self) -> List[str]:
        out: List[str] = []
        flagged = [r for r in self.results if r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)]
        for r in flagged:
            for t in r.malware_families:
                if t and t.lower() not in (x.lower() for x in out):
                    out.append(t)
        return out

    @property
    def flagged_by(self) -> List[str]:
        return [r.provider for r in self.results if r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)]

    def to_dict(self, include_raw: bool = False) -> dict:
        return {
            "observable": self.observable.value,
            "type": self.observable.type.value,
            "verdict": self.verdict.value,
            "score": self.score,
            "malicious": self.count(Verdict.MALICIOUS),
            "suspicious": self.count(Verdict.SUSPICIOUS),
            "harmless": self.count(Verdict.HARMLESS),
            "unknown": self.count(Verdict.UNKNOWN),
            "errors": self.count(Verdict.ERROR),
            "flagged_by": self.flagged_by,
            "malware_families": self.malware_families,
            "tags": self.tags,
            "results": [r.to_dict(include_raw) for r in self.results],
        }
