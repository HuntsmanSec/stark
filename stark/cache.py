"""Tiny SQLite result cache so repeated lookups don't burn API quota."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from .models import ProviderResult, Verdict
from .observables import Observable


class ResultCache:
    def __init__(self, path: Path, ttl: int):
        self.ttl = int(ttl)
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS results (provider TEXT, otype TEXT, value TEXT,"
            " ts REAL, data TEXT, PRIMARY KEY (provider, otype, value))"
        )
        self._db.commit()

    def get(self, provider: str, obs: Observable) -> Optional[ProviderResult]:
        if self.ttl <= 0:
            return None
        with self._lock:
            row = self._db.execute(
                "SELECT ts, data FROM results WHERE provider=? AND otype=? AND value=?",
                (provider, obs.type.value, obs.value),
            ).fetchone()
        if not row or time.time() - row[0] > self.ttl:
            return None
        res = ProviderResult.from_dict(obs, json.loads(row[1]))
        res.cached = True
        return res

    def put(self, res: ProviderResult) -> None:
        if self.ttl <= 0 or res.verdict is Verdict.ERROR:
            return
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO results VALUES (?,?,?,?,?)",
                (
                    res.provider,
                    res.observable.type.value,
                    res.observable.value,
                    time.time(),
                    json.dumps(res.to_dict(include_raw=True), default=str),
                ),
            )
            self._db.commit()

    def clear(self) -> int:
        with self._lock:
            n = self._db.execute("DELETE FROM results").rowcount
            self._db.commit()
        return n

    def close(self) -> None:
        with self._lock:
            self._db.close()
