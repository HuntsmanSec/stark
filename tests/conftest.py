import json
import os

import pytest


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("STARK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("STARK_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("NO_COLOR", "1")
    for k in list(os.environ):
        if k.startswith("STARK_") and k.endswith("_API_KEY"):
            monkeypatch.delenv(k)
    yield


class FakeResponse:
    def __init__(self, status=200, payload=None, text=None):
        self.status_code = status
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload or {})

    def json(self):
        return self._payload


class FakeSession:
    """Routes requests by URL substring to canned responses and records calls."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []
        self.headers = {}

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        for needle, resp in self.routes.items():
            if needle in url:
                return resp(method, url, kw) if callable(resp) else resp
        return FakeResponse(404, {})


@pytest.fixture
def fake_session():
    return FakeSession
