# Contributing to S.T.A.R.K

Thanks for helping. Bug reports, new sources and integrations are all welcome.

## Development setup

```bash
git clone https://github.com/HuntsmanSec/stark.git && cd stark
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest && ruff check .
```

Tests never call real APIs. Use the `FakeSession` helper in `tests/conftest.py`.

## Adding a reputation source

1. Create a class in `stark/providers/` (or add it to a themed module):

```python
from ..models import Verdict
from ..observables import IP_TYPES
from .base import Provider, score_to_verdict

class ExampleIntel(Provider):
    name = "exampleintel"            # CLI + config key name
    display = "Example Intel"
    homepage = "https://example.com"
    supported = IP_TYPES
    rate_limit = 30                  # requests/minute, free-tier friendly
    description = "One line shown in `stark providers`."

    def query(self, obs):
        d = self.get_json(f"https://api.example.com/ip/{obs.value}", headers={"Key": self.api_key})
        return self.result(obs, score_to_verdict(d["score"]), score=d["score"],
                           summary=f"score {d['score']}", link=f"https://example.com/ip/{obs.value}")
```

2. Register it in `stark/providers/__init__.py`.
3. Add a test with canned responses, a row in `docs/providers.md` and the README key table.
4. Document how the verdict is derived. Be conservative: sources that only show *presence* (pulses,
   breaches, CVEs) should rarely return `malicious` on their own.

Raise `NotFound` for "no record", `ProviderError` for user-facing failures. HTTP 401/403/429 are
handled by `Provider.request`.

## Versioning and releases

The project uses [SemVer](https://semver.org):

- **MAJOR**: incompatible CLI, output-schema or library API changes
- **MINOR**: new sources, formats, integrations or flags (backwards compatible)
- **PATCH**: bug fixes, source API adjustments

To release:

1. Update `__version__` in `stark/__init__.py` and move `[Unreleased]` items in `CHANGELOG.md` under a new heading.
2. Commit, then `git tag vX.Y.Z && git push --tags`. The release workflow builds wheels and standalone
   binaries and publishes the GitHub release.

## Commit style

Use short imperative subjects (`Add Censys provider`, `Fix OTX URL encoding`) and reference issues where relevant.
