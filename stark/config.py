"""User configuration: API keys and settings.

Keys are resolved in this order (first wins):

1. Environment variable ``STARK_<NAME>_API_KEY`` (e.g. ``STARK_VIRUSTOTAL_API_KEY``)
2. The ``[keys]`` table of the config file

The config file lives at (override with ``STARK_CONFIG``):

* Windows: ``%APPDATA%\\stark\\config.toml``
* macOS / Linux: ``$XDG_CONFIG_HOME/stark/config.toml`` (default ``~/.config/stark/config.toml``)
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

DEFAULT_SETTINGS: Dict[str, Any] = {
    "timeout": 20,          # seconds per HTTP request
    "workers": 8,           # concurrent lookups
    "cache_ttl": 86400,     # seconds; 0 disables the cache
    "max_age_days": 90,     # look-back window for sources that support it
    "verify_tls": True,
    "proxy": "",            # e.g. http://127.0.0.1:8080
}


def config_dir() -> Path:
    if os.environ.get("STARK_CONFIG"):
        return Path(os.environ["STARK_CONFIG"]).expanduser().parent
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "stark"


def config_path() -> Path:
    if os.environ.get("STARK_CONFIG"):
        return Path(os.environ["STARK_CONFIG"]).expanduser()
    return config_dir() / "config.toml"


def cache_dir() -> Path:
    if os.environ.get("STARK_CACHE_DIR"):
        return Path(os.environ["STARK_CACHE_DIR"]).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "stark" / "cache"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "stark"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "stark"


def env_var_for(name: str) -> str:
    return f"STARK_{name.upper().replace('-', '_')}_API_KEY"


def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


class Config:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else config_path()
        self.keys: Dict[str, str] = {}
        self.settings: Dict[str, Any] = dict(DEFAULT_SETTINGS)
        self.disabled: List[str] = []
        self.provider_options: Dict[str, Dict[str, Any]] = {}
        self.load()

    # ------------------------------------------------------------------ io
    def load(self) -> None:
        if not self.path.exists():
            return
        with open(self.path, "rb") as fh:
            data = tomllib.load(fh)
        self.keys = {k.lower(): str(v) for k, v in (data.get("keys") or {}).items() if v}
        self.settings.update(data.get("settings") or {})
        prov = data.get("providers") or {}
        self.disabled = [p.lower() for p in prov.get("disabled", [])]
        self.provider_options = {
            k.lower(): v for k, v in prov.items() if isinstance(v, dict)
        }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# S.T.A.R.K configuration - Security Threat Assessment and Reputation Kit",
            "# Keep this file private: it contains your API keys.",
            "",
            "[keys]",
        ]
        for k in sorted(self.keys):
            lines.append(f"{k} = {_toml_value(self.keys[k])}")
        lines += ["", "[settings]"]
        for k in sorted(self.settings):
            lines.append(f"{k} = {_toml_value(self.settings[k])}")
        lines += ["", "[providers]", f"disabled = {_toml_value(self.disabled)}"]
        for name in sorted(self.provider_options):
            lines += ["", f"[providers.{name}]"]
            for k, v in sorted(self.provider_options[name].items()):
                lines.append(f"{k} = {_toml_value(v)}")
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        if os.name != "nt":
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp, self.path)

    # ------------------------------------------------------------- helpers
    def get_key(self, name: str) -> Optional[str]:
        return os.environ.get(env_var_for(name)) or self.keys.get(name.lower()) or None

    def key_source(self, name: str) -> Optional[str]:
        if os.environ.get(env_var_for(name)):
            return "env"
        if self.keys.get(name.lower()):
            return "config"
        return None

    def set_key(self, name: str, value: str) -> None:
        self.keys[name.lower()] = value

    def unset_key(self, name: str) -> bool:
        return self.keys.pop(name.lower(), None) is not None

    def option(self, provider: str, key: str, default: Any = None) -> Any:
        return self.provider_options.get(provider, {}).get(key, default)


def mask(secret: Optional[str]) -> str:
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
