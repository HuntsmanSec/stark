"""Keeping a local install safe across updates: data locations, backups, restore and updates.

Nothing the user creates lives inside the application. Updating (pip, pipx, a new binary,
a new Docker image) replaces the program only:

* workspace database (accounts, workspaces, API keys, cases, pentest notes, assets):
  the per-user data folder (``stark paths`` shows it)
* CLI API keys and settings: ``config.toml`` in the per-user config folder
* lookup cache: the per-user cache folder (safe to delete)

Before a newer version changes the database schema, a copy of the database is saved in
``<data folder>/backups`` automatically, so an update can always be rolled back.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__

REPO = "HuntsmanSec/stark"
RELEASES_API = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases/latest"
KEEP_BACKUPS = 10
CHECK_EVERY = 12 * 3600


def parse_version(v: str) -> tuple:
    out = []
    for part in str(v or "").lstrip("vV").split("-")[0].split("."):
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    return tuple((out + [0, 0, 0])[:3])


# ------------------------------------------------------------------ locations


def data_dir() -> Path:
    from .web.db import data_dir as _dd
    return _dd()


def db_path() -> Path:
    return data_dir() / "workspace.sqlite"


def backups_dir() -> Path:
    return data_dir() / "backups"


def paths() -> Dict[str, str]:
    from .config import cache_dir, config_path
    return {"data": str(data_dir()), "database": str(db_path()), "backups": str(backups_dir()),
            "config": str(config_path()), "cache": str(cache_dir()), "program": install_location()}


def install_location() -> str:
    return sys.executable if getattr(sys, "frozen", False) else str(Path(__file__).resolve().parent)


def install_kind() -> str:
    """binary | docker | source | pipx | pip"""
    if getattr(sys, "frozen", False):
        return "binary"
    if Path("/.dockerenv").exists() or os.environ.get("STARK_IN_DOCKER"):
        return "docker"
    if (Path(__file__).resolve().parent.parent / ".git").exists():
        return "source"
    if "pipx" in sys.prefix.replace("\\", "/").lower():
        return "pipx"
    return "pip"


# ------------------------------------------------------------------ backups


def copy_database(src: Path, dest: Path) -> Path:
    """Consistent copy of a live SQLite database (WAL-safe, uses the backup API)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    s = sqlite3.connect(str(src))
    d = sqlite3.connect(str(dest))
    try:
        s.backup(d)
    finally:
        d.close()
        s.close()
    if os.name != "nt":
        os.chmod(dest, 0o600)
    return dest


def prune_backups(folder: Path, keep: int = KEEP_BACKUPS) -> None:
    files = sorted(folder.glob("workspace-*.sqlite"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[keep:]:
        try:
            old.unlink()
        except OSError:
            pass


def auto_backup(db_file: Path, reason: str) -> Optional[Path]:
    """Copy the database into ``backups/`` next to it before it is upgraded."""
    if not db_file.exists() or db_file.stat().st_size == 0:
        return None
    folder = db_file.parent / "backups"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = folder / f"workspace-{stamp}-{reason}.sqlite"
    copy_database(db_file, dest)
    prune_backups(folder)
    return dest


def list_backups() -> List[Dict[str, Any]]:
    folder = backups_dir()
    if not folder.exists():
        return []
    return [{"file": str(p), "size": p.stat().st_size, "created": p.stat().st_mtime}
            for p in sorted(folder.glob("workspace-*.sqlite"), key=lambda p: p.stat().st_mtime, reverse=True)]


def create_backup(out: Path, db_file: Optional[Path] = None, config_file: Optional[Path] = None) -> Path:
    """Write a zip with the workspace database and the CLI config (API keys)."""
    from .config import config_path
    db_file = Path(db_file or db_path())
    config_file = Path(config_file or config_path())
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        manifest = {"stark_version": __version__, "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "files": []}
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            if db_file.exists():
                snap = copy_database(db_file, Path(tmp) / "workspace.sqlite")
                z.write(snap, "workspace.sqlite")
                manifest["files"].append("workspace.sqlite")
            if config_file.exists():
                z.write(config_file, "config.toml")
                manifest["files"].append("config.toml")
            z.writestr("manifest.json", json.dumps(manifest, indent=2))
    if os.name != "nt":
        os.chmod(out, 0o600)
    return out


def restore_backup(archive: Path, db_file: Optional[Path] = None, config_file: Optional[Path] = None) -> Dict[str, Any]:
    """Restore a backup zip (or a bare .sqlite). The current data is saved to backups/ first."""
    from .config import config_path
    db_file = Path(db_file or db_path())
    config_file = Path(config_file or config_path())
    archive = Path(archive)
    restored: List[str] = []
    saved = auto_backup(db_file, "before-restore")
    if archive.suffix == ".sqlite":
        _check_sqlite(archive)
        _replace_db(archive, db_file)
        return {"restored": ["workspace.sqlite"], "previous": str(saved) if saved else None}
    with zipfile.ZipFile(archive) as z, tempfile.TemporaryDirectory() as tmp:
        names = set(z.namelist())
        if not names & {"workspace.sqlite", "config.toml"}:
            raise ValueError("This file is not a S.T.A.R.K backup")
        if "workspace.sqlite" in names:
            p = Path(z.extract("workspace.sqlite", tmp))
            _check_sqlite(p)
            _replace_db(p, db_file)
            restored.append("workspace.sqlite")
        if "config.toml" in names:
            config_file.parent.mkdir(parents=True, exist_ok=True)
            if config_file.exists():
                shutil.copy2(config_file, config_file.with_suffix(".toml.bak"))
            config_file.write_bytes(z.read("config.toml"))
            if os.name != "nt":
                os.chmod(config_file, 0o600)
            restored.append("config.toml")
    return {"restored": restored, "previous": str(saved) if saved else None}


def _check_sqlite(p: Path) -> None:
    con = sqlite3.connect(str(p))
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.DatabaseError as exc:
        raise ValueError("The backup database is damaged or not a S.T.A.R.K database") from exc
    finally:
        con.close()
    if not {"users", "workspaces", "cases"} <= tables:
        raise ValueError("The backup database is not a S.T.A.R.K workspace database")


def _replace_db(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("-wal", "-shm"):
        side = Path(str(dest) + suffix)
        if side.exists():
            side.unlink()
    copy_database(src, dest)


# ------------------------------------------------------------------ updates

_cache: Dict[str, Any] = {}


def update_checks_enabled() -> bool:
    return os.environ.get("STARK_NO_UPDATE_CHECK", "").strip().lower() not in ("1", "true", "yes")


def latest_release(timeout: float = 5.0, use_cache: bool = True) -> Optional[Dict[str, Any]]:
    """Latest published release from GitHub. Sends no user data; cached for 12 hours."""
    now = time.time()
    if use_cache and _cache.get("at", 0) > now - CHECK_EVERY:
        return _cache.get("release")
    import requests
    try:
        r = requests.get(RELEASES_API, timeout=timeout, headers={"Accept": "application/vnd.github+json",
                                                                 "User-Agent": f"stark/{__version__}"})
        r.raise_for_status()
        d = r.json()
        rel = {"version": str(d.get("tag_name") or "").lstrip("v"), "url": d.get("html_url") or RELEASES_PAGE,
               "published": d.get("published_at"), "notes": (d.get("body") or "")[:4000],
               "assets": {a["name"]: a["browser_download_url"] for a in d.get("assets") or []}}
    except Exception:  # noqa: BLE001 - offline or rate-limited: no update information
        rel = None
    _cache.update(at=now, release=rel)
    return rel


def update_status(check: bool = True) -> Dict[str, Any]:
    kind = install_kind()
    out: Dict[str, Any] = {"current": __version__, "kind": kind, "enabled": update_checks_enabled(),
                           "latest": None, "newer": False, "url": RELEASES_PAGE, "steps": instructions(kind)}
    if check and out["enabled"]:
        rel = latest_release()
        if rel and rel["version"]:
            out.update(latest=rel["version"], url=rel["url"],
                       newer=parse_version(rel["version"]) > parse_version(__version__),
                       steps=instructions(kind, rel["version"]))
    return out


def binary_asset_name() -> Optional[str]:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Windows":
        return "stark-windows-x64.exe"
    if system == "Darwin":
        return "stark-macos-arm64" if machine in ("arm64", "aarch64") else None
    if system == "Linux":
        return "stark-linux-x64" if machine in ("x86_64", "amd64") else None
    return None


def instructions(kind: str, version: Optional[str] = None) -> List[str]:
    tag = f"v{version}" if version else "the latest version"
    if kind == "binary":
        return ["Run `stark update` (or the downloaded program with `update`): it downloads the new program, checks "
                "its SHA-256 checksum and replaces this one.",
                f"Or download {binary_asset_name() or 'the file for your system'} from the releases page and "
                "replace the old file.",
                "Your accounts, API keys and cases stay where they are; you don't need to set anything up again."]
    if kind == "docker":
        return ["Rebuild or pull the new image, then recreate the container with the same data volume "
                "(`-v stark-data:/data`).",
                "Everything is stored in the /data volume, so it carries over."]
    if kind == "source":
        return ["In your S.T.A.R.K folder run `git pull`, then `python -m pip install -e .` to pick up new dependencies",
                "Restart the workspace."]
    if kind == "pipx":
        return [f"Run `stark update`, or `pipx install --force git+https://github.com/{REPO}.git@{tag if version else 'main'}`.",
                "Restart the workspace."]
    return ["Run `stark update` (it upgrades this installation with pip), or "
            f"`python -m pip install --upgrade git+https://github.com/{REPO}.git@{tag if version else 'main'}`.",
            "Restart the workspace."]


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def update_binary(rel: Dict[str, Any], log=print) -> Path:
    """Download the release binary for this platform, verify its checksum and swap it in."""
    import requests
    name = binary_asset_name()
    if not name or name not in rel["assets"]:
        raise RuntimeError(f"No release file for this system. Download it from {rel['url']}")
    sums_url = rel["assets"].get("SHA256SUMS.txt")
    if not sums_url:
        raise RuntimeError("The release has no SHA256SUMS.txt, so the download can't be verified")
    sums = requests.get(sums_url, timeout=30).text
    expected = next((ln.split()[0] for ln in sums.splitlines() if ln.strip().endswith(name)), None)
    if not expected:
        raise RuntimeError(f"No checksum listed for {name}")
    exe = Path(sys.executable).resolve()
    new = exe.with_name(exe.name + ".new")
    log(f"[*] downloading {name} {rel['version']} …")
    with requests.get(rel["assets"][name], stream=True, timeout=60) as r:
        r.raise_for_status()
        with open(new, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
    if _sha256(new) != expected.lower():
        new.unlink(missing_ok=True)
        raise RuntimeError("Checksum mismatch: the download was discarded and nothing was changed")
    if os.name != "nt":
        os.chmod(new, 0o755)
    old = exe.with_name(exe.name + ".old")
    if old.exists():
        old.unlink()
    os.replace(exe, old)  # a running program can be renamed, even on Windows
    os.replace(new, exe)
    try:
        old.unlink()
    except OSError:
        pass  # Windows keeps the running .old file; it is removed on the next update
    return exe


def update_pip(version: str, pipx: bool = False) -> int:
    url = f"git+https://github.com/{REPO}.git@v{version}"
    if pipx:
        return subprocess.call(["pipx", "install", "--force", url])
    return subprocess.call([sys.executable, "-m", "pip", "install", "--upgrade", url])
