"""SQLite storage for the workspace (accounts, workspaces, cases).

Only case data the analyst chooses to keep is stored here: observables, artifacts,
techniques, pinned timeline events, actions, comments and the report. Raw logs
processed by the Log Arranger are never written to this database.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL COLLATE NOCASE, name TEXT NOT NULL,
  password_hash TEXT NOT NULL, created_at REAL NOT NULL, theme TEXT DEFAULT 'system'
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at REAL NOT NULL, expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('personal','team')),
  owner_id INTEGER NOT NULL REFERENCES users(id), invite_code TEXT UNIQUE, created_at REAL NOT NULL,
  case_seq INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS memberships (
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','member')), joined_at REAL NOT NULL,
  PRIMARY KEY (workspace_id, user_id)
);
CREATE TABLE IF NOT EXISTS workspace_keys (
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL, value TEXT NOT NULL, updated_at REAL NOT NULL, PRIMARY KEY (workspace_id, name)
);
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  ref TEXT NOT NULL, title TEXT NOT NULL, description TEXT DEFAULT '', severity TEXT DEFAULT 'medium',
  status TEXT DEFAULT 'open', tlp TEXT DEFAULT 'amber', classification TEXT DEFAULT '',
  assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_by INTEGER REFERENCES users(id),
  created_at REAL NOT NULL, updated_at REAL NOT NULL, updated_by INTEGER,
  incident_start TEXT, incident_end TEXT, report_md TEXT DEFAULT '', report_updated_at REAL
);
CREATE INDEX IF NOT EXISTS ix_cases_ws ON cases(workspace_id, updated_at);
CREATE TABLE IF NOT EXISTS observables (
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  value TEXT NOT NULL, type TEXT NOT NULL, verdict TEXT DEFAULT 'pending', score INTEGER,
  flagged_by TEXT DEFAULT '[]', families TEXT DEFAULT '[]', tags TEXT DEFAULT '[]', results TEXT DEFAULT '[]',
  note TEXT DEFAULT '', source TEXT DEFAULT '', added_by INTEGER, created_at REAL NOT NULL, enriched_at REAL,
  UNIQUE (case_id, type, value)
);
CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, value TEXT NOT NULL, note TEXT DEFAULT '', added_by INTEGER, created_at REAL NOT NULL,
  UNIQUE (case_id, kind, value)
);
CREATE TABLE IF NOT EXISTS techniques (
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  technique_id TEXT NOT NULL, name TEXT NOT NULL, tactic TEXT NOT NULL, note TEXT DEFAULT '',
  added_by INTEGER, created_at REAL NOT NULL, UNIQUE (case_id, technique_id)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  time TEXT, text TEXT NOT NULL, added_by INTEGER, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  text TEXT NOT NULL, done_at TEXT, added_by INTEGER, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  user_id INTEGER, body TEXT NOT NULL, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, user_id INTEGER, text TEXT NOT NULL,
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_activity_ws ON activity(workspace_id, created_at);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  key TEXT NOT NULL, category TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL,
  description TEXT DEFAULT '', interpretation TEXT DEFAULT '', recommendation TEXT DEFAULT '',
  mitre TEXT DEFAULT '[]', entities TEXT DEFAULT '{}', evidence TEXT DEFAULT '[]', extra TEXT DEFAULT '{}',
  count INTEGER DEFAULT 0, first TEXT, last TEXT, status TEXT DEFAULT 'open', note TEXT DEFAULT '',
  added_by INTEGER, created_at REAL NOT NULL, UNIQUE (case_id, key)
);
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  hostname TEXT DEFAULT '', ip TEXT DEFAULT '', mac TEXT DEFAULT '', os TEXT DEFAULT '', owner TEXT DEFAULT '',
  department TEXT DEFAULT '', location TEXT DEFAULT '', criticality TEXT DEFAULT '', notes TEXT DEFAULT '',
  updated_at REAL NOT NULL, updated_by INTEGER
);
CREATE INDEX IF NOT EXISTS ix_assets_ws ON assets(workspace_id);
"""

MIGRATIONS = [
    "ALTER TABLE cases ADD COLUMN verdict TEXT DEFAULT ''",
    "ALTER TABLE cases ADD COLUMN confidence TEXT DEFAULT ''",
    "ALTER TABLE users ADD COLUMN onboarded INTEGER DEFAULT 0",
    "ALTER TABLE observables ADD COLUMN sources_checked INTEGER DEFAULT 0",
]


def data_dir() -> Path:
    if os.environ.get("STARK_DATA_DIR"):
        return Path(os.environ["STARK_DATA_DIR"]).expanduser()
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "stark"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "stark"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "stark"


class DB:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else data_dir() / "workspace.sqlite"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        with self.connect() as con:
            con.executescript(SCHEMA)
            for sql in MIGRATIONS:  # idempotent upgrades of databases created by older versions
                try:
                    con.execute(sql)
                except sqlite3.OperationalError:
                    pass
        if os.name != "nt":
            try:
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass

    def connect(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(str(self.path), timeout=15, check_same_thread=False)
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA foreign_keys=ON")
            self._local.con = con
        return con

    # small helpers --------------------------------------------------------
    def q(self, sql: str, args: Iterable[Any] = ()) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.connect().execute(sql, tuple(args)).fetchall()]

    def one(self, sql: str, args: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
        r = self.connect().execute(sql, tuple(args)).fetchone()
        return dict(r) if r else None

    def x(self, sql: str, args: Iterable[Any] = ()) -> int:
        con = self.connect()
        cur = con.execute(sql, tuple(args))
        con.commit()
        return cur.lastrowid or cur.rowcount

    def ins(self, sql: str, args: Iterable[Any] = ()) -> int:
        """Execute an INSERT OR IGNORE and return 1 if a row was inserted, else 0."""
        con = self.connect()
        cur = con.execute(sql, tuple(args))
        con.commit()
        return cur.rowcount

    def many(self, sql: str, rows: List[Iterable[Any]]) -> int:
        con = self.connect()
        cur = con.executemany(sql, [tuple(r) for r in rows])
        con.commit()
        return cur.rowcount

    # domain helpers -------------------------------------------------------
    def log(self, workspace_id: int, user_id: Optional[int], text: str, case_id: Optional[int] = None) -> None:
        self.x("INSERT INTO activity (workspace_id, case_id, user_id, text, created_at) VALUES (?,?,?,?,?)",
               (workspace_id, case_id, user_id, text, time.time()))

    def touch_case(self, case_id: int, user_id: Optional[int]) -> None:
        self.x("UPDATE cases SET updated_at=?, updated_by=? WHERE id=?", (time.time(), user_id, case_id))

    def next_ref(self, workspace_id: int) -> str:
        con = self.connect()
        with con:
            con.execute("UPDATE workspaces SET case_seq = case_seq + 1 WHERE id=?", (workspace_id,))
            seq = con.execute("SELECT case_seq FROM workspaces WHERE id=?", (workspace_id,)).fetchone()[0]
        return f"CASE-{time.strftime('%Y')}-{seq:04d}"


def new_token(n: int = 32) -> str:
    return secrets.token_urlsafe(n)


def invite_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))
