"""S.T.A.R.K workspace: a small Flask JSON API plus a static single-page UI."""

from __future__ import annotations

import io
import json
import mimetypes
import re
import threading
import time
from collections import defaultdict
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, Request, Response, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

from .. import __version__
from .. import mitre as mitre_mod
from ..config import Config, mask
from ..observables import ObsType, iter_lines, parse_observable
from ..summary import filter_report
from .db import DB, invite_code, new_token

mimetypes.add_type("application/javascript", ".js")  # Windows registry sometimes maps .js to text/plain
mimetypes.add_type("text/css", ".css")

STATIC = Path(__file__).parent / "static"
SESSION_COOKIE = "stark_session"
SESSION_DAYS = 14
MAX_UPLOAD_MB = 64

SEVERITIES = ["info", "low", "medium", "high", "critical"]
STATUSES = ["open", "in_progress", "contained", "closed"]
TLPS = ["clear", "green", "amber", "amber+strict", "red"]
VERDICTS = ["", "true_positive", "likely_malicious", "suspicious", "benign", "false_positive", "inconclusive"]
CONFIDENCES = ["", "high", "medium", "low"]
FINDING_STATUS = ["open", "confirmed", "dismissed"]
ARTIFACT_KINDS = ["host", "user", "process", "command_line", "file", "registry", "email", "other"]


class InMemoryRequest(Request):
    """Keep uploaded files in RAM. Werkzeug would otherwise spool large uploads to temp
    files, and client logs must never touch the disk."""

    max_form_memory_size = MAX_UPLOAD_MB * 1024 * 1024

    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        return io.BytesIO()


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _j(v: Optional[str], default=None):
    try:
        return json.loads(v) if v else (default if default is not None else [])
    except ValueError:
        return default if default is not None else []


def create_app(db_path: Optional[str] = None, allow_signup: bool = True, secure_cookies: bool = False) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.request_class = InMemoryRequest
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
    db = DB(Path(db_path) if db_path else None)
    app.config["DB"] = db
    app.config["ALLOW_SIGNUP"] = allow_signup
    jobs: Dict[int, Dict[str, Any]] = {}
    jobs_lock = threading.Lock()
    login_fails: Dict[str, List[float]] = defaultdict(list)

    # ------------------------------------------------------------ plumbing
    @app.errorhandler(ApiError)
    def _api_error(e: ApiError):
        return jsonify({"error": e.message}), e.status

    @app.errorhandler(500)
    def _server_error(_e):
        return jsonify({"error": "Something went wrong on the server. Check the S.T.A.R.K console output."}), 500

    @app.errorhandler(413)
    def _too_big(_e):
        return jsonify({"error": f"Upload too large (limit {MAX_UPLOAD_MB} MB)"}), 413

    @app.before_request
    def _load_user():
        g.user = None
        tok = request.cookies.get(SESSION_COOKIE)
        if tok:
            row = db.one("SELECT u.id, u.email, u.name, u.theme, u.onboarded FROM sessions s JOIN users u ON u.id=s.user_id "
                         "WHERE s.token=? AND s.expires_at>?", (tok, time.time()))
            g.user = row
        # CSRF defence: state-changing API calls must carry a custom header that a
        # cross-site form cannot set (cookies are also SameSite=Strict).
        if request.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.headers.get("X-Stark") != "1":
                raise ApiError(403, "Missing X-Stark header")

    @app.after_request
    def _headers(resp: Response):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def body() -> Dict[str, Any]:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not g.user:
                raise ApiError(401, "Please sign in")
            return fn(*a, **kw)
        return wrapper

    def membership(ws_id: int) -> Dict[str, Any]:
        m = db.one("SELECT w.*, m.role FROM workspaces w JOIN memberships m ON m.workspace_id=w.id "
                   "WHERE w.id=? AND m.user_id=?", (ws_id, g.user["id"]))
        if not m:
            raise ApiError(404, "Workspace not found")
        return m

    def require_admin(ws: Dict[str, Any]) -> None:
        if ws["role"] not in ("owner", "admin"):
            raise ApiError(403, "Only workspace owners and admins can do this")

    def get_case(case_id: int) -> Dict[str, Any]:
        c = db.one("SELECT * FROM cases WHERE id=?", (case_id,))
        if not c:
            raise ApiError(404, "Case not found")
        g.ws = membership(c["workspace_id"])
        return c

    def changed(case: Dict[str, Any], text: Optional[str] = None) -> None:
        db.touch_case(case["id"], g.user["id"])
        if text:
            db.log(case["workspace_id"], g.user["id"], text, case["id"])

    def user_payload(u: Dict[str, Any]) -> Dict[str, Any]:
        wss = db.q("SELECT w.id, w.name, w.kind, w.owner_id, m.role, "
                   "(SELECT COUNT(*) FROM memberships mm WHERE mm.workspace_id=w.id) AS members "
                   "FROM workspaces w JOIN memberships m ON m.workspace_id=w.id WHERE m.user_id=? "
                   "ORDER BY w.kind DESC, w.name", (u["id"],))
        for w in wss:
            w["keys_configured"] = db.one("SELECT COUNT(*) AS n FROM workspace_keys WHERE workspace_id=?", (w["id"],))["n"]
        return {"id": u["id"], "email": u["email"], "name": u["name"], "theme": u.get("theme") or "system",
                "onboarded": bool(u.get("onboarded")), "workspaces": wss}

    def start_session(user_id: int) -> Response:
        tok = new_token()
        now = time.time()
        db.x("INSERT INTO sessions VALUES (?,?,?,?)", (tok, user_id, now, now + SESSION_DAYS * 86400))
        db.x("DELETE FROM sessions WHERE expires_at<?", (now,))
        u = db.one("SELECT id, email, name, theme, onboarded FROM users WHERE id=?", (user_id,))
        resp = jsonify({"user": user_payload(u)})
        resp.set_cookie(SESSION_COOKIE, tok, max_age=SESSION_DAYS * 86400, httponly=True, samesite="Strict",
                        secure=secure_cookies, path="/")
        return resp

    def create_workspace(owner_id: int, name: str, kind: str) -> int:
        ws_id = db.x("INSERT INTO workspaces (name, kind, owner_id, invite_code, created_at) VALUES (?,?,?,?,?)",
                     (name, kind, owner_id, invite_code() if kind == "team" else None, time.time()))
        db.x("INSERT INTO memberships VALUES (?,?,?,?)", (ws_id, owner_id, "owner", time.time()))
        db.log(ws_id, owner_id, f"created the {'team ' if kind == 'team' else ''}workspace “{name}”")
        return ws_id

    # ---------------------------------------------------------------- auth
    @app.get("/api/meta")
    def meta():
        has_users = db.one("SELECT 1 AS x FROM users LIMIT 1") is not None
        return jsonify({"version": __version__, "allow_signup": app.config["ALLOW_SIGNUP"] or not has_users,
                        "has_users": has_users})

    @app.post("/api/auth/register")
    def register():
        d = body()
        has_users = db.one("SELECT 1 AS x FROM users LIMIT 1") is not None
        if has_users and not app.config["ALLOW_SIGNUP"]:
            raise ApiError(403, "Sign-up is disabled on this server. Ask an administrator for an account.")
        name = (d.get("name") or "").strip()[:80]
        email = (d.get("email") or "").strip().lower()[:200]
        pw = d.get("password") or ""
        if not name or "@" not in email:
            raise ApiError(400, "Please enter your name and a valid email")
        if len(pw) < 10:
            raise ApiError(400, "Password must be at least 10 characters")
        if db.one("SELECT id FROM users WHERE email=?", (email,)):
            raise ApiError(409, "An account with this email already exists")
        uid = db.x("INSERT INTO users (email, name, password_hash, created_at) VALUES (?,?,?,?)",
                   (email, name, generate_password_hash(pw), time.time()))
        create_workspace(uid, f"{name.split()[0]}'s workspace", "personal")
        kind = d.get("account_type")
        if kind == "team" and (d.get("team_name") or "").strip():
            create_workspace(uid, d["team_name"].strip()[:80], "team")
        elif kind == "join" and (d.get("invite_code") or "").strip():
            _join(uid, d["invite_code"])
        return start_session(uid)

    @app.post("/api/auth/login")
    def login():
        d = body()
        email = (d.get("email") or "").strip().lower()
        key = f"{request.remote_addr}|{email}"
        now = time.time()
        login_fails[key] = [t for t in login_fails[key] if now - t < 900]
        if len(login_fails[key]) >= 8:
            raise ApiError(429, "Too many failed attempts. Try again in 15 minutes.")
        u = db.one("SELECT id, password_hash FROM users WHERE email=?", (email,))
        if not u or not check_password_hash(u["password_hash"], d.get("password") or ""):
            login_fails[key].append(now)
            raise ApiError(401, "Email or password is incorrect")
        login_fails.pop(key, None)
        return start_session(u["id"])

    @app.post("/api/auth/logout")
    def logout():
        tok = request.cookies.get(SESSION_COOKIE)
        if tok:
            db.x("DELETE FROM sessions WHERE token=?", (tok,))
        resp = jsonify({"ok": True})
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get("/api/me")
    @login_required
    def me():
        return jsonify({"user": user_payload(g.user)})

    @app.patch("/api/me")
    @login_required
    def update_me():
        d = body()
        if "name" in d and d["name"].strip():
            db.x("UPDATE users SET name=? WHERE id=?", (d["name"].strip()[:80], g.user["id"]))
        if "onboarded" in d:
            db.x("UPDATE users SET onboarded=? WHERE id=?", (1 if d["onboarded"] else 0, g.user["id"]))
        if d.get("theme") in ("system", "light", "dark"):
            db.x("UPDATE users SET theme=? WHERE id=?", (d["theme"], g.user["id"]))
        if d.get("new_password"):
            u = db.one("SELECT password_hash FROM users WHERE id=?", (g.user["id"],))
            if not check_password_hash(u["password_hash"], d.get("current_password") or ""):
                raise ApiError(400, "Current password is incorrect")
            if len(d["new_password"]) < 10:
                raise ApiError(400, "Password must be at least 10 characters")
            db.x("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(d["new_password"]),
                                                                  g.user["id"]))
            db.x("DELETE FROM sessions WHERE user_id=? AND token<>?", (g.user["id"], request.cookies.get(SESSION_COOKIE)))
        u = db.one("SELECT id, email, name, theme, onboarded FROM users WHERE id=?", (g.user["id"],))
        return jsonify({"user": user_payload(u)})

    # ---------------------------------------------------------- workspaces
    def _join(user_id: int, code: str) -> int:
        ws = db.one("SELECT * FROM workspaces WHERE invite_code=? AND kind='team'", (code.strip().upper(),))
        if not ws:
            raise ApiError(404, "Invite code not found. Check it with your team owner.")
        if not db.one("SELECT 1 AS x FROM memberships WHERE workspace_id=? AND user_id=?", (ws["id"], user_id)):
            db.x("INSERT INTO memberships VALUES (?,?,?,?)", (ws["id"], user_id, "member", time.time()))
            db.log(ws["id"], user_id, "joined the team")
        return ws["id"]

    @app.post("/api/workspaces")
    @login_required
    def new_workspace():
        name = (body().get("name") or "").strip()[:80]
        if not name:
            raise ApiError(400, "Team name is required")
        ws_id = create_workspace(g.user["id"], name, "team")
        return jsonify({"id": ws_id, "user": user_payload(g.user)})

    @app.post("/api/workspaces/join")
    @login_required
    def join_workspace():
        ws_id = _join(g.user["id"], body().get("code") or "")
        return jsonify({"id": ws_id, "user": user_payload(g.user)})

    @app.get("/api/workspaces/<int:ws_id>")
    @login_required
    def workspace(ws_id):
        ws = membership(ws_id)
        members = db.q("SELECT u.id, u.name, u.email, m.role, m.joined_at FROM memberships m JOIN users u "
                       "ON u.id=m.user_id WHERE m.workspace_id=? ORDER BY m.role='owner' DESC, u.name", (ws_id,))
        out = {k: ws[k] for k in ("id", "name", "kind", "role", "created_at")}
        out["members"] = members
        out["invite_code"] = ws["invite_code"] if ws["role"] in ("owner", "admin") else None
        return jsonify(out)

    @app.patch("/api/workspaces/<int:ws_id>")
    @login_required
    def update_workspace(ws_id):
        ws = membership(ws_id)
        require_admin(ws)
        d = body()
        if d.get("name", "").strip():
            db.x("UPDATE workspaces SET name=? WHERE id=?", (d["name"].strip()[:80], ws_id))
        if d.get("regenerate_invite") and ws["kind"] == "team":
            db.x("UPDATE workspaces SET invite_code=? WHERE id=?", (invite_code(), ws_id))
        return workspace(ws_id)

    @app.patch("/api/workspaces/<int:ws_id>/members/<int:uid>")
    @login_required
    def update_member(ws_id, uid):
        ws = membership(ws_id)
        require_admin(ws)
        role = body().get("role")
        target = db.one("SELECT role FROM memberships WHERE workspace_id=? AND user_id=?", (ws_id, uid))
        if not target or target["role"] == "owner" or role not in ("admin", "member"):
            raise ApiError(400, "Cannot change this member's role")
        db.x("UPDATE memberships SET role=? WHERE workspace_id=? AND user_id=?", (role, ws_id, uid))
        return workspace(ws_id)

    @app.delete("/api/workspaces/<int:ws_id>/members/<int:uid>")
    @login_required
    def remove_member(ws_id, uid):
        ws = membership(ws_id)
        if uid != g.user["id"]:
            require_admin(ws)
        target = db.one("SELECT role FROM memberships WHERE workspace_id=? AND user_id=?", (ws_id, uid))
        if not target:
            raise ApiError(404, "Member not found")
        if target["role"] == "owner":
            raise ApiError(400, "The owner cannot leave or be removed")
        db.x("DELETE FROM memberships WHERE workspace_id=? AND user_id=?", (ws_id, uid))
        db.log(ws_id, g.user["id"], "left the team" if uid == g.user["id"] else "removed a member")
        return jsonify({"ok": True})

    @app.get("/api/workspaces/<int:ws_id>/activity")
    @login_required
    def ws_activity(ws_id):
        membership(ws_id)
        rows = db.q("SELECT a.*, u.name AS user_name, c.ref AS case_ref FROM activity a LEFT JOIN users u ON "
                    "u.id=a.user_id LEFT JOIN cases c ON c.id=a.case_id WHERE a.workspace_id=? "
                    "ORDER BY a.created_at DESC LIMIT 40", (ws_id,))
        return jsonify(rows)

    @app.get("/api/workspaces/<int:ws_id>/dashboard")
    @login_required
    def dashboard(ws_id):
        membership(ws_id)
        stats = db.one(
            "SELECT SUM(status<>'closed') AS open, SUM(status<>'closed' AND severity IN ('high','critical')) AS urgent,"
            " SUM(status='closed') AS closed, COUNT(*) AS total FROM cases WHERE workspace_id=?", (ws_id,))
        flagged = db.one("SELECT COUNT(*) AS n FROM observables o JOIN cases c ON c.id=o.case_id WHERE "
                         "c.workspace_id=? AND o.verdict IN ('malicious','suspicious')", (ws_id,))
        recent = db.q("SELECT c.id, c.ref, c.title, c.severity, c.status, c.updated_at, u.name AS assignee_name "
                      "FROM cases c LEFT JOIN users u ON u.id=c.assignee_id WHERE c.workspace_id=? "
                      "ORDER BY c.updated_at DESC LIMIT 6", (ws_id,))
        return jsonify({"stats": {k: (v or 0) for k, v in stats.items()} | {"flagged_iocs": flagged["n"]},
                        "recent": recent})

    # --------------------------------------------------------------- keys
    @app.get("/api/workspaces/<int:ws_id>/keys")
    @login_required
    def get_keys(ws_id):
        ws = membership(ws_id)
        from ..providers import PROVIDERS, key_names
        stored = {r["name"]: r["value"] for r in db.q("SELECT name, value FROM workspace_keys WHERE workspace_id=?",
                                                       (ws_id,))}
        local = Config()
        out = []
        for k in key_names():
            provs = [p for p in PROVIDERS if p.config_key() == k]
            out.append({
                "name": k, "providers": [p.display for p in provs],
                "required": any(p.requires_key for p in provs),
                "homepage": provs[0].homepage if provs else "",
                "description": provs[0].description if provs else "",
                "set": k in stored, "masked": mask(stored.get(k)) if ws["role"] in ("owner", "admin") else
                ("set" if k in stored else ""),
                "local_fallback": bool(local.get_key(k)) and k not in stored,
            })
        return jsonify({"keys": out, "can_edit": ws["role"] in ("owner", "admin")})

    @app.put("/api/workspaces/<int:ws_id>/keys")
    @login_required
    def put_keys(ws_id):
        ws = membership(ws_id)
        require_admin(ws)
        from ..providers import key_names
        valid = set(key_names())
        for name, value in (body().get("keys") or {}).items():
            if name not in valid:
                continue
            value = (value or "").strip()
            if value:
                db.x("INSERT OR REPLACE INTO workspace_keys VALUES (?,?,?,?)", (ws_id, name, value, time.time()))
            elif value == "" and body().get("clear_empty"):
                db.x("DELETE FROM workspace_keys WHERE workspace_id=? AND name=?", (ws_id, name))
        db.log(ws_id, g.user["id"], "updated API keys")
        return get_keys(ws_id)

    @app.delete("/api/workspaces/<int:ws_id>/keys/<name>")
    @login_required
    def delete_key(ws_id, name):
        ws = membership(ws_id)
        require_admin(ws)
        db.x("DELETE FROM workspace_keys WHERE workspace_id=? AND name=?", (ws_id, name))
        return get_keys(ws_id)

    def engine_for(ws_id: int, providers=None, include_informational=False):
        from ..engine import Stark
        cfg = Config()
        for r in db.q("SELECT name, value FROM workspace_keys WHERE workspace_id=?", (ws_id,)):
            cfg.keys[r["name"]] = r["value"]
        return Stark(config=cfg, providers=providers, include_informational=include_informational)

    # --------------------------------------------------------------- cases
    def case_row(c: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(c)
        out.pop("report_md", None)
        return out

    @app.get("/api/workspaces/<int:ws_id>/cases")
    @login_required
    def list_cases(ws_id):
        membership(ws_id)
        sql = ("SELECT c.*, u.name AS assignee_name, "
               "(SELECT COUNT(*) FROM observables o WHERE o.case_id=c.id) AS ioc_count, "
               "(SELECT COUNT(*) FROM observables o WHERE o.case_id=c.id AND o.verdict='malicious') AS malicious_count "
               "FROM cases c LEFT JOIN users u ON u.id=c.assignee_id WHERE c.workspace_id=?")
        args: List[Any] = [ws_id]
        status = request.args.get("status")
        if status == "active":
            sql += " AND c.status<>'closed'"
        elif status in STATUSES:
            sql += " AND c.status=?"
            args.append(status)
        q = (request.args.get("q") or "").strip()
        if q:
            sql += (" AND (c.title LIKE ? OR c.ref LIKE ? OR c.description LIKE ? OR EXISTS (SELECT 1 FROM observables o"
                    " WHERE o.case_id=c.id AND o.value LIKE ?))")
            args += [f"%{q}%"] * 4
        sql += " ORDER BY c.updated_at DESC LIMIT 500"
        return jsonify([case_row(c) for c in db.q(sql, args)])

    @app.post("/api/workspaces/<int:ws_id>/cases")
    @login_required
    def create_case(ws_id):
        membership(ws_id)
        d = body()
        title = (d.get("title") or "").strip()[:200]
        if not title:
            raise ApiError(400, "Give the case a title")
        now = time.time()
        sev = d.get("severity") if d.get("severity") in SEVERITIES else "medium"
        tlp = d.get("tlp") if d.get("tlp") in TLPS else "amber"
        cid = db.x("INSERT INTO cases (workspace_id, ref, title, description, severity, status, tlp, classification,"
                   " assignee_id, created_by, created_at, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (ws_id, db.next_ref(ws_id), title, (d.get("description") or "")[:20000], sev, "open", tlp,
                    (d.get("classification") or "")[:80], g.user["id"], g.user["id"], now, now, g.user["id"]))
        c = db.one("SELECT * FROM cases WHERE id=?", (cid,))
        db.log(ws_id, g.user["id"], f"opened case {c['ref']}: {title}", cid)
        return jsonify(case_row(c)), 201

    def full_case(c: Dict[str, Any]) -> Dict[str, Any]:
        cid = c["id"]
        out = dict(c)
        out["observables"] = [
            {**o, "flagged_by": _j(o["flagged_by"]), "families": _j(o["families"]), "tags": _j(o["tags"]),
             "results": _j(o["results"])}
            for o in db.q("SELECT * FROM observables WHERE case_id=? ORDER BY created_at, id", (cid,))]
        out["artifacts"] = db.q("SELECT * FROM artifacts WHERE case_id=? ORDER BY kind, created_at", (cid,))
        out["techniques"] = db.q("SELECT * FROM techniques WHERE case_id=? ORDER BY technique_id", (cid,))
        out["events"] = db.q("SELECT e.*, u.name AS added_by_name FROM events e LEFT JOIN users u ON u.id=e.added_by "
                             "WHERE case_id=? ORDER BY time, id", (cid,))
        out["actions"] = db.q("SELECT a.*, u.name AS added_by_name FROM actions a LEFT JOIN users u ON "
                              "u.id=a.added_by WHERE case_id=? ORDER BY done_at, id", (cid,))
        out["comments"] = db.q("SELECT c.*, u.name AS user_name FROM comments c LEFT JOIN users u ON u.id=c.user_id "
                               "WHERE case_id=? ORDER BY created_at", (cid,))
        out["findings"] = [
            {**f, "mitre": _j(f["mitre"]), "entities": _j(f["entities"], {}), "evidence": _j(f["evidence"]),
             "extra": _j(f["extra"], {})}
            for f in db.q("SELECT * FROM findings WHERE case_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 "
                          "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id", (cid,))]
        out["activity"] = db.q("SELECT a.*, u.name AS user_name FROM activity a LEFT JOIN users u ON u.id=a.user_id "
                               "WHERE case_id=? ORDER BY created_at DESC LIMIT 100", (cid,))
        out["members"] = db.q("SELECT u.id, u.name FROM memberships m JOIN users u ON u.id=m.user_id "
                              "WHERE m.workspace_id=? ORDER BY u.name", (c["workspace_id"],))
        out["workspace"] = {"id": g.ws["id"], "name": g.ws["name"], "kind": g.ws["kind"], "role": g.ws["role"]}
        with jobs_lock:
            out["job"] = dict(jobs[cid]) if cid in jobs else None
        u = db.one("SELECT name FROM users WHERE id=?", (c.get("updated_by"),)) if c.get("updated_by") else None
        out["updated_by_name"] = u["name"] if u else None
        from ..report import assess
        out["assessment"] = assess(out)
        return out

    @app.get("/api/cases/<int:case_id>")
    @login_required
    def get_case_api(case_id):
        return jsonify(full_case(get_case(case_id)))

    @app.get("/api/cases/<int:case_id>/version")
    @login_required
    def case_version(case_id):
        c = get_case(case_id)
        with jobs_lock:
            job = dict(jobs[case_id]) if case_id in jobs else None
        u = db.one("SELECT name FROM users WHERE id=?", (c.get("updated_by"),)) if c.get("updated_by") else None
        return jsonify({"updated_at": c["updated_at"], "updated_by": c.get("updated_by"),
                        "updated_by_name": u["name"] if u else None, "job": job})

    @app.patch("/api/cases/<int:case_id>")
    @login_required
    def update_case(case_id):
        c = get_case(case_id)
        d = body()
        sets, args, notes = [], [], []
        for f, allowed in (("severity", SEVERITIES), ("status", STATUSES), ("tlp", TLPS), ("verdict", VERDICTS),
                           ("confidence", CONFIDENCES)):
            if f in d and d[f] in allowed and d[f] != c[f]:
                sets.append(f"{f}=?")
                args.append(d[f])
                notes.append(f"{f} → {d[f].replace('_', ' ')}")
        for f, limit in (("title", 200), ("description", 20000), ("classification", 80), ("incident_start", 40),
                         ("incident_end", 40)):
            if f in d and isinstance(d[f], str):
                sets.append(f"{f}=?")
                args.append(d[f][:limit])
                if f == "title":
                    notes.append("renamed the case")
        if "assignee_id" in d:
            aid = d["assignee_id"]
            if aid is not None and not db.one("SELECT 1 AS x FROM memberships WHERE workspace_id=? AND user_id=?",
                                              (c["workspace_id"], aid)):
                raise ApiError(400, "Assignee must be a workspace member")
            sets.append("assignee_id=?")
            args.append(aid)
            notes.append("changed the assignee")
        if "report_md" in d and isinstance(d["report_md"], str):
            sets += ["report_md=?", "report_updated_at=?"]
            from ..report import defang_markdown
            args += [defang_markdown(d["report_md"][:1_000_000]), time.time()]
            notes.append("saved the report")
        if sets:
            db.x(f"UPDATE cases SET {', '.join(sets)} WHERE id=?", (*args, case_id))
            changed(c, f"updated {c['ref']}: {', '.join(notes)}" if notes else None)
        return jsonify(full_case(db.one("SELECT * FROM cases WHERE id=?", (case_id,))))

    @app.delete("/api/cases/<int:case_id>")
    @login_required
    def delete_case(case_id):
        c = get_case(case_id)
        if g.ws["role"] not in ("owner", "admin") and c["created_by"] != g.user["id"]:
            raise ApiError(403, "Only the case creator or a workspace admin can delete a case")
        db.x("DELETE FROM cases WHERE id=?", (case_id,))
        db.log(c["workspace_id"], g.user["id"], f"deleted case {c['ref']}: {c['title']}")
        return jsonify({"ok": True})

    # ---------------------------------------------------------- observables
    @app.post("/api/cases/<int:case_id>/observables")
    @login_required
    def add_observables(case_id):
        c = get_case(case_id)
        d = body()
        items = d.get("items")
        parsed = []
        if isinstance(items, list):
            for it in items[:5000]:
                v = it.get("value") if isinstance(it, dict) else it
                t = it.get("type") if isinstance(it, dict) else None
                o = parse_observable(str(v), forced=ObsType(t) if t in [x.value for x in ObsType] else None)
                if o:
                    parsed.append(o)
        if d.get("text"):
            parsed += list(iter_lines(str(d["text"]).splitlines()))
        source = (d.get("source") or "manual")[:60]
        now = time.time()
        added = 0
        for o in dict.fromkeys(parsed):
            added += db.ins("INSERT OR IGNORE INTO observables (case_id, value, type, source, added_by, created_at) "
                          "VALUES (?,?,?,?,?,?)", (case_id, o.value, o.type.value, source, g.user["id"], now))
        if added:
            changed(c, f"added {added} observable{'s' if added != 1 else ''} to {c['ref']}")
        if d.get("enrich") and added:
            _start_enrich(c, None)
        return jsonify({"added": added, "skipped": len(parsed) - added, "case": full_case(get_case(case_id))})

    @app.patch("/api/cases/<int:case_id>/observables/<int:oid>")
    @login_required
    def update_observable(case_id, oid):
        c = get_case(case_id)
        d = body()
        if "note" in d:
            db.x("UPDATE observables SET note=? WHERE id=? AND case_id=?", (str(d["note"])[:2000], oid, case_id))
        if d.get("verdict") in ("malicious", "suspicious", "harmless", "unknown"):
            db.x("UPDATE observables SET verdict=? WHERE id=? AND case_id=?", (d["verdict"], oid, case_id))
        changed(c)
        return jsonify(full_case(get_case(case_id)))

    @app.post("/api/cases/<int:case_id>/observables/delete")
    @login_required
    def delete_observables(case_id):
        c = get_case(case_id)
        ids = [int(i) for i in body().get("ids") or [] if str(i).isdigit()]
        if ids:
            db.x(f"DELETE FROM observables WHERE case_id=? AND id IN ({','.join('?' * len(ids))})", (case_id, *ids))
            changed(c, f"removed {len(ids)} observable(s) from {c['ref']}")
        return jsonify(full_case(get_case(case_id)))

    def _start_enrich(c: Dict[str, Any], ids: Optional[List[int]]):
        cid = c["id"]
        with jobs_lock:
            if cid in jobs and jobs[cid].get("running"):
                raise ApiError(409, "Enrichment is already running for this case")
            jobs[cid] = {"running": True, "done": 0, "total": 0, "started_at": time.time(), "error": None,
                         "by": g.user["name"]}
        user_id = g.user["id"]
        ws_id = c["workspace_id"]

        def run():
            try:
                rows = db.q("SELECT * FROM observables WHERE case_id=?", (cid,))
                if ids:
                    rows = [r for r in rows if r["id"] in ids]
                eng = engine_for(ws_id)
                if not eng.providers:
                    raise RuntimeError("No reputation sources are available. Add API keys in Settings.")
                obs_map = {}
                for r in rows:
                    o = parse_observable(r["value"], forced=ObsType(r["type"]))
                    if o:
                        obs_map[o] = r["id"]
                with jobs_lock:
                    jobs[cid]["total"] = sum(1 for o in obs_map for p in eng.providers if p.supports(o))

                def progress(done, total, _res):
                    with jobs_lock:
                        jobs[cid]["done"] = done

                reports = eng.query_many(list(obs_map), progress=progress)
                now = time.time()
                for rep in reports:
                    # Only sources with an actual opinion are kept: errors, unsupported or
                    # "no record" answers never reach the investigation.
                    d = filter_report(rep.to_dict())
                    db.x("UPDATE observables SET verdict=?, score=?, flagged_by=?, families=?, tags=?, results=?, "
                         "enriched_at=?, sources_checked=? WHERE id=?",
                         (d["verdict"], d["score"], json.dumps(d["flagged_by"]), json.dumps(d["malware_families"]),
                          json.dumps(d["tags"][:20]), json.dumps(d["results"]), now, d["sources_checked"],
                          obs_map[rep.observable]))
                bad = sum(1 for r in reports if r.verdict.value == "malicious")
                db.touch_case(cid, user_id)
                db.log(ws_id, user_id, f"enriched {len(reports)} observable(s) in {c['ref']}: {bad} malicious", cid)
                with jobs_lock:
                    jobs[cid].update(running=False, finished_at=time.time())
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI
                with jobs_lock:
                    jobs[cid].update(running=False, error=str(exc), finished_at=time.time())
                db.touch_case(cid, user_id)

        threading.Thread(target=run, name=f"enrich-{cid}", daemon=True).start()

    @app.post("/api/cases/<int:case_id>/enrich")
    @login_required
    def enrich(case_id):
        c = get_case(case_id)
        ids = [int(i) for i in body().get("ids") or [] if str(i).isdigit()] or None
        _start_enrich(c, ids)
        return jsonify({"started": True})

    # --------------------------------------------------- simple child records
    def _child_add(table: str, case_id: int, cols: Dict[str, Any], note: str):
        c = get_case(case_id)
        cols = {**cols, "case_id": case_id, "added_by": g.user["id"], "created_at": time.time()}
        keys = list(cols)
        db.x(f"INSERT OR IGNORE INTO {table} ({','.join(keys)}) VALUES ({','.join('?' * len(keys))})",
             [cols[k] for k in keys])
        changed(c, note)
        return jsonify(full_case(get_case(case_id)))

    def _child_delete(table: str, case_id: int, rid: int):
        c = get_case(case_id)
        db.x(f"DELETE FROM {table} WHERE id=? AND case_id=?", (rid, case_id))
        changed(c)
        return jsonify(full_case(get_case(case_id)))

    @app.post("/api/cases/<int:case_id>/artifacts")
    @login_required
    def add_artifacts(case_id):
        c = get_case(case_id)
        d = body()
        items = d.get("items") or [d]
        now = time.time()
        n = 0
        for it in items[:2000]:
            kind = it.get("kind") if it.get("kind") in ARTIFACT_KINDS else "other"
            value = str(it.get("value") or "").strip()[:5000]
            if value:
                n += db.ins("INSERT OR IGNORE INTO artifacts (case_id, kind, value, note, added_by, created_at) "
                          "VALUES (?,?,?,?,?,?)", (case_id, kind, value, str(it.get("note") or "")[:1000],
                                                  g.user["id"], now))
        if n:
            changed(c, f"added {n} artifact(s) to {c['ref']}")
        return jsonify(full_case(get_case(case_id)))

    @app.delete("/api/cases/<int:case_id>/artifacts/<int:rid>")
    @login_required
    def del_artifact(case_id, rid):
        return _child_delete("artifacts", case_id, rid)

    @app.post("/api/cases/<int:case_id>/techniques")
    @login_required
    def add_techniques(case_id):
        c = get_case(case_id)
        d = body()
        items = d.get("items") or [d]
        now = time.time()
        n = 0
        for it in items[:200]:
            tid = str(it.get("technique_id") or it.get("id") or "").strip().upper()
            if not tid.startswith("T"):
                continue
            t = mitre_mod.technique(tid)
            n += db.ins("INSERT OR IGNORE INTO techniques (case_id, technique_id, name, tactic, note, added_by, created_at)"
                      " VALUES (?,?,?,?,?,?,?)", (case_id, t["id"], t["name"], t["tactic"],
                                                  str(it.get("note") or "")[:2000], g.user["id"], now))
        if n:
            changed(c, f"mapped {n} ATT&CK technique(s) in {c['ref']}")
        return jsonify(full_case(get_case(case_id)))

    @app.patch("/api/cases/<int:case_id>/techniques/<int:rid>")
    @login_required
    def update_technique(case_id, rid):
        c = get_case(case_id)
        db.x("UPDATE techniques SET note=? WHERE id=? AND case_id=?", (str(body().get("note") or "")[:2000], rid, case_id))
        changed(c)
        return jsonify(full_case(get_case(case_id)))

    @app.delete("/api/cases/<int:case_id>/techniques/<int:rid>")
    @login_required
    def del_technique(case_id, rid):
        return _child_delete("techniques", case_id, rid)

    @app.post("/api/cases/<int:case_id>/events")
    @login_required
    def add_events(case_id):
        c = get_case(case_id)
        d = body()
        items = d.get("items") or [d]
        now = time.time()
        for it in items[:2000]:
            text = str(it.get("text") or "").strip()[:4000]
            if text:
                db.x("INSERT INTO events (case_id, time, text, added_by, created_at) VALUES (?,?,?,?,?)",
                     (case_id, str(it.get("time") or "")[:40] or None, text, g.user["id"], now))
        changed(c, f"pinned {len(items)} event(s) to the {c['ref']} timeline")
        return jsonify(full_case(get_case(case_id)))

    @app.delete("/api/cases/<int:case_id>/events/<int:rid>")
    @login_required
    def del_event(case_id, rid):
        return _child_delete("events", case_id, rid)

    @app.post("/api/cases/<int:case_id>/actions")
    @login_required
    def add_action(case_id):
        d = body()
        text = str(d.get("text") or "").strip()[:4000]
        if not text:
            raise ApiError(400, "Describe the action")
        done_at = str(d.get("done_at") or "")[:40] or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return _child_add("actions", case_id, {"text": text, "done_at": done_at}, "recorded a response action")

    @app.delete("/api/cases/<int:case_id>/actions/<int:rid>")
    @login_required
    def del_action(case_id, rid):
        return _child_delete("actions", case_id, rid)

    @app.post("/api/cases/<int:case_id>/comments")
    @login_required
    def add_comment(case_id):
        c = get_case(case_id)
        text = str(body().get("body") or "").strip()[:10000]
        if not text:
            raise ApiError(400, "Comment is empty")
        db.x("INSERT INTO comments (case_id, user_id, body, created_at) VALUES (?,?,?,?)",
             (case_id, g.user["id"], text, time.time()))
        changed(c, f"commented on {c['ref']}")
        return jsonify(full_case(get_case(case_id)))

    # ------------------------------------------------------------ report
    @app.post("/api/cases/<int:case_id>/report/generate")
    @login_required
    def gen_report(case_id):
        from ..report import generate
        c = full_case(get_case(case_id))
        return jsonify({"markdown": generate(c, author=g.user["name"])})

    @app.get("/api/cases/<int:case_id>/export/<fmt>")
    @login_required
    def export(case_id, fmt):
        from ..models import ObservableReport, ProviderResult
        from ..output import render
        c = full_case(get_case(case_id))
        reports = []
        for o in c["observables"]:
            ob = parse_observable(o["value"], forced=ObsType(o["type"]))
            if not ob:
                continue
            reports.append(ObservableReport(ob, [ProviderResult.from_dict(ob, r) for r in o["results"]]))
        name = c["ref"]
        if fmt == "stix":
            text, mime, ext = render("stix", reports, tlp=(c["tlp"] or "amber").split("+")[0]), "application/json", "stix.json"
        elif fmt in ("csv", "irflow", "vestigex", "hashset", "json", "md"):
            text = render(fmt, reports)
            mime, ext = {"json": ("application/json", "json"), "md": ("text/markdown", "md"),
                         "hashset": ("text/plain", "hashset.txt")}.get(fmt, ("text/csv", f"{fmt}.csv"))
        elif fmt == "report":
            text, mime, ext = c.get("report_md") or "", "text/markdown", "report.md"
        else:
            raise ApiError(404, "Unknown export format")
        resp = Response(text, mimetype=mime)
        resp.headers["Content-Disposition"] = f'attachment; filename="{name}.{ext}"'
        return resp

    # ------------------------------------------------ ephemeral log arranger
    @app.post("/api/arrange")
    @login_required
    def arrange_logs():
        """Parse uploaded/pasted logs IN MEMORY and return the arranged timeline.

        Nothing from the request is stored: no DB writes, no temp files, no logging
        of the body. The browser keeps the result in memory only."""
        from ..logarranger import arrange
        sources = []
        for f in request.files.getlist("files")[:50]:
            raw = f.read()
            sources.append((f.filename or "upload", raw.decode("utf-8-sig", errors="replace")))
            del raw
        text = request.form.get("text") or (body().get("text") if request.is_json else None)
        if text and text.strip():
            sources.append(("pasted", text))
        if not sources:
            raise ApiError(400, "Add a log file or paste some log lines")
        result = arrange(sources)
        sources.clear()
        resp = jsonify(result)
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        resp.headers["X-Stark-Ephemeral"] = "1"
        return resp

    # ----------------------------------------------------- lookup & mitre
    @app.post("/api/lookup")
    @login_required
    def lookup():
        d = body()
        ws = membership(int(d.get("workspace_id") or 0))
        obs = list(iter_lines(str(d.get("text") or "").splitlines()))[:100]
        if not obs:
            raise ApiError(400, "Enter at least one IP, domain, URL, hash or email")
        eng = engine_for(ws["id"])
        if not eng.providers:
            raise ApiError(400, "No reputation sources are available. Add API keys in Settings.")
        reps = eng.query_many(obs)
        results = [filter_report(r.to_dict()) for r in reps]
        for r in results:
            r["seen_in"] = _seen_in(ws["id"], r["observable"])
        return jsonify({"results": results})


    # ------------------------------------------------------------ findings
    @app.post("/api/cases/<int:case_id>/findings")
    @login_required
    def add_findings(case_id):
        c = get_case(case_id)
        now = time.time()
        n = 0
        for f in (body().get("items") or [])[:500]:
            if not isinstance(f, dict) or not f.get("key") or not f.get("title"):
                continue
            n += db.ins(
                "INSERT OR IGNORE INTO findings (case_id, key, category, title, severity, confidence, description, "
                "interpretation, recommendation, mitre, entities, evidence, extra, count, first, last, added_by, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (case_id, str(f["key"])[:200], str(f.get("category") or "process")[:20], str(f["title"])[:300],
                 f.get("severity") if f.get("severity") in SEVERITIES else "medium",
                 f.get("confidence") if f.get("confidence") in ("high", "medium", "low") else "medium",
                 str(f.get("description") or "")[:5000], str(f.get("interpretation") or "")[:5000],
                 str(f.get("recommendation") or "")[:3000], json.dumps(f.get("mitre") or [])[:20000],
                 json.dumps(f.get("entities") or {})[:20000], json.dumps((f.get("evidence") or [])[:8])[:40000],
                 json.dumps({k: f[k] for k in ("decoded", "decoded_iocs", "countries", "impersonates", "technique",
                                               "interval_seconds", "jitter", "tools") if k in f})[:20000],
                 int(f.get("count") or 0), f.get("first"), f.get("last"), g.user["id"], now))
            for t in f.get("mitre") or []:  # map the finding's techniques into the case automatically
                tid = t.get("id") if isinstance(t, dict) else str(t)
                if tid:
                    tt = mitre_mod.technique(tid)
                    db.ins("INSERT OR IGNORE INTO techniques (case_id, technique_id, name, tactic, note, added_by, created_at)"
                           " VALUES (?,?,?,?,?,?,?)", (case_id, tt["id"], tt["name"], tt["tactic"],
                                                       f"From finding: {str(f['title'])[:200]}", g.user["id"], now))
        if n:
            changed(c, f"added {n} security finding(s) to {c['ref']}")
        return jsonify(full_case(get_case(case_id)))

    @app.patch("/api/cases/<int:case_id>/findings/<int:fid>")
    @login_required
    def update_finding(case_id, fid):
        c = get_case(case_id)
        d = body()
        if d.get("status") in FINDING_STATUS:
            db.x("UPDATE findings SET status=? WHERE id=? AND case_id=?", (d["status"], fid, case_id))
        if "note" in d:
            db.x("UPDATE findings SET note=? WHERE id=? AND case_id=?", (str(d["note"])[:3000], fid, case_id))
        if d.get("severity") in SEVERITIES:
            db.x("UPDATE findings SET severity=? WHERE id=? AND case_id=?", (d["severity"], fid, case_id))
        changed(c, f"updated a finding in {c['ref']}" if "status" in d else None)
        return jsonify(full_case(get_case(case_id)))

    @app.delete("/api/cases/<int:case_id>/findings/<int:rid>")
    @login_required
    def del_finding(case_id, rid):
        return _child_delete("findings", case_id, rid)

    # -------------------------------------------------------------- assets
    def _norm_mac(v: str) -> str:
        hexes = re.sub(r"[^0-9a-fA-F]", "", v or "")
        return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).lower() if len(hexes) == 12 else (v or "").strip()

    def _asset_search(ws_id: int, q: str) -> List[Dict[str, Any]]:
        q = (q or "").strip()
        if not q:
            return db.q("SELECT * FROM assets WHERE workspace_id=? ORDER BY hostname LIMIT 1000", (ws_id,))
        mac = _norm_mac(q)
        like = f"%{q}%"
        return db.q("SELECT * FROM assets WHERE workspace_id=? AND (hostname LIKE ? OR ip LIKE ? OR mac LIKE ? OR mac=? "
                    "OR owner LIKE ? OR notes LIKE ?) ORDER BY hostname LIMIT 200",
                    (ws_id, like, like, like, mac, like, like))

    @app.get("/api/workspaces/<int:ws_id>/assets")
    @login_required
    def list_assets(ws_id):
        membership(ws_id)
        return jsonify(_asset_search(ws_id, request.args.get("q") or ""))

    @app.post("/api/workspaces/<int:ws_id>/assets")
    @login_required
    def add_assets(ws_id):
        membership(ws_id)
        d = body()
        items = d.get("items") or []
        if d.get("csv"):
            import csv as _csv
            import io as _io
            reader = _csv.DictReader(_io.StringIO(str(d["csv"]).lstrip("\ufeff")))
            for row in reader:
                low = {str(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
                items.append({
                    "hostname": low.get("hostname") or low.get("host") or low.get("name") or low.get("computername") or low.get("device") or "",
                    "ip": low.get("ip") or low.get("ipaddress") or low.get("ip address") or low.get("ipv4") or "",
                    "mac": low.get("mac") or low.get("macaddress") or low.get("mac address") or "",
                    "os": low.get("os") or low.get("operatingsystem") or low.get("operating system") or "",
                    "owner": low.get("owner") or low.get("user") or low.get("assigned to") or low.get("primary user") or "",
                    "department": low.get("department") or low.get("dept") or "",
                    "location": low.get("location") or low.get("site") or "",
                    "criticality": low.get("criticality") or low.get("tier") or "",
                    "notes": low.get("notes") or low.get("description") or "",
                })
        now = time.time()
        n = 0
        for it in items[:20000]:
            host = str(it.get("hostname") or "").strip()[:200]
            ip = str(it.get("ip") or "").strip()[:100]
            mac = _norm_mac(str(it.get("mac") or ""))[:50]
            if not (host or ip or mac):
                continue
            vals = (str(it.get("os") or "")[:100], str(it.get("owner") or "")[:200], str(it.get("department") or "")[:100],
                    str(it.get("location") or "")[:100], str(it.get("criticality") or "")[:30], str(it.get("notes") or "")[:1000])
            existing = db.one("SELECT id FROM assets WHERE workspace_id=? AND ((hostname<>'' AND lower(hostname)=lower(?)) "
                              "OR (mac<>'' AND mac=?))", (ws_id, host, mac))
            if existing:
                db.x("UPDATE assets SET hostname=COALESCE(NULLIF(?,''),hostname), ip=COALESCE(NULLIF(?,''),ip), "
                     "mac=COALESCE(NULLIF(?,''),mac), os=COALESCE(NULLIF(?,''),os), owner=COALESCE(NULLIF(?,''),owner), "
                     "department=COALESCE(NULLIF(?,''),department), location=COALESCE(NULLIF(?,''),location), "
                     "criticality=COALESCE(NULLIF(?,''),criticality), notes=COALESCE(NULLIF(?,''),notes), updated_at=?, "
                     "updated_by=? WHERE id=?", (host, ip, mac, *vals, now, g.user["id"], existing["id"]))
            else:
                db.x("INSERT INTO assets (workspace_id, hostname, ip, mac, os, owner, department, location, criticality, notes,"
                     " updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (ws_id, host, ip, mac, *vals, now, g.user["id"]))
            n += 1
        if n:
            db.log(ws_id, g.user["id"], f"updated {n} asset(s) in the inventory")
        return jsonify({"saved": n, "assets": _asset_search(ws_id, "")})

    @app.delete("/api/workspaces/<int:ws_id>/assets/<int:aid>")
    @login_required
    def delete_asset(ws_id, aid):
        membership(ws_id)
        db.x("DELETE FROM assets WHERE id=? AND workspace_id=?", (aid, ws_id))
        return jsonify({"ok": True})

    # -------------------------------------------------------------- search
    def _seen_in(ws_id: int, value: str) -> List[Dict[str, Any]]:
        return db.q("SELECT DISTINCT c.id, c.ref, c.title, c.status, c.severity, o.verdict FROM observables o JOIN cases c "
                    "ON c.id=o.case_id WHERE c.workspace_id=? AND lower(o.value)=lower(?) ORDER BY c.updated_at DESC LIMIT 20",
                    (ws_id, value))

    @app.get("/api/workspaces/<int:ws_id>/search")
    @login_required
    def search(ws_id):
        membership(ws_id)
        q = (request.args.get("q") or "").strip()[:500]
        if not q:
            return jsonify({"q": q, "ioc": None, "cases": [], "hits": [], "assets": []})
        obs = parse_observable(q)
        like = f"%{q if not obs else obs.value}%"
        cases = db.q("SELECT id, ref, title, status, severity, updated_at FROM cases WHERE workspace_id=? AND "
                     "(title LIKE ? OR ref LIKE ? OR description LIKE ?) ORDER BY updated_at DESC LIMIT 20",
                     (ws_id, f"%{q}%", f"%{q}%", f"%{q}%"))
        hits = []
        for table, col, kind in (("observables", "value", "indicator"), ("artifacts", "value", "artifact"),
                                 ("events", "text", "timeline event"), ("findings", "title", "finding"),
                                 ("actions", "text", "action")):
            for r in db.q(f"SELECT x.{col} AS value, c.id, c.ref, c.title FROM {table} x JOIN cases c ON c.id=x.case_id "
                          f"WHERE c.workspace_id=? AND x.{col} LIKE ? ORDER BY c.updated_at DESC LIMIT 25", (ws_id, like)):
                hits.append({**r, "kind": kind})
        return jsonify({"q": q, "ioc": obs.to_dict() if obs else None, "cases": cases, "hits": hits,
                        "assets": _asset_search(ws_id, q if not obs else obs.value)[:50]})

    # ---------------------------------------------------------- key tests
    @app.post("/api/workspaces/<int:ws_id>/keys/test")
    @login_required
    def test_key(ws_id):
        ws = membership(ws_id)
        require_admin(ws)
        from ..providers import PROVIDERS
        from ..providers.base import make_session
        d = body()
        name = d.get("name")
        value = (d.get("value") or "").strip() or (db.one("SELECT value FROM workspace_keys WHERE workspace_id=? AND name=?",
                                                          (ws_id, name)) or {}).get("value") or Config().get_key(name or "")
        provs = [p for p in PROVIDERS if p.config_key() == name]
        if not provs:
            raise ApiError(404, "Unknown source")
        if not value and provs[0].requires_key:
            return jsonify({"ok": False, "message": "No key entered yet"})
        samples = {"ipv4": "8.8.8.8", "domain": "example.com", "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                   "email": "test@example.com", "url": "https://example.com/"}
        p = provs[0](api_key=value, session=make_session(), timeout=15, options={"rate_limit": None})
        kind = next(k for k in ("ipv4", "domain", "sha256", "url", "email") if any(t.value == k for t in p.supported))
        res = p.lookup(parse_observable(samples[kind]))
        if res.verdict.value == "error":
            return jsonify({"ok": False, "message": res.error or "Lookup failed"})
        return jsonify({"ok": True, "message": f"Connected: test lookup of {samples[kind]} returned “{res.verdict.value}”."})

    @app.get("/api/mitre")
    @login_required
    def mitre_search():
        return jsonify({"tactics": [n for _, n in mitre_mod.TACTICS],
                        "techniques": mitre_mod.search(request.args.get("q") or "", 400)})

    @app.get("/api/providers")
    @login_required
    def providers():
        from ..providers import PROVIDERS
        return jsonify([{"name": p.name, "display": p.display, "key": p.config_key(), "types": sorted(
            t.value for t in p.supported), "requires_key": p.requires_key, "homepage": p.homepage,
            "description": p.description, "informational": p.informational} for p in PROVIDERS])

    # ------------------------------------------------------------- static
    @app.get("/")
    @app.get("/<path:path>")
    def spa(path: str = ""):
        if path.startswith("api/"):
            raise ApiError(404, "Not found")
        root = STATIC.resolve()
        target = (root / path).resolve()
        if path and target.is_file() and root in target.parents:  # no path traversal
            resp = send_from_directory(STATIC, path)
            resp.headers["Cache-Control"] = "no-cache"
            return resp
        resp = send_from_directory(STATIC, "index.html")
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    return app


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True, allow_signup: bool = True,
          db_path: Optional[str] = None, secure_cookies: bool = False) -> None:
    from waitress import serve as wserve

    app = create_app(db_path=db_path, allow_signup=allow_signup, secure_cookies=secure_cookies)
    url = f"http://{'localhost' if host in ('127.0.0.1', '0.0.0.0', '::') else host}:{port}/"
    print(f"\n  S.T.A.R.K workspace v{__version__}\n  Open {url} in your browser")
    print(f"  Data: {app.config['DB'].path}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("  ! Listening on the network: put it behind HTTPS (reverse proxy) and use --secure-cookies.")
    print("  Press Ctrl+C to stop.\n")
    if open_browser:
        import webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    limit = MAX_UPLOAD_MB * 1024 * 1024
    # inbuf_overflow = limit keeps request bodies in memory (waitress spools bigger bodies to temp files)
    wserve(app, host=host, port=port, threads=12, ident="stark", max_request_body_size=limit,
           inbuf_overflow=limit)
