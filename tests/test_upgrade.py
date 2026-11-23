"""Updating S.T.A.R.K must never lose accounts, API keys, cases or settings."""

import shutil
import zipfile
from pathlib import Path

import pytest

from stark import maintenance as m

H = {"X-Stark": "1"}
OLD_DB = Path(__file__).parent / "data" / "workspace-v0.3.1.sqlite"


@pytest.fixture
def old_db(tmp_path):
    p = tmp_path / "workspace.sqlite"
    shutil.copy(OLD_DB, p)
    return p


def login(client):
    r = client.post("/api/auth/login", json={"email": "old@example.test", "password": "correct-horse-1"}, headers=H)
    assert r.status_code == 200, r.get_json()
    return r.get_json()["user"]


def test_v031_database_upgrades_without_losing_data(old_db, capsys):
    from stark.web.app import create_app
    app = create_app(db_path=str(old_db))
    # a backup of the old database was saved before the upgrade
    backups = list((old_db.parent / "backups").glob("workspace-*.sqlite"))
    assert len(backups) == 1 and "-before-v" in backups[0].name
    assert "Saved a copy of your workspace before upgrading it" in capsys.readouterr().out
    c = app.test_client()
    u = login(c)                                              # the account still works
    ws = u["workspaces"][0]["id"]
    keys = {k["name"]: k for k in c.get(f"/api/workspaces/{ws}/keys").get_json()["keys"]}
    assert keys["virustotal"]["set"]                          # the API key survived
    cases = c.get(f"/api/workspaces/{ws}/cases").get_json()
    assert [x["title"] for x in cases] == ["Case from v0.3.1"]
    case = c.get(f"/api/cases/{cases[0]['id']}").get_json()
    assert case["description"] == "kept" and case["report_md"] == "# saved report"
    assert case["observables"][0]["value"] == "185.220.101.1"
    assert any(t["technique_id"] == "T1059.001" and t["note"] == "manual" for t in case["techniques"])
    # new features work on the upgraded database
    assert c.patch(f"/api/cases/{case['id']}", json={"alert_name": "x", "customer": "y"}, headers=H).status_code == 200
    assert c.post(f"/api/cases/{case['id']}/report/generate", json={}, headers=H).status_code == 200
    # opening it again with the same version doesn't make another backup
    create_app(db_path=str(old_db))
    assert len(list((old_db.parent / "backups").glob("workspace-*.sqlite"))) == 1


def test_backup_and_restore_roundtrip(old_db, tmp_path):
    from stark.web.app import create_app
    create_app(db_path=str(old_db)).config["DB"].close()
    cfg = tmp_path / "config.toml"
    cfg.write_text('[keys]\nvirustotal = "cli-key"\n')
    out = m.create_backup(tmp_path / "b.zip", db_file=old_db, config_file=cfg)
    assert set(zipfile.ZipFile(out).namelist()) == {"workspace.sqlite", "config.toml", "manifest.json"}
    # lose everything, then restore
    old_db.unlink()
    cfg.unlink()
    res = m.restore_backup(out, db_file=old_db, config_file=cfg)
    assert set(res["restored"]) == {"workspace.sqlite", "config.toml"}
    assert 'virustotal = "cli-key"' in cfg.read_text()
    c = create_app(db_path=str(old_db)).test_client()
    login(c)
    # a file that isn't a S.T.A.R.K backup is refused
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("x.txt", "x")
    with pytest.raises(ValueError):
        m.restore_backup(bad, db_file=old_db, config_file=cfg)


def test_backups_are_pruned(tmp_path):
    import sqlite3
    db = tmp_path / "workspace.sqlite"
    sqlite3.connect(str(db)).execute("CREATE TABLE t (x)").connection.commit()
    for i in range(m.KEEP_BACKUPS + 3):
        m.auto_backup(db, f"r{i}")
    assert len(list((tmp_path / "backups").glob("*.sqlite"))) <= m.KEEP_BACKUPS


def test_update_status_and_instructions(monkeypatch):
    monkeypatch.setattr(m, "latest_release", lambda **k: {"version": "99.0.0", "url": "https://example.test/r",
                                                          "assets": {}})
    s = m.update_status()
    assert s["newer"] and s["latest"] == "99.0.0" and s["steps"]
    monkeypatch.setenv("STARK_NO_UPDATE_CHECK", "1")
    assert m.update_status()["latest"] is None
    assert m.parse_version("v0.10.0") > m.parse_version("0.9.9")
    for kind in ("binary", "docker", "source", "pipx", "pip"):
        assert m.instructions(kind, "1.2.3")


def test_update_endpoint(tmp_path, monkeypatch):
    from stark.web.app import create_app
    monkeypatch.setattr(m, "latest_release", lambda **k: None)
    c = create_app(db_path=str(tmp_path / "ws.sqlite")).test_client()
    assert c.get("/api/update").status_code == 401
    c.post("/api/auth/register", json={"name": "A", "email": "a@example.test", "password": "correct-horse-1"}, headers=H)
    d = c.get("/api/update").get_json()
    assert d["current"] and d["data"]["database"].endswith("ws.sqlite") and d["newer"] is False
