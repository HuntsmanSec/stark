import pytest

from stark.report import code, generate

H = {"X-Stark": "1"}


@pytest.fixture
def client(tmp_path):
    from stark.web.app import create_app
    app = create_app(db_path=str(tmp_path / "ws.sqlite"))
    return app.test_client()


def register(c, email="a@example.test", **kw):
    body = {"name": "Alice Analyst", "email": email, "password": "correct-horse-1", **kw}
    r = c.post("/api/auth/register", json=body, headers=H)
    assert r.status_code == 200, r.get_json()
    return r.get_json()["user"]


def team_id(user):
    return next(w["id"] for w in user["workspaces"] if w["kind"] == "team")


def test_auth_flow_and_csrf(client):
    assert client.get("/api/me").status_code == 401
    assert client.post("/api/auth/register", json={"name": "x", "email": "x@y.z", "password": "short"}, headers=H).status_code == 400
    u = register(client)
    assert [w["kind"] for w in u["workspaces"]] == ["personal"]
    assert client.post("/api/auth/logout", headers=H).status_code == 200
    assert client.post("/api/auth/login", json={"email": "a@example.test", "password": "nope"}, headers=H).status_code == 401
    assert client.post("/api/auth/login", json={"email": "a@example.test", "password": "correct-horse-1"}, headers=H).status_code == 200
    ws = u["workspaces"][0]["id"]
    # state-changing request without the custom header is refused (CSRF defence)
    assert client.post(f"/api/workspaces/{ws}/cases", json={"title": "x"}).status_code == 403


def test_team_workspace_isolation(tmp_path):
    from stark.web.app import create_app
    app = create_app(db_path=str(tmp_path / "ws.sqlite"))
    a, b, outsider = app.test_client(), app.test_client(), app.test_client()
    ua = register(a, account_type="team", team_name="SOC")
    code = a.get(f"/api/workspaces/{team_id(ua)}").get_json()["invite_code"]
    ub = register(b, email="b@example.test", account_type="join", invite_code=code)
    register(outsider, email="c@example.test")
    case = a.post(f"/api/workspaces/{team_id(ua)}/cases", json={"title": "Phish", "severity": "high"}, headers=H).get_json()
    assert case["ref"].startswith("CASE-")
    # teammate sees and edits the case, and the update is visible to the owner
    assert b.patch(f"/api/cases/{case['id']}", json={"status": "in_progress"}, headers=H).status_code == 200
    v = a.get(f"/api/cases/{case['id']}/version").get_json()
    assert v["updated_by_name"] == "Alice Analyst" or v["updated_by"] == ub["id"]
    assert a.get(f"/api/cases/{case['id']}").get_json()["status"] == "in_progress"
    # outsider cannot see it
    assert outsider.get(f"/api/cases/{case['id']}").status_code == 404
    assert outsider.get(f"/api/workspaces/{team_id(ua)}/cases").status_code == 404
    # members can't change keys, admins can
    assert b.put(f"/api/workspaces/{team_id(ua)}/keys", json={"keys": {"virustotal": "x"}}, headers=H).status_code == 403
    r = a.put(f"/api/workspaces/{team_id(ua)}/keys", json={"keys": {"virustotal": "abcd1234efgh5678"}}, headers=H).get_json()
    vt = next(k for k in r["keys"] if k["name"] == "virustotal")
    assert vt["set"] and "abcd1234efgh5678" not in str(r)


def test_case_children_report_and_exports(client):
    u = register(client)
    ws = u["workspaces"][0]["id"]
    cid = client.post(f"/api/workspaces/{ws}/cases", json={"title": "Test"}, headers=H).get_json()["id"]
    d = client.post(f"/api/cases/{cid}/observables", json={"text": "185.220.101[.]1\nevil.example.org\n185.220.101.1"}, headers=H).get_json()
    assert d["added"] == 2
    d = client.post(f"/api/cases/{cid}/observables", json={"text": "185.220.101.1"}, headers=H).get_json()
    assert d["added"] == 0 and d["skipped"] == 1
    client.post(f"/api/cases/{cid}/artifacts", json={"items": [{"kind": "host", "value": "WS01"}]}, headers=H)
    client.post(f"/api/cases/{cid}/techniques", json={"items": [{"technique_id": "t1059.001"}]}, headers=H)
    client.post(f"/api/cases/{cid}/events", json={"items": [{"time": "2026-11-01T10:00:00Z", "text": "beacon to 185.220.101.1"}]}, headers=H)
    client.post(f"/api/cases/{cid}/actions", json={"text": "Blocked 185.220.101.1"}, headers=H)
    c = client.get(f"/api/cases/{cid}").get_json()
    assert c["techniques"][0]["tactic"] == "Execution"
    md = client.post(f"/api/cases/{cid}/report/generate", json={}, headers=H).get_json()["markdown"]
    for section in ("Executive Summary", "Technical Analysis", "MITRE ATT&CK", "Recommendations", "Actions Taken", "Artifacts"):
        assert section in md
    assert "`185.220.101.1`" in md and "`WS01`" in md
    assert "beacon to `185.220.101.1`" in md
    assert client.patch(f"/api/cases/{cid}", json={"report_md": md}, headers=H).status_code == 200
    for fmt in ("stix", "csv", "irflow", "report"):
        r = client.get(f"/api/cases/{cid}/export/{fmt}")
        assert r.status_code == 200 and r.data
    assert b'"type": "bundle"' in client.get(f"/api/cases/{cid}/export/stix").data


def test_arrange_is_ephemeral(client, tmp_path):
    import io
    register(client)
    secret = "UNIQUE-CLIENT-SECRET-7f3a"
    r = client.post("/api/arrange", data={"files": (io.BytesIO(f'{{"DeviceName":"h1","ActionType":"x","ReportId":1,"ProcessCommandLine":"echo {secret}"}}'.encode()), "d.json"),
                                          "text": "CEF:0|V|P|1|1|n|5|src=45.77.12.9"},
                    headers=H, content_type="multipart/form-data")
    assert r.status_code == 200 and r.headers["Cache-Control"].startswith("no-store")
    body = r.get_json()
    assert body["stats"]["rows"] == 2
    for f in tmp_path.iterdir():
        if f.name.startswith("ws.sqlite"):
            assert secret.encode() not in f.read_bytes()


def test_report_code_helper():
    assert code("1.2.3.4") == "`1.2.3.4`"
    assert code("a`b") == "`` a`b ``"
    assert code("http://evil.com", defang=True) == "`hxxp[://]evil[.]com`"
    md = generate({"title": "t", "observables": [], "artifacts": [], "techniques": []})
    assert md.startswith("# Incident Report: t")
