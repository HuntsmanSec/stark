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
    md = client.post(f"/api/cases/{cid}/report/generate", json={"template": "technical"}, headers=H).get_json()["markdown"]
    for section in ("Quick Verdict", "Executive Summary", "Timeline", "Event Details", "Analysis", "Interpretation",
                    "Confidence Level", "Recommendations", "Actions Taken", "IOCs & Artifacts"):
        assert "## " in md and section in md, section
    # indicators are always defanged (final dot) and rendered as code
    assert "`185.220.101[.]1`" in md and "`WS01`" in md and "185.220.101.1" not in md
    assert "beacon to `185.220.101[.]1`" in md
    assert "https://attack.mitre.org/techniques/T1059/001/" in md  # reference links stay usable
    # even if an analyst pastes live indicators into the report, the saved copy is defanged
    saved = client.patch(f"/api/cases/{cid}", json={"report_md": md + "\nextra http://evil.example.net/x"}, headers=H).get_json()
    assert "hxxp://evil.example[.]net/x" in saved["report_md"]
    assert saved["assessment"]["verdict"] in ("inconclusive", "suspicious", "likely_malicious", "true_positive")
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
    assert code("1.2.3.4") == "`1.2.3[.]4`"
    assert code("1.2.3.4", defang=False) == "`1.2.3.4`"
    assert code("a`b") == "`` a`b ``"
    assert code("http://evil.com", defang=True) == "`hxxp://evil[.]com`"
    md = generate({"title": "t", "observables": [], "artifacts": [], "techniques": []})
    assert md.startswith("# Incident Report: t")


def test_findings_assets_search_and_onboarding(client):
    u = register(client)
    assert u["onboarded"] is False
    ws = u["workspaces"][0]["id"]
    cid = client.post(f"/api/workspaces/{ws}/cases", json={"title": "T"}, headers=H).get_json()["id"]
    finding = {"key": "process:lsass", "category": "process", "title": "Credential dumping from LSASS", "severity": "critical",
               "confidence": "high", "description": "d", "interpretation": "i", "recommendation": "r",
               "mitre": [{"id": "T1003.001"}], "entities": {"hosts": ["WS01"]}, "evidence": [], "count": 1}
    c = client.post(f"/api/cases/{cid}/findings", json={"items": [finding, finding]}, headers=H).get_json()
    assert len(c["findings"]) == 1 and c["techniques"][0]["technique_id"] == "T1003.001"
    assert c["assessment"]["verdict"] in ("suspicious", "likely_malicious")
    fid = c["findings"][0]["id"]
    c = client.patch(f"/api/cases/{cid}/findings/{fid}", json={"status": "dismissed"}, headers=H).get_json()
    assert c["assessment"]["auto"]["verdict"] == "inconclusive"
    c = client.patch(f"/api/cases/{cid}", json={"verdict": "true_positive", "confidence": "high"}, headers=H).get_json()
    assert c["assessment"]["verdict"] == "true_positive" and c["assessment"]["overridden"]
    # asset inventory: CSV import + lookup by IP, hostname or MAC in any format
    csv = "hostname,ip,mac,owner,criticality\nFIN-WS-014,10.0.4.21,00-1A-2B-3C-4D-5E,Jane Doe,High\n"
    assert client.post(f"/api/workspaces/{ws}/assets", json={"csv": csv}, headers=H).get_json()["saved"] == 1
    for q in ("10.0.4.21", "fin-ws", "00:1a:2b:3c:4d:5e", "001A.2B3C.4D5E"):
        assert client.get(f"/api/workspaces/{ws}/assets?q={q}").get_json()[0]["hostname"] == "FIN-WS-014", q
    client.post(f"/api/cases/{cid}/observables", json={"text": "hxxps://evil[.]example[.]org/login"}, headers=H)
    s = client.get(f"/api/workspaces/{ws}/search?q=https://evil.example.org/login").get_json()
    assert s["ioc"]["type"] == "url" and any(h["kind"] == "indicator" for h in s["hits"])
    assert client.get(f"/api/workspaces/{ws}/search?q=10.0.4.21").get_json()["assets"][0]["owner"] == "Jane Doe"
    assert client.patch("/api/me", json={"onboarded": True}, headers=H).get_json()["user"]["onboarded"] is True


def test_relevance_filter_and_summary():
    from stark.summary import filter_report
    rep = {"observable": "185.220.101.1", "type": "ipv4", "verdict": "malicious", "malware_families": [], "results": [
        {"provider": "abuseipdb", "verdict": "malicious", "summary": "confidence 100%"},
        {"provider": "virustotal", "verdict": "error", "error": "HTTP 401"},
        {"provider": "shodan", "verdict": "unknown", "summary": "No record found"}]}
    out = filter_report(rep)
    assert [r["provider"] for r in out["results"]] == ["abuseipdb"] and out["sources_checked"] == 3
    assert "185[.]220[.]101[.]1" in out["summary"] and "MALICIOUS" in out["summary"] and "401" not in out["summary"]
    none = filter_report({**rep, "results": rep["results"][1:], "verdict": "error"})
    assert none["verdict"] == "unknown" and none["results"] == [] and "No reputation source" in none["summary"]


def test_auto_mitre_and_hide_restore(client):
    u = register(client)
    ws = u["workspaces"][0]["id"]
    cid = client.post(f"/api/workspaces/{ws}/cases", json={"title": "T"}, headers=H).get_json()["id"]
    d = client.post(f"/api/cases/{cid}/techniques/from-logs", headers=H, json={
        "products": ["Sysmon"], "items": [
            {"technique_id": "T1059.001", "count": 4, "example": "powershell -nop"},
            {"technique_id": "T1078", "count": 9, "example": "4624"},            # context-only: not mapped
            {"technique_id": "T1003.001", "count": 1, "finding": "Credential dumping from LSASS"}]}).get_json()
    tids = {t["technique_id"]: t for t in d["case"]["techniques"]}
    assert d["added"] == 2 and set(tids) == {"T1059.001", "T1003.001"}
    assert tids["T1059.001"]["auto"] and "Sysmon" in tids["T1059.001"]["basis"][0]
    # evidence-derived mapping (artifact) appears without any click
    client.post(f"/api/cases/{cid}/artifacts", json={"items": [{"kind": "command_line", "value": "mshta.exe http://x.example/a.hta"}]}, headers=H)
    c = client.get(f"/api/cases/{cid}").get_json()
    assert any(t["technique_id"] == "T1218.005" and t["id"] is None for t in c["techniques"])
    c = client.post(f"/api/cases/{cid}/techniques/hide", json={"technique_id": "T1218.005"}, headers=H).get_json()
    assert "T1218.005" not in {t["technique_id"] for t in c["techniques"]}
    assert [h["id"] for h in c["techniques_hidden"]] == ["T1218.005"]
    # re-arranging the same logs doesn't bring a hidden technique back
    client.post(f"/api/cases/{cid}/techniques/hide", json={"technique_id": "T1059.001"}, headers=H)
    d = client.post(f"/api/cases/{cid}/techniques/from-logs", headers=H, json={"items": [{"technique_id": "T1059.001", "count": 1}]}).get_json()
    assert d["added"] == 0 and "T1059.001" not in {t["technique_id"] for t in d["case"]["techniques"]}
    c = client.post(f"/api/cases/{cid}/techniques/restore", json={"technique_id": "T1218.005"}, headers=H).get_json()
    assert "T1218.005" in {t["technique_id"] for t in c["techniques"]}


def test_soc_report_with_related_records(client):
    u = register(client)
    ws = u["workspaces"][0]["id"]
    alert = {"alert_name": "Suspicious sign-in", "customer": "Contoso"}
    old = client.post(f"/api/workspaces/{ws}/cases", json={"title": "Earlier spray", **alert, "ticket_number": "INC0000042"},
                      headers=H).get_json()["id"]
    client.post(f"/api/cases/{old}/observables", json={"text": "45.77.12.9"}, headers=H)
    client.patch(f"/api/cases/{old}", json={"status": "in_progress", "disposition": "incident"}, headers=H)
    cid = client.post(f"/api/workspaces/{ws}/cases", json={"title": "New", **alert, "finding_id": "F-7",
                                                            "alert_url": "https://security.microsoft.com/alerts/9"},
                      headers=H).get_json()["id"]
    client.post(f"/api/cases/{cid}/observables", json={"text": "45.77.12[.]9"}, headers=H)
    r = client.post(f"/api/cases/{cid}/report/generate", json={}, headers=H).get_json()
    assert r["outcome"] == 1 and r["target"] == "INC0000042"
    assert r["markdown"].startswith('Appending finding "F-7" to "INC0000042"')
    # analyst can force another outcome
    r = client.post(f"/api/cases/{cid}/report/generate", json={"outcome": 3}, headers=H).get_json()
    assert r["outcome"] == 3 and "https://security.microsoft.com/alerts/9" in r["markdown"]
    saved = client.patch(f"/api/cases/{cid}", json={"report_md": r["markdown"]}, headers=H).get_json()
    assert "https://security.microsoft.com/alerts/9" in saved["report_md"]  # alert link stays live after save
    # imported records and pentest notes
    d = client.post(f"/api/cases/{cid}/context", json={"text": '[{"_type": "fusion-closure", "detail": "x", "closed_by": "A"},'
                                                               ' {"case number": "INC9", "status": "CLOSED"}]'}, headers=H).get_json()
    assert d["imported"] == 2
    assert client.post(f"/api/cases/{cid}/context", json={"text": "{bad"}, headers=H).status_code == 400
    notes = client.post(f"/api/workspaces/{ws}/pentests", json={"title": "Q4 test", "customer": "Contoso",
                                                                "tester_ips": "45.77.12.0/24, 198.51.100.7",
                                                                "client_instruction": "unannounced"}, headers=H).get_json()
    assert notes[0]["tester_ips"] == ["45.77.12.0/24", "198.51.100.7"]
    ctx = client.get(f"/api/cases/{cid}/context").get_json()
    assert len(ctx["records"]["closures"]) == 1 and len(ctx["records"]["pentests"]) == 1
    assert {t["case_number"] for t in ctx["records"]["tickets"]} == {"INC0000042", "INC9"}
    assert ctx["analysis"]["related"]["pentests"][0]["related"] is True
    # closing a case as non-threatening makes it a past closure for later cases
    client.patch(f"/api/cases/{old}", json={"status": "closed", "disposition": "non_threatening",
                                            "close_notes": "Corporate VPN"}, headers=H)
    ctx = client.get(f"/api/cases/{cid}/context").get_json()
    assert any(c.get("closure_note") == "Corporate VPN" for c in ctx["records"]["closures"])
