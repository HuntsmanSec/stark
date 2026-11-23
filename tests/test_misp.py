import json

from conftest import FakeResponse, FakeSession

from stark.integrations.misp import build_event, push_event
from stark.models import ObservableReport, ProviderResult, Verdict
from stark.observables import parse_observable
from stark.output import render
from stark.providers import REGISTRY, key_names

H = {"X-Stark": "1"}
URL = "https://misp.example.test"


def attr(value, to_ids=True, level="1", tags=(), warnings=None, event_id="12"):
    a = {"value": value, "to_ids": to_ids, "event_id": event_id,
         "Event": {"id": event_id, "info": "Emotet wave", "date": "2026-11-20", "threat_level_id": level,
                   "Orgc": {"name": "CIRCL"}, "Tag": [{"name": n} for n in tags]}}
    if warnings:
        a["warnings"] = warnings
    return a


def lookup(value, attrs, extra=None, key="k"):
    sess = FakeSession({"/attributes/restSearch": FakeResponse(200, {"response": {"Attribute": attrs}})})
    p = REGISTRY["misp"](api_key=key, session=sess, timeout=5, options={"rate_limit": None},
                         extra=extra if extra is not None else {"misp_url": URL + "/"})
    return p.lookup(parse_observable(value)), sess, p


def test_misp_needs_address_and_key():
    assert "misp_url" in key_names() and "misp" in key_names()
    _, _, p = lookup("1.2.3.4", [], extra={})
    assert not p.available
    _, _, p = lookup("1.2.3.4", [], key=None)
    assert not p.available


def test_misp_ids_attribute_in_high_event_is_malicious():
    tags = ['misp-galaxy:malpedia="Emotet"', "tlp:amber", 'misp-galaxy:threat-actor="TA542"']
    res, sess, _ = lookup("185.220.101.1", [attr("185.220.101.1", tags=tags)])
    assert res.verdict is Verdict.MALICIOUS and res.score == 95
    assert res.malware_families == ["Emotet"]
    assert "actor:TA542" in res.tags and not any(t.startswith("tlp:") for t in res.tags)
    assert res.link == f"{URL}/events/view/12"
    method, url, kw = sess.calls[0]
    assert method == "POST" and url == f"{URL}/attributes/restSearch"
    assert kw["headers"]["Authorization"] == "k" and kw["json"]["value"] == "185.220.101.1"


def test_misp_levels_context_and_false_positives():
    res, _, _ = lookup("evil.example.org", [attr("evil.example.org", level="3")])
    assert res.verdict is Verdict.SUSPICIOUS
    res, _, _ = lookup("evil.example.org", [attr("evil.example.org", to_ids=False)])
    assert res.verdict is Verdict.UNKNOWN and "context only" in res.summary
    res, _, _ = lookup("8.8.8.8", [attr("8.8.8.8", warnings=[{"warninglist_name": "Google DNS"}])])
    assert res.verdict is Verdict.HARMLESS
    res, _, _ = lookup("8.8.4.4", [attr("8.8.4.4", tags=['false-positive:risk="high"'])])
    assert res.verdict is Verdict.HARMLESS


def test_misp_not_found_and_bad_address():
    res, _, _ = lookup("1.2.3.4", [])
    assert res.verdict is Verdict.UNKNOWN
    res, _, _ = lookup("1.2.3.4", [attr("1.2.3.4")], extra={"misp_url": "misp.local"})
    assert res.verdict is Verdict.ERROR and "https://" in res.error


def _report(value, verdict, provider="virustotal", families=()):
    ob = parse_observable(value)
    return ObservableReport(ob, [ProviderResult(provider=provider, observable=ob, verdict=verdict, score=90,
                                                malware_families=list(families))])


def test_build_event_is_stable_and_skips_benign():
    reports = [_report("185.220.101.1", Verdict.MALICIOUS, families=["Emotet"]),
               _report("8.8.8.8", Verdict.HARMLESS),
               _report("44d88612fea8a8f36de82e1278abb02f", Verdict.UNKNOWN)]
    tech = [{"technique_id": "T1059.001", "name": "PowerShell"}]
    ev = build_event(reports, info="CASE-1: test", key="ws1:CASE-1", severity="high", tlp="amber", techniques=tech)["Event"]
    assert ev["threat_level_id"] == "1" and ev["analysis"] == "1" and ev["distribution"] == "0" and not ev["published"]
    vals = {a["value"]: a for a in ev["Attribute"]}
    assert set(vals) == {"185.220.101.1", "44d88612fea8a8f36de82e1278abb02f"}
    assert vals["185.220.101.1"]["to_ids"] and vals["185.220.101.1"]["type"] == "ip-dst"
    assert not vals["44d88612fea8a8f36de82e1278abb02f"]["to_ids"]
    names = [t["name"] for t in ev["Tag"]]
    assert "tlp:amber" in names and 'misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"' in names
    again = build_event(reports, info="x", key="ws1:CASE-1")["Event"]
    assert again["uuid"] == ev["uuid"] and again["Attribute"][0]["uuid"] == ev["Attribute"][0]["uuid"]
    assert json.loads(render("misp", reports))["Event"]["Attribute"]


def test_push_creates_then_updates(monkeypatch):
    import requests

    sent = []

    class Sess(requests.Session):
        def request(self, method, url, **kw):
            sent.append((method, url))
            if "/events/view/" in url:
                return FakeResponse(200 if len(sent) > 2 else 404, {})
            return FakeResponse(200, {"Event": {"id": "77", "uuid": "u"}})

    monkeypatch.setattr(requests, "Session", Sess)
    ev = build_event([_report("185.220.101.1", Verdict.MALICIOUS)], info="t", key="k")
    r = push_event(ev, URL, "key")
    assert r["created"] and r["url"] == f"{URL}/events/view/77" and sent[1][1].endswith("/events/add")
    r = push_event(ev, URL, "key")
    assert not r["created"] and "/events/edit/" in sent[3][1]


def test_workspace_misp_settings_export_and_send(tmp_path, monkeypatch):
    from stark.web.app import create_app
    app = create_app(db_path=str(tmp_path / "ws.sqlite"))
    c = app.test_client()
    u = c.post("/api/auth/register", json={"name": "A", "email": "a@example.test", "password": "correct-horse-1"},
               headers=H).get_json()["user"]
    ws = u["workspaces"][0]["id"]
    assert c.put(f"/api/workspaces/{ws}/keys", json={"keys": {"misp_url": "misp.local"}}, headers=H).status_code == 400
    keys = c.put(f"/api/workspaces/{ws}/keys", json={"keys": {"misp_url": URL + "/", "misp": "secretkey12345678"}},
                 headers=H).get_json()["keys"]
    url_row = next(k for k in keys if k["name"] == "misp_url")
    assert url_row["kind"] == "setting" and url_row["masked"] == URL
    assert next(k for k in keys if k["name"] == "misp")["masked"] != "secretkey12345678"

    cid = c.post(f"/api/workspaces/{ws}/cases", json={"title": "Phish", "severity": "high"}, headers=H).get_json()["id"]
    c.post(f"/api/cases/{cid}/observables", json={"text": "185.220.101.1"}, headers=H)
    ob = parse_observable("185.220.101.1")
    res = [ProviderResult(provider="abuseipdb", observable=ob, verdict=Verdict.MALICIOUS, score=100).to_dict()]
    app.config["DB"].x("UPDATE observables SET verdict='malicious', results=? WHERE case_id=?", (json.dumps(res), cid))

    exp = c.get(f"/api/cases/{cid}/export/misp")
    assert exp.status_code == 200 and "misp.json" in exp.headers["Content-Disposition"]
    assert exp.get_json()["Event"]["Attribute"][0]["value"] == "185.220.101.1"

    calls = {}

    def fake_push(event, url, key, verify=True, timeout=30):
        calls.update(url=url, key=key, n=len(event["Event"]["Attribute"]))
        return {"id": "5", "uuid": event["Event"]["uuid"], "url": f"{url}/events/view/5", "created": True}

    monkeypatch.setattr("stark.integrations.misp.push_event", fake_push)
    r = c.post(f"/api/cases/{cid}/misp", headers=H)
    assert r.status_code == 200 and r.get_json()["attributes"] == 1
    assert calls == {"url": URL, "key": "secretkey12345678", "n": 1}
