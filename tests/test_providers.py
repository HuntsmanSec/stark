from conftest import FakeResponse, FakeSession

from stark.models import Verdict
from stark.observables import parse_observable
from stark.providers import REGISTRY, resolve


def run(name, value, routes, key="k"):
    cls = REGISTRY[name]
    sess = FakeSession(routes)
    p = cls(api_key=key, session=sess, timeout=5, options={"rate_limit": None})
    p.limiter.interval = 0
    return p.lookup(parse_observable(value)), sess


def test_aliases():
    assert resolve("vt") == "virustotal"
    assert resolve("HA") == "hybridanalysis"


def test_virustotal_malicious():
    payload = {"data": {"id": "44d88612fea8a8f36de82e1278abb02f", "attributes": {
        "last_analysis_stats": {"malicious": 60, "suspicious": 0, "harmless": 0, "undetected": 10},
        "popular_threat_classification": {"suggested_threat_label": "eicar/test"},
        "tags": ["eicar"]}}}
    res, sess = run("virustotal", "44d88612fea8a8f36de82e1278abb02f", {"/files/": FakeResponse(200, payload)})
    assert res.verdict is Verdict.MALICIOUS
    assert res.score == 86
    assert res.malware_families == ["eicar/test"]
    assert sess.calls[0][2]["headers"]["x-apikey"] == "k"


def test_virustotal_not_found_is_unknown():
    res, _ = run("virustotal", "example.com", {})
    assert res.verdict is Verdict.UNKNOWN


def test_virustotal_url_id_is_base64():
    payload = {"data": {"id": "x", "attributes": {"last_analysis_stats": {"harmless": 5}}}}
    _, sess = run("virustotal", "https://example.com/", {"/urls/": FakeResponse(200, payload)})
    assert "/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8" in sess.calls[0][1]


def test_abuseipdb_scoring():
    payload = {"data": {"abuseConfidenceScore": 100, "totalReports": 900, "isp": "X", "countryCode": "DE"}}
    res, _ = run("abuseipdb", "185.220.101.1", {"abuseipdb": FakeResponse(200, payload)})
    assert res.verdict is Verdict.MALICIOUS and res.score == 100


def test_auth_failure_is_error():
    res, _ = run("abuseipdb", "1.1.1.1", {"abuseipdb": FakeResponse(401, {})})
    assert res.verdict is Verdict.ERROR and "authentication" in res.error


def test_rate_limit_is_error():
    res, _ = run("shodan", "1.1.1.1", {"shodan": FakeResponse(429, {})})
    assert res.verdict is Verdict.ERROR and "429" in res.error


def test_malwarebazaar_hit_and_miss():
    hit = {"query_status": "ok", "data": [{"signature": "AgentTesla", "file_type": "exe", "tags": ["rat"]}]}
    res, sess = run("malwarebazaar", "44d88612fea8a8f36de82e1278abb02f", {"mb-api": FakeResponse(200, hit)})
    assert res.verdict is Verdict.MALICIOUS and res.malware_families == ["AgentTesla"]
    assert sess.calls[0][2]["headers"]["Auth-Key"] == "k"
    res, _ = run("malwarebazaar", "44d88612fea8a8f36de82e1278abb02f",
                 {"mb-api": FakeResponse(200, {"query_status": "hash_not_found"})})
    assert res.verdict is Verdict.UNKNOWN


def test_threatfox():
    data = {"query_status": "ok", "data": [{"id": 1, "confidence_level": 100, "threat_type": "botnet_cc",
                                             "malware_printable": "Cobalt Strike", "tags": ["cs"]}]}
    res, _ = run("threatfox", "185.220.101.1", {"threatfox": FakeResponse(200, data)})
    assert res.verdict is Verdict.MALICIOUS and "Cobalt Strike" in res.malware_families


def test_hibp_breached_and_clean():
    res, _ = run("hibp", "a@example.com", {"breachedaccount": FakeResponse(200, [
        {"Name": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Passwords"], "IsVerified": True}])})
    assert res.verdict is Verdict.SUSPICIOUS and "Adobe" in res.summary
    res, _ = run("hibp", "a@example.com", {})
    assert res.verdict is Verdict.HARMLESS


def test_otx_pulses():
    data = {"pulse_info": {"count": 12, "pulses": [{"name": "C2", "tags": ["c2"], "malware_families": []}]}}
    res, _ = run("otx", "185.220.101.1", {"otx": FakeResponse(200, data)}, key=None)
    assert res.verdict is Verdict.SUSPICIOUS
    data["validation"] = [{"source": "akamai"}]
    res, _ = run("otx", "13.107.4.50", {"otx": FakeResponse(200, data)}, key=None)
    assert res.verdict is Verdict.HARMLESS


def test_recordedfuture():
    data = {"data": {"risk": {"score": 89, "criticality": 3, "criticalityLabel": "Malicious",
                              "evidenceDetails": [{"rule": "Current C&C Server"}]}, "intelCard": "https://rf/x"}}
    res, _ = run("recordedfuture", "185.220.101.1", {"recordedfuture": FakeResponse(200, data)})
    assert res.verdict is Verdict.MALICIOUS and res.link == "https://rf/x"


def test_mxtoolbox_listed():
    data = {"Failed": [{"Name": "Spamhaus ZEN"}, {"Name": "Barracuda"}, {"Name": "SORBS"}], "Passed": [{}] * 80}
    res, _ = run("mxtoolbox", "185.220.101.1", {"mxtoolbox": FakeResponse(200, data)})
    assert res.verdict is Verdict.MALICIOUS


def test_hybrid_analysis_hash_list_shape():
    data = [{"verdict": "malicious", "threat_score": 100, "vx_family": "Emotet", "sha256": "a" * 64}]
    res, _ = run("hybridanalysis", "a" * 64, {"search/hash": FakeResponse(200, data)})
    assert res.verdict is Verdict.MALICIOUS and res.malware_families == ["Emotet"]


def test_joesandbox():
    data = {"data": [{"webid": "123", "detection": "suspicious", "score": 5}]}
    res, _ = run("joesandbox", "a" * 64, {"analysis/search": FakeResponse(200, data)})
    assert res.verdict is Verdict.SUSPICIOUS and res.score == 50


def test_anyrun_threat_level():
    data = {"summary": {"threatLevel": 2, "tags": [{"tag": "lumma"}]}, "sourceTasks": [{}]}
    res, _ = run("anyrun", "evil.example.org", {"any.run": FakeResponse(200, data)})
    assert res.verdict is Verdict.MALICIOUS and "lumma" in res.tags


def test_talos_blocklist(monkeypatch):
    from stark.providers.network import Talos
    Talos._feed = None
    res, _ = run("talos", "185.220.101.1", {"ip-blacklist": FakeResponse(200, None, "185.220.101.1\n1.2.3.4\n")},
                 key=None)
    assert res.verdict is Verdict.MALICIOUS
    Talos._feed = None


def test_every_provider_has_metadata():
    for name, cls in REGISTRY.items():
        assert cls.display and cls.homepage and cls.supported and cls.description, name
