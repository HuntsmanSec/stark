import json

import stix2
from conftest import FakeResponse, FakeSession

from stark import stix
from stark.cli import main
from stark.engine import Stark
from stark.models import ObservableReport, ProviderResult, Verdict
from stark.observables import ObsType, parse_observable


def _report(value, verdict, families=()):
    o = parse_observable(value)
    return ObservableReport(o, [ProviderResult("virustotal", o, verdict, score=90, summary="x",
                                               malware_families=list(families), link="https://vt/x"),
                                ProviderResult("otx", o, Verdict.UNKNOWN, summary="0 pulses")])


def test_stix_bundle_is_valid():
    reports = [_report("185.220.101.1", Verdict.MALICIOUS, ["Cobalt Strike"]),
               _report("44d88612fea8a8f36de82e1278abb02f", Verdict.SUSPICIOUS),
               _report("https://evil.example.net/a'b", Verdict.MALICIOUS),
               _report("example.com", Verdict.HARMLESS)]
    bundle = stix.to_bundle(reports)
    parsed = stix2.parse(json.dumps(bundle), allow_custom=True)
    types = [o["type"] for o in parsed.objects]
    assert types.count("indicator") == 3
    assert "malware" in types and "note" in types and "relationship" in types
    # deterministic SCO id (spec 2.9): same value -> same id
    assert stix.sco_for(parse_observable("185.220.101.1"))["id"] == stix.sco_for(parse_observable("185.220.101.1"))["id"]


def test_stix_roundtrip_import():
    reports = [_report("185.220.101.1", Verdict.MALICIOUS), _report("44d88612fea8a8f36de82e1278abb02f",
                                                                   Verdict.MALICIOUS),
               _report("https://evil.example.net/a'b", Verdict.MALICIOUS)]
    obs = stix.observables_from_bundle(stix.to_bundle(reports))
    assert {o.value for o in obs} == {"185.220.101.1", "44d88612fea8a8f36de82e1278abb02f",
                                      "https://evil.example.net/a'b"}


def test_stix_pattern_import_compound():
    p = "[ipv4-addr:value = '1.2.3.4'] OR [file:hashes.'SHA-256' = '" + "a" * 64 + "'] OR [domain-name:value = 'x.org']"
    got = [(o.type, o.value) for o in stix.observables_from_pattern(p)]
    assert (ObsType.IPV4, "1.2.3.4") in got and (ObsType.SHA256, "a" * 64) in got and (ObsType.DOMAIN, "x.org") in got


def _engine_with_fake(routes, providers):
    eng = Stark(providers=providers, use_cache=False)
    sess = FakeSession(routes)
    for p in eng.providers:
        p.session = sess
        p.limiter.interval = 0
    return eng


def test_engine_aggregates(monkeypatch):
    monkeypatch.setenv("STARK_ABUSEIPDB_API_KEY", "k")
    eng = _engine_with_fake({"abuseipdb": FakeResponse(200, {"data": {"abuseConfidenceScore": 100}}),
                             "otx": FakeResponse(200, {"pulse_info": {"count": 0, "pulses": []}})},
                            ["abuseipdb", "otx"])
    reps = eng.query_many(["185.220.101.1", "example.com"])
    assert reps[0].verdict is Verdict.MALICIOUS and reps[0].flagged_by == ["abuseipdb"]
    assert [r.provider for r in reps[1].results] == ["otx"]  # abuseipdb doesn't do domains


def test_engine_skips_providers_without_keys():
    eng = Stark(use_cache=False)
    assert "virustotal" in eng.skipped and eng.skipped["virustotal"] == "no API key"
    assert "ipinfo" in eng.skipped  # informational only with --all


def test_cache_roundtrip(tmp_path):
    from stark.cache import ResultCache
    c = ResultCache(tmp_path / "c.sqlite", 60)
    o = parse_observable("1.2.3.4")
    c.put(ProviderResult("otx", o, Verdict.MALICIOUS, summary="s"))
    hit = c.get("otx", o)
    assert hit.cached and hit.verdict is Verdict.MALICIOUS


def test_cli_config_and_providers(capsys):
    assert main(["config", "set", "virustotal", "abcd1234efgh5678"]) == 0
    assert main(["config", "show"]) == 0
    out = capsys.readouterr().out
    assert "abcd********5678" in out and "abcd1234efgh5678" not in out
    assert main(["providers", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert next(r for r in rows if r["name"] == "virustotal")["status"] == "ready"


def test_cli_rejects_unknown_key():
    assert main(["config", "set", "nope", "x"]) == 2


def test_cli_extract_and_enrich_dry_run(capsys):
    assert main(["extract", "examples/hayabusa-sample.csv"]) == 0
    out = capsys.readouterr().out.split()
    assert "185.220.101.1" in out and "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" in out
    assert "f34d5f2d4577ed6d9ceec516c1f5a744" not in out  # IMPHASH filtered
    assert "10.0.0.5" not in out
    assert main(["enrich", "examples/hayabusa-sample.csv", "--preset", "hayabusa", "--dry-run", "-q"]) == 0
    assert "malicious-c2.example-bad.net" in capsys.readouterr().out
