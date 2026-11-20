import glob
import os

import pytest

from stark.analysis import analyze, decode_powershell, typosquat
from stark.logarranger import arrange
from stark.observables import defang, defang_text, refang

LOGS = os.path.join(os.path.dirname(__file__), "..", "examples", "logs")


@pytest.fixture(scope="module")
def findings():
    res = arrange([(os.path.basename(p), open(p, encoding="utf-8").read()) for p in sorted(glob.glob(os.path.join(LOGS, "*")))])
    return {f["key"].split(":")[0] + ":" + f["key"].split(":")[1]: f for f in res["findings"]}, res


def test_auth_findings(findings):
    f, _ = findings
    assert f["auth:bruteforce-success"]["severity"] == "high"
    assert f["auth:spray"]["entities"]["ips"] == ["45.155.205.233"]
    assert "fatigue" in f["auth:mfa"]["title"].lower()
    assert "RU → PH" in f["auth:travel"]["title"]
    assert "auth:legacy-or-scripted" in f
    # MFA denials must not be counted as password brute force
    assert not any(k.startswith("auth:bruteforce") and "bob" in v["title"] for k, v in f.items())


def test_process_and_malware_findings(findings):
    f, res = findings
    for key in ("process:lsass-dump", "process:shadow-delete", "process:rundll32", "process:ps-encoded", "process:office-child"):
        assert key in f, key
    assert "IEX (New-Object Net.WebClient)" in f["process:ps-encoded"]["decoded"][0]
    assert any(t["id"] == "T1490" for t in f["process:shadow-delete"]["mitre"])


def test_network_findings(findings):
    f, _ = findings
    beacon = f["network:beacon"]
    assert beacon["entities"]["hosts"] == ["WS02"] and 55 <= beacon["interval_seconds"] <= 65
    assert "network:port" in f and "4444" in f["network:port"]["title"]
    assert "network:dns-tunnel" in f
    squats = [x for x in findings[1]["findings"] if x["key"].startswith("network:typosquat")]
    names = {x["entities"]["domains"][0] for x in squats}
    assert {"paypa1.com", "contoso-hr-portal.com", "login-micros0ft-secure.com"} <= names
    assert "login.microsoftonline.com" not in names


@pytest.mark.parametrize("domain,expected", [
    ("paypa1.com", "paypal.com"), ("rnicrosoft.com", "microsoft.com"), ("micros0ft-support-login.com", "microsoft.com"),
    ("paypal.com.secure-check.xyz", "paypal.com"), ("docusign-review.net", "docusign.com"),
    ("google.com", None), ("login.microsoftonline.com", None), ("example.org", None), ("githubusercontent.com", None),
])
def test_typosquat(domain, expected):
    t = typosquat(domain)
    assert (t["target"] if t else None) == expected


def test_protected_org_domain():
    assert typosquat("c0ntoso.com", {"contoso": "contoso.com"})["target"] == "contoso.com"
    assert typosquat("contoso.com", {"contoso": "contoso.com"}) is None


def test_decode_powershell():
    assert decode_powershell("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA").startswith("IEX")
    assert decode_powershell("powershell -command Get-Date") is None


def test_beacon_needs_regularity():
    rows = [{"id": i, "time": f"2026-11-01T10:{m:02d}:00.000Z", "host": "H", "dst_ip": "91.215.85.17"}
            for i, m in enumerate([0, 1, 7, 9, 20, 21, 40, 52])]
    assert not [f for f in analyze(rows) if f["key"].startswith("network:beacon")]


def test_defang_everything():
    assert defang("185.220.101.1") == "185[.]220[.]101[.]1"
    assert defang("https://evil.com/a.php") == "hxxps[://]evil[.]com/a.php"
    assert defang("bob@evil.com") == "bob[@]evil[.]com"
    assert defang("44d88612fea8a8f36de82e1278abb02f") == "44d88612fea8a8f36de82e1278abb02f"
    for v in ("185.220.101.1", "https://evil.com/a.php?x=1", "bob@evil.com", "a.b.example.org"):
        assert refang(defang(v)) == v and defang(defang(v)) == defang(v)
    t = "ran powershell.exe against http://1.2.3.4:8080/p.ps1 and evil.example.com, see https://attack.mitre.org/x"
    out = defang_text(t, keep=["https://attack.mitre.org/x"])
    assert out == "ran powershell.exe against hxxp[://]1[.]2[.]3[.]4:8080/p.ps1 and evil[.]example[.]com, see https://attack.mitre.org/x"
