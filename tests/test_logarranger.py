import glob
import os

import pytest

from stark.logarranger import arrange, arrange_text, parse_line, parse_time

LOGS = os.path.join(os.path.dirname(__file__), "..", "examples", "logs")


def _one(text, name="x"):
    rows = arrange_text(text, name)
    assert len(rows) == 1
    return rows[0]


@pytest.mark.parametrize("value,expected", [
    ("2026-11-01T10:00:01.1234567Z", "2026-11-01T10:00:01.123Z"),
    ("1793527210000", "2026-11-01T10:00:10.000Z"),
    ("11/1/2026, 9:58:01.000 AM", "2026-11-01T09:58:01.000Z"),
    ("2026-11-01 10:06:10", "2026-11-01T10:06:10.000Z"),
    ("Nov 01 2026 10:04:00", "2026-11-01T10:04:00.000Z"),
    ("2026-11-01T12:00:00+02:00", "2026-11-01T10:00:00.000Z"),
])
def test_parse_time(value, expected):
    assert parse_time(value) == expected


def test_all_sample_sources_detected():
    sources = [(os.path.basename(p), open(p, encoding="utf-8").read()) for p in sorted(glob.glob(os.path.join(LOGS, "*")))]
    res = arrange(sources)
    products = set(res["stats"]["products"])
    for p in ("Microsoft Sentinel", "Microsoft Defender", "CrowdStrike Falcon", "SentinelOne", "Palo Alto Networks",
              "Elastic / ELK", "IBM QRadar", "LogRhythm", "Cisco ASA / FTD", "Fortinet FortiGate", "AWS WAF",
              "Windows Event Log"):
        assert p in products, p
    assert "Generic" not in products
    times = [r["time"] for r in res["rows"] if r["time"]]
    assert times == sorted(times)
    values = {i["value"] for i in res["iocs"]}
    assert {"185.220.101.1", "update-cdn-check.xyz", "45.77.12.9"} <= values
    assert not any(v in values for v in ("event.type", "zeek.dns", "src.process.cmdline"))
    assert next(i for i in res["iocs"] if i["value"] == "10.0.0.5")["internal"]
    tids = {m["id"] for m in res["mitre"]}
    assert {"T1059.001", "T1003.001", "T1490", "T1218.011"} <= tids
    assert "fields" not in res["rows"][0]


def test_cef_and_leef():
    r = _one("CEF:0|Imperva|WAF|1.0|SQLi|SQL Injection|8|src=203.0.113.77 dst=10.0.0.80 act=blocked request=https://a.example/x?q=1")
    assert (r["product"], r["src_ip"], r["dst_ip"], r["action"], r["event"]) == ("Imperva WAF", "203.0.113.77", "10.0.0.80", "blocked", "SQLi")
    r = _one("<13>Nov 01 10:04:00 qr LEEF:2.0|IBM|QRadar|7.5|Deny|^|src=1.2.3.4^dst=10.0.0.1^dstPort=3389^usrName=admin")
    assert (r["product"], r["src_ip"], r["dst_port"], r["user"]) == ("IBM QRadar", "1.2.3.4", "3389", "admin")


def test_cisco_asa_and_fortinet():
    r = parse_line('<134>Nov  1 10:06:00 asa01 %ASA-4-106023: Deny tcp src outside:198.51.100.23/51000 dst inside:10.0.0.2/445 by access-group "x"')
    assert (r["product"], r["src_ip"], r["dst_port"], r["action"], r["host"]) == ("Cisco ASA / FTD", "198.51.100.23", "445", "deny", "asa01")
    r = parse_line('date=2026-11-01 time=10:06:10 devname="FGT" devid="F1" logid="13" srcip=10.0.0.5 dstip=45.77.12.9 dstport=8443 action="deny"')
    assert (r["product"], r["time"], r["dst_ip"], r["action"]) == ("Fortinet FortiGate", "2026-11-01T10:06:10.000Z", "45.77.12.9", "deny")


def test_zeek_tsv():
    text = "#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n" \
           "1793527200.1\tC1\t10.0.0.5\t5000\t45.77.12.9\t443\ttcp\n"
    r = _one(text)
    assert (r["product"], r["src_ip"], r["dst_ip"], r["dst_port"], r["event"]) == ("Zeek", "10.0.0.5", "45.77.12.9", "443", "zeek.conn")


def test_suricata_and_splunk_raw():
    r = _one('{"timestamp":"2026-11-01T10:00:00.000000+0000","flow_id":1,"event_type":"alert","src_ip":"1.2.3.4","dest_ip":"10.0.0.1","alert":{"signature":"ET MALWARE Test"}}')
    assert r["product"] == "Suricata" and r["dst_ip"] == "10.0.0.1"
    r = _one('{"result":{"_raw":"<134>Nov  1 10:06:00 asa01 %ASA-4-106023: Deny tcp src outside:1.2.3.4/1 dst inside:10.0.0.2/445 by x","host":"asa01","sourcetype":"cisco:asa"}}')
    assert r["product"] == "Cisco ASA / FTD" and r["src_ip"] == "1.2.3.4"


def test_garbage_is_kept_as_raw():
    rows = arrange_text("just some text mentioning 45.77.12.9\nanother line")
    assert len(rows) == 2 and rows[0]["product"] == "Generic" and "45.77.12.9" in rows[0]["message"]
