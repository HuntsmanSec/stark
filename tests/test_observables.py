import pytest

from stark.observables import ObsType, defang, detect_type, extract, iter_lines, parse_observable, refang


@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", ObsType.IPV4),
    ("2001:4860:4860::8888", ObsType.IPV6),
    ("example.com", ObsType.DOMAIN),
    ("sub.example.co.uk", ObsType.DOMAIN),
    ("https://example.com/a?b=c", ObsType.URL),
    ("44d88612fea8a8f36de82e1278abb02f", ObsType.MD5),
    ("3395856ce81f2b7382dee72602f798b642f14140", ObsType.SHA1),
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", ObsType.SHA256),
    ("user@example.com", ObsType.EMAIL),
    ("invoice.exe", None),
    ("Security.evtx", None),
    ("not an ioc", None),
])
def test_detect(value, expected):
    assert detect_type(value) is expected


@pytest.mark.parametrize("raw,clean", [
    ("hxxps://evil[.]com/x", "https://evil.com/x"),
    ("evil[dot]com", "evil.com"),
    ("1.2.3[.]4", "1.2.3.4"),
    ("user[@]evil.com", "user@evil.com"),
    ("hxxp[://]bad.example/p", "http://bad.example/p"),
])
def test_refang(raw, clean):
    assert refang(raw) == clean


def test_normalisation():
    assert parse_observable("EXAMPLE.COM.").value == "example.com"
    assert parse_observable("44D88612FEA8A8F36DE82E1278ABB02F").value == "44d88612fea8a8f36de82e1278abb02f"


def test_defang_roundtrip():
    for v in ("https://evil.com/x", "evil.com", "8.8.8.8"):
        assert refang(defang(v)) == v


def test_extract_skips_private_and_noise():
    text = "conn 10.0.0.5 -> 185.220.101.1 dns www.microsoft.com and bad-domain.top ran payload.exe"
    found = {(o.type, o.value) for o in extract(text)}
    assert (ObsType.IPV4, "185.220.101.1") in found
    assert (ObsType.DOMAIN, "bad-domain.top") in found
    assert not any(v == "10.0.0.5" for _, v in found)
    assert not any("microsoft" in v for _, v in found)
    assert not any("payload" in v for _, v in found)


def test_extract_url_not_duplicated_as_domain():
    found = list(extract("GET hxxp://evil[.]com/gate.php"))
    assert [(o.type, o.value) for o in found] == [(ObsType.URL, "http://evil.com/gate.php")]


def test_iter_lines_comments_and_dupes():
    lines = ["# header", "8.8.8.8", "8.8.8[.]8  # dup", "", "example.com"]
    assert [o.value for o in iter_lines(lines)] == ["8.8.8.8", "example.com"]
