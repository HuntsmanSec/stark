import csv
import json

from stark.integrations import PRESETS, resolve_columns
from stark.integrations.irflow import ioc_csv
from stark.integrations.timeline import extract_rows, read_table, write_enriched
from stark.integrations.vestigex import hash_set
from stark.models import ObservableReport, ProviderResult, Verdict


def _reports(unique):
    out = []
    for o in unique:
        v = Verdict.MALICIOUS if o.value == "185.220.101.1" else Verdict.HARMLESS
        out.append(ObservableReport(o, [ProviderResult("otx", o, v, score=80 if v is Verdict.MALICIOUS else 0)]))
    return out


def test_hayabusa_csv_enrich(tmp_path):
    t = read_table("examples/hayabusa-sample.csv")
    cols = resolve_columns(PRESETS["hayabusa"], t.columns)
    assert cols == ["Details", "ExtraFieldInfo"]
    per_row, unique = extract_rows(t, columns=cols)
    out = tmp_path / "out.csv"
    n = write_enriched(t, per_row, _reports(unique), str(out), only_flagged=True)
    rows = list(csv.DictReader(open(out, encoding="utf-8")))
    assert n == 1 and rows[0]["RecordID"] == "1002" and rows[0]["STARK_Verdict"] == "malicious"


def test_hayabusa_concatenated_json(tmp_path):
    p = tmp_path / "t.json"
    p.write_text('{\n "Timestamp": "x",\n "Details": {"TgtIP": "185.220.101.1"}\n}\n'
                 '{\n "Timestamp": "y",\n "Details": {"Query": "bad.example-c2.org"}\n}\n')
    t = read_table(str(p))
    assert len(t.rows) == 2
    per_row, unique = extract_rows(t, columns=["Details"])
    assert {o.value for o in unique} == {"185.220.101.1", "bad.example-c2.org"}
    out = tmp_path / "o.jsonl"
    write_enriched(t, per_row, _reports(unique), str(out), out_kind="jsonl")
    first = json.loads(out.read_text().splitlines()[0])
    assert first["STARK"]["Verdict"] == "malicious"


def test_irflow_ioc_csv_has_ioc_value_header():
    t = read_table("examples/hayabusa-sample.csv")
    _, unique = extract_rows(t)
    text = ioc_csv(_reports(unique))
    assert text.splitlines()[0].startswith("ioc_value,ioc_type")
    assert "IPv4_Address" in text


def test_vestigex_hashset():
    t = read_table("examples/hayabusa-sample.csv")
    _, unique = extract_rows(t)
    reps = _reports(unique)
    for r in reps:
        if r.observable.type.is_hash:
            r.results[0].verdict = Verdict.MALICIOUS
    lines = [ln for ln in hash_set(reps).splitlines() if not ln.startswith("#")]
    assert "44d88612fea8a8f36de82e1278abb02f" in lines
