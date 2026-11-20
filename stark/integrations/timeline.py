"""Generic timeline / table reader, IOC extraction per row and enriched writer.

Supports CSV, TSV, JSON (array or concatenated objects) and JSONL - which
covers Hayabusa ``csv-timeline`` / ``json-timeline``, IRFlow Timeline CSV/TSV
exports and VESTIGEX CSV exports.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from ..models import ObservableReport, Verdict
from ..observables import ALL_TYPES, Observable, ObsType, extract

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

# Sysmon/Hayabusa "Hashes" fields carry IMPHASH (32 hex) which looks like an MD5.
_IMPHASH = re.compile(r"IMPHASH\s*[=:]\s*[0-9A-Fa-f]{32}", re.I)

STARK_COLUMNS = ["STARK_Verdict", "STARK_Score", "STARK_FlaggedBy", "STARK_Families", "STARK_IOCs"]


@dataclass
class Table:
    path: Path
    kind: str                      # csv | tsv | json | jsonl
    rows: List[Dict[str, Any]]
    columns: List[str] = field(default_factory=list)


def _sniff_kind(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in (".jsonl", ".ndjson"):
        return "jsonl"
    if ext == ".json":
        return "json"
    if ext == ".tsv":
        return "tsv"
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        head = fh.read(4096).lstrip()
    if head.startswith("{") or head.startswith("["):
        first = head.splitlines()[0].strip() if head else ""
        return "jsonl" if first.startswith("{") and first.endswith("}") else "json"
    return "tsv" if head.count("\t") > head.count(",") else "csv"


def _iter_concatenated_json(text: str) -> Iterator[Any]:
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \r\n\t,":
            i += 1
        if i >= n:
            break
        obj, i = dec.raw_decode(text, i)
        yield obj


def read_table(path: str) -> Table:
    p = Path(path)
    kind = _sniff_kind(p)
    if kind in ("csv", "tsv"):
        with open(p, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh, delimiter="\t" if kind == "tsv" else ",")
            rows = list(reader)
            cols = list(reader.fieldnames or [])
        return Table(p, kind, rows, cols)
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    rows: List[Dict[str, Any]] = []
    if kind == "jsonl":
        for line in text.splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    else:
        try:
            data = json.loads(text)
            rows = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:  # Hayabusa json-timeline: concatenated pretty-printed objects
            rows = list(_iter_concatenated_json(text))
    rows = [r for r in rows if isinstance(r, dict)]
    cols: List[str] = []
    for r in rows[:500]:
        for k in r:
            if k not in cols:
                cols.append(k)
    return Table(p, kind, rows, cols)


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{k}: {_flatten(v)}" for k, v in value.items())
    if isinstance(value, list):
        return " ".join(_flatten(v) for v in value)
    return "" if value is None else str(value)


def row_text(row: Dict[str, Any], columns: Optional[Sequence[str]] = None,
             skip: Sequence[str] = ()) -> str:
    keys = columns or [k for k in row.keys() if k not in skip]
    return " ¦ ".join(_flatten(row.get(k)) for k in keys if k in row and not str(k).startswith("STARK_"))


def extract_rows(
    table: Table,
    columns: Optional[Sequence[str]] = None,
    skip: Sequence[str] = (),
    types: Iterable[ObsType] = ALL_TYPES,
    include_private: bool = False,
) -> Tuple[List[List[Observable]], List[Observable]]:
    """Return (per-row observables, unique observables in first-seen order)."""
    types = set(types)
    per_row: List[List[Observable]] = []
    unique: Dict[Tuple[ObsType, str], Observable] = {}
    for i, row in enumerate(table.rows):
        text = _IMPHASH.sub(" ", row_text(row, columns, skip))
        found = list(extract(text, types=types, include_private=include_private,
                             source=f"{table.path.name}:{i + 1}"))
        per_row.append(found)
        for o in found:
            unique.setdefault((o.type, o.value), o)
    return per_row, list(unique.values())


def _row_annotation(found: List[Observable], by_obs: Dict[Observable, ObservableReport]) -> Dict[str, Any]:
    reps = [by_obs[o] for o in found if o in by_obs]
    if not reps:
        return {"STARK_Verdict": "", "STARK_Score": "", "STARK_FlaggedBy": "", "STARK_Families": "",
                "STARK_IOCs": ""}
    worst = max(reps, key=lambda r: r.verdict.rank)
    scores = [r.score for r in reps if r.score is not None]
    flagged = sorted({p for r in reps for p in r.flagged_by})
    fams: List[str] = []
    for r in reps:
        for f in r.malware_families:
            if f not in fams:
                fams.append(f)
    iocs = [f"{r.observable.value}={r.verdict.value}" for r in reps]
    return {
        "STARK_Verdict": worst.verdict.value,
        "STARK_Score": max(scores) if scores else "",
        "STARK_FlaggedBy": ";".join(flagged),
        "STARK_Families": ";".join(fams[:5]),
        "STARK_IOCs": ";".join(iocs),
    }


def write_enriched(
    table: Table,
    per_row: List[List[Observable]],
    reports: List[ObservableReport],
    out_path: str,
    only_flagged: bool = False,
    out_kind: Optional[str] = None,
) -> int:
    by_obs = {r.observable: r for r in reports}
    kind = out_kind or table.kind
    out = Path(out_path)
    written = 0
    flagged_values = {Verdict.MALICIOUS.value, Verdict.SUSPICIOUS.value}
    if kind in ("csv", "tsv"):
        cols = [c for c in table.columns if c not in STARK_COLUMNS] + STARK_COLUMNS
        if not table.columns:
            cols = []
            for r in table.rows[:500]:
                cols += [k for k in r if k not in cols]
            cols += STARK_COLUMNS
        with open(out, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, delimiter="\t" if kind == "tsv" else ",",
                               extrasaction="ignore")
            w.writeheader()
            for row, found in zip(table.rows, per_row):
                ann = _row_annotation(found, by_obs)
                if only_flagged and ann["STARK_Verdict"] not in flagged_values:
                    continue
                flat = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in row.items()}
                w.writerow({**flat, **ann})
                written += 1
        return written
    rows_out = []
    for row, found in zip(table.rows, per_row):
        ann = _row_annotation(found, by_obs)
        if only_flagged and ann["STARK_Verdict"] not in flagged_values:
            continue
        rows_out.append({**row, "STARK": {k[6:]: v for k, v in ann.items()}})
    with open(out, "w", encoding="utf-8") as fh:
        if kind == "jsonl":
            for r in rows_out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        else:
            json.dump(rows_out, fh, ensure_ascii=False, indent=2)
    return len(rows_out)
