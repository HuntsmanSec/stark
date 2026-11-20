"""Renderers: table, json, jsonl, csv, markdown, stix, irflow, vestigex, hashset."""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
import sys
import textwrap
from typing import Callable, Dict, List, Sequence

from . import __version__
from .models import ObservableReport, Verdict, utcnow

FORMATS = ("table", "json", "jsonl", "csv", "md", "stix", "irflow", "vestigex", "hashset")

_COLORS = {
    Verdict.MALICIOUS: "\033[1;31m",
    Verdict.SUSPICIOUS: "\033[33m",
    Verdict.HARMLESS: "\033[32m",
    Verdict.UNKNOWN: "\033[90m",
    Verdict.ERROR: "\033[35m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def use_color(stream=sys.stdout) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("STARK_NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":  # enable ANSI escape processing on Windows 10+
        try:
            import ctypes

            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            return False
    return True


def _v(verdict: Verdict, color: bool) -> str:
    label = verdict.value.upper()
    return f"{_COLORS[verdict]}{label}{_RESET}" if color else label


def _table(headers: Sequence[str], rows: List[Sequence[str]], color_col: Dict[int, List[Verdict]] = None,
           color: bool = False, width: int = 0) -> str:
    width = width or shutil.get_terminal_size((140, 20)).columns
    cols = len(headers)
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))
    # shrink the last column to fit the terminal
    fixed = sum(widths[:-1]) + 3 * (cols - 1)
    widths[-1] = max(20, min(widths[-1], width - fixed - 1))
    sep = "-+-".join("-" * w for w in widths)
    out = [" | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)), sep]
    for ri, r in enumerate(rows):
        cells = [str(c) for c in r]
        last = textwrap.wrap(cells[-1], widths[-1]) or [""]
        first = []
        for i, c in enumerate(cells[:-1]):
            txt = c.ljust(widths[i])
            if color and color_col and i in color_col:
                v = color_col[i][ri]
                txt = f"{_COLORS[v]}{txt}{_RESET}"
            first.append(txt)
        out.append(" | ".join(first + [last[0]]))
        pad = " | ".join(" " * widths[i] for i in range(cols - 1))
        for extra in last[1:]:
            out.append(pad + " | " + extra)
    return "\n".join(out)


def render_table(reports: List[ObservableReport], color: bool = False, verbose: bool = False) -> str:
    blocks = []
    detailed = verbose or len(reports) == 1
    if detailed:
        for rep in reports:
            o = rep.observable
            head = f"{_BOLD if color else ''}{o.value}{_RESET if color else ''}  [{o.type.value}]  ->  " \
                   f"{_v(rep.verdict, color)}"
            head += f"  ({rep.count(Verdict.MALICIOUS)} malicious, {rep.count(Verdict.SUSPICIOUS)} suspicious," \
                    f" {rep.count(Verdict.HARMLESS)} harmless, {len(rep.results)} sources)"
            if rep.malware_families:
                head += f"\n  families: {', '.join(rep.malware_families[:6])}"
            if not rep.results:
                blocks.append(head + "\n  (no configured source supports this observable type)")
                continue
            rows, verdicts = [], []
            for r in rep.results:
                text = r.error and f"ERROR: {r.error}" or r.summary
                if r.link:
                    text += f"  <{r.link}>"
                rows.append([r.provider + ("*" if r.cached else ""), r.verdict.value.upper(),
                             "" if r.score is None else str(r.score), text])
                verdicts.append(r.verdict)
            blocks.append(head + "\n" + _table(["Source", "Verdict", "Score", "Details"], rows,
                                              {1: verdicts}, color))
        if any(r.cached for rep in reports for r in rep.results):
            blocks.append("* = served from local cache (use --no-cache to refresh)")
        return "\n\n".join(blocks)

    rows, verdicts = [], []
    for rep in reports:
        rows.append([
            rep.observable.value if len(rep.observable.value) <= 70 else rep.observable.value[:67] + "...",
            rep.observable.type.value,
            rep.verdict.value.upper(),
            f"{rep.count(Verdict.MALICIOUS)}/{rep.count(Verdict.SUSPICIOUS)}/{len(rep.results)}",
            " | ".join(x for x in (", ".join(rep.flagged_by), ", ".join(rep.malware_families[:3])) if x) or "-",
        ])
        verdicts.append(rep.verdict)
    summary = _summary_line(reports)
    return _table(["Observable", "Type", "Verdict", "Mal/Sus/Src", "Flagged by | families"], rows,
                  {2: verdicts}, color) + "\n\n" + summary


def _summary_line(reports: List[ObservableReport]) -> str:
    counts = {v: sum(1 for r in reports if r.verdict is v) for v in Verdict}
    return (f"{len(reports)} observable(s): {counts[Verdict.MALICIOUS]} malicious, "
            f"{counts[Verdict.SUSPICIOUS]} suspicious, {counts[Verdict.HARMLESS]} harmless, "
            f"{counts[Verdict.UNKNOWN]} unknown, {counts[Verdict.ERROR]} error")


def render_json(reports, include_raw=False, **_):
    return json.dumps({"tool": "S.T.A.R.K", "version": __version__, "generated": utcnow(),
                       "results": [r.to_dict(include_raw) for r in reports]}, indent=2, default=str)


def render_jsonl(reports, include_raw=False, **_):
    return "\n".join(json.dumps(r.to_dict(include_raw), default=str) for r in reports)


CSV_FIELDS = ["observable", "type", "verdict", "score", "malicious", "suspicious", "harmless",
              "unknown", "errors", "flagged_by", "malware_families", "tags"]


def render_csv(reports, providers_cols: bool = True, **_):
    buf = io.StringIO()
    provs: List[str] = []
    for rep in reports:
        for r in rep.results:
            if r.provider not in provs:
                provs.append(r.provider)
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_FIELDS + [f"{p}_verdict" for p in provs] + [f"{p}_summary" for p in provs])
    for rep in reports:
        d = rep.to_dict()
        by = {r.provider: r for r in rep.results}
        w.writerow([d[k] if not isinstance(d[k], list) else ";".join(map(str, d[k])) for k in CSV_FIELDS]
                   + [by[p].verdict.value if p in by else "" for p in provs]
                   + [(by[p].error or by[p].summary) if p in by else "" for p in provs])
    return buf.getvalue()


def render_md(reports, **_):
    out = ["# S.T.A.R.K report", "", f"Generated {utcnow()} by S.T.A.R.K v{__version__}", "",
           "| Observable | Type | Verdict | Flagged by | Families |", "|---|---|---|---|---|"]
    for rep in reports:
        out.append(f"| `{rep.observable.defanged}` | {rep.observable.type.value} | **{rep.verdict.value}** | "
                   f"{', '.join(rep.flagged_by) or '-'} | {', '.join(rep.malware_families) or '-'} |")
    for rep in reports:
        out += ["", f"## `{rep.observable.defanged}` - {rep.verdict.value}", "",
                "| Source | Verdict | Score | Details |", "|---|---|---|---|"]
        for r in rep.results:
            det = (r.error or r.summary).replace("|", "\\|")
            if r.link:
                det += f" [link]({r.link})"
            out.append(f"| {r.provider} | {r.verdict.value} | {'' if r.score is None else r.score} | {det} |")
    out += ["", _summary_line(reports)]
    return "\n".join(out)


def render_stix(reports, all_indicators=False, tlp="clear", **_):
    from .stix import to_bundle

    return json.dumps(to_bundle(reports, all_indicators=all_indicators, tlp=tlp), indent=2)


def render_irflow(reports, **_):
    """IOC list for IRFlow Timeline (Actions -> IOC Matching -> load file).

    IRFlow picks the ``ioc_value`` column automatically; the remaining columns
    carry STARK's verdict so the analyst can triage hits."""
    from .integrations.irflow import ioc_csv

    return ioc_csv(reports)


def render_vestigex(reports, **_):
    from .integrations.vestigex import ioc_sweep_csv

    return ioc_sweep_csv(reports)


def render_hashset(reports, **_):
    from .integrations.vestigex import hash_set

    return hash_set(reports)


RENDERERS: Dict[str, Callable[..., str]] = {
    "json": render_json, "jsonl": render_jsonl, "csv": render_csv, "md": render_md,
    "stix": render_stix, "irflow": render_irflow, "vestigex": render_vestigex, "hashset": render_hashset,
}


def render(fmt: str, reports: List[ObservableReport], color: bool = False, **kw) -> str:
    if fmt == "table":
        return render_table(reports, color=color, verbose=kw.get("verbose", False))
    return RENDERERS[fmt](reports, **kw)
