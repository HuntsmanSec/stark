"""IRFlow Timeline (https://github.com/r3nzsec/irflow-timeline) integration.

Two directions:

1. **STARK -> IRFlow**: ``stark query ... --format irflow -o iocs.csv`` writes an
   IOC list whose first column is ``ioc_value`` - the header IRFlow's IOC
   Matching loader looks for - followed by STARK verdict columns. Load it via
   *Actions -> IOC Matching* to sweep the timeline for known-bad indicators.
2. **IRFlow -> STARK**: export a filtered/tagged view from IRFlow to CSV and run
   ``stark enrich export.csv --preset irflow`` to add STARK_* verdict columns,
   then re-open the enriched CSV in IRFlow.
"""

import csv
import io
from typing import List

from ..models import ObservableReport, Verdict

SKIP_COLUMNS = ["Tags", "Tag", "Bookmark", "Bookmarked", "Color", "Notes", "SourceFile", "rowid"]

IRFLOW_TYPE = {
    "ipv4": "IPv4_Address", "ipv6": "IPv6_Address", "domain": "Domain_Name", "url": "URL",
    "md5": "MD5_Hash", "sha1": "SHA1_Hash", "sha256": "SHA256_Hash", "email": "Email_Address",
}


def ioc_csv(reports: List[ObservableReport], min_verdict: Verdict = None) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["ioc_value", "ioc_type", "stark_verdict", "stark_score", "flagged_by",
                "malware_families", "tags", "reference"])
    for rep in reports:
        if min_verdict and rep.verdict.rank < min_verdict.rank:
            continue
        ref = next((r.link for r in rep.results if r.link and r.verdict is rep.verdict), "") or \
            next((r.link for r in rep.results if r.link), "")
        w.writerow([
            rep.observable.value, IRFLOW_TYPE[rep.observable.type.value], rep.verdict.value,
            "" if rep.score is None else rep.score, ";".join(rep.flagged_by),
            ";".join(rep.malware_families), ";".join(rep.tags[:10]), ref,
        ])
    return buf.getvalue()
