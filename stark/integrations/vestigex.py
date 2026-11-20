"""VESTIGEX (https://vestigex.app) integration.

VESTIGEX runs an IOC sweep across a whole case and supports hash sets. STARK
feeds it in three ways:

* ``--format vestigex`` - IOC sweep list (CSV: indicator, type, verdict, ...)
* ``--format hashset``  - plain hash set, one hash per line (known-bad file hashes)
* ``--format stix``     - STIX 2.1 bundle for tools that ingest STIX

And the other way: export a VESTIGEX timeline/findings view to CSV and run
``stark enrich export.csv --preset vestigex``.
"""

import csv
import io
from typing import List

from ..models import ObservableReport, Verdict

SKIP_COLUMNS = ["Examiner", "Bookmark", "Bookmarked", "Notes", "Evidence", "EvidenceItem", "CaseName",
                "Case", "RecordNumber"]


def ioc_sweep_csv(reports: List[ObservableReport]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["indicator", "type", "verdict", "score", "description", "source", "reference"])
    for rep in reports:
        desc = ", ".join(rep.malware_families) or ", ".join(rep.flagged_by) or rep.verdict.value
        ref = next((r.link for r in rep.results if r.link), "")
        w.writerow([rep.observable.value, rep.observable.type.value, rep.verdict.value,
                    "" if rep.score is None else rep.score, desc, "S.T.A.R.K", ref])
    return buf.getvalue()


def hash_set(reports: List[ObservableReport], min_verdict: Verdict = Verdict.SUSPICIOUS) -> str:
    """Known-bad hash set: hashes with verdict >= suspicious (all hashes if none were queried)."""
    lines = ["# S.T.A.R.K known-bad hash set"]
    for rep in reports:
        if not rep.observable.type.is_hash:
            continue
        if rep.results and rep.verdict.rank < min_verdict.rank:
            continue
        lines.append(rep.observable.value)
    return "\n".join(lines) + "\n"
