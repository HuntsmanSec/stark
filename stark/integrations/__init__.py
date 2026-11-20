"""Integrations with DFIR tooling.

Each preset tells the generic timeline enricher which columns hold evidence
worth mining for IOCs, and which columns to ignore.

* ``hayabusa``  - Yamato Security Hayabusa csv-timeline / json-timeline output
* ``irflow``    - IRFlow Timeline CSV/TSV exports (and IOC lists for IOC Matching)
* ``vestigex``  - VESTIGEX CSV exports (and IOC sweep lists / hash sets)
* ``generic``   - every column of any CSV/TSV/JSON/JSONL file
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import hayabusa, irflow, vestigex


@dataclass(frozen=True)
class Preset:
    name: str
    description: str
    columns: Optional[List[str]] = None       # None = all columns
    skip: List[str] = field(default_factory=list)


PRESETS: Dict[str, Preset] = {
    "generic": Preset("generic", "All columns of any CSV/TSV/JSON/JSONL file"),
    "hayabusa": Preset("hayabusa", "Hayabusa csv-timeline/json-timeline (Details, ExtraFieldInfo)",
                       columns=hayabusa.EVIDENCE_COLUMNS, skip=hayabusa.SKIP_COLUMNS),
    "irflow": Preset("irflow", "IRFlow Timeline CSV/TSV export (all columns except file paths/tags)",
                     skip=irflow.SKIP_COLUMNS),
    "vestigex": Preset("vestigex", "VESTIGEX timeline/findings CSV export", skip=vestigex.SKIP_COLUMNS),
}


def resolve_columns(preset: Preset, available: List[str]) -> Optional[List[str]]:
    if preset.columns is None:
        return None
    lower = {c.lower(): c for c in available}
    cols = [lower[c.lower()] for c in preset.columns if c.lower() in lower]
    return cols or None  # fall back to every column if the expected ones are absent
