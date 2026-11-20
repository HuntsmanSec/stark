# DFIR integrations

`stark enrich <file>` reads CSV, TSV, JSON (array or concatenated objects) or JSONL, extracts
observables row by row, queries them once each, and writes an **enriched copy** of the file with
five extra columns (or a `STARK` object for JSON):

| Column | Meaning |
|---|---|
| `STARK_Verdict` | worst verdict of any IOC in the row |
| `STARK_Score` | highest score |
| `STARK_FlaggedBy` | sources that flagged an IOC in the row |
| `STARK_Families` | malware families |
| `STARK_IOCs` | `value=verdict` for each IOC in the row |

Useful flags: `--only-flagged`, `--dry-run` (list IOCs only), `--types ip,hash`, `--columns A,B`,
`--include-private`, `--max N` (safety cap, default 500 unique IOCs), plus all `query` output flags
(`-F`, `-o`, `--stix`).

## Hayabusa

[Hayabusa](https://github.com/Yamato-Security/hayabusa) is a Sigma-based fast forensics timeline
generator for Windows event logs.

```bash
hayabusa csv-timeline -d C:\evtx -p verbose -o timeline.csv     # or json-timeline -L -o timeline.jsonl
stark enrich timeline.csv --preset hayabusa --only-flagged --enriched timeline.flagged.csv
```

The `hayabusa` preset mines `Details`, `ExtraFieldInfo` and `AllFieldInfo` (whichever exist) and
removes `IMPHASH=` values from Sysmon `Hashes` fields so they aren't treated as MD5s. Rule metadata
columns are ignored.

## IRFlow Timeline

[IRFlow Timeline](https://github.com/r3nzsec/irflow-timeline) is a macOS DFIR timeline viewer with
IOC Matching and VirusTotal enrichment.

- **STARK → IRFlow IOC Matching:** `stark query -f intel.txt -F irflow -o irflow-iocs.csv`. The file's
  first column is `ioc_value`, the header IRFlow's loader looks for. `ioc_type` uses IRFlow's category
  names (`IPv4_Address`, `SHA256_Hash`, ...). Load it in *Actions → IOC Matching*.
- **Enrich an IRFlow export:** export the view to CSV/TSV, then run
  `stark enrich export.csv --preset irflow` and open `export.stark.csv` in IRFlow. You can sort or
  filter on `STARK_Verdict`.
- **Pipeline:** Hayabusa → `stark enrich --preset hayabusa` → open the enriched CSV in IRFlow.

## VESTIGEX

[VESTIGEX](https://vestigex.app) is a Windows/Linux DFIR workstation with ATT&CK/IOC sweeps and hash sets.

- `stark query -f intel.txt -F vestigex -o sweep.csv`: IOC sweep list (`indicator,type,verdict,score,description,source,reference`)
- `stark query -f hashes.txt -F hashset -o known-bad.txt`: one hash per line, only hashes rated suspicious or worse
- `stark query -f intel.txt -F stix -o intel.stix.json`: STIX 2.1 for STIX-aware import
- `stark enrich vestigex-export.csv --preset vestigex`: enrich a VESTIGEX CSV export

## Any other tool

`--preset generic` (the default) mines every column. Plaso `psort` CSV, KAPE/EZ Tools CSVs, Velociraptor
JSONL, Timesketch exports and SIEM exports all work.
