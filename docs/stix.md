# STIX 2.1 support

## Export

`-F stix` (or `--stix FILE` alongside any other format) writes a STIX 2.1 bundle:

| Object | When | Notes |
|---|---|---|
| `identity` | always | S.T.A.R.K system identity, used as `created_by_ref` |
| `marking-definition` | always | TLP 2.0 (`--tlp clear\|green\|amber\|red`), applied to every object |
| SCO (`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`, `file`) | every observable | Deterministic UUIDv5 ids per STIX 2.1 §2.9, so the same IOC always gets the same id |
| `indicator` | consolidated verdict malicious/suspicious (every observable with `--stix-all`) | STIX pattern, `indicator_types` (`malicious-activity` / `anomalous-activity`), `confidence` from the highest source score, `external_references` to each source's report, `x_stark_verdict` |
| `relationship` `based-on` | per indicator | indicator → SCO |
| `malware` (`is_family: true`) | families reported by sources | linked from the indicator with `indicates` |
| `note` | every observable with results | Human-readable per-source summary, plus `x_stark_results` with the structured results |

The output validates with the OASIS `stix2` library (tested in CI).

## Import

`stark query --stix-in bundle.json` accepts:

- a STIX 2.0/2.1 bundle, a TAXII 2.1 envelope (`{"objects": [...]}`) or a bare list of objects
- `indicator` objects with `pattern_type: stix`. Every comparison on `ipv4-addr`, `ipv6-addr`,
  `domain-name`, `url`, `email-addr` and `file:hashes.(MD5|SHA-1|SHA-256)` is extracted, including
  compound `AND`/`OR` patterns
- SCOs of those types

Combine both to enrich a feed: `stark query --stix-in feed.json -F stix --stix-all -o feed.enriched.json`.
