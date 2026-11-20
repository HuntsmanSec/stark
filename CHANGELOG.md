# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-20

### Added
- `stark query` for single or bulk lookups of IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256 and email
  addresses from arguments, files, stdin or STIX bundles, with automatic refanging.
- 19 reputation sources: VirusTotal, AbuseIPDB, urlscan.io, ANY.RUN, Joe Sandbox, Hybrid Analysis,
  Recorded Future, Cisco Talos, AlienVault OTX, MalwareBazaar, ThreatFox, URLhaus, Have I Been Pwned,
  MXToolbox, Shodan, GreyNoise, Pulsedive, IPinfo and crt.sh.
- Consolidated verdicts with per-source scores, malware families, tags and pivot links.
- STIX 2.1 export (SCOs with deterministic ids, indicators, malware, relationships, notes, TLP 2.0
  markings) and STIX 2.x import from indicator patterns and SCOs.
- `stark enrich` for Hayabusa, IRFlow Timeline, VESTIGEX and generic CSV/TSV/JSON/JSONL timelines.
- `stark extract` for offline IOC extraction from text, logs and tables.
- Output formats: table, json, jsonl, csv, md, stix, irflow, vestigex, hashset.
- User-managed API keys through `stark config` or `STARK_<NAME>_API_KEY` environment variables.
- Per-source rate limiting, a SQLite result cache, proxy support, `--fail-on` exit codes.
- CI on Windows, macOS and Linux, and standalone release binaries.

[Unreleased]: https://github.com/HuntsmanSec/stark/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/HuntsmanSec/stark/releases/tag/v0.1.0
