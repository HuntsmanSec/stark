# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-20

### Added
- **S.T.A.R.K Workspace**: a browser-based case workspace for analysts and non-technical users
  (`stark serve`, or run `stark` with no arguments / double-click the binary).
  - Individual accounts with a personal workspace, plus team workspaces with invite codes,
    owner/admin/member roles, shared API keys and live sync of case changes between teammates.
  - Cases (triage) with severity, status, TLP, assignee, notes, team discussion and an activity log.
  - **Log Arranger**: normalises messy exports from Microsoft Sentinel, Microsoft Defender, Splunk,
    Elastic/ELK, IBM QRadar (LEEF), LogRhythm, CrowdStrike Falcon, SentinelOne, Palo Alto,
    Fortinet, Cisco ASA/FTD, AWS WAF, Cloudflare, Azure WAF, ModSecurity, Zeek, Suricata,
    Windows Event XML and generic syslog/CEF/CSV/JSON into one sorted timeline. It extracts
    indicators, hosts, accounts, processes and suggested MITRE ATT&CK techniques.
    It is **ephemeral**: logs are processed in memory and never written to the database or disk,
    and the arranged view auto-purges after 30 minutes.
  - Observables with one-click reputation checks across all configured sources (background job
    with progress), verdict overrides and analyst notes.
  - Artifacts (hosts, accounts, processes, command lines, files, registry keys).
  - MITRE ATT&CK mapping board with evidence notes.
  - Key-event timeline and actions-taken log.
  - **Incident report writer**: generates an initial analysis with an executive summary,
    technical analysis, MITRE ATT&CK mapping, recommendations, actions taken and an artifact list,
    with indicators rendered as Markdown code. Live preview, Markdown download, print/PDF.
  - Case exports: report, STIX 2.1, CSV, IRFlow IOC list, VESTIGEX sweep list, hash set.
  - Light/dark themes, responsive layout.
- `stark.logarranger`, `stark.mitre` and `stark.report` library modules.

### Changed
- `flask` and `waitress` are now dependencies (the workspace server).
- OTX: allow-list validation marks indicators harmless, a pulse count alone never escalates
  beyond suspicious, and pulse labels are reported as tags instead of malware families.

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

[Unreleased]: https://github.com/HuntsmanSec/stark/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/HuntsmanSec/stark/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/HuntsmanSec/stark/releases/tag/v0.1.0
