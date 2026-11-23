# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-11-23

### Added
- **Automatic MITRE ATT&CK mapping.** Techniques are mapped from the case evidence without manual
  steps: security findings, the logs arranged in the Log Arranger (behaviour patterns with a clear
  meaning, tagged with the log sources), threat intelligence on the case indicators (C2, phishing,
  brute force, scanning, Tor, miners, ransomware, stealers; look-alike domains), pinned events,
  recorded processes / command lines / files and the alert name. Each technique lists its basis.
  Context-only patterns (an ordinary successful logon, RDP port use) need a finding behind them.
  Analysts can remove a technique (it stays removed) and restore it later.
- **SOC write-up engine** (`stark.soc`) for MSSP triage. It correlates the raw-log evidence, OSINT
  enrichment, past tickets, past Non-Threatening closures and client pentest notes, reaches a
  verdict (True Positive - Malicious / Benign, False Positive, Inconclusive, with confidence) and
  writes exactly one outcome:
  - **Append** to an open ticket that shares exact entities (OSINT Info, Similar Entities Found,
    New Entities Found).
  - **Close as non-threatening**: pentest the client asked to ignore, already remediated (strong
    close notes, timing / blocked activity checked against the logs), or benign / misfire.
  - **Raise an incident**: analyst-only assessment (verdict, weighted investigation completeness,
    missing investigation work, ticket notification decision, priority) followed by the customer
    report (Executive Summary, Analysis, Recommendation, Action Taken, Artifacts).
  - Pentest handling for *ignore*, *raise and confirm* and *unannounced* tests; unrelated notes are
    never mentioned and unannounced tests never reach the customer report.
- Case **alert & ticket fields**: alert name, customer, Finding ID, log source / SIEM, alert link,
  alert creation time, incident / threat ID, ticket (INC) number, disposition, Finding IDs in the
  ticket and close notes. Closing a case as non-threatening makes it a past closure for later cases.
- **Related** tab: past tickets, closures and pentest notes with the entities they share, the
  decision preview, and JSON import of records from your ticketing system.
- Workspace **pentest notes** per customer (tester IPs / CIDR ranges, machines, test window, client
  instruction).
- Case statuses *On hold*, *Resolved* and *Cancelled*.
- Report tab: choose the SOC write-up or the detailed technical report, force an outcome, and copy
  the customer part or the analyst part separately.

### Changed
- Reports defang investigated domains, URLs and external IPv4 addresses by bracketing the **final
  dot only** (`hxxps://bad.example[.]com`, `192.0.2[.]10`). IPv6, internal addresses, accounts
  and hostnames are written exactly, and the alert link stays live.
- Finding evidence now keeps the log's action (allowed / blocked / failed) so the report can say
  whether activity actually succeeded.

### Fixed
- `Net.WebClient`-style .NET type names in command lines are no longer treated as domains.

## [0.3.1] - 2026-11-20

### Fixed
- Encoded PowerShell commands (`-enc` / `-EncodedCommand`) are now decoded and analysed when they
  appear in plain-text log lines (syslog, pasted snippets) as well as in structured EDR exports.

## [0.3.0] - 2026-11-20

### Added
- **Security finding analysis** (`stark.analysis`), run automatically on arranged logs:
  - *Authentication anomalies*: brute force and success-after-failures, password spraying, MFA
    failures and MFA fatigue, impossible travel and logins from multiple countries, new/unusual
    devices and user agents, legacy-protocol or scripted authentication, privileged logins from
    external IPs.
  - *Process & command-line activity*: PowerShell download cradles, IEX, hidden/bypass flags,
    AMSI/Defender tampering and **automatic decoding of `-EncodedCommand`**. Also mshta, rundll32,
    regsvr32, certutil, bitsadmin, wmic, msiexec, script hosts and other LOLBins; Office apps spawning
    shells; LSASS/SAM/NTDS credential dumping; shadow-copy deletion; log clearing; persistence
    (scheduled tasks, Run keys, new admin accounts); recon bursts; remote-access tools; PsExec.
  - *Malware & file findings*: known attack tooling, double extensions, look-alike system binary
    names, system binaries outside System32, executables in user-writable folders.
  - *Network & C2*: beaconing (interval/jitter analysis), suspicious ports, inbound RDP/SMB/SSH/WinRM
    from the internet, bare-IP downloads, **typosquatting** (homoglyphs, edit distance, brand +
    lure-word combos, brand-as-subdomain, punycode/IDN, look-alikes of your own domain), DGA-like
    domains, DNS tunnelling, abused TLDs.
  - Each finding has a severity, confidence, explanation, interpretation, recommendation, entities,
    ATT&CK mapping and evidence. Adding a finding to a case maps its techniques automatically.
- **Investigation & enrichment**: click any host, user or IP in the timeline to pivot; "related
  activity" ±15/60 minutes around any event (all sources, same host, or same user); time-range
  filter; "Show events" for a finding's evidence.
- **Asset lookup by IP, hostname or MAC**: a workspace asset inventory (CSV import from CMDB/EDR,
  any MAC format) plus a host ↔ IP ↔ MAC map built from the logs.
- **Quick reputation for a pasted IOC**: paste a bare IOC (fanged or defanged) in the top bar,
  dashboard or search page to get a plain-language verdict summary, the sources that flagged it, and
  the cases it was already seen in.
- **Structured incident report**: Quick verdict, Executive summary, Timeline, Event details,
  Analysis, Interpretation, Confidence level, Recommendations, Actions taken, IOCs & artifacts.
  Quick verdict and confidence are assessed from the evidence and can be overridden by the analyst.
- **Onboarding**: after sign-up, a setup guide asks the user/team to connect API keys (with a
  *Test* button per key) before opening the first case. Nudges appear while no source is connected.
- Findings tab with confirm/dismiss and analyst notes; a "seen in other cases" panel for indicators.

### Changed
- **Indicators in reports are always defanged** (`185[.]220[.]101[.]1`, `hxxps[://]evil[.]com/x`,
  `bob[@]evil[.]com`), including inside free text, command lines and anything an analyst pastes in
  before saving. Reference links (MITRE) stay clickable. `defang()` now brackets every dot.
- Fanged and defanged IOCs are accepted everywhere.
- **Non-relevant sources are ignored**: sources that error (missing/rejected key, quota, timeout),
  don't support the indicator type or have no record are dropped from case results, quick lookups and
  reports, so they never show error messages in an investigation. The CLI table hides them too
  (`--all-sources` shows them).
- HTTP retries no longer retry read timeouts, so one unreachable source can't stall a lookup.

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

[Unreleased]: https://github.com/HuntsmanSec/stark/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/HuntsmanSec/stark/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/HuntsmanSec/stark/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/HuntsmanSec/stark/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/HuntsmanSec/stark/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/HuntsmanSec/stark/releases/tag/v0.1.0
