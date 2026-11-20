# S.T.A.R.K Workspace

The workspace is a browser app that comes with S.T.A.R.K. It is built for analysts and for
non-technical people who need to follow an incident (managers, IT generalists, legal, MSP clients).

## Start it

| You have | Do this |
|---|---|
| The standalone download (`stark-windows-x64.exe`, `stark-macos-arm64`, `stark-linux-x64`) | Double-click it, or run it with no arguments. Your browser opens at `http://localhost:8765`. |
| A pip/pipx install | Run `stark` (or `stark serve`). |
| Docker | `docker build -t stark .` then `docker run -p 8765:8765 -v stark-data:/data stark` |

The first person to open a fresh install creates the first account.

## Accounts and workspaces

- **Personal workspace**: every account gets one. Only you can see its cases.
- **Team workspace**: choose *New team* at sign-up, or *Create a team workspace* from the workspace
  menu. The Team page shows an **invite code**. Teammates sign up with *Join a team* (or use *Join a
  team with a code* later).
  - Roles: **owner** (created the team), **admin** (can manage keys and members), **member**.
  - Cases, indicators, artifacts, ATT&CK mappings, timeline, actions, comments and reports are
    shared, and open case pages refresh within a few seconds when a teammate changes something.
  - API keys entered on *API keys & settings* are shared by the team. Only owners and admins can
    change them, and saved keys are never shown again.

## Working a case

1. **Open a case**: title, severity, incident type and TLP.
2. **Log Arranger**: drop in exports from any mix of tools. You get one timeline sorted by time,
   with source, event, host/user, network flow, action and details. Then:
   - filter by source, severity or free text, or show only rows that contain indicators
   - expand a row to see the normalised fields next to the original line
   - **pin** important rows to the case timeline
   - add extracted **indicators** (private IPs are unticked) and optionally check them straight away
   - add **hosts, accounts, processes and command lines** as artifacts
   - review and add **suggested ATT&CK techniques** (with the evidence that matched)
3. **Observables**: check reputation across all configured sources, read per-source results, add
   notes or override a verdict.
4. **ATT&CK**: the attack chain, grouped by tactic, with evidence notes.
5. **Timeline & actions**: key events and every response action you take.
6. **Report**: *Generate draft* writes the initial analysis:
   - Executive summary (plain language, key points for leadership)
   - Technical analysis (timeline, indicator analysis, affected assets, ATT&CK mapping)
   - Recommendations (containment, eradication, recovery, hardening, monitoring), drawn from the
     indicators, assets and techniques in the case
   - Actions taken
   - Artifacts (IOCs, hosts, accounts, processes, command lines, files, techniques)

   Every indicator is rendered as Markdown code (`` `185.220.101.1` ``). Edit the Markdown on the
   left and see the live preview on the right. Then save, copy, download `.md`, or *Print / PDF*.
   Tick *Defang indicators* for reports that will be emailed.
7. **Export** (top right of a case): report, STIX 2.1, CSV, IRFlow IOC list, VESTIGEX sweep list, hash set.

## Client data and privacy

- **The Log Arranger never stores logs.** Uploads are parsed in memory: uploads are kept in RAM
  (not spooled to temp files), nothing is written to the database, and the response is marked
  `no-store`. The arranged timeline lives only in the open browser tab (not in browser storage).
  It is wiped when you leave the case, click **Purge now**, reload the page, or after **30 minutes**.
- Only what you explicitly add to a case is saved: indicators, artifacts, techniques, pinned event
  summaries, actions, comments and the report.
- Reputation lookups send **only the indicator value** to the sources you have configured.
- The workspace database is a single SQLite file (`0600` on macOS/Linux):
  - Windows: `%LOCALAPPDATA%\stark\workspace.sqlite`
  - macOS: `~/Library/Application Support/stark/workspace.sqlite`
  - Linux: `~/.local/share/stark/workspace.sqlite`
  - override with `STARK_DATA_DIR` or `stark serve --db FILE`

## Running a shared team server

```bash
stark serve --host 0.0.0.0 --port 8765 --no-signup --secure-cookies
```

- Put it behind an HTTPS reverse proxy (Caddy, nginx, IIS, Traefik). `--secure-cookies` requires HTTPS.
- `--no-signup` stops strangers creating accounts once your team is set up (the first account can
  always be created). Teammates then need an admin to temporarily re-enable sign-up, or you can
  pre-create accounts and share invite codes while sign-up is open.
- Back up the SQLite file (and its `-wal` file) like any other database.
- Security measures: scrypt password hashing, HttpOnly + SameSite=Strict session cookies,
  a custom-header CSRF check on every state-changing request, a strict Content-Security-Policy,
  login throttling, and per-workspace authorisation on every case endpoint.

## Supported log sources (Log Arranger)

| Family | Formats recognised |
|---|---|
| SIEM | Microsoft Sentinel (CSV/JSON exports, Log Analytics API), Splunk (JSON/CSV exports, `_raw`), Elastic/ELK (`_source`, search responses, ECS), IBM QRadar (LEEF 1.0/2.0, CSV exports), LogRhythm (CSV exports) |
| EDR / XDR | Microsoft Defender (advanced hunting CSV/JSON/API), CrowdStrike Falcon (FDR/Event Search JSON, API `resources`), SentinelOne (Deep Visibility CSV/JSON, API `data`) |
| Firewalls | Palo Alto PAN-OS (syslog CSV: TRAFFIC/THREAT/URL…), Fortinet FortiGate (`key=value`), Cisco ASA/FTD (`%ASA-`), generic CEF |
| WAF | AWS WAF (JSON), Cloudflare (Logpush JSON), Azure WAF / Front Door, ModSecurity, Imperva (CEF) |
| Network | Zeek (`#fields` TSV and JSON), Suricata EVE JSON |
| Windows | Event XML (`<Event>` blocks, e.g. `wevtutil qe /f:xml`), EVTX exported to CSV/JSON (Hayabusa, EvtxECmd) |
| Generic | RFC 3164/5424 syslog, CEF, LEEF, `key=value`, CSV/TSV with header, JSON/JSONL/NDJSON |

Unrecognised lines are still kept as raw text and mined for indicators. Field names are mapped to a
common schema (`time, product, event, severity, action, host, user, src_ip, src_port, dst_ip,
dst_port, protocol, process, parent_process, command_line, hash, url, domain, message`), and all
timestamps are converted to UTC.
