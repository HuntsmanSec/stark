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

## First run: connect your sources

Right after sign-up, the **setup guide** asks you to connect the threat-intelligence sources you have
accounts for (VirusTotal, AbuseIPDB, abuse.ch, OTX, urlscan, GreyNoise, and enterprise sources such as
Recorded Future, ANY.RUN, Joe Sandbox, Hybrid Analysis or Shodan). Each key has a **Test** button that
runs a harmless lookup. In a team workspace the keys are shared and only owners/admins can change
them. Sources you don't connect are skipped quietly, and sources that fail or have no data on an
indicator are left out of results and reports entirely.

## Quick reputation for a pasted IOC

Paste any IOC, fanged (`http://evil.com`) or defanged (`hxxp[://]evil[.]com`, `185.220.101[.]1`),
into the top search bar, the dashboard box or the *IOC lookup & search* page. You get a
plain-language summary ("The IP address 185[.]220[.]101[.]1 is MALICIOUS: …"), the sources with an
opinion, and the cases it already appears in. *Add to case* puts it into an open investigation.

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
   - review the **security findings**: S.T.A.R.K analyses the arranged logs for
     - *authentication anomalies*: brute force, success after failures, password spraying, MFA
       failures/fatigue, impossible travel, many countries, unusual devices/user agents, legacy or
       scripted authentication, privileged logins from external IPs
     - *process & command line*: PowerShell cradles/IEX/hidden/AMSI tampering (encoded commands are
       decoded and shown), mshta, rundll32, regsvr32, certutil, bitsadmin, wmic, msiexec and other
       LOLBins, Office spawning shells, credential dumping, shadow-copy deletion, log clearing,
       persistence, recon, remote-access tools, PsExec
     - *malware & files*: attack tooling, double extensions, masquerading names, system binaries in
       the wrong folder, executables in user-writable paths
     - *network & C2*: beaconing, suspicious ports, exposed RDP/SMB/SSH/WinRM, bare-IP downloads,
       typosquatted and look-alike domains (including look-alikes of your own domain, inferred from
       user principal names), DGA-like domains, DNS tunnelling, abused TLDs

     Each finding shows what was seen, an interpretation, a recommended action, severity and
     confidence, entities, ATT&CK techniques and the evidence rows (*Show events*). *Add to case*
     keeps it, and its techniques are mapped automatically.
   - **investigate**: click a host, user or IP anywhere in the timeline to pivot; open a row for
     *Related activity* (±15/60 minutes across all sources, or the same host/user); filter by time
     range; use the **Assets** tab to look up an IP, hostname or MAC in the logs and the inventory.
3. **Findings**: confirm or dismiss each finding and add notes. Dismissed findings drop out of
   the verdict and the report.
4. **Observables**: check reputation across all configured sources, read per-source results, add
   notes or override a verdict.
5. **ATT&CK**: the attack chain, grouped by tactic, with evidence notes.
6. **Timeline & actions**: key events and every response action you take.
7. **Overview → Quick verdict**: an automatic verdict (true positive, likely malicious,
   suspicious, benign, inconclusive) and a confidence level based on how many independent kinds of
   evidence agree. The analyst can override both.
8. **Report**: *Generate draft* writes a structured report:
   - **Quick verdict** with confidence level and its basis
   - **1. Executive summary** in plain language, with key points for leadership
   - **2. Timeline** of pinned events, findings and actions
   - **3. Event details** for each finding: what was seen, entities, ATT&CK, evidence table, decoded commands
   - **4. Analysis**: findings by category, indicator reputation, ATT&CK mapping
   - **5. Interpretation**: what it means and the attack sequence
   - **6. Confidence level**: supporting factors and the gaps that limit confidence
   - **7. Recommendations**: containment, eradication, recovery, hardening, monitoring
   - **8. Actions taken**
   - **9. IOCs & artifacts**: indicators, hosts, accounts, processes, command lines, files, techniques

   Every indicator is rendered as Markdown code and **always defanged** (`` `185[.]220[.]101[.]1` ``,
   `` `hxxps[://]evil[.]com/x` ``), including inside command lines and free text. Anything pasted
   into the editor is defanged again when saved. Edit the Markdown on the left with the live preview
   on the right, then save, copy, download `.md`, or *Print / PDF*.
9. **Export** (top right of a case): report, STIX 2.1, CSV, IRFlow IOC list, VESTIGEX sweep list, hash set.

## Asset inventory

*Assets* holds the hosts your workspace knows about: hostname, IP, MAC, OS, owner, department,
location and criticality. Import a CSV export from your CMDB, Intune, EDR or DHCP server (download the
template from the page; common column names are recognised), or add assets by hand. Look an asset up
by IP, hostname or MAC in any format (`00:1A:…`, `00-1a-…`, `001a.2b3c.…`). The same lookup is
available inside the Log Arranger and in the global search, and indicators that match an asset say so.

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
