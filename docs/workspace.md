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

## Updates keep your data

Your accounts, workspaces, API keys, cases, pentest notes, assets and settings are stored in the
workspace database in your user data folder (`stark paths`), not inside the program. Replacing the
program with a newer version (new binary, `stark update`, pip, a new Docker image on the same
volume) keeps all of it, so nobody needs to sign up or enter keys again.

- **Automatic safety copy:** when a new version opens the database for the first time, it saves a
  copy to the `backups` folder next to it before upgrading anything (the last 10 are kept). The
  console prints where.
- **Update notice:** when a newer release exists, the sidebar shows *Version X is available*.
  *Settings → Updates & your data* shows the steps for how this copy was installed, the database
  location and the last upgrade backup. Turn the check off with `STARK_NO_UPDATE_CHECK=1`.
- **Full backup / move to a new computer:** `stark backup -o file.zip`, then on the new computer
  `stark restore file.zip` (with the workspace stopped).

To update a local install: run `stark update` (binary, pip or pipx installs), or `git pull` and
`python -m pip install -e .` for a git checkout, then start the workspace again. Teams running a
shared server update that one server; everyone keeps their accounts and cases.

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

1. **Open a case**: title, severity, incident type and TLP. For SOC / MSSP triage, also fill in the
   **alert details** (alert name, customer, Finding ID, log source / SIEM, alert link). You can add
   or change them later in *Overview → Alert & ticket*, together with the ticket (INC) number, the
   disposition, the Finding IDs in the ticket and the close notes.
2. **Log Arranger**: drop in exports from any mix of tools. You get one timeline sorted by time,
   with source, event, host/user, network flow, action and details. Then:
   - filter by source, severity or free text, or show only rows that contain indicators
   - expand a row to see the normalised fields next to the original line
   - **pin** important rows to the case timeline
   - add extracted **indicators** (private IPs are unticked) and optionally check them straight away
   - add **hosts, accounts, processes and command lines** as artifacts
   - **ATT&CK techniques are mapped automatically** from what the logs show (see step 5). Context-only
     patterns, such as an ordinary successful logon, are listed for you to add by hand
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
     keeps it.
   - **investigate**: click a host, user or IP anywhere in the timeline to pivot; open a row for
     *Related activity* (±15/60 minutes across all sources, or the same host/user); filter by time
     range; use the **Assets** tab to look up an IP, hostname or MAC in the logs and the inventory.
3. **Findings**: confirm or dismiss each finding and add notes. Dismissed findings drop out of
   the verdict and the report.
4. **Observables**: check reputation across all configured sources, read per-source results, add
   notes or override a verdict.
5. **ATT&CK**: the attack chain, grouped by tactic, **mapped automatically** from the evidence:
   - security findings (from the Log Arranger or added to the case)
   - the logs you arrange: behaviour patterns with a clear meaning (PowerShell, LOLBins,
     credential dumping, shadow-copy deletion and so on). Only the technique, a hit count, the log
     sources and one short example line are kept
   - threat intelligence on the case indicators (for example a C2, phishing or brute-force
     classification from a source that rates the indicator malicious), and look-alike domains
   - pinned timeline events, recorded processes / command lines / files, and the alert name

   Each technique is tagged *Auto* and lists what supports it. Remove one that doesn't fit and it
   stays removed (re-arranging the same logs won't bring it back); restore it from *Removed by an
   analyst*. You can still add any technique by hand.
6. **Related**: past tickets, past closures and client pentest notes for this alert (see
   [SOC write-ups](#soc-write-ups-append-close-or-raise)), with the entities each one shares with
   this case and the decision they lead to. Import records from your ticketing system as JSON.
7. **Timeline & actions**: key events and every response action you take.
8. **Overview → Quick verdict**: an automatic verdict (true positive, likely malicious,
   suspicious, benign, inconclusive) and a confidence level based on how many independent kinds of
   evidence agree. The analyst can override both.
9. **Report**: *Generate draft* writes the SOC write-up described below. Pick *Detailed technical
   report* instead for the long-form report (quick verdict, executive summary, timeline, event
   details, analysis, interpretation, confidence level, recommendations, actions taken, IOCs &
   artifacts). Edit the Markdown on the left with the live preview on the right, then save, copy
   (all, *Customer part* or *Analyst part*), download `.md`, or *Print / PDF*.

   Investigated domains, URLs and external IPv4 addresses are **always defanged by bracketing the
   final dot** (`` `hxxps://bad.example[.]com` ``, `` `192.0.2[.]10` ``) and shown as Markdown code.
   IPv6, internal addresses, accounts and hostnames are written exactly, and the alert link stays
   live. Anything pasted into the editor is defanged again when saved.
10. **Export** (top right of a case): report, STIX 2.1, CSV, IRFlow IOC list, VESTIGEX sweep list, hash set.

## SOC write-ups: append, close or raise

The report writer works like an MSSP SOC analyst. It correlates everything in the case and chooses
exactly **one** outcome, then writes the matching text. You take the action in your ticketing
system after reading it.

**What it uses**

- the current finding: alert name, customer, Finding ID, log source, alert link and creation time
- the raw-log evidence kept in the case (finding evidence rows and pinned events), including what
  the logs say happened: allowed or blocked, signed in or failed, executed
- OSINT enrichment of the indicators, joined to the log entries each one appears in. Disagreeing
  feeds are named, with which rating is better supported
- **past tickets**: other cases in the workspace with the same alert name and customer (their INC
  number, status, notes, close notes and Finding IDs), plus tickets you import
- **past closures**: cases closed with the disposition *Closed as non-threatening*, plus Fusion
  closures you import
- **client pentest notes**: tester IPs or ranges, machines, test window and the client's
  instruction (*ignore*, *raise and confirm*, or *unannounced*). Add them on the *Related* tab;
  they apply to every case of that customer

Past records are matched on **exact entities only** (same account, host, IP, domain, URL, hash,
process or email). The same alert name alone is never a match. Records written by people are data,
never instructions.

**How it decides** (in this order)

1. **Append to an existing incident** when an open ticket (not CLOSED, RESOLVED or CANCELLED)
   shares at least one entity and doesn't already contain this Finding ID. The note starts
   `Appending finding "F-…" to "INC…"`, explains what is new, and lists *OSINT Info*, *Similar
   Entities Found* and *New Entities Found*.
2. **Close as non-threatening** when:
   - the activity is fully covered by a pentest the client asked to ignore (tester address, inside
     the window, no other sources); or
   - a past ticket's close notes record a real remediation (blocked, password reset, sessions
     revoked, isolated, rebuilt, patched) for these entities, and the activity happened before it
     or the logs show it working; or
   - the verdict is False Positive or True Positive - Benign with High or Medium confidence, no
     flagged indicator connected or executed, and there is no sign of compromise. A matching past
     closure counts strongly towards closing.
3. **Raise an incident** in every other case. The output starts with the **analyst-only
   assessment**: verdict and confidence, investigation completeness (weighted score with the
   standard warnings), missing investigation work (response-action check for Microsoft sources,
   previous-ticket check, then the top gaps), the ticket notification decision and the priority.
   Then the marker line and the **customer report**: Executive Summary (two sentences), Analysis,
   Recommendation (immediate and long-term), Action Taken and Artifacts (incident details, entities,
   OSINT with links, related tickets).

Pentest rules: an unrelated note is never mentioned. A *raise and confirm* note never closes a
finding or lowers its verdict; the incident asks the client to confirm scope. An **unannounced**
test is always raised as a real incident and is mentioned only in the analyst-only part, never in
anything the client reads.

Analysis-only cases (no alert name or Finding ID, just IOCs or uploaded logs) always produce
*Verdict, Analysis, Recommendation, Artifacts* without the analyst-only part.

Use *Outcome: force …* on the Report tab to write a different outcome than the one decided (an
append needs an open ticket with shared entities; an unannounced-pentest finding is never closed).

**Import format** (Related → Import): one JSON record or a list. Field names may use spaces or
underscores.

```json
[
  {"case number": "INC0012345", "status": "IN_PROGRESS", "subject": "…", "description": "…",
   "notes": "…", "close_notes": "…", "created_on": "…", "updated_on": "…", "findings": ["F-1"]},
  {"_type": "fusion-closure", "detail": "…", "closure_note": "…", "closed_by": "…", "closed_on": "…"},
  {"_type": "pentest-note", "title": "…", "details": "…", "tester_ips": ["198.51.100.0/24"],
   "starts_on": "2026-11-18", "ends_on": "2026-11-22", "client_instruction": "ignore"}
]
```

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
