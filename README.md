<div align="center">

# S.T.A.R.K

**Security Threat Assessment and Reputation Kit**

One command, every reputation source. Consolidated OSINT / threat-intelligence lookups for
IPs, domains, URLs, file hashes and email addresses, with STIX 2.1 import/export and
DFIR timeline enrichment for Hayabusa, IRFlow Timeline and VESTIGEX.

[![CI](https://github.com/HuntsmanSec/stark/actions/workflows/ci.yml/badge.svg)](https://github.com/HuntsmanSec/stark/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/HuntsmanSec/stark?sort=semver)](https://github.com/HuntsmanSec/stark/releases)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## Features

- **19 reputation sources** in one query: VirusTotal, AbuseIPDB, urlscan.io, ANY.RUN, Joe Sandbox,
  Hybrid Analysis, Recorded Future, Cisco Talos, AlienVault OTX, MalwareBazaar, ThreatFox, URLhaus,
  Have I Been Pwned, MXToolbox, Shodan, GreyNoise, Pulsedive, IPinfo and crt.sh
- **Single or bulk lookups**: arguments, files, stdin pipes or STIX bundles. Defanged input
  (`hxxps://evil[.]com`) is refanged automatically
- **One consolidated verdict** per observable (`malicious`, `suspicious`, `harmless`, `unknown`)
  with per-source detail, scores, malware families and pivot links
- **STIX 2.1**: export indicators, observables, malware families, relationships and notes with
  TLP 2.0 markings. Import observables from any STIX 2.x bundle
- **DFIR integrations**: enrich Hayabusa timelines, feed IRFlow Timeline IOC Matching, build
  VESTIGEX IOC sweep lists and hash sets
- **Your keys, your control**: keys come from a local config file or environment variables and
  are never logged. Sources without a key are skipped
- **Fast and polite**: concurrent lookups, per-source rate limits tuned for free tiers, and a local
  SQLite cache so repeat lookups don't use up your quota
- **Cross-platform**: pure Python with a single runtime dependency (`requests`). Standalone
  binaries for Windows, macOS and Linux are attached to each release
- **Automation-friendly**: table, JSON, JSONL, CSV, Markdown and STIX output, plus
  `--fail-on malicious` exit codes for CI and SOAR pipelines

## Install

**pip / pipx** (recommended, works on every OS):

```bash
pipx install git+https://github.com/HuntsmanSec/stark.git
```

**From source:**

```bash
git clone https://github.com/HuntsmanSec/stark.git
cd stark
python -m pip install .
```

**Standalone binary:** download `stark-<os>` from the
[latest release](https://github.com/HuntsmanSec/stark/releases/latest). No Python needed.

**Docker:**

```bash
docker build -t stark .
docker run --rm -e STARK_VIRUSTOTAL_API_KEY stark query 8.8.8.8
```

## Configure API keys

You set every API key yourself. STARK never ships with keys.

```bash
stark config init                 # interactive, input hidden
stark config set virustotal       # prompt for one key (keeps it out of shell history)
stark config show                 # masked view of what is configured
stark providers                   # which sources are ready / need a key
```

Or use environment variables (these take precedence over the file):

```bash
export STARK_VIRUSTOTAL_API_KEY=...
export STARK_ABUSECH_API_KEY=...      # one abuse.ch Auth-Key covers MalwareBazaar, ThreatFox, URLhaus
```

```powershell
# Windows PowerShell
$env:STARK_VIRUSTOTAL_API_KEY = "..."
```

| Config key | Sources | Get a key |
|---|---|---|
| `virustotal` | VirusTotal | https://www.virustotal.com/gui/my-apikey |
| `abuseipdb` | AbuseIPDB | https://www.abuseipdb.com/account/api |
| `urlscan` | urlscan.io | https://urlscan.io/user/profile/ |
| `anyrun` | ANY.RUN TI Lookup | https://app.any.run/profile |
| `joesandbox` | Joe Sandbox | https://jbxcloud.joesecurity.org/user |
| `hybridanalysis` | Hybrid Analysis | https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab |
| `recordedfuture` | Recorded Future | Your Recorded Future account team |
| `otx` | AlienVault OTX (optional) | https://otx.alienvault.com/api |
| `abusech` | MalwareBazaar, ThreatFox, URLhaus | https://auth.abuse.ch/ |
| `hibp` | Have I Been Pwned | https://haveibeenpwned.com/API/Key |
| `mxtoolbox` | MXToolbox | https://mxtoolbox.com/User/Api/ |
| `shodan` | Shodan | https://account.shodan.io |
| `greynoise` | GreyNoise (optional) | https://viz.greynoise.io/account/api-key |
| `pulsedive` | Pulsedive (optional) | https://pulsedive.com/account |
| `ipinfo` | IPinfo (optional) | https://ipinfo.io/account/token |
| - | Cisco Talos, crt.sh | No key needed |

The config file is `%APPDATA%\stark\config.toml` on Windows and `~/.config/stark/config.toml`
on macOS/Linux. It is created with `0600` permissions. See
[`examples/config.example.toml`](examples/config.example.toml) and
[docs/providers.md](docs/providers.md).

## Usage

### Single observable

```text
$ stark query 185.220.101.1          # keyless sources only; add keys for VirusTotal, AbuseIPDB, ...
185.220.101.1  [ipv4]  ->  MALICIOUS  (1 malicious, 2 suspicious, 0 harmless, 4 sources)
  families: CryptoMining, SSH Brute Force, Tor Proxy
Source    | Verdict    | Score | Details
----------+------------+-------+------------------------------------------------------------------
talos     | UNKNOWN    |       | No public API - open the Reputation Center link  <https://talosintelligence.com/...>
otx       | SUSPICIOUS | 70    | 50 pulse(s): Webscanners ...  <https://otx.alienvault.com/indicator/ip/185.220.101.1>
greynoise | SUSPICIOUS |       | unknown, last seen 2026-11-20  <https://viz.greynoise.io/ip/185.220.101.1>
pulsedive | MALICIOUS  | 100   | risk critical, threats: CryptoMining, SSH Brute Force, Tor Proxy  <https://pulsedive.com/...>
```

### Multiple observables

```bash
stark query 8.8.8.8 evil[.]com hxxps://bad.example/payload 44d88612fea8a8f36de82e1278abb02f user@corp.com
stark query -f iocs.txt                       # one per line, '#' comments allowed
cat iocs.txt | stark query                    # stdin
stark query -f iocs.txt -F csv -o results.csv
stark query -f iocs.txt --types ip,hash       # only some types
stark query 1.2.3.4 -p vt,abuseipdb,greynoise # only some sources
stark query 1.2.3.4 -x shodan                 # skip a source
stark query example.com --all                 # include informational sources (IPinfo, crt.sh)
```

### Output formats

`-F/--format`: `table` (default), `json`, `jsonl`, `csv`, `md`, `stix`, `irflow`, `vestigex`, `hashset`.

```bash
stark query -f iocs.txt -F json --raw -o results.json   # include raw source details
stark query -f iocs.txt -F md -o report.md              # Markdown report (defanged)
stark query -f iocs.txt --stix bundle.json              # any format + a STIX bundle
stark query -f iocs.txt --fail-on malicious -q -F jsonl # exit code 3 if anything is malicious
```

### STIX 2.1

```bash
stark query -f iocs.txt -F stix --tlp amber -o stark.stix.json   # export
stark query --stix-in threat-feed.stix.json                       # import observables from a bundle
stark query --stix-in feed.json -F stix --stix-all -o enriched.json
```

See [docs/stix.md](docs/stix.md) for the object model.

### Extract IOCs without querying

```bash
stark extract report.pdf.txt phishing.eml --defang
stark extract timeline.csv -F csv
```

Private/reserved IPs, well-known Microsoft/CDN noise domains and file names that look like domains
(`invoice.exe`, `Security.evtx`) are filtered out. Use `--include-private` to keep RFC1918 addresses.

## DFIR integrations

| Tool | How STARK integrates |
|---|---|
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | `stark enrich timeline.csv --preset hayabusa` mines `Details`/`ExtraFieldInfo` (CSV or JSON/JSONL), skips `IMPHASH`, and writes the timeline back with `STARK_Verdict`, `STARK_Score`, `STARK_FlaggedBy`, `STARK_Families` and `STARK_IOCs` columns |
| [IRFlow Timeline](https://github.com/r3nzsec/irflow-timeline) | `-F irflow` writes an IOC list with the `ioc_value` header that IRFlow's *IOC Matching* loader reads, plus verdict columns. `stark enrich export.csv --preset irflow` enriches IRFlow CSV/TSV exports |
| [VESTIGEX](https://vestigex.app) | `-F vestigex` writes an IOC sweep list, `-F hashset` a known-bad hash set, `-F stix` a STIX bundle. `--preset vestigex` enriches VESTIGEX CSV exports |

```bash
# Hayabusa -> STARK -> IRFlow
hayabusa csv-timeline -d ./evtx -p verbose -o timeline.csv
stark enrich timeline.csv --preset hayabusa --only-flagged \
      --enriched timeline.flagged.csv -F irflow -o irflow-iocs.csv --stix iocs.stix.json
# open timeline.flagged.csv in IRFlow, or load irflow-iocs.csv in Actions -> IOC Matching
```

Details and workflows: [docs/integrations.md](docs/integrations.md).

## Library use

```python
from stark import Stark

stark = Stark(providers=["virustotal", "abuseipdb"])
for report in stark.query_many(["185.220.101.1", "evil.example"]):
    print(report.observable.value, report.verdict.value, report.flagged_by)
```

## How verdicts are consolidated

Each source result is normalised to `malicious`, `suspicious`, `harmless`, `unknown` or `error`,
plus an optional 0-100 score. The consolidated verdict is the **worst** answer from any source that
answered. Errors (bad key, quota, timeout) never count as a verdict. Per-source thresholds are
documented in [docs/providers.md](docs/providers.md). Always confirm a verdict before acting on it.

## OPSEC

STARK only does **passive lookups**. It never submits files or URLs for scanning, so nothing you
look up gets published to public scan feeds. Your queries still reach every source you enable, so
disable the ones you don't want with `stark config disable <provider>` or `-x`.

## Versioning

STARK follows [Semantic Versioning 2.0.0](https://semver.org). Releases are tagged `vMAJOR.MINOR.PATCH`
and listed in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), including how to add a
new source in about 40 lines. Source ideas come from
[awesome-osint](https://github.com/jivoi/awesome-osint).

## License

[MIT](LICENSE) © HuntsmanSec. Third-party services are subject to their own terms of use and API
limits. You are responsible for complying with them.
