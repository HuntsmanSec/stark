# Reputation sources

`stark providers` shows the live status of each source on your machine.

| Provider | Key | Types | Default rate | How the verdict is derived |
|---|---|---|---|---|
| `virustotal` | required | ip, domain, url, hash | 4/min (public tier) | ≥3 engines malicious → malicious. 1-2 malicious or any suspicious → suspicious. Otherwise harmless. Score = % of engines flagging |
| `abuseipdb` | required | ip | 60/min | confidence ≥75 → malicious, ≥25 → suspicious, else harmless. Allow-listed → harmless |
| `urlscan` | required | ip, domain, url, sha256 | 30/min | Passive search of existing public scans. Uses the newest scan's `verdicts.overall` |
| `anyrun` | required (TI Lookup) | ip, domain, url, hash | 30/min | `threatLevel` 2 → malicious, 1 → suspicious, 0 → harmless |
| `joesandbox` | required | ip, domain, url, hash | 30/min | Worst `detection` among existing analyses. On-prem: `[providers.joesandbox] base_url` |
| `hybridanalysis` | required | ip, domain, url, hash | 60/min | Worst report `verdict` (malicious / suspicious / no specific threat) |
| `recordedfuture` | required | ip, domain, url, hash | 60/min | criticality ≥3 or risk ≥65 → malicious. ≥2 or ≥25 → suspicious |
| `talos` | none | ip, domain, url | - | No public API. IPs are checked against the Talos IP blocklist feed, and a Reputation Center pivot link is always returned |
| `otx` | optional | ip, domain, url, hash | 60/min | ≥1 pulse → suspicious (OTX alone never escalates further). Any allow-list validation → harmless |
| `malwarebazaar` | `abusech` | hash | 60/min | Known sample → malicious |
| `threatfox` | `abusech` | ip, domain, url, hash | 60/min | IOC present: confidence ≥50 → malicious, else suspicious |
| `urlhaus` | `abusech` | ip, domain, url, md5, sha256 | 60/min | Listed URL, payload or host → malicious |
| `hibp` | required | email | 10/min | Found in breaches → suspicious (exposure). Not found → harmless |
| `mxtoolbox` | required | ipv4, domain | 30/min | Listed on ≥3 blocklists → malicious, 1-2 → suspicious, 0 → harmless |
| `shodan` | required | ip, domain (resolved) | 60/min | Tags `malware`/`c2`/`compromised`/`botnet` → malicious, known CVEs → suspicious, else unknown |
| `greynoise` | optional | ipv4 | 10/min | `malicious` → malicious, benign/RIOT → harmless, other internet noise → suspicious |
| `pulsedive` | optional | ip, domain, url, hash | 30/min | risk high/critical → malicious, low/medium → suspicious, none → harmless |
| `ipinfo` | optional | ip | 60/min | Informational (geo/ASN), runs only with `--all` or `-p ipinfo` |
| `crtsh` | none | domain | 20/min | Informational (certificates/subdomains), runs only with `--all` or `-p crtsh` |

## Tuning

```toml
[providers]
disabled = ["shodan"]          # never query these unless named with -p

[providers.virustotal]
rate_limit = 500               # requests/minute on a premium key

[providers.joesandbox]
base_url = "https://joe.internal.example/api"
```

Global settings (`stark config setting <name> <value>`): `timeout`, `workers`, `cache_ttl`
(seconds, 0 = off), `max_age_days`, `verify_tls`, `proxy`.

## Notes on other awesome-osint sources

The sources above were chosen from the *Threat Intelligence* and *IP/Domain* sections of
[awesome-osint](https://github.com/jivoi/awesome-osint) because they offer a usable API for
automated reputation lookups. Pull requests that add more (Censys, IBM X-Force, Spamhaus,
PhishTank, CIRCL, ...) are welcome. See [CONTRIBUTING.md](../CONTRIBUTING.md).
