# Toronto SOC Automation Toolkit

A dependency-free Python toolkit that demonstrates the building blocks of a **SOC Analyst / Threat Hunter** workflow: structured logging, SIEM-style detection mapped to **MITRE ATT&CK**, live log monitoring, port scanning and password-strength analysis.

> **Portfolio project** · created April 2026 · v2.0 modernised October 2026 · by **Marotinho**
> Forked from [Aceknight4/security-toolkit](https://github.com/Aceknight4/security-toolkit) and heavily improved.

---

## Features

| Tool | What it does | Why it matters in a SOC |
|------|--------------|-------------------------|
| **Log Writer** | Writes validated, sanitised events (`[time] [SEVERITY] TYPE - text \| User \| Location`) | Consistent, parseable logs are the input of every SIEM |
| **Threat Detector** | Regex rules for brute force, suspicious geo/anonymisers, phishing, privilege escalation, exfiltration and recon; each rule is tagged with a MITRE ATT&CK technique | Mirrors how Splunk / Elastic / Sigma detections are structured |
| **Real-Time Monitor** | `tail -F`-style follower with inline alerts; handles partial lines, truncation and log rotation | Live triage of incoming events |
| **Port Scanner** | Concurrent TCP connect scan with `open / closed / filtered` states and service names | Basic attack-surface discovery (authorised targets only) |
| **Password Checker** | 0–100 score, entropy estimate, blocklist and pattern checks, hidden input | Illustrates credential-hygiene reviews |

### What changed in v2.0

- **Security fixes**: log-injection protection (newlines / `\|` in input can no longer forge events), hidden password input (`getpass`), authorisation prompt before scanning, log file created with `0600` permissions.
- **Better detection**: word-boundary regexes (fewer false positives), user/location fields are no longer scanned, MITRE ATT&CK tags, severity filtering, JSON/CSV export.
- **Robust monitor**: no more half-line alerts, survives truncation and logrotate.
- **Faster scanner**: thread pool instead of one port at a time.
- **No hard-coded personal data**: user and location come from environment variables.
- **Real CLI** (`argparse` sub-commands) *and* the classic interactive menu, with meaningful exit codes for automation.
- **Typed, documented code** (dataclasses, enums, type hints, docstrings) and a **44-test** suite.

---

## Quick start

Requires **Python 3.9+**. No packages to install.

```bash
git clone https://github.com/Marotinh0/toronto-soc-automation-toolkit.git
cd toronto-soc-automation-toolkit
python3 soc_toolkit.py            # interactive menu
```

### Command line

```bash
# Write events
python3 soc_toolkit.py log -t LOGIN -s HIGH -m "Failed login for admin from 203.0.113.7"
python3 soc_toolkit.py log -t DATA_EXFIL -s CRITICAL -m "Bulk download of 4GB"

# Detect threats (exit code 2 = threats found)
python3 soc_toolkit.py detect
python3 soc_toolkit.py detect --min-severity HIGH --export report.json

# Live monitoring (Ctrl+C to stop, or --duration N seconds)
python3 soc_toolkit.py monitor
python3 soc_toolkit.py monitor --from-start --duration 30

# Port scan (only systems you are authorised to test)
python3 soc_toolkit.py scan localhost --ports 22,80,443,8000-8010 --authorized

# Password check (input is hidden, nothing is stored)
python3 soc_toolkit.py password
```

Use `python3 soc_toolkit.py --help` or `<command> --help` for every option.

### Configuration (optional environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `SOC_LOG_FILE` | `soc_logs.txt` | Log file path (or use `-f/--log-file`) |
| `SOC_LOCATION` | `Toronto` | Location tag written to events |
| `SOC_ANALYST` | OS user name | User tag written to events |
| `NO_COLOR` | – | Disable coloured output |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success / nothing suspicious |
| `1` | Usage or runtime error |
| `2` | `detect` found at least one threat (handy in cron jobs and CI) |

---

## Detection rules

| Rule | Severity | ATT&CK technique | Example trigger |
|------|----------|------------------|-----------------|
| `brute_force` | HIGH | T1110 Brute Force | `failed login`, `invalid password`, `auth fail` |
| `suspicious_geo` | MEDIUM | T1090 Proxy | `tor exit node`, `foreign ip`, `vpn flagged` |
| `phishing` | HIGH | T1566 Phishing | `phishing`, `spoofed sender`, `malicious link` |
| `privilege_esc` | CRITICAL | T1548 Abuse Elevation Control | `sudo failure`, `privilege escalation` |
| `data_exfil` | CRITICAL | T1041 Exfiltration Over C2 | `large transfer`, `bulk download` |
| `recon_scan` | MEDIUM | T1046 Network Service Discovery | `port scan`, `nmap` |

The ATT&CK mappings are a pragmatic approximation for a learning project — confirm them at <https://attack.mitre.org> before using them operationally. Adding a rule is one `ThreatRule(...)` entry in `THREAT_RULES`.

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

---

## Limitations & responsible use

- This is an **educational / portfolio** tool, not a replacement for a real SIEM, EDR or password-policy engine. Passing the password checker does not make a password compliant with any specific regulation or company policy.
- Detection is keyword-based: it will miss obfuscated activity and can produce false positives.
- **Only scan systems you own or have explicit written permission to test.** Unauthorised scanning may be illegal (in Canada, see Criminal Code s. 342.1).

## Roadmap ideas

- Threshold/correlation rules (e.g. 5 failed logins from one IP within 60 s)
- IP extraction + enrichment (AbuseIPDB / GeoIP)
- Sigma rule import, syslog / JSON log formats
- GitHub Actions workflow to run the tests

## License

MIT — see [LICENSE](LICENSE).
