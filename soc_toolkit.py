#!/usr/bin/env python3
"""
Toronto SOC Automation Toolkit  (v2.0.0)
========================================

A small, dependency-free (standard library only) toolkit that demonstrates the
day-to-day building blocks of a SOC Analyst / Threat Hunter workflow:

    1. Log Writer        - write structured, sanitised security events
    2. Threat Detector   - SIEM-style regex detection, mapped to MITRE ATT&CK
    3. Real-Time Monitor - ``tail -f`` with inline alerting (rotation-aware)
    4. Port Scanner      - concurrent TCP connect scan (authorised use only)
    5. Password Checker  - scoring + entropy estimate, input is never echoed

How to run
----------
    python3 soc_toolkit.py                 # interactive menu (same as v1)
    python3 soc_toolkit.py --help          # full CLI reference
    python3 soc_toolkit.py log -t LOGIN -s HIGH -m "Failed login for admin"
    python3 soc_toolkit.py detect --min-severity HIGH --export report.json
    python3 soc_toolkit.py monitor --duration 60
    python3 soc_toolkit.py scan localhost --ports 22,80,443,8000-8010 --authorized
    python3 soc_toolkit.py password

Exit codes (useful for cron / CI pipelines)
-------------------------------------------
    0  success / nothing suspicious found
    1  usage or runtime error (missing file, bad input, DNS failure, ...)
    2  ``detect`` finished and found at least one threat

Environment variables (all optional)
------------------------------------
    SOC_LOG_FILE   path of the log file          (default: soc_logs.txt)
    SOC_LOCATION   location tag written to logs  (default: Toronto)
    SOC_ANALYST    user tag written to logs      (default: the OS user name)
    NO_COLOR       set to any value to disable ANSI colours

Credits
-------
Forked from https://github.com/Aceknight4/security-toolkit and heavily
improved by Marotinho.  Licensed under the MIT License (see LICENSE).

Educational use only.  Only scan systems you own or are explicitly authorised
to test; unauthorised scanning may be illegal (e.g. Canada's Criminal Code,
s. 342.1, "unauthorized use of computer").
"""

from __future__ import annotations

import argparse
import csv
import errno
import getpass
import json
import math
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence

__version__ = "2.0.0"

# =============================================================================
# CONFIGURATION
# =============================================================================
# Defaults can be overridden with environment variables so that the code never
# needs to be edited (and no personal data is hard-coded, unlike v1 which wrote
# a fixed "User: marotinhos" into every log line).

DEFAULT_LOG_FILE = Path(os.environ.get("SOC_LOG_FILE", "soc_logs.txt"))
DEFAULT_LOCATION = os.environ.get("SOC_LOCATION", "Toronto")

# Maximum length of any free-text field written to the log. Prevents a single
# event from bloating the file (and from hiding other data in a huge line).
MAX_FIELD_LENGTH = 500


def default_user() -> str:
    """Return the analyst name used in log lines (env var, then OS user)."""
    configured = os.environ.get("SOC_ANALYST")
    if configured:
        return configured
    try:
        return getpass.getuser()
    except (KeyError, OSError):  # e.g. containers without a passwd entry
        return "unknown"


# =============================================================================
# SMALL TERMINAL HELPERS (colour output)
# =============================================================================

_COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _color_enabled() -> bool:
    """Colour only when writing to a real terminal and NO_COLOR is not set.

    Respecting ``NO_COLOR`` (https://no-color.org) and non-TTY output keeps
    redirected output (``> report.txt``) free of escape codes.
    """
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def paint(text: str, color: str) -> str:
    """Wrap *text* in an ANSI colour when colour output is enabled."""
    if not _color_enabled():
        return text
    return f"{_COLORS[color]}{text}{_COLORS['reset']}"


def info(message: str) -> None:
    print(paint("[INFO]  ", "cyan") + message)


def ok(message: str) -> None:
    print(paint("[ OK ]  ", "green") + message)


def warn(message: str) -> None:
    print(paint("[WARN]  ", "yellow") + message)


def error(message: str) -> None:
    """Errors go to stderr so they never pollute piped/exported output."""
    prefix = "[ERROR] "
    if sys.stderr.isatty() and "NO_COLOR" not in os.environ:
        prefix = f"{_COLORS['red']}{prefix}{_COLORS['reset']}"
    print(prefix + message, file=sys.stderr)


# =============================================================================
# SEVERITY
# =============================================================================


class Severity(IntEnum):
    """Event severity.

    ``IntEnum`` gives us ordering for free (``Severity.HIGH > Severity.LOW``),
    which is what makes "show me HIGH and above" and "take the worst severity
    among several matched rules" trivial.  It also fixes a v1 cosmetic bug:
    v1 stored the allowed values in a ``set`` so the error message listed them
    in random order.  An enum keeps the declaration order.
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        """Convert user text such as ``" high "`` into ``Severity.HIGH``."""
        try:
            return cls[value.strip().upper()]
        except KeyError:
            allowed = ", ".join(member.name for member in cls)
            raise ValueError(
                f"Invalid severity {value!r}. Choose one of: {allowed}"
            ) from None


# =============================================================================
# TOOL 1 - LOG WRITER
# =============================================================================
# Line format (kept backwards compatible with v1 so old log files still work):
#
#   [2026-10-13 18:49:03] [HIGH] LOGIN - Failed login for admin | User: guilherme | Location: Toronto

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def sanitize_field(value: str, max_length: int = MAX_FIELD_LENGTH) -> str:
    """Make free text safe to embed in a single log line.

    Why this matters (log injection, CWE-117): if an attacker controls part of
    a message, a ``\\n`` followed by a forged ``[CRITICAL] ...`` line could
    create fake events.  We therefore:

    * replace control characters (newlines, tabs, ESC, ...) with a space,
    * replace ``|`` so the value cannot fake our ``| User:`` / ``| Location:``
      field separators,
    * trim to ``max_length`` characters.
    """
    cleaned = _CONTROL_CHARS.sub(" ", value).replace("|", "/").strip()
    return cleaned[:max_length]


def format_log_line(
    timestamp: datetime,
    severity: Severity,
    event_type: str,
    description: str,
    user: str,
    location: str,
) -> str:
    """Build one log line (without trailing newline) from already-clean parts."""
    return (
        f"[{timestamp:%Y-%m-%d %H:%M:%S}] [{severity.name}] "
        f"{event_type} - {description} | User: {user} | Location: {location}"
    )


def write_log(
    log_file: Path,
    event_type: str,
    severity: Severity,
    description: str,
    *,
    user: str | None = None,
    location: str | None = None,
    now: datetime | None = None,
) -> str:
    """Validate, sanitise and append one event to *log_file*.

    Returns the exact line that was written (handy for tests and for echoing
    back to the user).  Raises ``ValueError`` on empty input.
    """
    # Event types are single tokens (LOGIN, DATA_EXFIL, ...): collapse spaces so
    # the line stays parseable ("failed login" -> "FAILED_LOGIN").
    clean_type = re.sub(r"\s+", "_", sanitize_field(event_type)).upper()
    clean_description = sanitize_field(description)
    if not clean_type:
        raise ValueError("Event type cannot be empty.")
    if not clean_description:
        raise ValueError("Description cannot be empty.")

    line = format_log_line(
        now or datetime.now(),
        severity,
        clean_type,
        clean_description,
        sanitize_field(user or default_user(), 100),
        sanitize_field(location or DEFAULT_LOCATION, 100),
    )

    log_file.parent.mkdir(parents=True, exist_ok=True)
    # Logs can contain sensitive data, so create the file private (0o600) on
    # POSIX systems.  ``mode`` only applies when the file is first created.
    if not log_file.exists():
        log_file.touch(mode=0o600)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    return line


# =============================================================================
# LOG PARSING
# =============================================================================


@dataclass
class LogEntry:
    """Structured view of one log line (the 'parsed event')."""

    timestamp: str
    severity: str
    event_type: str
    description: str
    user: str = ""
    location: str = ""


# The user/location groups are optional so older or hand-written lines such as
# "[2026-01-01 10:00:00] [LOW] LOGIN - ok" still parse.
LOG_LINE_RE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<severity>[A-Za-z]+)\]\s+"
    r"(?P<event_type>\S+)\s+-\s+(?P<description>.*?)"
    r"(?:\s+\|\s+User:\s*(?P<user>.*?))?"
    r"(?:\s+\|\s+Location:\s*(?P<location>.*?))?\s*$"
)


def parse_log_line(line: str) -> LogEntry | None:
    """Parse *line* into a ``LogEntry`` or return ``None`` if it does not match.

    Unparseable lines are NOT discarded by the detector - they are still scanned
    as raw text - so a malformed line can never be used to hide an attack.
    """
    match = LOG_LINE_RE.match(line.strip())
    if not match:
        return None
    parts = match.groupdict(default="")
    return LogEntry(**parts)


# =============================================================================
# TOOL 2 - THREAT DETECTOR
# =============================================================================


@dataclass(frozen=True)
class ThreatRule:
    """One detection rule: a name, a regex, a severity and its ATT&CK mapping.

    This mirrors how a SIEM rule is organised (Splunk correlation search,
    Elastic detection rule, Sigma rule): logic + severity + framework tags.
    """

    name: str
    pattern: re.Pattern[str]
    severity: Severity
    mitre_id: str
    tactic: str
    summary: str


def _rx(pattern: str) -> re.Pattern[str]:
    """Compile a case-insensitive pattern (all rules share this behaviour)."""
    return re.compile(pattern, re.IGNORECASE)


# ``[\s_-]?`` accepts "failed login", "failed_login" and "failed-login", which
# are the separators log sources typically use.  ``\b`` stops substring false
# positives (e.g. "tor exit" must not match inside "factor exit").
#
# NOTE: the ATT&CK mappings are a pragmatic approximation for a portfolio
# project - verify them against https://attack.mitre.org before relying on them.
THREAT_RULES: tuple[ThreatRule, ...] = (
    ThreatRule(
        name="brute_force",
        pattern=_rx(
            r"\b(?:failed[\s_-]?(?:login|logon|password|auth\w*)"
            r"|invalid[\s_-]?password"
            r"|brute[\s_-]?force"
            r"|auth(?:entication)?[\s_-]?fail\w*)\b"
        ),
        severity=Severity.HIGH,
        mitre_id="T1110",
        tactic="Credential Access",
        summary="Repeated or failed authentication attempts",
    ),
    ThreatRule(
        name="suspicious_geo",
        pattern=_rx(
            r"\b(?:unknown[\s_-]?location|foreign[\s_-]?ip|geo[\s_-]?block\w*"
            r"|tor[\s_-]?exit(?:[\s_-]?node)?|proxy[\s_-]?detected"
            r"|vpn[\s_-]?flag\w*)\b"
        ),
        severity=Severity.MEDIUM,
        mitre_id="T1090",
        tactic="Command and Control",
        summary="Traffic from anonymisation networks or unexpected geographies",
    ),
    ThreatRule(
        name="phishing",
        pattern=_rx(
            r"\b(?:phish\w*|spoof\w*|malicious[\s_-]?link"
            r"|credential[\s_-]?harvest\w*)\b"
        ),
        severity=Severity.HIGH,
        mitre_id="T1566",
        tactic="Initial Access",
        summary="Phishing, spoofing or credential-harvesting indicators",
    ),
    ThreatRule(
        name="privilege_esc",
        pattern=_rx(
            r"\b(?:privilege[\s_-]?escalat\w*|sudo[\s_-]?fail\w*"
            r"|unauthori[sz]ed[\s_-]?admin\w*|root[\s_-]?access)\b"
        ),
        severity=Severity.CRITICAL,
        mitre_id="T1548",
        tactic="Privilege Escalation",
        summary="Attempts to gain higher privileges than granted",
    ),
    ThreatRule(
        name="data_exfil",
        pattern=_rx(
            r"\b(?:large[\s_-]?transfer|data[\s_-]?exfil\w*"
            r"|unusual[\s_-]?upload|bulk[\s_-]?download\w*)\b"
        ),
        severity=Severity.CRITICAL,
        mitre_id="T1041",
        tactic="Exfiltration",
        summary="Unusual outbound data volume or bulk downloads",
    ),
    ThreatRule(
        name="recon_scan",
        pattern=_rx(r"\b(?:port[\s_-]?scan\w*|nmap|network[\s_-]?sweep)\b"),
        severity=Severity.MEDIUM,
        mitre_id="T1046",
        tactic="Discovery",
        summary="Network service discovery / reconnaissance",
    ),
)


@dataclass
class Finding:
    """One flagged log line (what a SIEM would call an 'alert')."""

    line_number: int
    severity: str
    rules: list[str]
    mitre: list[str]
    line: str


@dataclass
class ScanResult:
    """Outcome of scanning a log: how much we read and what we flagged."""

    total_lines: int = 0
    findings: list[Finding] = field(default_factory=list)


def match_rules(
    line: str, rules: Sequence[ThreatRule] = THREAT_RULES
) -> list[ThreatRule]:
    """Return every rule that matches *line*.

    We search only the *event type + description*, not the ``User:`` and
    ``Location:`` tail.  Searching the whole raw line (as v1 did) causes false
    positives such as a service account called ``proxy-detected-svc``.
    If the line cannot be parsed we fall back to scanning all of it.
    """
    entry = parse_log_line(line)
    haystack = f"{entry.event_type} {entry.description}" if entry else line
    return [rule for rule in rules if rule.pattern.search(haystack)]


def detect_threats(
    lines: Iterable[str],
    rules: Sequence[ThreatRule] = THREAT_RULES,
    min_severity: Severity | None = None,
) -> ScanResult:
    """Scan *lines* and return every flagged line.

    A line that matches several rules produces ONE finding listing all of them
    (v1 behaved the same way) whose severity is the highest of:
    the matched rules and the severity written in the log line itself.
    """
    result = ScanResult()
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue  # blank lines are not events
        result.total_lines += 1

        matched = match_rules(line, rules)
        if not matched:
            continue

        severity = max(rule.severity for rule in matched)
        entry = parse_log_line(line)
        if entry:
            try:
                severity = max(severity, Severity.parse(entry.severity))
            except ValueError:
                pass  # unknown severity word in a hand-written line: ignore it

        if min_severity is not None and severity < min_severity:
            continue

        result.findings.append(
            Finding(
                line_number=number,
                severity=severity.name,
                rules=[rule.name for rule in matched],
                mitre=[f"{rule.mitre_id} ({rule.tactic})" for rule in matched],
                line=line,
            )
        )
    return result


def scan_file(
    log_file: Path, min_severity: Severity | None = None
) -> ScanResult:
    """Stream *log_file* line by line (constant memory, even for big logs)."""
    # errors="replace" so one stray non-UTF-8 byte cannot crash the whole scan.
    with log_file.open("r", encoding="utf-8", errors="replace") as handle:
        return detect_threats(handle, min_severity=min_severity)


def export_findings(findings: Sequence[Finding], destination: Path) -> None:
    """Save findings as JSON or CSV, chosen from the file extension."""
    suffix = destination.suffix.lower()
    if suffix == ".json":
        destination.write_text(
            json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    elif suffix == ".csv":
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["line_number", "severity", "rules", "mitre", "line"])
            for f in findings:
                writer.writerow(
                    [f.line_number, f.severity, ";".join(f.rules),
                     ";".join(f.mitre), f.line]
                )
    else:
        raise ValueError("Export file must end in .json or .csv")


_SEVERITY_COLOR = {
    "LOW": "cyan",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "magenta",
}


def print_scan_report(result: ScanResult) -> None:
    """Pretty-print findings plus a per-rule summary table."""
    print(f"Scanned {result.total_lines} log entries.\n")
    if not result.findings:
        ok("No threats detected in current logs.")
        return

    for finding in result.findings:
        tag = paint(f"[{finding.severity}]", _SEVERITY_COLOR[finding.severity])
        rules = ", ".join(name.upper() for name in finding.rules)
        print(f"{tag} line {finding.line_number}: {rules}")
        print(f"        {finding.line}")

    counts: dict[str, int] = {}
    for finding in result.findings:
        for name in finding.rules:
            counts[name] = counts.get(name, 0) + 1

    print("\nSummary")
    print("-------")
    for name, count in sorted(counts.items(), key=lambda item: -item[1]):
        print(f"  {name:<16} {count}")
    print(f"\nFlagged {len(result.findings)} of {result.total_lines} entries.")


# =============================================================================
# TOOL 3 - REAL-TIME MONITOR
# =============================================================================


def follow(
    path: Path,
    *,
    poll_interval: float = 0.5,
    from_start: bool = False,
    duration: float | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Iterator[str]:
    """Yield new lines appended to *path*, like ``tail -F``.

    Improvements over v1's bare ``while True: readline()``:

    * **Partial lines** - a writer may be mid-write when we read; we buffer
      until the newline arrives so an alert never fires on half a line.
    * **Truncation** - if the file becomes smaller than our position (e.g.
      ``> soc_logs.txt``) we start again from the top.
    * **Rotation** - if the inode changes (logrotate replaced the file) we
      reopen the new file instead of watching a deleted one forever.
    * **Testable** - ``sleep`` and ``clock`` can be injected, and ``duration``
      ends the loop on its own (handy for scripts and unit tests).

    Known limitation: truncation is detected by size, so if the file is
    replaced by one *larger* than our old position within a single poll
    interval and the inode is unchanged, that swap goes unnoticed.
    """
    deadline = None if duration is None else clock() + duration
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch(mode=0o600)

    def open_file():
        return path.open("r", encoding="utf-8", errors="replace", newline="")

    handle = open_file()
    try:
        inode = os.fstat(handle.fileno()).st_ino
        if not from_start:
            handle.seek(0, os.SEEK_END)  # only show events from now on
        buffer = ""

        while True:
            if deadline is not None and clock() >= deadline:
                return

            chunk = handle.readline()
            if chunk:
                buffer += chunk
                if buffer.endswith("\n"):
                    yield buffer.rstrip("\r\n")
                    buffer = ""
                continue

            # End of file reached: check for truncation / rotation, then wait.
            try:
                stat = os.stat(path)
            except FileNotFoundError:
                stat = None  # file briefly missing during rotation
            if stat is not None and (
                stat.st_ino != inode or stat.st_size < handle.tell()
            ):
                handle.close()
                handle = open_file()
                inode = os.fstat(handle.fileno()).st_ino
                buffer = ""
            sleep(poll_interval)
    finally:
        handle.close()


# =============================================================================
# TOOL 4 - PORT SCANNER
# =============================================================================

# A short list of ports that matter in enterprise environments.
DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080,
)
MAX_PORTS = 1024  # safety cap: this is a demo tool, not a full-range scanner


@dataclass
class PortResult:
    port: int
    state: str       # "open" | "closed" | "filtered" | "error"
    service: str     # name from the OS services database, or "unknown"


def parse_ports(spec: str) -> list[int]:
    """Turn ``"22,80,8000-8010"`` into a sorted, de-duplicated list of ints."""
    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if "-" in token:
                start_text, end_text = token.split("-", 1)
                start, end = int(start_text), int(end_text)
                if start > end:
                    raise ValueError
                candidates = range(start, end + 1)
            else:
                candidates = range(int(token), int(token) + 1)
        except ValueError:
            raise ValueError(f"Invalid port or range: {token!r}") from None
        for port in candidates:
            if not 1 <= port <= 65535:
                raise ValueError(f"Port out of range (1-65535): {port}")
            ports.add(port)
        if len(ports) > MAX_PORTS:
            raise ValueError(f"Too many ports (maximum {MAX_PORTS}).")
    if not ports:
        raise ValueError("No ports given.")
    return sorted(ports)


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(address: str, port: int, timeout: float) -> PortResult:
    """Probe one TCP port with a full connect (no raw packets, no root needed).

    State meanings:
      open      - the handshake completed (something is listening)
      closed    - the host actively refused (RST), so it is reachable
      filtered  - no answer in time: usually a firewall silently dropping us
      error     - any other OS-level problem (network unreachable, ...)
    """
    service = _service_name(port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((address, port))
    except socket.timeout:
        return PortResult(port, "filtered", service)
    except OSError:
        return PortResult(port, "error", service)

    if code == 0:
        return PortResult(port, "open", service)
    if code == errno.ECONNREFUSED:
        return PortResult(port, "closed", service)
    # connect_ex reports a timeout as EAGAIN/EWOULDBLOCK/ETIMEDOUT.
    return PortResult(port, "filtered", service)


def scan_ports(
    host: str,
    ports: Sequence[int],
    *,
    timeout: float = 1.0,
    workers: int = 50,
) -> tuple[str, list[PortResult]]:
    """Resolve *host* once, then scan *ports* concurrently.

    v1 scanned sequentially: 1 s timeout x N filtered ports = N seconds.  A
    thread pool makes the wait roughly ``ports / workers`` seconds instead.
    Raises ``socket.gaierror`` if the name cannot be resolved.
    """
    address = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ports)))) as pool:
        # ``map`` preserves input order, so the report is sorted by port.
        results = list(pool.map(lambda p: scan_port(address, p, timeout), ports))
    return address, results


# =============================================================================
# TOOL 5 - PASSWORD CHECKER
# =============================================================================

# Tiny built-in blocklist.  NIST SP 800-63B favours blocklists and length over
# composition rules; a real deployment would check against a large breach list
# (e.g. the Have I Been Pwned k-anonymity API).
COMMON_PASSWORDS = frozenset({
    "password", "123456", "123456789", "12345678", "qwerty", "abc123",
    "111111", "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon",
    "passw0rd", "football", "login", "changeme",
})
WEAK_FRAGMENTS = ("password", "passw0rd", "qwerty", "letmein", "welcome",
                  "admin", "123456", "iloveyou")
_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789",
              "qwertyuiop", "asdfghjkl", "zxcvbnm")
_SYMBOLS = re.compile(r"[^A-Za-z0-9\s]")


@dataclass
class PasswordReport:
    score: int                 # 0-100
    rating: str                # WEAK | MEDIUM | STRONG
    entropy_bits: float        # rough upper bound, see evaluate_password()
    feedback: list[str]


def _has_sequence(value: str, run: int = 4) -> bool:
    """True if *value* contains an ascending/descending run such as abcd/4321/qwer."""
    lowered = value.lower()
    for sequence in _SEQUENCES:
        for candidate in (sequence, sequence[::-1]):
            for i in range(len(candidate) - run + 1):
                if candidate[i:i + run] in lowered:
                    return True
    return False


def evaluate_password(password: str) -> PasswordReport:
    """Score *password* from 0 to 100 and explain how to improve it.

    Scoring (maximum exactly 100):
        length      up to 40 points (full marks at 16+ characters)
        lowercase   15 points
        uppercase   15 points
        digit       15 points
        symbol      15 points
    Then penalties: a common password caps the score at 10, a weak fragment
    (``password``, ``qwerty``, ...) costs 30, repeated characters (``aaa``)
    cost 10 and keyboard/alphabet sequences (``abcd``, ``1234``) cost 10.
    Anything shorter than 12 characters can never be rated STRONG.

    The entropy figure is ``length * log2(character pool size)``.  It assumes
    every character was chosen at random, so for human-made passwords it is an
    optimistic upper bound - treat it as a guide, not a guarantee.
    """
    feedback: list[str] = []
    length = len(password)

    score = min(40, round(length / 16 * 40))
    if length < 12:
        feedback.append(f"Use at least 12 characters (currently {length}); length matters most.")

    checks = (
        (any(c.islower() for c in password), 26, "Add lowercase letters."),
        (any(c.isupper() for c in password), 26, "Add uppercase letters."),
        (any(c.isdigit() for c in password), 10, "Add numbers."),
        (bool(_SYMBOLS.search(password)), 32, "Add special characters (!@#$% ...)."),
    )
    pool = 0
    for present, pool_size, advice in checks:
        if present:
            score += 15
            pool += pool_size
        else:
            feedback.append(advice)

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        score = min(score, 10)
        feedback.append("This is one of the most commonly used passwords.")
    elif any(fragment in lowered for fragment in WEAK_FRAGMENTS):
        score -= 30
        feedback.append("Avoid predictable words such as 'password' or 'qwerty'.")

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        feedback.append("Avoid repeating the same character 3+ times in a row.")
    if _has_sequence(password):
        score -= 10
        feedback.append("Avoid sequences such as 'abcd', '1234' or 'qwer'.")

    if length < 12:
        score = min(score, 79)  # never STRONG under the 12-character minimum
    score = max(0, min(100, score))

    if score >= 80:
        rating = "STRONG"
    elif score >= 50:
        rating = "MEDIUM"
    else:
        rating = "WEAK"

    entropy = length * math.log2(pool) if pool else 0.0
    return PasswordReport(score, rating, round(entropy, 1), feedback)


def print_password_report(report: PasswordReport) -> None:
    color = {"STRONG": "green", "MEDIUM": "yellow", "WEAK": "red"}[report.rating]
    print(f"\nScore:   {report.score}/100  {paint(report.rating, color)}")
    print(f"Entropy: ~{report.entropy_bits} bits (optimistic estimate)")
    if report.feedback:
        print("\nSuggestions:")
        for tip in report.feedback:
            print(f"  - {tip}")


# =============================================================================
# COMMAND HANDLERS (thin wrappers around the functions above)
# =============================================================================


def print_banner() -> None:
    print("\n" + "=" * 60)
    print(paint(f"  TORONTO SOC AUTOMATION TOOLKIT  v{__version__}", "bold"))
    print("  Built for SOC Analyst / Threat Hunter roles in Toronto")
    print("=" * 60)
    print(f"  {datetime.now():%Y-%m-%d %H:%M:%S}\n")


def cmd_log(args: argparse.Namespace) -> int:
    try:
        line = write_log(
            args.log_file, args.type, Severity.parse(args.severity), args.message,
            user=args.user, location=args.location,
        )
    except ValueError as exc:
        error(str(exc))
        return 1
    ok(f"Log written to {args.log_file}")
    print(f"        {line}")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    if not args.log_file.exists():
        error(f"No logs found at {args.log_file}. Run the log writer first.")
        return 1
    try:
        minimum = Severity.parse(args.min_severity) if args.min_severity else None
        result = scan_file(args.log_file, minimum)
    except ValueError as exc:
        error(str(exc))
        return 1

    if result.total_lines == 0:
        warn("Log file exists but is empty.")
        return 0

    print_scan_report(result)
    if args.export:
        try:
            export_findings(result.findings, args.export)
        except (ValueError, OSError) as exc:
            error(f"Export failed: {exc}")
            return 1
        ok(f"Findings exported to {args.export}")
    return 2 if result.findings else 0


def cmd_monitor(args: argparse.Namespace) -> int:
    info(f"Monitoring {args.log_file} (Ctrl+C to stop)\n")
    try:
        for line in follow(
            args.log_file, from_start=args.from_start, duration=args.duration
        ):
            print(f"LIVE: {line}")
            for rule in match_rules(line):
                tag = paint(f"[{rule.severity.name}]", _SEVERITY_COLOR[rule.severity.name])
                print(f"  ALERT {tag} {rule.name.upper()} - {rule.mitre_id} ({rule.tactic})")
    except KeyboardInterrupt:
        print()
    info("Monitoring stopped.")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.authorized:
        warn("Only scan systems you own or have written permission to test.")
        answer = input("Do you have authorisation to scan this target? [y/N]: ")
        if answer.strip().lower() not in {"y", "yes"}:
            error("Scan cancelled: authorisation not confirmed.")
            return 1
    try:
        ports = parse_ports(args.ports) if args.ports else list(DEFAULT_PORTS)
        address, results = scan_ports(
            args.target, ports, timeout=args.timeout, workers=args.workers
        )
    except ValueError as exc:
        error(str(exc))
        return 1
    except socket.gaierror as exc:
        error(f"Could not resolve {args.target!r}: {exc}")
        return 1

    print(f"\nScan report for {args.target} ({address})\n")
    print(f"{'PORT':<8}{'STATE':<10}SERVICE")
    state_color = {"open": "green", "closed": "cyan", "filtered": "yellow", "error": "red"}
    for result in results:
        print(f"{result.port:<8}{paint(f'{result.state:<10}', state_color[result.state])}{result.service}")
    opened = sum(1 for r in results if r.state == "open")
    print(f"\n{opened} open / {len(results)} scanned.")
    return 0


def cmd_password(_: argparse.Namespace) -> int:
    # getpass hides what you type and keeps it out of the terminal scrollback.
    # The password is evaluated in memory only - it is never logged or saved.
    password = getpass.getpass("Enter password to test (input hidden): ")
    print_password_report(evaluate_password(password))
    return 0


# =============================================================================
# INTERACTIVE MENU (same experience as v1, now built on the functions above)
# =============================================================================


def _menu_log_writer(log_file: Path) -> None:
    print("\nLOG WRITER")
    event_type = input("Event type (e.g. LOGIN, ALERT, ERROR): ")
    severity = input("Severity (LOW/MEDIUM/HIGH/CRITICAL): ")
    description = input("Description: ")
    try:
        line = write_log(log_file, event_type, Severity.parse(severity), description)
    except ValueError as exc:
        error(str(exc))
        return
    ok(f"Log written to {log_file}")
    print(f"        {line}")


def _menu_port_scanner() -> None:
    print("\nPORT SCANNER")
    target = input("Target IP or hostname (e.g. 192.168.1.1 or localhost): ").strip()
    if not target:
        error("Target cannot be empty.")
        return
    cmd_scan(argparse.Namespace(
        target=target, ports=None, timeout=1.0, workers=50, authorized=False,
    ))


def interactive_menu(log_file: Path) -> int:
    """Classic numbered menu.  Ctrl+C inside a tool returns to the menu."""
    while True:
        print_banner()
        print("  1. Log Writer")
        print("  2. Threat Detector (SIEM-style)")
        print("  3. Real-Time Monitor")
        print("  4. Port Scanner")
        print("  5. Password Strength Checker")
        print("  6. Exit")

        try:
            choice = input("\nEnter your choice (1-6): ").strip()
        except EOFError:  # input stream closed (e.g. piped, Ctrl+D)
            return 0

        if choice == "6":
            print("\nThank you for using the Toronto SOC Toolkit. Good luck out there!")
            return 0

        try:
            if choice == "1":
                _menu_log_writer(log_file)
            elif choice == "2":
                cmd_detect(argparse.Namespace(
                    log_file=log_file, min_severity=None, export=None))
            elif choice == "3":
                cmd_monitor(argparse.Namespace(
                    log_file=log_file, from_start=False, duration=None))
            elif choice == "4":
                _menu_port_scanner()
            elif choice == "5":
                cmd_password(argparse.Namespace())
            else:
                error("Invalid choice. Try again.")
            input("\nPress Enter to return to the menu...")
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")


# =============================================================================
# COMMAND-LINE INTERFACE
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc_toolkit",
        description="Toronto SOC Automation Toolkit - log analysis, detection "
                    "and security utilities. Run without a command for the "
                    "interactive menu.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-f", "--log-file", type=Path, default=DEFAULT_LOG_FILE,
        help="log file to use (default: %(default)s, or $SOC_LOG_FILE)",
    )
    sub = parser.add_subparsers(dest="command", metavar="command")

    p_log = sub.add_parser("log", help="write one structured event to the log")
    p_log.add_argument("-t", "--type", required=True, help="event type, e.g. LOGIN")
    p_log.add_argument("-s", "--severity", required=True,
                       help="LOW, MEDIUM, HIGH or CRITICAL")
    p_log.add_argument("-m", "--message", required=True, help="event description")
    p_log.add_argument("--user", help="override the user tag ($SOC_ANALYST / OS user)")
    p_log.add_argument("--location", help="override the location tag ($SOC_LOCATION)")
    p_log.set_defaults(handler=cmd_log)

    p_detect = sub.add_parser("detect", help="scan the log for threats")
    p_detect.add_argument("--min-severity", help="only report this severity and above")
    p_detect.add_argument("--export", type=Path, help="save findings to a .json or .csv file")
    p_detect.set_defaults(handler=cmd_detect)

    p_monitor = sub.add_parser("monitor", help="follow the log live and alert")
    p_monitor.add_argument("--duration", type=float,
                           help="stop automatically after N seconds")
    p_monitor.add_argument("--from-start", action="store_true",
                           help="replay existing lines before following")
    p_monitor.set_defaults(handler=cmd_monitor)

    p_scan = sub.add_parser("scan", help="TCP connect scan (authorised use only)")
    p_scan.add_argument("target", help="hostname or IPv4 address")
    p_scan.add_argument("-p", "--ports",
                        help="e.g. 22,80,443 or 8000-8010 (default: common ports)")
    p_scan.add_argument("--timeout", type=float, default=1.0,
                        help="seconds to wait per port (default: %(default)s)")
    p_scan.add_argument("--workers", type=int, default=50,
                        help="parallel connections (default: %(default)s)")
    p_scan.add_argument("--authorized", action="store_true",
                        help="confirm you are allowed to scan this target")
    p_scan.set_defaults(handler=cmd_scan)

    p_pwd = sub.add_parser("password", help="check password strength (hidden input)")
    p_pwd.set_defaults(handler=cmd_password)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command is None:
            return interactive_menu(args.log_file)
        return args.handler(args)
    except KeyboardInterrupt:
        print("\n\nExiting toolkit. See you in the SOC!")
        return 130  # conventional exit code for Ctrl+C
    except OSError as exc:
        error(f"I/O error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
