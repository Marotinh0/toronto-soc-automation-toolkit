#!/usr/bin/env python3
# =====================================================
# TORONTO SOC AUTOMATION TOOLKIT
# Customized by Marotinho
# Portfolio Project - April 2026
# Forked & heavily improved from: https://github.com/Aceknight4/security-toolkit
#
# Purpose: Demonstrate real-world SOC Analyst skills for Toronto job market
# =====================================================

import os
import sys
import datetime
import re
import socket
import time
from typing import Dict, List

# ====================== CONFIG ======================
LOG_FILE = "soc_logs.txt"

# Replaced with patterns that match actual suspicious IP/geo indicators in the
# *event description* field rather than the static location tag.
THREAT_PATTERNS = {
    "brute_force":    r"(?i)(failed login|invalid password|brute force|auth.?fail)",
    "suspicious_geo": r"(?i)(unknown.?location|foreign.?ip|geo.?block|tor.?exit|proxy.?detected|vpn.?flag)",
    "phishing":       r"(?i)(phish|spoof|malicious.?link|credential.?harvest)",
    "privilege_esc":  r"(?i)(privilege.?escalat|sudo.?fail|unauthorized.?admin|root.?access)",
    "data_exfil":     r"(?i)(large.?transfer|data.?exfil|unusual.?upload|bulk.?download)",
}

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

def print_header():
    print("\n" + "="*60)
    print("🚀 Marotinho - Fork SOC AUTOMATION TOOLKIT")
    print("Built for SOC Analyst / Threat Hunter roles in Toronto")
    print("="*60)
    print(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

# ====================== TOOL 1: LOG WRITER ======================
def log_writer():
    """Simulates writing structured security logs (like Splunk syslog)."""
    print("\n📝 LOG WRITER - Toronto SOC Log Generator")
    event_type = input("Event type (e.g. LOGIN, ALERT, ERROR): ").upper().strip()
    if not event_type:
        print("❌ Event type cannot be empty.")
        return

    severity = input("Severity (LOW/MEDIUM/HIGH/CRITICAL): ").upper().strip()
    # Validate severity instead of accepting any freeform string
    if severity not in VALID_SEVERITIES:
        print(f"❌ Invalid severity '{severity}'. Must be one of: {', '.join(VALID_SEVERITIES)}")
        return

    description = input("Description: ").strip()
    if not description:
        print("❌ Description cannot be empty.")
        return

    log_entry = (
        f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
        f"[{severity}] {event_type} - {description} "
        f"| User: marotinhos | Location: Toronto\n"
    )

    with open(LOG_FILE, "a") as f:
        f.write(log_entry)
    print(f"✅ Log written to {LOG_FILE} (ready for threat detection)")

# ====================== TOOL 2: THREAT DETECTOR ======================
def threat_detector():
    """SIEM-style threat detection using regex (mirrors Splunk/ELK rules)."""
    print("\n🔍 THREAT DETECTOR - SIEM-style Log Analysis")

    # Guard against missing log file (was also missing in realtime_monitor)
    if not os.path.exists(LOG_FILE):
        print("❌ No logs found. Run Log Writer first!")
        return

    with open(LOG_FILE, "r") as f:
        logs = f.readlines()

    if not logs:
        print("⚠️  Log file exists but is empty.")
        return

    print(f"Scanning {len(logs)} log entries for threats...\n")
    threats_found = 0
    # Track which lines triggered alerts to avoid duplicate prints
    alerted_lines: Dict[int, List[str]] = {}

    for idx, line in enumerate(logs):
        line = line.strip()
        if not line:
            continue
        for threat_name, pattern in THREAT_PATTERNS.items():
            if re.search(pattern, line):
                alerted_lines.setdefault(idx, []).append(threat_name)

    for idx, threat_names in alerted_lines.items():
        label = ", ".join(t.upper() for t in threat_names)
        print(f"🚨 [{label}] → {logs[idx].strip()}")
        threats_found += 1

    if threats_found == 0:
        print("✅ No threats detected in current logs.")
    else:
        print(f"\n📊 Total log lines flagged: {threats_found} / {len(logs)} "
              f"(PIPEDA compliance logging applied)")

# ====================== TOOL 3: REAL-TIME MONITOR ======================
def realtime_monitor():
    """Live log tailing (like tail -f + alerting)."""
    print("\n📡 REAL-TIME MONITOR - Live Log Watcher (Ctrl+C to stop)")

    # Create file if it doesn't exist instead of crashing with FileNotFoundError
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()
        print(f"ℹ️  Created {LOG_FILE} — waiting for new entries...\n")
    else:
        print(f"Monitoring {LOG_FILE} for new events...\n")

    try:
        with open(LOG_FILE, "r") as f:
            f.seek(0, 2)  # Go to end of file
            while True:
                line = f.readline()
                if line:
                    line = line.strip()
                    print(f"LIVE: {line}")
                    # Inline threat check for immediate alerting
                    for threat_name, pattern in THREAT_PATTERNS.items():
                        if re.search(pattern, line):
                            print(f"  ⚡ ALERT → {threat_name.upper()} pattern matched!")
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n⛔ Monitoring stopped.")

# ====================== TOOL 4: PORT SCANNER ======================
def port_scanner():
    """Basic port scanner (educational use only)."""
    print("\n🔌 PORT SCANNER - Network Recon (Toronto enterprise demo)")
    target = input("Enter target IP or hostname (e.g. 192.168.1.1 or localhost): ").strip()
    if not target:
        print("❌ Target cannot be empty.")
        return

    ports = [22, 80, 443, 3389, 8080]  # Common Toronto enterprise ports
    print(f"\nScanning {target} on ports {ports}...\n")

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                status = "OPEN" if result == 0 else "CLOSED"
                print(f"Port {port:5} → {status}")
        # Replaced bare 'except' with specific exceptions for better diagnostics
        except socket.gaierror as e:
            print(f"Port {port:5} → DNS ERROR ({e})")
        except socket.timeout:
            print(f"Port {port:5} → TIMEOUT")
        except OSError as e:
            print(f"Port {port:5} → ERROR ({e})")

# ====================== TOOL 5: PASSWORD CHECKER ======================
def password_checker():
    """Enterprise-grade password strength checker."""
    print("\n🔐 PASSWORD STRENGTH CHECKER - Toronto Bank Compliance")
    pwd = input("Enter password to test: ")

    checks = {
        "length_12":  (len(pwd) >= 12,        40, "❌ Minimum 12 characters (RBC/TD policy)"),
        "uppercase":  (bool(re.search(r"[A-Z]", pwd)), 15, "❌ Add uppercase letters"),
        "lowercase":  (bool(re.search(r"[a-z]", pwd)), 15, "❌ Add lowercase letters"),
        "digit":      (bool(re.search(r"\d",   pwd)), 15, "❌ Add numbers"),
        "symbol":     (bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", pwd)),
                       15, "❌ Add special characters (!@#$%^&* etc.)"),
    }
    # Normalised scoring — total possible is exactly 100, not 120.
    # Old code: length=40, upper=20, lower=20, digit=20, symbol=20 → max 120.
    # Thresholds of 80/"STRONG" and 50/"MEDIUM" were miscalibrated against 120 max.

    score = sum(pts for (passed, pts, _) in checks.values() if passed)
    feedback = [msg for (passed, _, msg) in checks.values() if not passed]

    print(f"\nPassword score: {score}/100")
    if score >= 80:
        print("✅ STRONG PASSWORD (Enterprise Ready)")
    elif score >= 50:
        print("⚠️  MEDIUM - Add complexity for Toronto financial compliance")
    else:
        print("❌ WEAK - Does not meet PIPEDA standards")

    if feedback:
        print("\nSuggestions:")
        for tip in feedback:
            print(f"  {tip}")

# ====================== MAIN MENU ======================
def main():
    while True:
        print_header()
        print("1. 📝 Log Writer")
        print("2. 🔍 Threat Detector (SIEM-style)")
        print("3. 📡 Real-Time Monitor")
        print("4. 🔌 Port Scanner")
        print("5. 🔐 Password Strength Checker")
        print("6. Exit")

        choice = input("\nEnter your choice (1-6): ").strip()

        if choice == "1":
            log_writer()
        elif choice == "2":
            threat_detector()
        elif choice == "3":
            realtime_monitor()
        elif choice == "4":
            port_scanner()
        elif choice == "5":
            password_checker()
        elif choice == "6":
            print("\n👋 Thank you for using marotinhos's Toronto SOC Toolkit!")
            print("Good luck with your Toronto cybersecurity job hunt!")
            sys.exit(0)
        else:
            print("❌ Invalid choice. Try again.")

        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Exiting toolkit. See you in the SOC!")
