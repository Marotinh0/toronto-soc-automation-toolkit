"""Unit tests for soc_toolkit.py.

Run from the repository root with either:

    python3 -m unittest discover -s tests -v
    pytest -v                      # optional, if pytest is installed

Only the standard library is required.
"""

import json
import socket
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

# Make ``import soc_toolkit`` work no matter where the tests are launched from.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import soc_toolkit as soc  # noqa: E402


class SeverityTests(unittest.TestCase):
    def test_parse_is_case_and_space_insensitive(self):
        self.assertEqual(soc.Severity.parse("  high "), soc.Severity.HIGH)

    def test_invalid_severity_lists_choices_in_order(self):
        with self.assertRaises(ValueError) as ctx:
            soc.Severity.parse("urgent")
        self.assertIn("LOW, MEDIUM, HIGH, CRITICAL", str(ctx.exception))

    def test_ordering(self):
        self.assertTrue(soc.Severity.CRITICAL > soc.Severity.LOW)


class LogWriterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "logs" / "soc.txt"

    def test_write_and_parse_roundtrip(self):
        when = datetime(2026, 10, 13, 18, 49, 3)
        line = soc.write_log(
            self.log, "login", soc.Severity.HIGH, "Failed login for admin",
            user="alice", location="Toronto", now=when,
        )
        self.assertEqual(
            line,
            "[2026-10-13 18:49:03] [HIGH] LOGIN - Failed login for admin "
            "| User: alice | Location: Toronto",
        )
        self.assertEqual(self.log.read_text().count("\n"), 1)

        entry = soc.parse_log_line(line)
        self.assertEqual(entry.severity, "HIGH")
        self.assertEqual(entry.event_type, "LOGIN")
        self.assertEqual(entry.description, "Failed login for admin")
        self.assertEqual(entry.user, "alice")
        self.assertEqual(entry.location, "Toronto")

    def test_event_type_spaces_become_underscores(self):
        line = soc.write_log(self.log, "failed login", soc.Severity.LOW, "x")
        self.assertIn("] FAILED_LOGIN - x", line)

    def test_log_injection_is_neutralised(self):
        evil = "ok\n[2026-01-01 00:00:00] [CRITICAL] FAKE - forged | User: root"
        soc.write_log(self.log, "info", soc.Severity.LOW, evil, user="alice")
        # Still exactly one physical line, and our field separators are intact:
        # the forged "| User: root" must not replace the real user.
        content = self.log.read_text()
        self.assertEqual(content.count("\n"), 1)
        entry = soc.parse_log_line(content)
        self.assertEqual(entry.severity, "LOW")
        self.assertEqual(entry.user, "alice")

    def test_empty_values_rejected(self):
        with self.assertRaises(ValueError):
            soc.write_log(self.log, "   ", soc.Severity.LOW, "desc")
        with self.assertRaises(ValueError):
            soc.write_log(self.log, "LOGIN", soc.Severity.LOW, "\n\t")

    def test_long_text_is_truncated(self):
        line = soc.write_log(self.log, "x", soc.Severity.LOW, "a" * 5000)
        self.assertLess(len(line), 700)

    def test_legacy_line_without_user_parses(self):
        entry = soc.parse_log_line("[2026-01-01 10:00:00] [LOW] LOGIN - all good")
        self.assertEqual(entry.description, "all good")
        self.assertEqual(entry.user, "")

    def test_garbage_line_returns_none(self):
        self.assertIsNone(soc.parse_log_line("not a log line"))


class ThreatDetectionTests(unittest.TestCase):
    def detect(self, *lines, **kwargs):
        return soc.detect_threats(lines, **kwargs)

    def test_each_rule_fires(self):
        samples = {
            "brute_force": "[2026-01-01 10:00:00] [LOW] LOGIN - Failed login for bob",
            "suspicious_geo": "[2026-01-01 10:00:00] [LOW] NET - connection from tor exit node",
            "phishing": "[2026-01-01 10:00:00] [LOW] MAIL - phishing email reported",
            "privilege_esc": "[2026-01-01 10:00:00] [LOW] SYS - sudo failure on host",
            "data_exfil": "[2026-01-01 10:00:00] [LOW] NET - large transfer to unknown host",
            "recon_scan": "[2026-01-01 10:00:00] [LOW] IDS - port scan from 10.0.0.9",
        }
        for rule, line in samples.items():
            with self.subTest(rule=rule):
                result = self.detect(line)
                self.assertEqual(len(result.findings), 1)
                self.assertIn(rule, result.findings[0].rules)

    def test_separator_variants_match(self):
        for text in ("failed_login", "failed-login", "FAILED LOGIN"):
            with self.subTest(text=text):
                self.assertEqual(len(self.detect(f"EVENT - {text}").findings), 1)

    def test_clean_lines_are_not_flagged(self):
        result = self.detect("[2026-01-01 10:00:00] [LOW] BACKUP - nightly job finished")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.total_lines, 1)

    def test_user_and_location_fields_do_not_cause_false_positives(self):
        line = ("[2026-01-01 10:00:00] [LOW] LOGIN - successful login "
                "| User: proxy-detected-svc | Location: Toronto")
        self.assertEqual(self.detect(line).findings, [])

    def test_word_boundaries_prevent_substring_matches(self):
        # "factor exit" must not be read as "tor exit".
        self.assertEqual(self.detect("EVENT - factor exit completed").findings, [])

    def test_multiple_rules_one_finding_with_worst_severity(self):
        result = self.detect("EVENT - failed login then privilege escalation")
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(set(finding.rules), {"brute_force", "privilege_esc"})
        self.assertEqual(finding.severity, "CRITICAL")

    def test_log_severity_can_raise_finding_severity(self):
        line = "[2026-01-01 10:00:00] [CRITICAL] NET - port scan detected"
        self.assertEqual(self.detect(line).findings[0].severity, "CRITICAL")

    def test_min_severity_filter(self):
        lines = ("EVENT - port scan seen",            # MEDIUM
                 "EVENT - privilege escalation seen")  # CRITICAL
        result = soc.detect_threats(lines, min_severity=soc.Severity.HIGH)
        self.assertEqual([f.severity for f in result.findings], ["CRITICAL"])

    def test_unparseable_lines_are_still_scanned(self):
        self.assertEqual(len(self.detect("garbage >>> brute force <<<").findings), 1)

    def test_blank_lines_ignored_and_line_numbers_kept(self):
        result = self.detect("fine", "", "EVENT - phishing attempt")
        self.assertEqual(result.total_lines, 2)
        self.assertEqual(result.findings[0].line_number, 3)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.findings = soc.detect_threats(["EVENT - brute force detected"]).findings

    def test_json_export(self):
        path = Path(self.tmp.name) / "out.json"
        soc.export_findings(self.findings, path)
        data = json.loads(path.read_text())
        self.assertEqual(data[0]["rules"], ["brute_force"])

    def test_csv_export(self):
        path = Path(self.tmp.name) / "out.csv"
        soc.export_findings(self.findings, path)
        rows = path.read_text().splitlines()
        self.assertEqual(rows[0], "line_number,severity,rules,mitre,line")
        self.assertEqual(len(rows), 2)

    def test_unknown_extension_rejected(self):
        with self.assertRaises(ValueError):
            soc.export_findings(self.findings, Path(self.tmp.name) / "out.txt")


class FollowTests(unittest.TestCase):
    """The monitor is tested with a fake clock/sleep so no real waiting occurs."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "live.log"

    def run_follow(self, on_first_sleep, **kwargs):
        state = {"t": 0.0, "sleeps": 0}

        def sleep(_):
            state["sleeps"] += 1
            state["t"] += 1.0
            if state["sleeps"] == 1:
                on_first_sleep()

        return list(soc.follow(
            self.path, duration=4, sleep=sleep, clock=lambda: state["t"], **kwargs
        ))

    def test_only_new_lines_are_returned_by_default(self):
        self.path.write_text("old\n")

        def append():
            with self.path.open("a") as fh:
                fh.write("new\n")

        self.assertEqual(self.run_follow(append), ["new"])

    def test_from_start_replays_existing_lines(self):
        self.path.write_text("old\n")
        self.assertEqual(self.run_follow(lambda: None, from_start=True), ["old"])

    def test_partial_line_is_buffered_until_newline(self):
        self.path.write_text("")

        def write_in_two_parts():
            with self.path.open("a") as fh:
                fh.write("half")
                fh.flush()
            with self.path.open("a") as fh:
                fh.write(" and half\n")

        self.assertEqual(self.run_follow(write_in_two_parts), ["half and half"])

    def test_truncation_restarts_from_beginning(self):
        self.path.write_text("aaaa\nbbbb\n")

        def truncate_and_write():
            self.path.write_text("c\n")

        self.assertEqual(self.run_follow(truncate_and_write), ["c"])

    def test_missing_file_is_created(self):
        self.assertFalse(self.path.exists())
        self.run_follow(lambda: None)
        self.assertTrue(self.path.exists())


class PortScannerTests(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(soc.parse_ports("80, 22,8000-8002,22"), [22, 80, 8000, 8001, 8002])

    def test_parse_ports_errors(self):
        for bad in ("", "abc", "0", "70000", "10-5", "1-5000"):
            with self.subTest(spec=bad):
                with self.assertRaises(ValueError):
                    soc.parse_ports(bad)

    def test_detects_open_and_closed_ports_on_localhost(self):
        # Open a listening socket on an OS-assigned free port...
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            open_port = server.getsockname()[1]

            # ...and find another port that is guaranteed to be closed.
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                closed_port = probe.getsockname()[1]
            # probe is closed now, nothing listens there.

            address, results = soc.scan_ports(
                "127.0.0.1", sorted([open_port, closed_port]), timeout=1.0
            )

        states = {r.port: r.state for r in results}
        self.assertEqual(address, "127.0.0.1")
        self.assertEqual(states[open_port], "open")
        self.assertEqual(states[closed_port], "closed")

    def test_unresolvable_host_raises(self):
        with self.assertRaises(socket.gaierror):
            soc.scan_ports("this-host-does-not-exist.invalid", [80], timeout=0.5)


class PasswordTests(unittest.TestCase):
    def test_strong_password(self):
        report = soc.evaluate_password("vT9#mQ2$zL8!pRx4")
        self.assertEqual(report.rating, "STRONG")
        self.assertEqual(report.score, 100)
        self.assertEqual(report.feedback, [])

    def test_common_password_is_weak(self):
        report = soc.evaluate_password("password")
        self.assertEqual(report.rating, "WEAK")
        self.assertLessEqual(report.score, 10)

    def test_complexity_without_length_is_not_strong(self):
        report = soc.evaluate_password("Xk9#mQ2$")  # all classes, only 8 chars
        self.assertNotEqual(report.rating, "STRONG")

    def test_weak_fragment_is_penalised(self):
        plain = soc.evaluate_password("Tq7!mZ4#wLp2")
        fragment = soc.evaluate_password("Passw0rd!Xy9#")
        self.assertLess(fragment.score, plain.score)

    def test_repeats_and_sequences_are_flagged(self):
        report = soc.evaluate_password("Aaaa1234!!zzQQ")
        text = " ".join(report.feedback)
        self.assertIn("repeating", text)
        self.assertIn("sequences", text)

    def test_empty_password(self):
        report = soc.evaluate_password("")
        self.assertEqual(report.score, 0)
        self.assertEqual(report.entropy_bits, 0.0)

    def test_score_never_exceeds_bounds(self):
        for pwd in ("", "a", "A" * 200, "!@#$%^&*()" * 5, "Zz9$" * 10):
            with self.subTest(pwd=pwd[:10]):
                self.assertTrue(0 <= soc.evaluate_password(pwd).score <= 100)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "cli.log"

    def run_cli(self, *argv):
        return soc.main(["--log-file", str(self.log), *argv])

    def test_detect_without_log_returns_1(self):
        self.assertEqual(self.run_cli("detect"), 1)

    def test_log_then_detect_exit_codes(self):
        self.assertEqual(self.run_cli("log", "-t", "BACKUP", "-s", "low", "-m", "job finished"), 0)
        self.assertEqual(self.run_cli("detect"), 0)  # clean log
        self.assertEqual(self.run_cli("log", "-t", "LOGIN", "-s", "high", "-m", "Failed login"), 0)
        self.assertEqual(self.run_cli("detect"), 2)  # threat present

    def test_invalid_severity_returns_1(self):
        self.assertEqual(self.run_cli("log", "-t", "X", "-s", "urgent", "-m", "m"), 1)

    def test_export_via_cli(self):
        self.run_cli("log", "-t", "LOGIN", "-s", "high", "-m", "brute force")
        out = Path(self.tmp.name) / "report.json"
        self.assertEqual(self.run_cli("detect", "--export", str(out)), 2)
        self.assertTrue(out.exists())

    def test_monitor_with_duration_terminates(self):
        self.assertEqual(self.run_cli("monitor", "--duration", "0.2"), 0)


if __name__ == "__main__":
    unittest.main()
