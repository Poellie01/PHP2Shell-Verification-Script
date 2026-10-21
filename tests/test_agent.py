#!/usr/bin/env python3
"""
Integration tests for verify_php2shell.php.

Runs the agent under the local php binary with INI overrides and asserts the
status it reports for each advisory item. Skipped entirely if php is missing.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, "verify_php2shell.php")
PHP = shutil.which("php")


def run_agent(*ini):
    """Run the agent with -d overrides, return parsed JSON."""
    cmd = [PHP]
    for setting in ini:
        cmd += ["-d", setting]
    cmd += [AGENT, "--json"]
    proc = subprocess.run(cmd, capture_output=True, timeout=60)
    if proc.returncode not in (0, 1):
        raise AssertionError("agent exited %d: %s"
                             % (proc.returncode, proc.stderr.decode("utf-8", "replace")))
    return json.loads(proc.stdout.decode("utf-8", "replace"))


def status_of(payload, title):
    """Status of the check with this exact title, else the first partial match."""
    for check in payload["checks"]:
        if check["title"].lower() == title.lower():
            return check["status"]
    for check in payload["checks"]:
        if title.lower() in check["title"].lower():
            return check["status"]
    raise AssertionError("no check titled like %r; have: %s"
                         % (title_fragment, [c["title"] for c in payload["checks"]]))


@unittest.skipIf(PHP is None, "php binary not available")
class TestAgentOutput(unittest.TestCase):
    def test_json_is_valid_and_self_identifying(self):
        d = run_agent()
        self.assertEqual(d["script"], "verify_php2shell")
        for key in ("version", "php_version", "sapi", "branch", "patched",
                    "fixed_versions", "counts", "checks"):
            self.assertIn(key, d)
        self.assertGreater(len(d["checks"]), 10)

    def test_banner_art_never_enters_json(self):
        # The watermark must not break machine parsing.
        proc = subprocess.run([PHP, AGENT, "--json"], capture_output=True, timeout=60)
        raw = proc.stdout.decode("utf-8", "replace")
        self.assertNotIn("_ \\", raw)
        self.assertTrue(raw.lstrip().startswith("{"))

    def test_fixed_versions_match_the_advisories(self):
        d = run_agent()
        self.assertEqual(d["fixed_versions"],
                         {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"})

    def test_counts_match_checks(self):
        d = run_agent()
        tally = {}
        for c in d["checks"]:
            tally[c["status"]] = tally.get(c["status"], 0) + 1
        for status, n in tally.items():
            self.assertEqual(d["counts"][status], n, status)

    def test_every_check_is_attributed_to_a_cve(self):
        d = run_agent()
        for c in d["checks"]:
            self.assertIn(c["cve"], ("109618", "109619", "both", "-"), c["title"])


@unittest.skipIf(PHP is None, "php binary not available")
class TestAdvisoryItems(unittest.TestCase):
    def test_upload_progress_on_is_reported(self):
        d = run_agent("session.upload_progress.enabled=1")
        # FAIL on an unpatched build, WARN once patched -- never PASS.
        self.assertIn(status_of(d, "session.upload_progress"), ("FAIL", "WARN"))

    def test_upload_progress_off_passes(self):
        d = run_agent("session.upload_progress.enabled=0")
        self.assertEqual(status_of(d, "session.upload_progress"), "PASS")

    def test_memory_limit_unlimited_passes(self):
        d = run_agent("memory_limit=-1")
        self.assertEqual(status_of(d, "memory_limit"), "PASS")

    def test_finite_memory_limit_is_flagged(self):
        d = run_agent("memory_limit=128M")
        self.assertIn(status_of(d, "memory_limit"), ("WARN", "INFO"))

    def test_unlimited_post_max_size_fails(self):
        d = run_agent("post_max_size=0")
        self.assertIn(status_of(d, "post_max_size"), ("FAIL", "INFO"))

    def test_small_post_max_size_passes(self):
        d = run_agent("post_max_size=8M", "file_uploads=0")
        self.assertEqual(status_of(d, "post_max_size"), "PASS")

    def test_default_input_bounds_do_not_warn(self):
        # Regression: this item used to WARN unconditionally on every
        # unpatched host, which trained people to ignore the WARN level.
        d = run_agent("max_input_vars=1000", "max_file_uploads=20")
        self.assertEqual(status_of(d, "Input and multipart bounds"), "INFO")

    def test_permissive_input_bounds_warn(self):
        d = run_agent("max_input_vars=5000", "max_file_uploads=200")
        self.assertIn(status_of(d, "Input and multipart bounds"), ("WARN", "INFO"))

    def test_nesting_level_above_default_warns(self):
        d = run_agent("max_input_nesting_level=64")
        self.assertIn(status_of(d, "max_input_nesting_level"), ("WARN", "INFO"))

    def test_low_nesting_level_passes(self):
        d = run_agent("max_input_nesting_level=8")
        self.assertEqual(status_of(d, "max_input_nesting_level"), "PASS")

    def test_open_basedir_conflict_is_reported_as_a_diagnostic_emitter(self):
        # A configured path outside open_basedir is rejected during INI
        # application, which is one of the advisory's named consumers.
        d = run_agent("open_basedir=/var/www", "error_log=/tmp/x.log")
        self.assertIn(status_of(d, "pre-init diagnostics"), ("WARN", "INFO"))

    def test_clean_config_has_no_diagnostic_emitters(self):
        d = run_agent("open_basedir=", "auto_detect_line_endings=0")
        self.assertEqual(status_of(d, "pre-init diagnostics"), "PASS")

    def test_patch_level_check_always_present(self):
        d = run_agent()
        self.assertIn(status_of(d, "Patch level"), ("PASS", "FAIL", "UNKNOWN"))


@unittest.skipIf(PHP is None, "php binary not available")
class TestWebGate(unittest.TestCase):
    """The agent must not answer over HTTP until a token is configured."""

    @classmethod
    def setUpClass(cls):
        cls.port = cls._free_port()
        cls.proc = subprocess.Popen(
            [PHP, "-S", "127.0.0.1:%d" % cls.port, "-t", ROOT],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.2)
        cls.tearDownClass()
        raise unittest.SkipTest("built-in server did not start")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None):
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()

    @staticmethod
    def _free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def get(self, path):
        import urllib.error
        import urllib.request
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def test_refuses_without_configured_token(self):
        status, body = self.get("/verify_php2shell.php")
        self.assertEqual(status, 403)
        self.assertIn("Web access disabled", body)

    def test_refuses_an_arbitrary_token_when_unconfigured(self):
        status, _ = self.get("/verify_php2shell.php?token=guess")
        self.assertIn(status, (403, 404))

    def test_does_not_leak_configuration_in_the_refusal(self):
        _, body = self.get("/verify_php2shell.php?token=guess")
        for leak in ("memory_limit", "upload_progress", "php_version", "document_root"):
            self.assertNotIn(leak, body.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
