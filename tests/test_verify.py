#!/usr/bin/env python3
"""Unit tests for php2shell_verify. Standard library only: python3 -m unittest discover tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import php2shell_verify as pv  # noqa: E402


class FakeArgs:
    """Minimal stand-in for argparse results."""
    def __init__(self, **kw):
        self.header = None
        self.basic_auth = None
        for k, v in kw.items():
            setattr(self, k, v)


class TestVersionParsing(unittest.TestCase):
    def test_full_version(self):
        self.assertEqual(pv.parse_version("PHP/8.4.27"), (8, 4, 27))
        self.assertEqual(pv.parse_version("PHP/8.2.35-1ubuntu2"), (8, 2, 35))

    def test_no_version(self):
        self.assertIsNone(pv.parse_version("PHP"))
        self.assertIsNone(pv.parse_version(""))
        self.assertIsNone(pv.parse_version(None))

    def test_truncated_version_yields_branch_only(self):
        self.assertIsNone(pv.parse_version("PHP/8.4"))
        self.assertEqual(pv.parse_branch("PHP/8.4"), (8, 4))

    def test_headers(self):
        self.assertEqual(pv.version_from_headers({"x-powered-by": "PHP/8.3.36"}),
                         ((8, 3, 36), (8, 3)))
        self.assertEqual(pv.version_from_headers({"x-powered-by": "PHP/8.3"}),
                         (None, (8, 3)))
        self.assertEqual(pv.version_from_headers({"x-powered-by": "Express"}), (None, None))
        self.assertEqual(pv.version_from_headers({}), (None, None))


class TestClassify(unittest.TestCase):
    """The verdicts people will act on. Fixed versions are from the php.net advisories."""

    def test_patched_boundary(self):
        for v in [(8, 2, 35), (8, 2, 36), (8, 3, 36), (8, 4, 27), (8, 5, 12), (8, 5, 99)]:
            self.assertEqual(pv.classify(v, pv.FIXED)[0], pv.V_PATCHED, v)

    def test_vulnerable_boundary(self):
        for v in [(8, 2, 34), (8, 3, 35), (8, 4, 26), (8, 5, 11), (8, 2, 0)]:
            self.assertEqual(pv.classify(v, pv.FIXED)[0], pv.V_VULNERABLE, v)

    def test_eol_branches_need_vendor_confirmation(self):
        # A distro may backport without changing the version string, so these
        # must never be reported as a clean PATCHED or a definite VULNERABLE.
        for v in [(8, 1, 29), (8, 0, 30), (7, 4, 33)]:
            self.assertEqual(pv.classify(v, pv.FIXED)[0], pv.V_VENDOR, v)

    def test_ancient_is_vulnerable(self):
        self.assertEqual(pv.classify((5, 4, 0), pv.FIXED)[0], pv.V_VULNERABLE)
        self.assertEqual(pv.classify((7, 3, 33), pv.FIXED)[0], pv.V_VULNERABLE)

    def test_future_branch_is_unknown_not_patched(self):
        verdict, detail = pv.classify((8, 6, 0), pv.FIXED)
        self.assertEqual(verdict, pv.V_UNKNOWN)
        self.assertIn("8.6", detail)

    def test_no_version_is_unknown(self):
        self.assertEqual(pv.classify(None, pv.FIXED)[0], pv.V_UNKNOWN)

    def test_branch_only_reports_required_version(self):
        verdict, detail = pv.classify(None, pv.FIXED, branch=(8, 4))
        self.assertEqual(verdict, pv.V_UNKNOWN)
        self.assertIn("8.4.27", detail)

    def test_branch_only_eol(self):
        self.assertEqual(pv.classify(None, pv.FIXED, branch=(8, 1))[0], pv.V_VENDOR)

    def test_fixed_override(self):
        fixed = pv.parse_fixed_override("8.6=8.6.1")
        self.assertEqual(pv.classify((8, 6, 0), fixed)[0], pv.V_VULNERABLE)
        self.assertEqual(pv.classify((8, 6, 1), fixed)[0], pv.V_PATCHED)
        # existing entries survive
        self.assertEqual(pv.classify((8, 4, 27), fixed)[0], pv.V_PATCHED)

    def test_fixed_override_can_raise_a_branch(self):
        fixed = pv.parse_fixed_override("8.2=8.2.40")
        self.assertEqual(pv.classify((8, 2, 35), fixed)[0], pv.V_VULNERABLE)

    def test_bad_fixed_override_rejected(self):
        for bad in ["8.2", "8.2=", "=8.2.35", "8=8.0.1", "8.2.3=8.2.35"]:
            with self.assertRaises(ValueError, msg=bad):
                pv.parse_fixed_override(bad)


class TestPhpinfoParsing(unittest.TestCase):
    PAGE = """<html><head><title>phpinfo()</title></head><body>
    <h1 class="p">PHP Version 8.4.26</h1><table>
    <tr><td class="e">session.upload_progress.enabled</td><td class="v">On</td><td class="v">On</td></tr>
    <tr><td class="e">memory_limit</td><td class="v">128M</td><td class="v">128M</td></tr>
    <tr><td class="e">unrelated.directive</td><td class="v">zzz</td><td class="v">zzz</td></tr>
    </table></body></html>"""

    def test_extracts_version_and_relevant_keys_only(self):
        version, branch, cfg = pv.parse_phpinfo(self.PAGE)
        self.assertEqual(version, (8, 4, 26))
        self.assertEqual(branch, (8, 4))
        self.assertEqual(cfg["session.upload_progress.enabled"], "On")
        self.assertEqual(cfg["memory_limit"], "128M")
        self.assertNotIn("unrelated.directive", cfg)

    def test_non_phpinfo_page_ignored(self):
        self.assertEqual(pv.parse_phpinfo("<html>home</html>"), (None, None, {}))


class TestHelpers(unittest.TestCase):
    def test_normalise_adds_both_schemes(self):
        self.assertEqual(pv.normalise("example.com"),
                         ["https://example.com", "http://example.com"])

    def test_normalise_respects_explicit_scheme(self):
        self.assertEqual(pv.normalise("http://example.com"), ["http://example.com"])
        self.assertEqual(pv.normalise("https://a.example.com:8443"),
                         ["https://a.example.com:8443"])

    def test_sapi_hint(self):
        self.assertIn("mod_php", pv.sapi_hint({"server": "Apache/2.4.62 (Debian)"}))
        self.assertIn("FPM", pv.sapi_hint({"server": "nginx/1.24.0"}))
        self.assertEqual(pv.sapi_hint({}), "")

    def test_basic_auth_header(self):
        h = pv.build_headers(FakeArgs(basic_auth="user:pass"))
        self.assertEqual(h["Authorization"], "Basic dXNlcjpwYXNz")

    def test_custom_headers(self):
        h = pv.build_headers(FakeArgs(header=["X-Bypass: yes", "X-Two:  spaced "]))
        self.assertEqual(h["X-Bypass"], "yes")
        self.assertEqual(h["X-Two"], "spaced")

    def test_bad_header_rejected(self):
        with self.assertRaises(ValueError):
            pv.build_headers(FakeArgs(header=["no-colon"]))
        with self.assertRaises(ValueError):
            pv.build_headers(FakeArgs(basic_auth="nocolon"))

    def test_vstr(self):
        self.assertEqual(pv.vstr((8, 4, 27)), "8.4.27")
        self.assertEqual(pv.vstr(None), "-")


class TestAgentPayload(unittest.TestCase):
    def payload(self, patched, counts=None):
        return {"script": "verify_php2shell", "php_version": "8.4.6", "branch": "8.4",
                "sapi": "fpm-fcgi", "patched": patched,
                "counts": counts or {"FAIL": 1, "WARN": 2, "UNKNOWN": 0},
                "checks": [{"status": "FAIL", "title": "Patch level"},
                           {"status": "WARN", "title": "memory_limit"},
                           {"status": "PASS", "title": "ignored"}]}

    def test_rejects_foreign_payload(self):
        self.assertFalse(pv.is_agent_payload({"script": "something-else"}))
        self.assertFalse(pv.is_agent_payload("a string"))
        self.assertTrue(pv.is_agent_payload(self.payload(False)))

    def test_unpatched_agent_is_vulnerable(self):
        r = pv.apply_agent(pv.blank_result("h"), self.payload(False), "ssh", "src")
        self.assertEqual(r["verdict"], pv.V_VULNERABLE)
        self.assertEqual(r["php_version"], (8, 4, 6))
        self.assertEqual(r["sapi"], "fpm-fcgi")
        # only FAIL/WARN items are surfaced
        self.assertEqual([s for s, _ in r["agent_items"]], ["FAIL", "WARN"])

    def test_patched_agent_is_patched(self):
        r = pv.apply_agent(pv.blank_result("h"), self.payload(True), "agent", "src")
        self.assertEqual(r["verdict"], pv.V_PATCHED)

    def test_unknown_patch_status_needs_vendor_check(self):
        r = pv.apply_agent(pv.blank_result("h"), self.payload(None), "ssh", "src")
        self.assertEqual(r["verdict"], pv.V_VENDOR)


class TestNagios(unittest.TestCase):
    """Nagios exit codes: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN."""

    def results(self, *verdicts):
        out = []
        for i, v in enumerate(verdicts):
            r = pv.blank_result("h%d" % i)
            r["verdict"] = v
            out.append(r)
        return out

    def setUp(self):
        import io
        self._stdout = sys.stdout
        sys.stdout = io.StringIO()

    def tearDown(self):
        sys.stdout = self._stdout

    def test_critical_when_any_vulnerable(self):
        self.assertEqual(pv.print_nagios(self.results(pv.V_PATCHED, pv.V_VULNERABLE)), 2)

    def test_warning_on_vendor_check(self):
        self.assertEqual(pv.print_nagios(self.results(pv.V_PATCHED, pv.V_VENDOR)), 1)

    def test_warning_when_some_unverifiable(self):
        self.assertEqual(pv.print_nagios(self.results(pv.V_PATCHED, pv.V_UNKNOWN)), 1)

    def test_unknown_when_nothing_determined(self):
        self.assertEqual(pv.print_nagios(self.results(pv.V_UNKNOWN, pv.V_UNREACHABLE)), 3)

    def test_ok_only_when_all_patched(self):
        self.assertEqual(pv.print_nagios(self.results(pv.V_PATCHED, pv.V_PATCHED)), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
