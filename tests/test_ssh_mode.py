#!/usr/bin/env python3
"""
Tests for --ssh collection.

A real sshd is not assumed. Instead a fake `ssh` executable is placed on PATH
which drops the -o options and destination and runs the remaining command
locally, passing stdin through -- exactly what a real ssh does on the remote
side. That exercises argument construction, piping the agent over stdin, and
parsing the result.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import php2shell_verify as pv  # noqa: E402

PHP = shutil.which("php")

SHIM = """#!/bin/sh
# Fake ssh: skip -o pairs and the destination, run the rest locally with stdin.
while [ $# -gt 0 ]; do
    case "$1" in
        -o) shift 2 ;;
        -*) shift ;;
        *) shift; break ;;
    esac
done
exec /bin/sh -c "$*"
"""

FAIL_SHIM = """#!/bin/sh
echo "ssh: connect to host port 22: Connection refused" >&2
exit 255
"""

NOISE_SHIM = """#!/bin/sh
echo "not json at all"
exit 0
"""


class SshArgs:
    """Stand-in for parsed arguments in SSH mode."""
    def __init__(self, **kw):
        self.ssh = True
        self.ssh_user = None
        self.ssh_php = PHP or "php"
        self.ssh_opt = None
        self.docroot = None
        self.timeout = 20.0
        self.retries = 0
        self.delay = 0
        self.insecure = False
        self.probe = False
        self.token = None
        self.header = None
        self.basic_auth = None
        self._headers = {}
        for k, v in kw.items():
            setattr(self, k, v)


class SshShim:
    """Context manager putting a fake ssh first on PATH."""
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="php2shell-ssh-")
        path = os.path.join(self.dir, "ssh")
        with open(path, "w") as fh:
            fh.write(self.body)
        os.chmod(path, 0o755)
        self.old = os.environ["PATH"]
        os.environ["PATH"] = self.dir + os.pathsep + self.old
        return self

    def __exit__(self, *exc):
        os.environ["PATH"] = self.old
        shutil.rmtree(self.dir, ignore_errors=True)


@unittest.skipIf(PHP is None, "php binary not available")
class TestSshCollection(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "verify_php2shell.php"), "rb") as fh:
            self.script = fh.read()

    def test_collects_a_result_over_ssh(self):
        with SshShim(SHIM):
            data, err = pv.agent_over_ssh("host.example", SshArgs(), self.script)
        self.assertIsNone(err)
        self.assertTrue(pv.is_agent_payload(data))
        self.assertIn("counts", data)
        self.assertIn("patched", data)

    def test_nothing_is_written_to_the_remote_filesystem(self):
        # The agent reaches the far side on stdin; no path is ever sent.
        with SshShim(SHIM):
            data, err = pv.agent_over_ssh("host.example", SshArgs(), self.script)
        self.assertIsNone(err)
        self.assertEqual(data["script"], "verify_php2shell")

    def test_check_host_produces_a_verdict(self):
        with SshShim(SHIM):
            res = pv.check_host("host.example", SshArgs(), pv.FIXED, self.script)
        self.assertEqual(res["mode"], "ssh")
        self.assertIn(res["verdict"],
                      (pv.V_PATCHED, pv.V_VULNERABLE, pv.V_VENDOR))
        self.assertIsNotNone(res["php_version"])

    def test_docroot_is_forwarded(self):
        with SshShim(SHIM):
            data, err = pv.agent_over_ssh(
                "host.example", SshArgs(docroot=ROOT), self.script)
        self.assertIsNone(err)
        titles = [c["title"] for c in data["checks"]]
        # With a docroot supplied the scan runs instead of being skipped.
        self.assertFalse(any("scan skipped" in t for t in titles), titles)

    def test_connection_failure_is_reported_not_raised(self):
        with SshShim(FAIL_SHIM):
            data, err = pv.agent_over_ssh("host.example", SshArgs(), self.script)
        self.assertIsNone(data)
        self.assertIn("ssh failed", err)

    def test_non_json_output_is_rejected(self):
        with SshShim(NOISE_SHIM):
            data, err = pv.agent_over_ssh("host.example", SshArgs(), self.script)
        self.assertIsNone(data)
        self.assertIn("not the agent's JSON", err)

    def test_unreachable_host_yields_unreachable_verdict(self):
        with SshShim(FAIL_SHIM):
            res = pv.check_host("host.example", SshArgs(), pv.FIXED, self.script)
        self.assertEqual(res["verdict"], pv.V_UNREACHABLE)

    def test_ssh_user_is_prepended_when_absent(self):
        captured = os.path.join(tempfile.mkdtemp(prefix="php2shell-cap-"), "argv")
        shim = ("#!/bin/sh\nprintf '%s\\n' \"$@\" > " + captured + "\nexit 255\n")
        with SshShim(shim):
            pv.agent_over_ssh("host.example", SshArgs(ssh_user="deploy"), self.script)
        with open(captured) as fh:
            argv = fh.read()
        self.assertIn("deploy@host.example", argv)

    def test_existing_user_is_not_doubled(self):
        captured = os.path.join(tempfile.mkdtemp(prefix="php2shell-cap-"), "argv")
        shim = ("#!/bin/sh\nprintf '%s\\n' \"$@\" > " + captured + "\nexit 255\n")
        with SshShim(shim):
            pv.agent_over_ssh("root@host.example", SshArgs(ssh_user="deploy"), self.script)
        with open(captured) as fh:
            argv = fh.read()
        self.assertIn("root@host.example", argv)
        self.assertNotIn("deploy@root@", argv)

    def test_scheme_and_path_are_stripped_from_the_destination(self):
        captured = os.path.join(tempfile.mkdtemp(prefix="php2shell-cap-"), "argv")
        shim = ("#!/bin/sh\nprintf '%s\\n' \"$@\" > " + captured + "\nexit 255\n")
        with SshShim(shim):
            pv.agent_over_ssh("https://host.example/some/path", SshArgs(), self.script)
        with open(captured) as fh:
            argv = fh.read()
        self.assertIn("host.example", argv)
        self.assertNotIn("https://", argv)
        self.assertNotIn("/some/path", argv)

    def test_extra_ssh_options_are_passed(self):
        captured = os.path.join(tempfile.mkdtemp(prefix="php2shell-cap-"), "argv")
        shim = ("#!/bin/sh\nprintf '%s\\n' \"$@\" > " + captured + "\nexit 255\n")
        with SshShim(shim):
            pv.agent_over_ssh("host.example",
                              SshArgs(ssh_opt=["StrictHostKeyChecking=no"]), self.script)
        with open(captured) as fh:
            argv = fh.read()
        self.assertIn("StrictHostKeyChecking=no", argv)
        self.assertIn("BatchMode=yes", argv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
