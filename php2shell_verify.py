#!/usr/bin/env python3
"""
php2shell_verify — check hosts against the PHP advisories of 2026-10-21.

  CVE-2026-109618  RCE via OOM corruption      GHSA-w8hw-w9fx-j79w
  CVE-2026-109619  RCE via stale global state  GHSA-6wmf-4rv5-p3rp

Fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12.

Three modes, in increasing order of confidence:

  REMOTE (default) -- read-only HTTP. Determines the PHP patch level when the
  host exposes it (X-Powered-By, or a leftover phpinfo with --probe). Sends no
  payloads and attempts no exploitation. Honest limitation: nothing else in
  these advisories is remotely observable, so hosts that hide their version
  come back UNKNOWN.

  AGENT (--token) -- fetches verify_php2shell.php over HTTP from each host and
  reports its full advisory check results.

  SSH (--ssh) -- pipes verify_php2shell.php to each host over SSH and runs it
  there. Nothing is written to the remote filesystem, so there is no file in a
  document root to remember to delete. Preferred when you have shell access.

Usage:
  php2shell_verify.py -u example.com
  php2shell_verify.py -u a.example.com -u b.example.com --probe
  php2shell_verify.py -f hosts.txt --csv report.csv
  php2shell_verify.py -f hosts.txt --token YOUR_TOKEN
  php2shell_verify.py -f hosts.txt --ssh
  php2shell_verify.py -u example.com --nagios

Exit codes: 0 = nothing vulnerable, 1 = at least one VULNERABLE, 2 = usage
error. With --nagios: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.

Author: Poellie -- https://github.com/Poellie01
License: MIT
"""
import argparse
import base64
import concurrent.futures
import csv
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.1.0"

BANNER = r"""
 ___          _ _ _
| _ \___  ___| | (_)___     php2shell_verify %s
|  _/ _ \/ -_) | | / -_)    CVE-2026-109618 / CVE-2026-109619
|_| \___/\___|_|_|_\___|    by Poellie - github.com/Poellie01
""".strip("\n")

# Confirmed by the php.net advisories of 2026-10-21.
FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
# Branches the PHP project no longer updates, but for which minimal source
# backports were published and distributions/LTS vendors ship their own. A
# version string on these branches cannot tell you whether a fix is applied.
BACKPORT_EOL = {(7, 4), (8, 0), (8, 1)}

PROBE_PATHS = ["/phpinfo.php", "/info.php", "/php.php", "/test.php",
               "/pinfo.php", "/phpinfo", "/_phpinfo.php"]

PHPINFO_KEYS = [
    "session.upload_progress.enabled",
    "fatal_error_backtraces",
    "memory_limit",
    "post_max_size",
    "upload_max_filesize",
    "max_input_nesting_level",
]

UA = ("php2shell_verify/%s (read-only advisory configuration check; "
      "no payloads sent)" % __version__)
MAX_BODY = 1024 * 1024
DEFAULT_AGENT = "verify_php2shell.php"

V_VULNERABLE = "VULNERABLE"
V_PATCHED = "PATCHED"
V_VENDOR = "VENDOR-CHECK"
V_UNKNOWN = "UNKNOWN"
V_UNREACHABLE = "UNREACHABLE"

SORT_ORDER = {V_VULNERABLE: 0, V_VENDOR: 1, V_UNKNOWN: 2, V_UNREACHABLE: 3, V_PATCHED: 4}

_ver_re = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_branch_re = re.compile(r"(\d+)\.(\d+)")
_row_re = re.compile(
    r'<tr>\s*<td class="e">\s*([^<]+?)\s*</td>\s*<td class="v">\s*(.*?)\s*</td>', re.S)
_h1_re = re.compile(r"PHP Version\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s<]*)")
_tag_re = re.compile(r"<[^>]+>")

COLOURS = {V_VULNERABLE: "\033[31m", V_PATCHED: "\033[32m", V_VENDOR: "\033[33m",
           V_UNKNOWN: "\033[35m", V_UNREACHABLE: "\033[90m",
           "FAIL": "\033[31m", "WARN": "\033[33m", "PASS": "\033[32m",
           "INFO": "\033[36m"}


def colourise(text, key, enabled):
    if not enabled or key not in COLOURS:
        return text
    return COLOURS[key] + text + "\033[0m"


def blank_result(target):
    return {
        "target": target, "url": None, "verdict": V_UNREACHABLE, "detail": "",
        "php_version": None, "branch": None, "source": None, "server": None,
        "sapi": None, "sapi_hint": "", "mode": "remote", "config": {},
        "phpinfo_url": None, "agent_counts": None, "agent_items": [], "notes": [],
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def ssl_context(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def build_headers(args):
    headers = {"User-Agent": UA}
    for raw in args.header or []:
        if ":" not in raw:
            raise ValueError("bad --header %r (want 'Name: value')" % raw)
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()
    if args.basic_auth:
        if ":" not in args.basic_auth:
            raise ValueError("bad --basic-auth (want 'user:password')")
        token = base64.b64encode(args.basic_auth.encode()).decode()
        headers["Authorization"] = "Basic " + token
    return headers


def fetch(url, args):
    """GET url -> (status, lowercased headers, body). Retries transport errors."""
    attempts = max(1, args.retries + 1)
    last = None
    for attempt in range(attempts):
        if args.delay and attempt > 0:
            time.sleep(args.delay)
        req = urllib.request.Request(url, headers=args._headers, method="GET")
        try:
            with urllib.request.urlopen(
                    req, timeout=args.timeout, context=ssl_context(not args.insecure)) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, \
                    r.read(MAX_BODY).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            # A status code is a real answer, not a transport failure.
            return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, \
                e.read(MAX_BODY).decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 - transport errors are retried
            last = e
            if attempt + 1 < attempts:
                time.sleep(min(2.0 * (attempt + 1), 5.0))
    raise last


def normalise(target):
    """Candidate URLs for a target, preserving an explicit scheme."""
    target = target.strip()
    if "://" in target:
        return [target]
    return ["https://" + target, "http://" + target]


# ---------------------------------------------------------------------------
# Version handling
# ---------------------------------------------------------------------------
def parse_version(text):
    m = _ver_re.search(text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def parse_branch(text):
    """Branch from a possibly truncated version such as 'PHP/8.4'."""
    m = _branch_re.search(text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def version_from_headers(hdrs):
    """-> (full version or None, branch or None)"""
    pb = hdrs.get("x-powered-by", "")
    if "php" not in pb.lower():
        return None, None
    return parse_version(pb), parse_branch(pb)


def parse_phpinfo(body):
    if "phpinfo()" not in body and "PHP Version" not in body:
        return None, None, {}
    version = branch = None
    m = _h1_re.search(body)
    if m:
        version, branch = parse_version(m.group(1)), parse_branch(m.group(1))
    directives = {}
    for name, value in _row_re.findall(body):
        if name in PHPINFO_KEYS:
            directives[name] = _tag_re.sub("", value).strip() or "(empty)"
    return version, branch, directives


def classify(version, fixed, branch=None):
    """-> (verdict, detail). `branch` is used when only a partial version leaked."""
    if version is None:
        if branch and branch in fixed:
            t = fixed[branch]
            return V_UNKNOWN, ("branch %d.%d exposed but not the patch level; needs >= "
                               "%d.%d.%d" % (branch + t))
        if branch and branch in BACKPORT_EOL:
            return V_VENDOR, "branch %d.%d is EOL upstream; backports exist" % branch
        if branch:
            return V_UNKNOWN, "branch %d.%d exposed but not the patch level" % branch
        return V_UNKNOWN, "PHP version not exposed"
    b = version[:2]
    if b in fixed:
        t = fixed[b]
        if version >= t:
            return V_PATCHED, "%d.%d.%d >= %d.%d.%d" % (version + t)
        return V_VULNERABLE, "%d.%d.%d < %d.%d.%d" % (version + t)
    if b in BACKPORT_EOL:
        return V_VENDOR, "branch %d.%d is EOL upstream; backports exist" % b
    if b < (7, 4):
        return V_VULNERABLE, "branch %d.%d long out of support" % b
    return V_UNKNOWN, "branch %d.%d not in fixed-version table" % b


def sapi_hint(hdrs):
    """Best-effort SAPI guess from the Server header. A hint, never proof."""
    server = (hdrs.get("server") or "").lower()
    if "apache" in server:
        return ("Apache -- if this is mod_php it is the highest-risk configuration: "
                "109618 RCE is confirmed there, before any application code runs")
    if "nginx" in server:
        return "nginx -- likely PHP-FPM, where 109619 RCE is confirmed via session upload progress"
    if "litespeed" in server:
        return "LiteSpeed/LSAPI -- advisories call this a conditional, unvalidated candidate"
    if "caddy" in server or "frankenphp" in server:
        return "Caddy/FrankenPHP -- likely susceptible to 109618, unvalidated"
    return ""


# ---------------------------------------------------------------------------
# Agent result handling (shared by HTTP agent mode and SSH mode)
# ---------------------------------------------------------------------------
def is_agent_payload(data):
    return isinstance(data, dict) and data.get("script") == "verify_php2shell"


def apply_agent(res, data, mode, source):
    res["mode"] = mode
    res["source"] = source
    res["php_version"] = parse_version(data.get("php_version", ""))
    res["branch"] = parse_branch(data.get("branch") or data.get("php_version", ""))
    res["sapi"] = data.get("sapi")
    res["agent_counts"] = data.get("counts") or {}
    patched = data.get("patched")
    res["verdict"] = V_PATCHED if patched is True else \
        V_VULNERABLE if patched is False else V_VENDOR
    res["agent_items"] = [(c["status"], c.get("title", ""))
                          for c in data.get("checks", [])
                          if c.get("status") in ("FAIL", "WARN")]
    c = res["agent_counts"]
    res["detail"] = "agent: %d FAIL, %d WARN, %d UNKNOWN" % (
        c.get("FAIL", 0), c.get("WARN", 0), c.get("UNKNOWN", 0))
    return res


def agent_over_http(base, args):
    url = base + args.agent_path + "?" + urllib.parse.urlencode(
        {"token": args.token, "json": "1"})
    try:
        status, _, body = fetch(url, args)
    except Exception:
        return None
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return None
    return data if is_agent_payload(data) else None


def agent_over_ssh(target, args, script):
    """Pipe the agent to the host and run it. Nothing is written remotely."""
    dest = target
    for prefix in ("ssh://", "https://", "http://"):
        if dest.startswith(prefix):
            dest = dest[len(prefix):]
    dest = dest.split("/", 1)[0]
    if args.ssh_user and "@" not in dest:
        dest = args.ssh_user + "@" + dest

    cmd = ["ssh", "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=%d" % max(1, int(args.timeout))]
    for opt in args.ssh_opt or []:
        cmd += ["-o", opt]
    remote = "%s -- --json" % args.ssh_php
    if args.docroot:
        remote += " --docroot=%s" % args.docroot
    cmd += [dest, remote]

    try:
        proc = subprocess.run(cmd, input=script, capture_output=True,
                              timeout=max(15.0, args.timeout * 3))
    except subprocess.TimeoutExpired:
        return None, "ssh timed out"
    except FileNotFoundError:
        return None, "ssh client not found"
    if proc.returncode not in (0, 1):
        err = (proc.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        return None, "ssh failed: " + (err[-1] if err else "exit %d" % proc.returncode)
    try:
        data = json.loads((proc.stdout or b"").decode("utf-8", "replace"))
    except ValueError:
        return None, "remote output was not the agent's JSON (is php installed?)"
    if not is_agent_payload(data):
        return None, "unexpected remote payload"
    return data, None


# ---------------------------------------------------------------------------
# Per-host check
# ---------------------------------------------------------------------------
def check_host(target, args, fixed, script=None):
    res = blank_result(target)

    # SSH mode bypasses HTTP entirely.
    if args.ssh:
        data, err = agent_over_ssh(target, args, script)
        if data:
            return apply_agent(res, data, "ssh", "verify_php2shell.php over ssh")
        res["detail"] = err or "ssh collection failed"
        return res

    base, hdrs, errors = None, {}, []
    for url in normalise(target):
        try:
            _, hdrs, _ = fetch(url, args)
        except Exception as e:
            errors.append("%s: %s" % (url, type(e).__name__))
            continue
        base, res["url"] = url.rstrip("/"), url
        res["server"] = hdrs.get("server")
        break

    if base is None:
        res["detail"] = "; ".join(errors) or "no response"
        return res

    res["sapi_hint"] = sapi_hint(hdrs)

    if args.token:
        data = agent_over_http(base, args)
        if data:
            return apply_agent(res, data, "agent", "verify_php2shell.php over http")
        res["notes"].append("agent not reachable at %s -- fell back to remote fingerprint "
                            "(not deployed, wrong token, or blocked)" % args.agent_path)

    version, branch = version_from_headers(hdrs)
    if version or branch:
        res["php_version"], res["branch"] = version, branch
        res["source"] = "X-Powered-By"

    if args.probe:
        for path in PROBE_PATHS:
            try:
                status, phdrs, body = fetch(base + path, args)
            except Exception:
                continue
            if res["php_version"] is None:
                v, b = version_from_headers(phdrs)
                if v or b:
                    res["php_version"], res["branch"] = v, b or res["branch"]
                    res["source"] = "X-Powered-By on " + path
            if status != 200:
                continue
            pv, pb, directives = parse_phpinfo(body)
            if pv or pb or directives:
                res["phpinfo_url"] = base + path
                res["notes"].append("publicly reachable phpinfo at %s -- a finding in its own "
                                    "right, remove it" % path)
                if pv:
                    res["php_version"], res["source"] = pv, "phpinfo at " + path
                if pb:
                    res["branch"] = pb
                res["config"] = directives
                break
            if args.delay:
                time.sleep(args.delay)

    res["verdict"], res["detail"] = classify(res["php_version"], fixed, res["branch"])

    cfg = res["config"]
    up = cfg.get("session.upload_progress.enabled", "")
    if up:
        if up.lower() in ("on", "1"):
            res["notes"].append("session.upload_progress.enabled=On -- the 109619 consumer used "
                                "in the RCE confirmed against both mod_php and FPM")
        else:
            res["notes"].append("session.upload_progress.enabled=%s -- demonstrated 109619 "
                                "session path closed" % up)
    ml = cfg.get("memory_limit", "")
    if ml and ml.strip() != "-1":
        res["notes"].append("memory_limit=%s -- not -1, so the predictable per-request limit the "
                            "109618 exploit relies on is present" % ml)
    feb = cfg.get("fatal_error_backtraces", "")
    if feb and feb.lower() in ("on", "1") and res["branch"] == (8, 5):
        res["notes"].append("fatal_error_backtraces=On on 8.5 -- the advisory's strongest "
                            "confirmed 109619 producer")
    return res


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def vstr(v):
    return "%d.%d.%d" % v if v else "-"


def tally(results):
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return counts


def print_report(results, args, colour):
    width = max([len(r["target"]) for r in results] + [6])
    print("%-*s  %-12s  %-9s  %s" % (width, "HOST", "VERDICT", "PHP", "DETAIL"))
    print("-" * min(110, width + 42))
    for r in results:
        print("%-*s  %s  %-9s  %s" % (
            width, r["target"], colourise("%-12s" % r["verdict"], r["verdict"], colour),
            vstr(r["php_version"]), r["detail"]))
        if r["source"]:
            print("%*s    source: %s%s" % (width, "", r["source"],
                                           "  sapi: " + r["sapi"] if r["sapi"] else ""))
        if r["sapi_hint"] and r["mode"] == "remote":
            print("%*s    %s" % (width, "", r["sapi_hint"]))
        for key in PHPINFO_KEYS:
            if key in r["config"]:
                print("%*s    %s = %s" % (width, "", key, r["config"][key]))
        for status, title in r["agent_items"]:
            print("%*s    %s %s" % (width, "", colourise(status, status, colour), title))
        for note in r["notes"]:
            print("%*s    ! %s" % (width, "", note))

    counts = tally(results)
    print()
    print("Summary: " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))

    groups = [
        (V_VULNERABLE, "VULNERABLE -- update to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 and restart "
                       "all workers:"),
        (V_VENDOR, "VENDOR-CHECK -- EOL branch; a backport may be applied without changing the\n"
                   "version string. Confirm against the package changelog before trusting:"),
    ]
    for verdict, heading in groups:
        hosts = [r["target"] for r in results if r["verdict"] == verdict]
        if hosts:
            print("\n" + heading)
            for h in hosts:
                print("  - " + h)

    unknown = [r["target"] for r in results if r["verdict"] in (V_UNKNOWN, V_UNREACHABLE)]
    if unknown:
        print("\nNo answer for %d host(s):" % len(unknown))
        for h in unknown:
            print("  - " + h)
        if not (args.token or args.ssh):
            print("Use --ssh if you have shell access (nothing is written remotely), or deploy")
            print("verify_php2shell.php and use --token, or ask whoever operates them for 'php -v'.")

    if args.ssh:
        n = sum(1 for r in results if r["mode"] == "ssh")
        print("\nSSH mode: %d of %d host(s) answered." % (n, len(results)))
    elif args.token:
        n = sum(1 for r in results if r["mode"] == "agent")
        print("\nAgent mode: %d of %d host(s) answered on %s." % (n, len(results), args.agent_path))
    else:
        print("\nRemote mode reports PHP patch level only. session.upload_progress.enabled,")
        print("memory_limit, fatal_error_backtraces and .user.ini overrides are not remotely")
        print("observable -- use --ssh or --token to check those.")


def print_nagios(results):
    """Single-line Nagios/Icinga output. Returns the plugin exit code."""
    counts = tally(results)
    total = len(results)
    vuln = counts.get(V_VULNERABLE, 0)
    vendor = counts.get(V_VENDOR, 0)
    unknown = counts.get(V_UNKNOWN, 0) + counts.get(V_UNREACHABLE, 0)
    patched = counts.get(V_PATCHED, 0)
    perf = ("vulnerable=%d;;;0 vendor_check=%d patched=%d unknown=%d hosts=%d"
            % (vuln, vendor, patched, unknown, total))

    if vuln:
        state, code = "CRITICAL", 2
        msg = "%d of %d host(s) unpatched for CVE-2026-109618/109619" % (vuln, total)
    elif vendor:
        state, code = "WARNING", 1
        msg = "%d host(s) on EOL branches need vendor confirmation" % vendor
    elif patched == 0:
        state, code = "UNKNOWN", 3
        msg = "no host returned a usable PHP version"
    elif unknown:
        state, code = "WARNING", 1
        msg = "%d of %d host(s) patched, %d unverifiable" % (patched, total, unknown)
    else:
        state, code = "OK", 0
        msg = "all %d host(s) patched" % total

    print("PHP2SHELL %s - %s | %s" % (state, msg, perf))
    return code


def write_csv(path, results):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "verdict", "php_version", "detail", "mode", "source",
                    "server", "sapi", "phpinfo_url", "agent_fail", "agent_warn", "notes"])
        for r in results:
            c = r["agent_counts"] or {}
            w.writerow([r["target"], r["verdict"], vstr(r["php_version"]), r["detail"],
                        r["mode"], r["source"] or "", r["server"] or "", r["sapi"] or "",
                        r["phpinfo_url"] or "", c.get("FAIL", ""), c.get("WARN", ""),
                        " | ".join(r["notes"])])


def parse_fixed_override(spec):
    out = dict(FIXED)
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError("bad --fixed entry %r (want 8.6=8.6.1)" % item)
        branch, version = item.split("=", 1)
        bits = branch.strip().split(".")
        v = parse_version(version)
        if len(bits) != 2 or not v:
            raise ValueError("bad --fixed entry %r (want 8.6=8.6.1)" % item)
        out[(int(bits[0]), int(bits[1]))] = v
    return out


def load_agent_script(args, parser):
    path = args.agent_file or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), DEFAULT_AGENT)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        parser.error("--ssh needs %s: %s" % (DEFAULT_AGENT, e))
    if b"verify_php2shell" not in data:
        parser.error("%s does not look like the agent script" % path)
    return data


def build_parser():
    p = argparse.ArgumentParser(
        prog="php2shell_verify.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Check hosts against CVE-2026-109618 / CVE-2026-109619.",
        epilog="Read-only: sends no payloads and attempts no exploitation.")

    t = p.add_argument_group("targets")
    t.add_argument("-u", "--url", action="append", default=[], metavar="HOST",
                   help="host or URL to check; repeatable")
    t.add_argument("-f", "--file", metavar="PATH",
                   help="file of hosts, one per line ('#' comments allowed)")
    t.add_argument("positional", nargs="*", metavar="HOST",
                   help="hosts may also be given positionally")

    a = p.add_argument_group("authoritative collection")
    a.add_argument("--token", metavar="TOKEN",
                   help="ACCESS_TOKEN of a deployed verify_php2shell.php (HTTP agent mode)")
    a.add_argument("--agent-path", default="/verify_php2shell.php", metavar="PATH",
                   help="URL path of the deployed agent (default: %(default)s)")
    a.add_argument("--ssh", action="store_true",
                   help="run the agent over SSH instead; writes nothing to the remote host")
    a.add_argument("--ssh-user", metavar="USER", help="SSH user when a target has no 'user@'")
    a.add_argument("--ssh-php", default="php", metavar="CMD",
                   help="remote PHP binary (default: %(default)s)")
    a.add_argument("--ssh-opt", action="append", metavar="OPT",
                   help="extra ssh -o option; repeatable")
    a.add_argument("--agent-file", metavar="PATH",
                   help="path to verify_php2shell.php (default: next to this script)")
    a.add_argument("--docroot", metavar="PATH",
                   help="document root to scan for .user.ini overrides (SSH mode)")

    h = p.add_argument_group("http")
    h.add_argument("--probe", action="store_true",
                   help="also look for a leftover phpinfo page to read the real config "
                        "(off by default: it looks like scanning in access logs)")
    h.add_argument("--header", action="append", metavar="'K: V'",
                   help="extra request header; repeatable")
    h.add_argument("--basic-auth", metavar="USER:PASS", help="HTTP basic auth credentials")
    h.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
                   help="per-request timeout (default: %(default)s)")
    h.add_argument("--retries", type=int, default=1, metavar="N",
                   help="retries after a transport error (default: %(default)s)")
    h.add_argument("--delay", type=float, default=0.0, metavar="SEC",
                   help="pause between requests to the same host (default: %(default)s)")
    h.add_argument("--workers", type=int, default=8, metavar="N",
                   help="hosts checked in parallel (default: %(default)s)")
    h.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")

    o = p.add_argument_group("output")
    o.add_argument("--fixed", metavar="SPEC",
                   help="add or override fixed versions, e.g. 8.6=8.6.1")
    o.add_argument("--json", metavar="PATH", help="write full results as JSON")
    o.add_argument("--csv", metavar="PATH", help="write a summary CSV")
    o.add_argument("--nagios", action="store_true",
                   help="single-line Nagios/Icinga output with perfdata and plugin exit codes")
    o.add_argument("--no-colour", action="store_true")
    o.add_argument("--no-banner", action="store_true", help="suppress the banner")
    o.add_argument("-V", "--version", action="version", version="%(prog)s " + __version__)
    return p


def main():
    p = build_parser()
    args = p.parse_args()

    targets, seen = [], set()
    for t in list(args.url) + list(args.positional):
        if t and t not in seen:
            seen.add(t)
            targets.append(t)
    if args.file:
        try:
            with open(args.file) as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if line and line not in seen:
                        seen.add(line)
                        targets.append(line)
        except OSError as e:
            p.error("cannot read --file: %s" % e)
    if not targets:
        p.error("no hosts given; use -u HOST, positional hosts, or -f FILE")

    try:
        args._headers = build_headers(args)
        fixed = parse_fixed_override(args.fixed) if args.fixed else dict(FIXED)
    except ValueError as e:
        p.error(str(e))

    script = load_agent_script(args, p) if args.ssh else None
    quiet = args.nagios
    colour = (not args.no_colour) and not quiet and sys.stdout.isatty() \
        and os.environ.get("TERM") != "dumb"

    if not quiet:
        if not args.no_banner:
            print(BANNER % __version__)
            print()
        print("Fixed in PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 (advisories of 2026-10-21)")
        mode = "ssh" if args.ssh else ("agent + remote" if args.token else "remote")
        print("Mode: %s | %d host(s)\n" % (mode, len(targets)))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(check_host, t, args, fixed, script): t for t in targets}
        for fut in concurrent.futures.as_completed(futures):
            t = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:  # noqa: BLE001 - one bad host must not kill the run
                bad = blank_result(t)
                bad["detail"] = "%s: %s" % (type(e).__name__, e)
                results.append(bad)

    results.sort(key=lambda r: (SORT_ORDER.get(r["verdict"], 9), r["target"]))

    if quiet:
        code = print_nagios(results)
    else:
        print_report(results, args, colour)
        code = 1 if any(r["verdict"] == V_VULNERABLE for r in results) else 0

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([dict(r, php_version=vstr(r["php_version"]),
                            branch=("%d.%d" % r["branch"]) if r["branch"] else None)
                       for r in results], fh, indent=2)
        if not quiet:
            print("\nJSON written to %s" % args.json)
    if args.csv:
        write_csv(args.csv, results)
        if not quiet:
            print("CSV written to %s" % args.csv)

    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
