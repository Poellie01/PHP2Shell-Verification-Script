#!/usr/bin/env python3
"""
php2shell_verify — check hosts against the PHP advisories of 2026-10-21.

  CVE-2026-109618  RCE via OOM corruption      GHSA-w8hw-w9fx-j79w
  CVE-2026-109619  RCE via stale global state  GHSA-6wmf-4rv5-p3rp

Fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12.

Two modes:

  REMOTE (default) -- read-only HTTP. Determines the PHP patch level when the
  host exposes it (X-Powered-By, or a leftover phpinfo with --probe). Sends no
  payloads and attempts no exploitation. Safe against production you do not
  operate. Honest limitation: nothing else in these advisories is remotely
  observable, so hosts that hide their version come back UNKNOWN.

  AGENT (--token) -- fetches verify_php2shell.php from each host and reports its
  full advisory check results. Deploy that file on each host, set its
  ACCESS_TOKEN, and this becomes an authoritative fleet-wide verification
  instead of a fingerprint.

Usage:
  php2shell_verify.py -u example.com
  php2shell_verify.py -u a.example.com -u b.example.com --probe
  php2shell_verify.py -f hosts.txt --csv report.csv
  php2shell_verify.py -f hosts.txt --token YOUR_TOKEN        # authoritative
  php2shell_verify.py -f hosts.txt --fixed 8.6=8.6.1         # new branch

Exit codes: 0 = nothing vulnerable, 1 = at least one VULNERABLE, 2 = usage error.

Author: Poellie -- https://github.com/Poellie01
License: MIT
"""
import argparse
import concurrent.futures
import csv
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.0.0"
AUTHOR = "Poellie"
AUTHOR_URL = "https://github.com/Poellie01"

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
# backports were published and distributions/LTS vendors ship their own.
# A version string on these branches cannot tell you whether a fix is applied.
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

V_VULNERABLE = "VULNERABLE"
V_PATCHED = "PATCHED"
V_VENDOR = "VENDOR-CHECK"
V_UNKNOWN = "UNKNOWN"
V_UNREACHABLE = "UNREACHABLE"

SORT_ORDER = {V_VULNERABLE: 0, V_VENDOR: 1, V_UNKNOWN: 2, V_UNREACHABLE: 3, V_PATCHED: 4}

_ver_re = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_row_re = re.compile(
    r'<tr>\s*<td class="e">\s*([^<]+?)\s*</td>\s*<td class="v">\s*(.*?)\s*</td>', re.S)
_h1_re = re.compile(r"PHP Version\s*([0-9]+\.[0-9]+\.[0-9]+[^\s<]*)")
_tag_re = re.compile(r"<[^>]+>")

COLOURS = {V_VULNERABLE: "\033[31m", V_PATCHED: "\033[32m", V_VENDOR: "\033[33m",
           V_UNKNOWN: "\033[35m", V_UNREACHABLE: "\033[90m",
           "FAIL": "\033[31m", "WARN": "\033[33m", "PASS": "\033[32m",
           "INFO": "\033[36m"}


def colourise(text, key, enabled):
    if not enabled or key not in COLOURS:
        return text
    return COLOURS[key] + text + "\033[0m"


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def ssl_context(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(url, timeout, verify):
    """GET url -> (status, lowercased headers, body text). Raises on transport error."""
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context(verify)) as r:
            body = r.read(MAX_BODY).decode("utf-8", "replace")
            return r.status, {k.lower(): v for k, v in r.headers.items()}, body
    except urllib.error.HTTPError as e:
        body = e.read(MAX_BODY).decode("utf-8", "replace")
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        return e.code, hdrs, body


def normalise(target):
    """Turn a bare host into candidate URLs, preserving an explicit scheme."""
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


def version_from_headers(hdrs):
    pb = hdrs.get("x-powered-by", "")
    if "php" in pb.lower():
        v = parse_version(pb)
        if v:
            return v
    return None


def parse_phpinfo(body):
    """Return (version, {directive: local value}) if body looks like phpinfo."""
    if "phpinfo()" not in body and "PHP Version" not in body:
        return None, {}
    version = None
    m = _h1_re.search(body)
    if m:
        version = parse_version(m.group(1))
    directives = {}
    for name, value in _row_re.findall(body):
        if name in PHPINFO_KEYS:
            directives[name] = _tag_re.sub("", value).strip() or "(empty)"
    return version, directives


def classify(version, fixed):
    """-> (verdict, detail)"""
    if version is None:
        return V_UNKNOWN, "PHP version not exposed"
    branch = version[:2]
    if branch in fixed:
        target = fixed[branch]
        if version >= target:
            return V_PATCHED, "%d.%d.%d >= %d.%d.%d" % (version + target)
        return V_VULNERABLE, "%d.%d.%d < %d.%d.%d" % (version + target)
    if branch in BACKPORT_EOL:
        return V_VENDOR, "branch %d.%d is EOL upstream; backports exist" % branch
    if branch < (7, 4):
        return V_VULNERABLE, "branch %d.%d long out of support" % branch
    return V_UNKNOWN, "branch %d.%d not in fixed-version table" % branch


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
# Per-host checks
# ---------------------------------------------------------------------------
def agent_check(base, token, agent_path, timeout, verify):
    """Fetch the on-host PHP verifier's JSON. -> dict or None."""
    qs = urllib.parse.urlencode({"token": token, "json": "1"})
    url = base + agent_path + "?" + qs
    try:
        status, _, body = fetch(url, timeout, verify)
    except Exception:
        return None
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("script") == "verify_php2shell" else None


def check_host(target, args, fixed):
    res = {
        "target": target, "url": None, "verdict": V_UNREACHABLE, "detail": "",
        "php_version": None, "source": None, "server": None, "sapi": None,
        "sapi_hint": "", "mode": "remote", "config": {}, "phpinfo_url": None,
        "agent_counts": None, "agent_items": [], "notes": [],
    }

    base, hdrs = None, {}
    errors = []
    for url in normalise(target):
        try:
            _, hdrs, _ = fetch(url, args.timeout, not args.insecure)
        except Exception as e:
            errors.append("%s: %s" % (url, type(e).__name__))
            continue
        base = url.rstrip("/")
        res["url"] = url
        res["server"] = hdrs.get("server")
        break

    if base is None:
        res["detail"] = "; ".join(errors) or "no response"
        return res

    res["sapi_hint"] = sapi_hint(hdrs)

    # Authoritative path: the on-host agent.
    if args.token:
        data = agent_check(base, args.token, args.agent_path, args.timeout, not args.insecure)
        if data:
            res["mode"] = "agent"
            res["php_version"] = parse_version(data.get("php_version", ""))
            res["source"] = "verify_php2shell.php"
            res["sapi"] = data.get("sapi")
            res["agent_counts"] = data.get("counts")
            patched = data.get("patched")
            if patched is True:
                res["verdict"] = V_PATCHED
            elif patched is False:
                res["verdict"] = V_VULNERABLE
            else:
                res["verdict"] = V_VENDOR
            for c in data.get("checks", []):
                if c.get("status") in ("FAIL", "WARN"):
                    res["agent_items"].append((c["status"], c.get("title", "")))
            counts = res["agent_counts"] or {}
            res["detail"] = "agent: %d FAIL, %d WARN, %d UNKNOWN" % (
                counts.get("FAIL", 0), counts.get("WARN", 0), counts.get("UNKNOWN", 0))
            return res
        res["notes"].append("agent not reachable at %s -- fell back to remote fingerprint "
                            "(not deployed, wrong token, or blocked)" % args.agent_path)

    # Remote fingerprint.
    version = version_from_headers(hdrs)
    if version:
        res["php_version"], res["source"] = version, "X-Powered-By"

    if args.probe:
        for path in PROBE_PATHS:
            try:
                status, phdrs, body = fetch(base + path, args.timeout, not args.insecure)
            except Exception:
                continue
            if res["php_version"] is None:
                v = version_from_headers(phdrs)
                if v:
                    res["php_version"], res["source"] = v, "X-Powered-By on " + path
            if status != 200:
                continue
            pv, directives = parse_phpinfo(body)
            if pv or directives:
                res["phpinfo_url"] = base + path
                res["notes"].append("publicly reachable phpinfo at %s -- a finding in its own "
                                    "right, remove it" % path)
                if pv:
                    res["php_version"], res["source"] = pv, "phpinfo at " + path
                res["config"] = directives
                break

    res["verdict"], res["detail"] = classify(res["php_version"], fixed)

    cfg = res["config"]
    up = cfg.get("session.upload_progress.enabled", "")
    if up:
        if up.lower() in ("on", "1"):
            res["notes"].append("session.upload_progress.enabled=On -- the 109619 consumer used in "
                                "the RCE confirmed against both mod_php and FPM")
        else:
            res["notes"].append("session.upload_progress.enabled=%s -- demonstrated 109619 session "
                                "path closed" % up)
    ml = cfg.get("memory_limit", "")
    if ml and ml.strip() != "-1":
        res["notes"].append("memory_limit=%s -- not -1, so the predictable per-request limit the "
                            "109618 exploit relies on is present" % ml)
    feb = cfg.get("fatal_error_backtraces", "")
    if feb and feb.lower() in ("on", "1") and res["php_version"] and res["php_version"][:2] == (8, 5):
        res["notes"].append("fatal_error_backtraces=On on 8.5 -- the advisory's strongest confirmed "
                            "109619 producer")
    return res


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def vstr(v):
    return "%d.%d.%d" % v if v else "-"


def print_report(results, args, colour):
    width = max([len(r["target"]) for r in results] + [6])
    print("%-*s  %-12s  %-9s  %s" % (width, "HOST", "VERDICT", "PHP", "DETAIL"))
    print("-" * min(110, width + 42))
    for r in results:
        print("%-*s  %s  %-9s  %s" % (
            width, r["target"],
            colourise("%-12s" % r["verdict"], r["verdict"], colour),
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

    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print()
    print("Summary: " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))

    vuln = [r["target"] for r in results if r["verdict"] == V_VULNERABLE]
    vendor = [r["target"] for r in results if r["verdict"] == V_VENDOR]
    unknown = [r["target"] for r in results
               if r["verdict"] in (V_UNKNOWN, V_UNREACHABLE)]

    if vuln:
        print("\nVULNERABLE -- update to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 and restart all workers:")
        for t in vuln:
            print("  - " + t)
    if vendor:
        print("\nVENDOR-CHECK -- EOL branch; a backport may be applied without changing the version")
        print("string. Confirm against the package changelog before trusting:")
        for t in vendor:
            print("  - " + t)
    if unknown:
        print("\nNo remote answer for %d host(s) -- the version is not exposed:" % len(unknown))
        for t in unknown:
            print("  - " + t)
        if not args.token:
            print("Deploy verify_php2shell.php on these hosts and re-run with --token for an")
            print("authoritative result, or ask whoever operates them for 'php -v' output.")

    if args.token:
        agents = sum(1 for r in results if r["mode"] == "agent")
        print("\nAgent mode: %d of %d host(s) answered on %s."
              % (agents, len(results), args.agent_path))
    else:
        print("\nRemote mode reports PHP patch level only. session.upload_progress.enabled,")
        print("memory_limit, fatal_error_backtraces and .user.ini overrides are not remotely")
        print("observable -- use --token with verify_php2shell.php deployed to check those.")


def write_csv(path, results):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "verdict", "php_version", "detail", "mode", "source",
                    "server", "sapi", "phpinfo_url", "notes"])
        for r in results:
            w.writerow([r["target"], r["verdict"], vstr(r["php_version"]), r["detail"],
                        r["mode"], r["source"] or "", r["server"] or "", r["sapi"] or "",
                        r["phpinfo_url"] or "", " | ".join(r["notes"])])


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


def main():
    p = argparse.ArgumentParser(
        prog="php2shell_verify.py",
        description="Check hosts against CVE-2026-109618 / CVE-2026-109619.",
        epilog="Read-only: sends no payloads and attempts no exploitation.")
    p.add_argument("-u", "--url", action="append", default=[], metavar="HOST",
                   help="host or URL to check; repeatable")
    p.add_argument("-f", "--file", metavar="PATH",
                   help="file of hosts, one per line ('#' comments allowed)")
    p.add_argument("positional", nargs="*", metavar="HOST",
                   help="hosts may also be given positionally")
    p.add_argument("--token", metavar="TOKEN",
                   help="ACCESS_TOKEN of verify_php2shell.php; enables authoritative agent mode")
    p.add_argument("--agent-path", default="/verify_php2shell.php", metavar="PATH",
                   help="path to the deployed verifier (default: %(default)s)")
    p.add_argument("--probe", action="store_true",
                   help="also look for a leftover phpinfo page to read the real config "
                        "(off by default: it looks like scanning in access logs)")
    p.add_argument("--timeout", type=float, default=10.0, metavar="SEC")
    p.add_argument("--workers", type=int, default=8, metavar="N")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    p.add_argument("--fixed", metavar="SPEC",
                   help="add or override fixed versions, e.g. 8.6=8.6.1")
    p.add_argument("--json", metavar="PATH", help="write full results as JSON")
    p.add_argument("--csv", metavar="PATH", help="write a summary CSV")
    p.add_argument("--no-colour", action="store_true")
    p.add_argument("--no-banner", action="store_true", help="suppress the banner")
    p.add_argument("-V", "--version", action="version", version="%(prog)s " + __version__)
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
        fixed = parse_fixed_override(args.fixed) if args.fixed else dict(FIXED)
    except ValueError as e:
        p.error(str(e))

    colour = (not args.no_colour) and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"

    if not args.no_banner:
        print(BANNER % __version__)
        print()
    print("Fixed in PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 (advisories of 2026-10-21)")
    print("Mode: %s | %d host(s)\n" % ("agent + remote" if args.token else "remote", len(targets)))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(check_host, t, args, fixed): t for t in targets}
        for fut in concurrent.futures.as_completed(futures):
            t = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"target": t, "verdict": V_UNREACHABLE,
                                "detail": "%s: %s" % (type(e).__name__, e),
                                "php_version": None, "source": None, "server": None,
                                "sapi": None, "sapi_hint": "", "mode": "remote",
                                "config": {}, "phpinfo_url": None, "agent_counts": None,
                                "agent_items": [], "notes": [], "url": None})

    results.sort(key=lambda r: (SORT_ORDER.get(r["verdict"], 9), r["target"]))
    print_report(results, args, colour)

    if args.json:
        payload = [dict(r, php_version=vstr(r["php_version"])) for r in results]
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2)
        print("\nJSON written to %s" % args.json)
    if args.csv:
        write_csv(args.csv, results)
        print("CSV written to %s" % args.csv)

    return 1 if any(r["verdict"] == V_VULNERABLE for r in results) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
