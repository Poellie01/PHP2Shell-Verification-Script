#!/usr/bin/env python3
"""
scan_logs — review PHP/web server logs for the patterns the php2shell
advisories say are worth investigating.

  CVE-2026-109618  RCE via OOM corruption      GHSA-w8hw-w9fx-j79w
  CVE-2026-109619  RCE via stale global state  GHSA-6wmf-4rv5-p3rp

GHSA-6wmf-4rv5-p3rp recommends enabling log_errors with error_reporting=E_ALL
and then reviewing logs for specific error classes. This does that review.

IMPORTANT: neither advisory publishes indicators of compromise, and there are
none here. These patterns are the *producers* the advisories name -- the error
classes that leave stale state behind, plus the crash signatures a failed
attempt leaves. A hit means "worth investigating", not "you were exploited".
Equally, no hits does not mean you are safe: a crash can happen before PHP
writes anything, and both advisories say logs supplement a configuration and
application review rather than replacing it.

Usage:
  ./scan_logs.py /var/log/php*.log /var/log/nginx/error.log
  ./scan_logs.py /var/log/apache2/error.log.*.gz --top 5
  journalctl -u php8.2-fpm --no-pager | ./scan_logs.py -
  ./scan_logs.py /var/log/php/*.log --json findings.json

Author: Poellie -- https://github.com/Poellie01
License: MIT
"""
import argparse
import gzip
import io
import json
import os
import re
import sys

__version__ = "1.1.0"

BANNER = r"""
 ___          _ _ _
| _ \___  ___| | (_)___     scan_logs %s
|  _/ _ \/ -_) | | / -_)    php2shell advisory log review
|_| \___/\___|_|_|_\___|    by Poellie - github.com/Poellie01
""".strip("\n")

# (key, label, severity, cve, regex, why it matters)
PATTERNS = [
    ("oom", "Memory exhaustion", "high", "109618",
     re.compile(r"Allowed memory size of \d+ bytes exhausted|Out of memory \(allocated"
                r"|cannot allocate memory", re.I),
     "OOM is the 109618 trigger and a named 109619 producer. Attacker-shaped "
     "multipart bodies are one documented way to reach it."),

    ("segv", "Worker crash / segfault", "high", "both",
     re.compile(r"exited on signal (11|6|7)\b|signal: Segmentation fault|segfault at"
                r"|child pid \d+ exit signal (Segmentation fault|Bus error|Aborted)"
                r"|exited with code 139", re.I),
     "Both CVEs are memory-corruption bugs. A crashing worker is what a failed "
     "or unreliable attempt looks like, and is the strongest single signal here."),

    ("timeout", "Execution timeout", "medium", "109619",
     re.compile(r"Maximum execution time of \d+ seconds? exceeded"
                r"|Maximum execution time exceeded", re.I),
     "Named explicitly as a 109619 producer. The advisory says to treat these as "
     "fatal errors and fix the slow path; raising the limit does not mitigate it."),

    ("startup", "Startup / pre-init diagnostics", "medium", "109619",
     re.compile(r"PHP Startup:|in Unknown on line 0", re.I),
     "Diagnostics raised during early INI application are a confirmed 109619 "
     "consumer. They fire even when not displayed, and suppressing them does not help."),

    ("fatal", "Fatal / parse / uncaught errors", "medium", "109619",
     re.compile(r"PHP Fatal error|PHP Parse error|Uncaught \w*(Error|Exception)"
                r"|Failed opening required", re.I),
     "Fatal errors, compile failures and require failures are named 109619 "
     "producers: they can leave request-owned state in a worker global."),

    ("shutdown", "Diagnostics during shutdown or cleanup", "medium", "109619",
     re.compile(r"during shutdown|in shutdown|post-deactivation|RSHUTDOWN"
                r"|Error in shutdown function", re.I),
     "The advisory asks you to remove diagnostics emitted during extension "
     "post-deactivation and server cleanup."),

    ("upload", "Upload / multipart processing errors", "low", "both",
     re.compile(r"Unable to (move|create) uploaded file|POST Content-Length of \d+ bytes exceeds"
                r"|Maximum number of allowable file uploads|multipart/form-data POST data", re.I),
     "Upload and multipart handling is the documented route to both the OOM "
     "trigger and the session upload_progress consumer."),

    ("deprecated", "Deprecations and warnings", "low", "109619",
     re.compile(r"PHP Deprecated:|PHP Warning:|PHP Notice:", re.I),
     "Any diagnostic raised before initialization can act as the consumer. High "
     "counts here are noise to clean up, not evidence on their own."),
]

# Collapse variable parts so repeats group together.
_noise = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?\b"), "<ts>"),
    (re.compile(r"\[\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}[^\]]*\]"), "<ts>"),
    (re.compile(r"\bpid \d+|\bpool \w+|\bchild \d+"), "<proc>"),
    (re.compile(r"on line \d+"), "on line <n>"),
    (re.compile(r"\b\d{2,}\b"), "<n>"),
    (re.compile(r"0x[0-9a-f]+", re.I), "<addr>"),
    (re.compile(r"/[\w./-]{8,}"), "<path>"),
]


def normalise(line):
    out = line.strip()
    for pattern, replacement in _noise:
        out = pattern.sub(replacement, out)
    return out[:200]


def open_log(path):
    if path == "-":
        return io.TextIOWrapper(sys.stdin.buffer, errors="replace")
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def scan(paths, args):
    findings = {key: {"count": 0, "samples": {}, "files": set(), "first": None, "last": None}
                for key, *_ in PATTERNS}
    scanned, skipped, lines_read = [], [], 0

    for path in paths:
        try:
            handle = open_log(path)
        except OSError as e:
            skipped.append("%s (%s)" % (path, e.strerror or e))
            continue
        with handle:
            scanned.append(path)
            for lineno, line in enumerate(handle, 1):
                lines_read += 1
                if args.max_lines and lines_read > args.max_lines:
                    skipped.append("%s (stopped at --max-lines)" % path)
                    break
                for key, _label, _sev, _cve, regex, _why in PATTERNS:
                    if regex.search(line):
                        f = findings[key]
                        f["count"] += 1
                        f["files"].add(os.path.basename(path))
                        where = "%s:%d" % (os.path.basename(path), lineno)
                        if f["first"] is None:
                            f["first"] = where
                        f["last"] = where
                        sig = normalise(line)
                        f["samples"][sig] = f["samples"].get(sig, 0) + 1
    return findings, scanned, skipped, lines_read


def main():
    p = argparse.ArgumentParser(
        prog="scan_logs.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Review logs for the error classes the php2shell advisories name.",
        epilog="These are not indicators of compromise. A hit means 'worth "
               "investigating'; no hits does not mean safe.")
    p.add_argument("paths", nargs="+", metavar="LOG",
                   help="log files ('-' for stdin; .gz is read transparently)")
    p.add_argument("--top", type=int, default=3, metavar="N",
                   help="distinct sample messages to show per finding (default: %(default)s)")
    p.add_argument("--max-lines", type=int, default=0, metavar="N",
                   help="stop after N lines in total (0 = no limit)")
    p.add_argument("--min-severity", choices=["low", "medium", "high"], default="low",
                   help="hide findings below this severity (default: %(default)s)")
    p.add_argument("--json", metavar="PATH", help="write findings as JSON")
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("-V", "--version", action="version", version="%(prog)s " + __version__)
    args = p.parse_args()

    if not args.no_banner:
        print(BANNER % __version__)
        print()

    findings, scanned, skipped, lines_read = scan(args.paths, args)

    rank = {"low": 0, "medium": 1, "high": 2}
    floor = rank[args.min_severity]

    print("Scanned %d file(s), %d line(s)." % (len(scanned), lines_read))
    if skipped:
        print("Skipped: " + "; ".join(skipped))
    print()

    hits = 0
    for key, label, severity, cve, _regex, why in PATTERNS:
        f = findings[key]
        if not f["count"] or rank[severity] < floor:
            continue
        hits += 1
        tag = "CVE-2026-" + cve if cve != "both" else "both CVEs"
        print("[%s] %s -- %d occurrence(s)  [%s]"
              % (severity.upper(), label, f["count"], tag))
        print("    why: %s" % why)
        print("    in: %s" % ", ".join(sorted(f["files"])))
        print("    first %s, last %s" % (f["first"], f["last"]))
        top = sorted(f["samples"].items(), key=lambda kv: -kv[1])[:max(1, args.top)]
        for sig, n in top:
            print("    %4dx %s" % (n, sig))
        print()

    if not hits:
        print("No matching patterns found in the logs provided.")
        print()
        print("That is not proof of safety. A crash can occur before PHP writes a")
        print("message, and these advisories publish no indicators of compromise.")
        print("Confirm log_errors=On, a working error_log and error_reporting=E_ALL")
        print("are set in startup config, then re-check after real traffic.")
    else:
        print("-" * 72)
        print("%d pattern group(s) matched. These are the error classes the advisories" % hits)
        print("name as producers, plus crash signatures -- not indicators of compromise.")
        print("Investigate the high-severity groups first, especially worker crashes")
        print("and memory exhaustion on attacker-reachable routes (uploads, imports,")
        print("callbacks, plugin options).")

    if args.json:
        payload = {
            "script": "scan_logs", "version": __version__,
            "author": "Poellie (https://github.com/Poellie01)",
            "scanned": scanned, "skipped": skipped, "lines": lines_read,
            "findings": [
                {"key": key, "label": label, "severity": sev, "cve": cve,
                 "count": findings[key]["count"],
                 "files": sorted(findings[key]["files"]),
                 "first": findings[key]["first"], "last": findings[key]["last"],
                 "samples": sorted(findings[key]["samples"].items(),
                                   key=lambda kv: -kv[1])[:max(1, args.top)]}
                for key, label, sev, cve, _r, _w in PATTERNS if findings[key]["count"]
            ],
        }
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2)
        print("\nJSON written to %s" % args.json)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
