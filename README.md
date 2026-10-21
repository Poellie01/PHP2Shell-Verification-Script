```
 ___          _ _ _
| _ \___  ___| | (_)___     PHP2Shell - Verification Script
|  _/ _ \/ -_) | | / -_)    CVE-2026-109618 / CVE-2026-109619
|_| \___/\___|_|_|_\___|    by Poellie - github.com/Poellie01
```

# PHP2Shell — Verification Script

Defensive verification tooling for the two critical PHP vulnerabilities disclosed on
**2026-10-21**. It tells you whether a host is patched and whether the advisories'
mitigations are *actually in effect* — including the override traps the advisories
warn about.

**This repository contains no exploit code.** Both tools are read-only: they inspect
versions and configuration. Nothing here sends an attack payload.

| CVE | Title | Advisory |
|---|---|---|
| CVE-2026-109618 | RCE via OOM corruption | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) |
| CVE-2026-109619 | RCE via stale global state | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) |

Both are CVSS v4.0 **9.2**, unauthenticated RCE as the web worker account.

**Fixed in PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12.** Updating is the only complete fix —
both advisories say so explicitly. Everything else reduces exposure to specific paths.

## Contents

| File | Role |
|---|---|
| `php2shell_verify.py` | Python CLI. Checks one host or a whole fleet. No dependencies beyond the standard library. |
| `verify_php2shell.php` | Optional on-host agent. Checks every advisory item from inside the worker that serves your traffic. |

## Quick start

```bash
# one host
./php2shell_verify.py -u example.com

# several
./php2shell_verify.py -u a.example.com -u b.example.com

# a fleet
./php2shell_verify.py -f hosts.txt --csv report.csv
```

Exit code is `1` if any host is VULNERABLE, so it drops straight into CI or cron.

## The honest limitation

These two bugs have **no remote oracle**. Over HTTP you can learn the PHP patch
level and nothing else. Any tool claiming to remotely confirm exploitability for
these CVEs is guessing.

| Fact | Remotely? | How |
|---|---|---|
| PHP patch level | Yes, if exposed | `X-Powered-By`, or a leftover `phpinfo` with `--probe` |
| `session.upload_progress.enabled` | No | on-host agent |
| `memory_limit`, `post_max_size` | No | on-host agent |
| `fatal_error_backtraces` (8.5) | No | on-host agent |
| `.user.ini` overrides | No | on-host agent |
| Frontend `PHP_VALUE` passing | No | on-host agent |

A host that hides its version returns `UNKNOWN`. That is the correct answer, not a
gap to paper over.

### Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | Version below the fix for its branch. Patch it. |
| `PATCHED` | At or above the fixed version for its branch. |
| `VENDOR-CHECK` | On 7.4 / 8.0 / 8.1. Upstream-EOL, but the PHP team published minimal source backports and distributions ship their own — so the version string cannot tell you. Confirm against the package changelog. |
| `UNKNOWN` | Version not exposed. Use the agent, or ask the operator. |
| `UNREACHABLE` | No HTTP response. |

Note that a distribution may backport a fix **without changing the version string**.
Check `apt changelog php8.2` or `rpm -q --changelog php` before treating a
`VULNERABLE` verdict on a distro build as final.

## Agent mode — the authoritative check

Deploy `verify_php2shell.php` on each host, set its `ACCESS_TOKEN`, and the Python
tool collects full results from every host at once.

```bash
# 1. generate a token
php -r 'echo bin2hex(random_bytes(16)), PHP_EOL;'

# 2. set it in verify_php2shell.php
#    const ACCESS_TOKEN = '<that value>';

# 3. deploy to each docroot, then
./php2shell_verify.py -f hosts.txt --token <that value>
```

The agent refuses all web requests until `ACCESS_TOKEN` is set, and returns `404` on
a token mismatch via `hash_equals()`. **Remove it from the document root when you are
done** — do not leave it reachable, for the same reason you would not leave a
`phpinfo` page up.

It can also run directly on the host:

```bash
php verify_php2shell.php --docroot=/var/www/html
php verify_php2shell.php --json          # machine-readable
```

Run it under the SAPI that serves your traffic. A CLI run reads the CLI `php.ini`,
which is frequently **not** what PHP-FPM or mod_php uses. The script says so when it
detects a CLI run.

## What the agent checks

**Patch level** — the only complete fix, with the distro-backport caveat called out.

**SAPI exposure**, using the advisories' own confirmation matrix:

- **mod_php** — highest risk. 109618 RCE confirmed over HTTP with default limits; shutdown runs even when startup fails, so it completes before any application code. `.htaccess` and `php_value`/`php_flag` are an early consumer for 109619.
- **PHP-FPM** — 109618 partial (the child exits on startup failure; no complete exploit demonstrated). 109619 RCE *validated*, via session upload progress, with a normal dynamic pool.
- **FrankenPHP** — likely susceptible to 109618 (calls shutdown unconditionally), unvalidated.
- **LiteSpeed/LSAPI** — conditional candidate, unvalidated.

**CVE-2026-109618 (OOM corruption)**

- `memory_limit = -1`, the primary configuration mitigation — plus an empirical `ini_set()` probe proving whether application code can restore a finite limit, and a global-vs-effective comparison catching a pool or directory that already has.
- `post_max_size`, `upload_max_filesize`, `max_input_nesting_level`, `max_input_vars`, `max_file_uploads`.
- `RLIMIT_AS` / `RLIMIT_DATA` from `/proc/self/limits` — the advisory warns these *cause* the vulnerable path.
- cgroup `memory.max`, the preferred availability boundary.

**CVE-2026-109619 (stale global state)**

- `session.upload_progress.enabled` — the consumer in the RCE confirmed against both mod_php and FPM. Enabled by default, needs no `session_start()`.
- `fatal_error_backtraces` on 8.5 — the advisory's strongest confirmed producer.
- Pre-init diagnostic emitters the advisory names: `auto_detect_line_endings`, `report_memleaks=0` and nonzero `intl.error_level` on 8.5, empty `date.timezone`, and paths falling outside `open_basedir`.
- `PHP_VALUE`/`PHP_ADMIN_VALUE` arriving from the frontend — the FPM INI-diagnostics consumer.
- `.user.ini` files that re-enable a mitigated directive.
- `max_execution_time`, since "Maximum execution time exceeded" is a named producer.
- Logging posture for the log review the advisory recommends.

Once a host is patched, the configuration items are reported as **hardening**, not
failures — the script adjusts severity based on patch status rather than nagging about
a fixed build.

## Mitigations if you cannot update yet

Neither of these makes an installation safe. From the advisories:

```ini
; CVE-2026-109618 — set administratively (php_admin_value), restart all workers
memory_limit = -1
post_max_size = 8M        ; 32M if uploads are required
; keep upload_max_filesize below post_max_size, and reduce max_input_nesting_level
; avoid RLIMIT_AS / RLIMIT_DATA — they trigger the vulnerable path
; bound multipart parts, headers per part and input vars at the frontend

; CVE-2026-109619 — set administratively, restart all workers
session.upload_progress.enabled = 0
fatal_error_backtraces = 0   ; PHP 8.5 only
```

Use `php.ini`, an FPM pool, or server config that applies **before request parsing**.
Do not rely on `ini_set()` or `.user.ini` — the advisory says so directly. Suppressing
diagnostics with `error_reporting`, `display_errors` or `@` does **not** help.

## Scanning hosts you do not operate

`--probe` looks for leftover `phpinfo` pages, which resembles scanning in an access
log. It is **off by default** for that reason. If a third party operates your
infrastructure, tell them before you run it, so their incident response is not chasing
you. Only check hosts you own or are authorised to test.

## License

MIT — see `LICENSE`.

## Credits

Written by **Poellie** ([@Poellie01](https://github.com/Poellie01)).

Built strictly from the PHP project's own advisories:

- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [php.net security bulletin, 2026-10-21](https://www.php.net/)

Thanks to the PHP security team for the detail in both write-ups.
