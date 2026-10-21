```
 ___          _ _ _
| _ \___  ___| | (_)___     PHP2Shell - Verification Script
|  _/ _ \/ -_) | | / -_)    CVE-2026-109618 / CVE-2026-109619
|_| \___/\___|_|_|_\___|    by Poellie - github.com/Poellie01
```

# PHP2Shell — Verification Script

Defensive verification tooling for the two critical PHP vulnerabilities disclosed on
**2026-10-21**. It tells you whether a host is patched, whether the advisories'
mitigations are *actually in effect* — including the override traps the advisories warn
about — and whether your logs contain the error classes they tell you to review.

**This repository contains no exploit code.** Everything here is read-only: it inspects
versions, configuration and logs. Nothing sends an attack payload. CI fails the build if
exploit-shaped content appears.

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
| `php2shell_verify.py` | Python CLI. One host or a whole fleet. Standard library only. |
| `verify_php2shell.php` | On-host agent. Checks every advisory item from inside the serving worker. |
| `scan_logs.py` | Log review for the error classes GHSA-6wmf-4rv5-p3rp says to investigate. |
| `deploy/ansible-verify.yml` | Run the agent fleet-wide with Ansible, writing nothing remotely. |
| `deploy/prepare-agent.sh` | Generate a token and a configured agent copy for HTTP deployment. |
| `docs/supplier-request.md` | Template for getting answers out of a third-party host. |

## Quick start

```bash
# one host
./php2shell_verify.py -u example.com

# several
./php2shell_verify.py -u a.example.com -u b.example.com

# a fleet
./php2shell_verify.py -f hosts.txt --csv report.csv

# authoritative, over SSH — writes nothing to the remote host
./php2shell_verify.py -f hosts.txt --ssh

# monitoring
./php2shell_verify.py -f hosts.txt --nagios
```

Exit code is `1` if any host is VULNERABLE, so it drops straight into CI or cron.
With `--nagios`, standard plugin codes apply instead: `0` OK, `1` WARNING,
`2` CRITICAL, `3` UNKNOWN.

## The three modes

| Mode | Flag | Confidence | Needs |
|---|---|---|---|
| Remote | *(default)* | Patch level only | Nothing |
| SSH | `--ssh` | Everything | Shell access |
| HTTP agent | `--token` | Everything | Agent deployed in a docroot |

**SSH mode is the one to prefer.** It pipes `verify_php2shell.php` to the host and runs
it there, so nothing is written to the remote filesystem and there is no file in a
document root to remember to delete:

```bash
./php2shell_verify.py -f hosts.txt --ssh --ssh-user deploy --docroot /var/www/html
```

**HTTP agent mode** is for when you can deploy a file but not get a shell:

```bash
./deploy/prepare-agent.sh                 # generates a token + configured copy
# upload it, then
./php2shell_verify.py -f hosts.txt --token <token>
# then delete it from the docroot
```

The agent refuses all web requests until `ACCESS_TOKEN` is set, and returns `404` on a
token mismatch, compared with `hash_equals()`.

It also runs standalone on a host:

```bash
php verify_php2shell.php --docroot=/var/www/html
php verify_php2shell.php --json
```

Run it under the SAPI that serves your traffic. A CLI run reads the CLI `php.ini`, which
is frequently **not** what PHP-FPM or mod_php uses — the script says so when it detects
a CLI run.

## The honest limitation

These two bugs have **no remote oracle**. Over HTTP you can learn the PHP patch level
and nothing else. Any tool claiming to remotely confirm exploitability for these CVEs is
guessing.

| Fact | Remotely? | How |
|---|---|---|
| PHP patch level | Yes, if exposed | `X-Powered-By`, or a leftover `phpinfo` with `--probe` |
| `session.upload_progress.enabled` | No | `--ssh` or `--token` |
| `memory_limit`, `post_max_size` | No | `--ssh` or `--token` |
| `fatal_error_backtraces` (8.5) | No | `--ssh` or `--token` |
| `.user.ini` overrides | No | `--ssh` or `--token` |
| Frontend `PHP_VALUE` passing | No | `--ssh` or `--token` |

A host that hides its version returns `UNKNOWN`. That is the correct answer, not a gap
to paper over.

### Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | Version below the fix for its branch. Patch it. |
| `PATCHED` | At or above the fixed version for its branch. |
| `VENDOR-CHECK` | On 7.4 / 8.0 / 8.1. Upstream-EOL, but the PHP team published minimal source backports and distributions ship their own — so the version string cannot tell you. Confirm against the package changelog. |
| `UNKNOWN` | Version not exposed, or only the branch leaked. |
| `UNREACHABLE` | No HTTP response, or SSH collection failed. |

A distribution may backport a fix **without changing the version string**. Check
`apt changelog php8.2` or `rpm -q --changelog php` before treating a `VULNERABLE`
verdict on a distro build as final.

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
- Pre-init diagnostic emitters the advisory names: `auto_detect_line_endings`, `report_memleaks=0` and nonzero `intl.error_level` on 8.5, and paths falling outside `open_basedir`.
- `PHP_VALUE`/`PHP_ADMIN_VALUE` arriving from the frontend — the FPM INI-diagnostics consumer.
- `.user.ini` files that re-enable a mitigated directive.
- `max_execution_time`, since "Maximum execution time exceeded" is a named producer.
- Logging posture for the log review the advisory recommends.

Once a host is patched, these are reported as **hardening** rather than failures — the
script adjusts severity by patch status instead of nagging about a fixed build.

Some emitters cannot be observed from inside a request at all. An invalid
`date.timezone`, for example, is rewritten to UTC during startup *after* the diagnostic
is raised, so no in-request check can ever see it. The agent says so and points at
`php -i 2>&1 | grep -i 'PHP Startup'` instead of pretending otherwise.

## Log review

GHSA-6wmf-4rv5-p3rp recommends enabling `log_errors` with `error_reporting=E_ALL` and
reviewing logs. `scan_logs.py` performs that review:

```bash
./scan_logs.py /var/log/php*.log /var/log/nginx/error.log
./scan_logs.py /var/log/apache2/error.log.*.gz --min-severity high
journalctl -u php8.2-fpm --no-pager | ./scan_logs.py -
```

It groups memory exhaustion, worker crashes and segfaults, execution timeouts, startup
diagnostics, fatal/parse/uncaught errors, cleanup diagnostics and upload errors, with
the reason each matters.

**These are not indicators of compromise** — neither advisory publishes any. They are
the *producers* the advisories name, plus the crash signatures a failed attempt leaves.
A hit means "worth investigating". No hits does not mean safe: a crash can happen before
PHP writes anything.

## Options

### `php2shell_verify.py`

| Flag | Purpose |
|---|---|
| `-u, --url HOST` | Host or URL to check; repeatable. Hosts may also be positional. |
| `-f, --file PATH` | File of hosts, one per line, `#` comments allowed. |
| `--token TOKEN` | `ACCESS_TOKEN` of a deployed agent (HTTP agent mode). |
| `--agent-path PATH` | URL path of the deployed agent. Default `/verify_php2shell.php`. |
| `--ssh` | Run the agent over SSH. Writes nothing to the remote host. |
| `--ssh-user USER` | SSH user when a target has no `user@`. |
| `--ssh-php CMD` | Remote PHP binary. Default `php`. |
| `--ssh-opt OPT` | Extra `ssh -o` option; repeatable. |
| `--agent-file PATH` | Path to `verify_php2shell.php`. Default: next to the script. |
| `--docroot PATH` | Document root to scan for `.user.ini` overrides (SSH mode). |
| `--probe` | Also look for a leftover `phpinfo` page. Off by default. |
| `--header 'K: V'` | Extra request header; repeatable. |
| `--basic-auth USER:PASS` | HTTP basic auth credentials. |
| `--timeout SEC` | Per-request timeout. Default `10`. |
| `--retries N` | Retries after a transport error. Default `1`. |
| `--delay SEC` | Pause between requests to the same host. Default `0`. |
| `--workers N` | Hosts checked in parallel. Default `8`. |
| `--insecure` | Do not verify TLS certificates. |
| `--fixed SPEC` | Add or override fixed versions, e.g. `8.6=8.6.1`. |
| `--json PATH` | Write full results as JSON. |
| `--csv PATH` | Write a summary CSV. |
| `--nagios` | One-line Nagios/Icinga output with perfdata and plugin exit codes. |
| `--no-colour`, `--no-banner` | Quieten the output. |

When a future branch ships, no code change is needed:

```bash
./php2shell_verify.py -f hosts.txt --fixed 8.6=8.6.1
```

### `verify_php2shell.php`

| Argument | Purpose |
|---|---|
| `--docroot=PATH` | Document root to scan for `.user.ini` overrides. |
| `--json` | Machine-readable output. The banner is omitted so it stays parseable. |
| `?token=…` | Required for web access, once `ACCESS_TOKEN` is set. |
| `?token=…&json=1` | Machine-readable output over HTTP. |

### `scan_logs.py`

| Flag | Purpose |
|---|---|
| `LOG...` | Log files. `-` reads stdin; `.gz` is read transparently. |
| `--top N` | Distinct sample messages per finding. Default `3`. |
| `--min-severity` | Hide findings below `low`/`medium`/`high`. |
| `--max-lines N` | Stop after N lines in total. |
| `--json PATH` | Write findings as JSON. |

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

Use `php.ini`, an FPM pool, or server config that applies **before request parsing**. Do
not rely on `ini_set()` or `.user.ini` — the advisory says so directly. Suppressing
diagnostics with `error_reporting`, `display_errors` or `@` does **not** help.

## Fleet use

With Ansible, writing nothing to any remote host:

```bash
ansible-playbook -i inventory deploy/ansible-verify.yml
```

Per-host JSON lands in `php2shell-results/`, and the play fails for any unpatched host.

If a third party operates your infrastructure, `docs/supplier-request.md` has a request
template covering the facts no remote check can observe.

## Scanning hosts you do not operate

`--probe` looks for leftover `phpinfo` pages, which resembles scanning in an access log.
It is **off by default** for that reason. If a third party operates your infrastructure,
tell them before you run it, so their incident response is not chasing you. Only check
hosts you own or are authorised to test.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

65 tests, standard library only. Version classification at every boundary, phpinfo
parsing, header and auth construction, Nagios exit codes, agent payload handling, plus
integration tests that run the PHP agent under INI overrides and assert the status of
each advisory item — including a regression test for the warning that used to fire
unconditionally. CI runs them against PHP 8.2–8.5 and Python 3.9–3.13.

## License

MIT — see `LICENSE`.

## Credits

Written by **Poellie** ([@Poellie01](https://github.com/Poellie01)).

Built strictly from the PHP project's own advisories:

- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [php.net security bulletin, 2026-10-21](https://www.php.net/)

Thanks to the PHP security team for the detail in both write-ups.
