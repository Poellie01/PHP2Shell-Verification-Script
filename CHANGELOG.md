# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-10-21

### Added

- **SSH mode** (`--ssh`). Pipes the agent to each host over SSH and runs it
  there, writing nothing to the remote filesystem — no file in a document root
  to remember to delete. Preferred over the HTTP agent when shell access exists.
- **`scan_logs.py`**, a log review helper covering GHSA-6wmf-4rv5-p3rp's
  recommendation to review logs. Groups memory exhaustion, worker crashes,
  execution timeouts, startup diagnostics, fatal errors and cleanup diagnostics,
  reads `.gz` and stdin, and states plainly that these are named producers
  rather than indicators of compromise.
- **Nagios/Icinga mode** (`--nagios`): one-line output with perfdata and plugin
  exit codes, for monitoring after the patch window.
- HTTP authentication support: `--header` (repeatable) and `--basic-auth`, so
  hosts behind basic auth or a header allowlist can be checked at all.
- `--retries` and `--delay`, for fleets behind a shared WAF or rate limiter.
- Branch-only version handling: a truncated `X-Powered-By: PHP/8.4` now reports
  which patch version that branch needs, instead of a bare `UNKNOWN`.
- Test suite (65 tests, standard library only) and CI across PHP 8.2–8.5 and
  Python 3.9–3.13, including hygiene checks that fail the build if a token is
  committed or exploit-shaped content appears.
- `SECURITY.md`, `CHANGELOG.md`, a supplier request template, and Ansible /
  agent-preparation helpers under `deploy/`.
- The agent now reports its own `version` in JSON, for fleet auditing.

### Fixed

- **An always-firing warning.** "Input and multipart bounds" warned on every
  unpatched host regardless of the actual values, which trains people to ignore
  the WARN level. It is now INFO at or below defaults and WARN only above them.
- **Removed a check that could never fire.** The empty-`date.timezone` test was
  dead code: PHP rewrites an invalid value to UTC during startup, after raising
  the diagnostic, so `ini_get()` never observes it. The script now says so and
  points at the startup log instead.
- All 14 CLI flags are documented in the README; previously only 7 were.

## [1.0.0] — 2026-10-21

Initial release, published the day of the PHP advisories.

- `php2shell_verify.py`: remote patch-level checking for one host (`-u`) or a
  fleet (`-f`), with `VULNERABLE` / `PATCHED` / `VENDOR-CHECK` / `UNKNOWN` /
  `UNREACHABLE` verdicts, optional `--probe` for leftover `phpinfo` pages,
  CSV/JSON export and a non-zero exit code for CI.
- `verify_php2shell.php`: token-gated on-host agent verifying every mitigation
  in both advisories, with severity that adapts to patch status.
