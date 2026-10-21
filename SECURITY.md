# Security Policy

## Scope

This repository contains **verification tooling only** — it reads versions and
configuration and reports what it finds. It contains no exploit code, and pull
requests adding exploit code, payloads or weaponised proofs-of-concept will be
declined.

For the vulnerabilities themselves (CVE-2026-109618 / CVE-2026-109619), report
to the PHP project, not here: https://github.com/php/php-src/security

## Reporting an issue in these scripts

Open a [private security advisory](https://github.com/Poellie01/PHP2Shell-Verification-Script/security/advisories/new),
or a public issue if the problem is not sensitive.

Things worth reporting:

- A **wrong verdict** — a host reported `PATCHED` that is not, or `VULNERABLE`
  that is. This is the most serious class of bug here, because people act on it.
- A check that cannot actually observe what it claims to. One such case has
  already been removed: an invalid `date.timezone` is rewritten to UTC during
  startup, so no in-request check can ever see it.
- Information disclosure by the agent, including anything leaked before the
  token gate.
- A crash or hang against an unusual host.

Please include the PHP version, SAPI, and the relevant `php -i` lines.

## Using the agent safely

`verify_php2shell.php` is intended to be short-lived:

- It refuses all web requests until `ACCESS_TOKEN` is set, and returns `404` on
  a token mismatch, compared with `hash_equals()`.
- Prefer `--ssh` mode, which pipes the agent to the host and runs it there
  without writing anything to the remote filesystem.
- If you do deploy it to a document root, **remove it afterwards.** Leaving it
  reachable is the same mistake as leaving a `phpinfo()` page up.
- Never commit a real token. CI fails the build if `ACCESS_TOKEN` is non-empty.

## Authorisation

Only check hosts you own or are explicitly authorised to test. `--probe` looks
for leftover `phpinfo` pages, which resembles scanning in an access log, and is
off by default for that reason. If a third party operates your infrastructure,
tell them before you run it.
