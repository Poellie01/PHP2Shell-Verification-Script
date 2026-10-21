# Requesting confirmation from a hosting supplier

If a third party operates your infrastructure, the fastest route to a reliable
answer is usually asking them — one message covers every site at once, and it
gets you the facts no remote check can observe.

Replace the bracketed parts and send it.

---

**Subject:** Urgent — PHP emergency release 2026-10-21, per-host confirmation needed

Hello,

PHP published an emergency release on 2026-10-21 for two critical
vulnerabilities, both rated CVSS v4.0 9.2 and both allowing unauthenticated
remote code execution as the web worker account:

- CVE-2026-109618 — RCE via OOM corruption (GHSA-w8hw-w9fx-j79w)
- CVE-2026-109619 — RCE via stale global state (GHSA-6wmf-4rv5-p3rp)

Fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12. For each site you operate for
us ([list sites]), please confirm in writing:

1. **PHP version**, exactly as `php -v` reports it, per host.
2. **Whether the host has been updated** to the fixed release for its branch,
   and if not, your patch timeline.
3. **The SAPI in use** (mod_php, PHP-FPM, LiteSpeed, FrankenPHP). The advisories
   rate mod_php highest risk — CVE-2026-109618 has a confirmed exploit there
   that completes before any application code runs. If any of our sites run
   mod_php, please prioritise them.
4. **Output of this command**, run on each host:

   ```
   php -i | grep -E 'session.upload_progress|fatal_error_backtraces|memory_limit|post_max_size|max_input_nesting_level'
   ```

5. **Any `.user.ini` files** setting those directives:

   ```
   find /var/www -name '.user.ini' -exec grep -Hn -E 'session.upload_progress|memory_limit|post_max_size|fatal_error_backtraces' {} +
   ```

6. **Whether any host runs PHP 8.1 or older.** Those receive no fix from the
   PHP project. Some distributions and LTS vendors backport, so please state
   which applies and reference the package changelog.
7. **Confirmation that no `phpinfo()` page is publicly reachable.**

If patching is not immediate, please confirm which interim measures are in
place. The advisories list these, and note that none makes an installation
safe:

- `memory_limit=-1`, set so applications cannot override it (`php_admin_value`
  in the FPM pool or Apache config), with all workers restarted.
- A conservative `post_max_size`, with request size also bounded at the proxy.
- `session.upload_progress.enabled=0`, set in startup configuration rather than
  `.user.ini` or `ini_set()`, with all workers restarted.
- On PHP 8.5, `fatal_error_backtraces=0`, with all workers restarted.

Finally, please confirm `log_errors=On` with `error_reporting=E_ALL` and a
working `error_log`, which the advisory recommends so the logs can be reviewed.

We are happy to run the verification ourselves if you prefer. There is an
open-source checker at
<https://github.com/Poellie01/PHP2Shell-Verification-Script> which is read-only
and sends no payloads; it can run over SSH without writing anything to your
filesystem.

Thank you,
[name]

---

## Why these specific questions

Items 1–3 decide whether a host is vulnerable at all. Items 4–5 cover the
mitigations, and are asked as command output rather than yes/no because the
advisories warn that per-directory and per-request overrides can quietly undo
them — a pool or `.user.ini` setting can put a finite `memory_limit` back.
Item 6 matters because a version string on an EOL branch cannot tell you
whether a backport was applied.

If they would rather you did the work, `--ssh` mode needs nothing but shell
access and leaves no file behind:

```sh
./php2shell_verify.py -f hosts.txt --ssh --csv report.csv
```
