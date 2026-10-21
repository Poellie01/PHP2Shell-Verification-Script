<?php
/**
 * PHP2Shell verification script
 *
 *   CVE-2026-109618  RCE via OOM corruption      GHSA-w8hw-w9fx-j79w
 *   CVE-2026-109619  RCE via stale global state  GHSA-6wmf-4rv5-p3rp
 *
 * Verifies one host against the PHP advisories of 2026-10-21: patch level
 * first, then every configuration mitigation the advisories list, including
 * the override traps they warn about.
 *
 * READ-ONLY. Contains no exploit code. It inspects the running configuration
 * of the worker that serves it and reports what is actually in effect.
 *
 * Run it under the SAPI that serves your web traffic. A CLI run reads the CLI
 * php.ini, which is frequently not the configuration PHP-FPM or mod_php uses.
 *
 *   CLI:  php verify_php2shell.php [--docroot=/var/www/html] [--json]
 *   Web:  set ACCESS_TOKEN below, then
 *         curl 'https://host/verify_php2shell.php?token=YOUR_TOKEN'
 *
 * Exit code: 0 = no FAIL items, 1 = at least one FAIL.
 *
 * Remove this file from any public document root when you are done.
 *
 * Author: Poellie -- https://github.com/Poellie01
 *
 * Sources:
 *   https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
 *   https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
 *
 * License: MIT
 */

// ---------------------------------------------------------------------------
// Web access gate. Empty = CLI only.
// To allow web use set a long random string, e.g. bin2hex(random_bytes(16)).
// ---------------------------------------------------------------------------
const ACCESS_TOKEN = '';

const FIXED        = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
const BACKPORT_EOL = ['7.4', '8.0', '8.1']; // PHP team published minimal source backports

$IS_CLI  = (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg');
$WANT_JSON = false;
$DOCROOT = '';

if ($IS_CLI) {
    foreach (array_slice($argv, 1) as $a) {
        if ($a === '--json') {
            $WANT_JSON = true;
        } elseif (strpos($a, '--docroot=') === 0) {
            $DOCROOT = substr($a, 10);
        } elseif ($a === '-h' || $a === '--help') {
            fwrite(STDOUT, "Usage: php verify_php2shell.php [--docroot=/var/www/html] [--json]\n");
            exit(0);
        }
    }
} else {
    header('Content-Type: text/plain; charset=utf-8');
    header('X-Robots-Tag: noindex, nofollow');
    header('Cache-Control: no-store');
    if (ACCESS_TOKEN === '') {
        http_response_code(403);
        echo "Web access disabled.\n\nSet ACCESS_TOKEN in this file to a long random string,\n";
        echo "then request it as ?token=<that string>.\n";
        exit(1);
    }
    if (!hash_equals(ACCESS_TOKEN, isset($_GET['token']) ? (string) $_GET['token'] : '')) {
        http_response_code(404);
        echo "Not found\n";
        exit(1);
    }
    $WANT_JSON = isset($_GET['json']);
}
if ($DOCROOT === '' && isset($_SERVER['DOCUMENT_ROOT'])) {
    $DOCROOT = (string) $_SERVER['DOCUMENT_ROOT'];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
$CHECKS = [];

function add($status, $cve, $title, $detail, $action = '')
{
    global $CHECKS;
    $CHECKS[] = ['status' => $status, 'cve' => $cve, 'title' => $title,
                 'detail' => $detail, 'action' => $action];
}

/** Severity that depends on whether the host is already patched. */
function sev($patched, $unpatchedStatus, $patchedStatus = 'INFO')
{
    return $patched === true ? $patchedStatus : $unpatchedStatus;
}

function parse_bytes($v)
{
    $v = trim((string) $v);
    if ($v === '' || $v === '0') {
        return 0;
    }
    if ($v === '-1') {
        return -1;
    }
    $num  = (float) $v;
    switch (strtolower(substr($v, -1))) {
        case 'g':
            $num *= 1024;
            // no break
        case 'm':
            $num *= 1024;
            // no break
        case 'k':
            $num *= 1024;
    }
    return (int) $num;
}

function human_bytes($b)
{
    if ($b === -1) {
        return 'unlimited (-1)';
    }
    if ($b === 0) {
        return 'unlimited (0)';
    }
    $u = ['B', 'K', 'M', 'G'];
    $i = 0;
    while ($b >= 1024 && $i < 3) {
        $b /= 1024;
        $i++;
    }
    return rtrim(rtrim(number_format($b, 1, '.', ''), '0'), '.') . $u[$i];
}

function is_truthy($v)
{
    return in_array(strtolower(trim((string) $v)), ['1', 'on', 'yes', 'true'], true);
}

function ini_detail($name)
{
    static $all = null;
    if ($all === null) {
        $all = function_exists('ini_get_all') ? @ini_get_all(null, true) : [];
        if (!is_array($all)) {
            $all = [];
        }
    }
    return isset($all[$name]) ? $all[$name] : null;
}

/** session.save_path may be "N;/path" or "N;MODE;/path". */
function save_path_dir($v)
{
    $v = (string) $v;
    if ($v === '') {
        return '';
    }
    $parts = explode(';', $v);
    return end($parts);
}

function within_open_basedir($path, $obd)
{
    if ($path === '') {
        return true;
    }
    foreach (explode(PATH_SEPARATOR, $obd) as $base) {
        $base = trim($base);
        if ($base !== '' && strpos($path, $base) === 0) {
            return true;
        }
    }
    return false;
}

$branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

// ---------------------------------------------------------------------------
// 0. Environment
// ---------------------------------------------------------------------------
$pid = function_exists('getmypid') ? @getmypid() : false;
add('INFO', '-', 'Environment',
    sprintf('PHP %s, SAPI %s%s', PHP_VERSION, PHP_SAPI, $pid ? ', worker PID ' . $pid : ''),
    $IS_CLI
        ? 'This is a CLI run, reading the CLI php.ini, which is frequently NOT the configuration '
          . 'used by PHP-FPM or mod_php. Re-run under your web SAPI for the authoritative answer.'
        : '');

$scanned = trim((string) php_ini_scanned_files());
$nScan   = $scanned === '' ? 0 : count(array_filter(array_map('trim', explode(',', $scanned))));
add('INFO', '-', 'Loaded configuration',
    'php.ini: ' . (php_ini_loaded_file() ?: '(none)') . ' | ' . $nScan . ' additional .ini file(s)', '');

// ---------------------------------------------------------------------------
// 1. Patch level — the only complete fix for either CVE
// ---------------------------------------------------------------------------
$patched = null; // true | false | null (unknown)
if (isset(FIXED[$branch])) {
    $target  = FIXED[$branch];
    $patched = version_compare(PHP_VERSION, $target, '>=');
    if ($patched) {
        add('PASS', 'both', 'Patch level',
            PHP_VERSION . ' >= ' . $target . ' — patched against both CVEs. Remaining items below '
            . 'are hardening, not requirements.', '');
    } else {
        add('FAIL', 'both', 'Patch level',
            PHP_VERSION . ' < ' . $target . ' — UNPATCHED for CVE-2026-109618 and CVE-2026-109619. '
            . 'Both advisories state updating is the only complete mitigation.',
            'Update to ' . $target . ' or later and restart every worker. If your distribution '
            . 'backports fixes without changing the PHP version string, confirm against your package '
            . 'changelog (apt changelog php' . $branch . ' / rpm -q --changelog php) before treating '
            . 'this as a false positive.');
    }
} elseif (in_array($branch, BACKPORT_EOL, true)) {
    add('UNKNOWN', 'both', 'Patch level',
        'PHP ' . PHP_VERSION . ' is on branch ' . $branch . ', which the PHP project no longer updates. '
        . 'The version string alone cannot show whether a fix is applied.',
        'The PHP security team published minimal source backports for 7.4/8.0/8.1, and distributions '
        . 'and LTS vendors ship their own. Confirm with your vendor package changelog, or upgrade to a '
        . 'supported branch. Treat as vulnerable until confirmed.');
} elseif (version_compare($branch, '8.2', '<')) {
    add('FAIL', 'both', 'Patch level',
        'PHP ' . PHP_VERSION . ' predates every branch covered by these advisories and is long out of support.',
        'Upgrade to a supported branch (8.2+).');
} else {
    add('UNKNOWN', 'both', 'Patch level',
        'PHP ' . PHP_VERSION . ' is on branch ' . $branch . ', newer than this script\'s table.',
        'Check the php.net advisory for this branch\'s fixed version, then update FIXED in this file.');
}

// ---------------------------------------------------------------------------
// 2. SAPI exposure, per the advisories' own confirmation matrix
// ---------------------------------------------------------------------------
switch (PHP_SAPI) {
    case 'apache2handler':
        add('WARN', 'both', 'SAPI exposure: mod_php (highest risk)',
            '109618: CONFIRMED full RCE, validated over HTTP with default input and memory limits on '
            . 'normal prefork configurations — shutdown runs even when startup fails, so the attack '
            . 'completes before any application code. 109619: basis of the confirmed mod_php RCE; '
            . '.htaccess and php_value/php_flag/php_admin_* apply before php_request_startup() and are '
            . 'an early consumer.',
            'Prioritise this host above all others. If you cannot patch immediately, consider moving '
            . 'to PHP-FPM, where 109618 has no demonstrated exploit.');
        break;
    case 'fpm-fcgi':
        add('INFO', 'both', 'SAPI exposure: PHP-FPM',
            '109618: partial — FPM exits the child when startup fails, which blocks the invalid state; '
            . 'source analysis supports susceptibility after normal startup but no complete exploit has '
            . 'been demonstrated. 109619: RCE VALIDATED against FPM via session upload progress, with a '
            . 'normal dynamic pool.',
            'The session.upload_progress item below is the one that matters most here.');
        break;
    case 'litespeed':
        add('INFO', 'both', 'SAPI exposure: LiteSpeed/LSAPI',
            'Modeled on FPM. Both advisories call it a conditional candidate: likely susceptible, not validated.', '');
        break;
    case 'frankenphp':
        add('WARN', '109618', 'SAPI exposure: FrankenPHP',
            'Source analysis suggests it is likely susceptible to 109618, because it calls shutdown '
            . 'unconditionally like mod_php. Not validated.', '');
        break;
    case 'cgi-fcgi':
        add('INFO', 'both', 'SAPI exposure: CGI/FastCGI',
            'A web-serving SAPI, so both CVEs apply. The advisories do not single this one out.', '');
        break;
    default:
        if (!$IS_CLI) {
            add('INFO', 'both', 'SAPI exposure: ' . PHP_SAPI,
                'All web-serving SAPIs are affected. mod_php is rated highest risk.', '');
        }
}

// FPM: PHP_VALUE / PHP_ADMIN_VALUE from the frontend is the 109619 INI-diagnostics consumer
if (PHP_SAPI === 'fpm-fcgi' || PHP_SAPI === 'cgi-fcgi') {
    $passed = array_values(array_filter(['PHP_VALUE', 'PHP_ADMIN_VALUE'],
        static function ($k) { return isset($_SERVER[$k]); }));
    if ($passed) {
        add(sev($patched, 'WARN'), '109619', 'FastCGI PHP_VALUE passed by the frontend',
            'The frontend sends ' . implode(' and ', $passed) . ' with this request. Per GHSA-6wmf-4rv5-p3rp, '
            . 'FPM is exploitable through INI diagnostics only when the frontend passes these and one of '
            . 'them triggers a diagnostic.',
            'Move these settings into the FPM pool configuration, which applies at worker start and is '
            . 'not an early consumer, and remove them from the nginx/Apache FastCGI parameters.');
    } else {
        add('PASS', '109619', 'FastCGI PHP_VALUE not passed',
            'No PHP_VALUE/PHP_ADMIN_VALUE in this request, so the INI-diagnostics consumer path is not '
            . 'exposed via the frontend.', '');
    }
}

// ---------------------------------------------------------------------------
// 3. CVE-2026-109618 — RCE via OOM corruption
// ---------------------------------------------------------------------------
$mlLocal  = ini_get('memory_limit');
$mlB      = parse_bytes($mlLocal);
$mlDet    = ini_detail('memory_limit');
$mlGlobal = $mlDet ? $mlDet['global_value'] : null;

if ($mlB === -1) {
    add('PASS', '109618', 'memory_limit',
        'memory_limit = -1, the advisory\'s primary configuration mitigation. Note it is not complete: '
        . 'if mmap() or another allocation fails, the vulnerable path can still be reached.', '');
} else {
    $extra = ($mlGlobal !== null && parse_bytes($mlGlobal) === -1)
        ? ' The global value is -1, so a pool, directory or application setting has restored a finite '
          . 'limit (global=-1, effective=' . $mlLocal . ') — the advisory tells you to check for exactly this.'
        : '';
    add(sev($patched, 'WARN'), '109618', 'memory_limit',
        'memory_limit = ' . $mlLocal . ' (' . human_bytes($mlB) . '), not -1. The exploit relies on a '
        . 'predictable per-request limit.' . $extra,
        'Set memory_limit=-1 administratively (php_admin_value in the FPM pool or Apache config), '
        . 'restart all workers, and confirm no pool, directory or application setting restores a finite '
        . 'limit. Pair it with a per-worker container or cgroup limit.');
}

if ($mlB === -1) {
    $probe = @ini_set('memory_limit', '2048M');
    $stuck = (parse_bytes(ini_get('memory_limit')) !== -1);
    if ($probe !== false) {
        @ini_set('memory_limit', '-1');
    }
    if ($stuck) {
        add(sev($patched, 'WARN'), '109618', 'memory_limit is overridable at runtime',
            'ini_set(\'memory_limit\', ...) succeeded, so application code can restore a finite limit '
            . 'and undo the mitigation.',
            'Pin it with php_admin_value rather than php_value or ini_set.');
    } else {
        add('PASS', '109618', 'memory_limit is pinned',
            'Runtime ini_set() cannot change memory_limit — it is enforced administratively.', '');
    }
}

// post_max_size. The advisory gives no number; 8M/32M come from the php.net bulletin.
$pms       = ini_get('post_max_size');
$pmsB      = parse_bytes($pms);
$umf       = ini_get('upload_max_filesize');
$umfB      = parse_bytes($umf);
$uploadsOn = is_truthy(ini_get('file_uploads')) && $umfB !== 0;
$ceiling   = $uploadsOn ? 32 * 1024 * 1024 : 8 * 1024 * 1024;
$ceilLabel = $uploadsOn ? '32M (uploads in use)' : '8M (no uploads needed)';

if ($pmsB === 0 || $pmsB === -1) {
    add(sev($patched, 'FAIL'), '109618', 'post_max_size',
        'post_max_size = ' . $pms . ' — no limit on request body size.',
        'Set post_max_size to ' . $ceilLabel . ' and enforce decoded request size at the frontend too. '
        . 'Note a multipart request without a usable declared Content-Length can pass the initial '
        . 'post_max_size check and keep supplying body data, so the frontend limit matters.');
} elseif ($pmsB <= $ceiling) {
    add('PASS', '109618', 'post_max_size',
        'post_max_size = ' . $pms . ', within the bulletin\'s ceiling of ' . $ceilLabel . '.', '');
} else {
    add(sev($patched, 'WARN'), '109618', 'post_max_size',
        'post_max_size = ' . $pms . ' (' . human_bytes($pmsB) . '), above the bulletin\'s ceiling of ' . $ceilLabel . '.',
        'Lower it to 8M without uploads, 32M with, and enforce decoded request size at the frontend.');
}

if ($uploadsOn && $umfB > 0 && $pmsB > 0) {
    if ($umfB >= $pmsB) {
        add(sev($patched, 'WARN'), '109618', 'upload_max_filesize',
            'upload_max_filesize = ' . $umf . ' is not below post_max_size = ' . $pms . '.',
            'Keep upload_max_filesize below post_max_size.');
    } else {
        add('PASS', '109618', 'upload_max_filesize',
            'upload_max_filesize = ' . $umf . ' is below post_max_size = ' . $pms . '.', '');
    }
}

// Input-shape bounds the advisory asks you to reduce
$nest = (int) ini_get('max_input_nesting_level');
if ($nest >= 64) {
    add(sev($patched, 'WARN'), '109618', 'max_input_nesting_level',
        'max_input_nesting_level = ' . $nest . ' (default 64). The advisory asks you to reduce it, '
        . 'because nested field names multiply the memory used per request.',
        'Lower it to the smallest value your application tolerates.');
} else {
    add('PASS', '109618', 'max_input_nesting_level',
        'max_input_nesting_level = ' . $nest . ', below the default of 64.', '');
}

$maxVars    = (int) ini_get('max_input_vars');
$maxUploads = (int) ini_get('max_file_uploads');
add(sev($patched, 'WARN'), '109618', 'Input and multipart bounds',
    'max_input_vars = ' . $maxVars . ', max_file_uploads = ' . $maxUploads . '. Headers per multipart '
    . 'part are unbounded in PHP, and empty file controls do not count toward max_file_uploads but '
    . 'still allocate file metadata — both are named OOM triggers.',
    'Bound the number of input variables, multipart parts, headers per part and uploads at the '
    . 'frontend or application level. If the application does not use multipart form data, block that '
    . 'content type at the frontend entirely.');

// Address-space rlimits, which the advisory explicitly warns against
if (@is_readable('/proc/self/limits')) {
    $txt  = (string) @file_get_contents('/proc/self/limits');
    $hits = [];
    foreach (['Max address space' => 'RLIMIT_AS', 'Max data size' => 'RLIMIT_DATA'] as $label => $name) {
        if (preg_match('/^' . preg_quote($label, '/') . '\s+(\S+)\s+(\S+)/mi', $txt, $m)
            && strtolower($m[1]) !== 'unlimited') {
            $hits[] = $name . ' soft=' . $m[1];
        }
    }
    if ($hits) {
        add(sev($patched, 'WARN'), '109618', 'Address-space rlimit is set',
            implode(', ', $hits) . ' on this worker. The advisory warns these make mmap() fail at the '
            . 'limit, which triggers the vulnerable longjmp() path.',
            'Remove RLIMIT_AS/RLIMIT_DATA and use a per-worker container or cgroup memory limit instead.');
    } else {
        add('PASS', '109618', 'Address-space rlimits',
            'No RLIMIT_AS / RLIMIT_DATA cap on this worker, as the advisory prefers.', '');
    }
}

// cgroup memory ceiling (the recommended availability boundary)
$cg = null;
foreach (['/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory/memory.limit_in_bytes'] as $f) {
    if (@is_readable($f)) {
        $cg = trim((string) @file_get_contents($f));
        break;
    }
}
if ($cg !== null) {
    $unlimited = ($cg === 'max' || $cg === '' || (is_numeric($cg) && (float) $cg > 1e15));
    add('INFO', '109618', 'cgroup memory ceiling',
        $unlimited
            ? 'No cgroup memory ceiling on this worker.'
            : 'cgroup memory ceiling: ' . human_bytes((int) $cg) . '.',
        'The advisory prefers a container or cgroup limit over memory_limit, but notes it does not '
        . 'guarantee allocation failure, and that killing a container can take down the master and all '
        . 'workers unless each worker has its own cgroup.');
}

// ---------------------------------------------------------------------------
// 4. CVE-2026-109619 — RCE via stale global state
// ---------------------------------------------------------------------------
$upLocal  = ini_get('session.upload_progress.enabled');
$upDet    = ini_detail('session.upload_progress.enabled');
$upGlobal = $upDet ? $upDet['global_value'] : null;

if ($upLocal === false && $upDet === null) {
    add('UNKNOWN', '109619', 'session.upload_progress.enabled',
        'Directive not readable (session extension missing, or ini_get_all disabled).',
        'Confirm with: php -i | grep session.upload_progress.enabled');
} elseif (is_truthy($upLocal)) {
    $extra = ($upGlobal !== null && !is_truthy($upGlobal))
        ? ' The global value is off but the effective value is on, so it has been re-enabled '
          . 'per-directory or per-request — the advisory says not to rely on those.'
        : '';
    add(sev($patched, 'FAIL', 'WARN'), '109619', 'session.upload_progress.enabled',
        'session.upload_progress.enabled is ON.' . $extra . ' This is the consumer used in the RCE '
        . 'validated against both mod_php and FPM. It reaches session handling before ordinary '
        . 'initialization, needs no session_start() call, and is enabled by default.',
        ($patched === true
            ? 'You are patched, so this is no longer exploitable via the known paths. The advisory still '
              . 'recommends disabling it if unused, calling the feature "hardly-used and hardly-tested".'
            : 'Set session.upload_progress.enabled=0 administratively — php.ini, FPM pool, or server '
              . 'config that applies before request parsing — then restart every worker. Do not rely on '
              . 'ini_set() or .user.ini. This blocks the demonstrated producer and consumer, not other '
              . 'lifecycle paths.'));
} else {
    add('PASS', '109619', 'session.upload_progress.enabled',
        'Off in this worker, blocking the demonstrated session producer and consumer (though not other '
        . 'lifecycle paths).', '');
}

// 8.5 fatal_error_backtraces — the advisory's strongest confirmed case
$feb = ini_get('fatal_error_backtraces');
if ($branch === '8.5') {
    if ($feb === false) {
        add('UNKNOWN', '109619', 'fatal_error_backtraces',
            'Directive not readable on this 8.5 build.',
            'Confirm with: php -i | grep fatal_error_backtraces');
    } elseif (is_truthy($feb)) {
        add(sev($patched, 'FAIL', 'INFO'), '109619', 'fatal_error_backtraces (PHP 8.5)',
            'fatal_error_backtraces is ON. This is the advisory\'s strongest confirmed case: fatal error '
            . 'handling stores request-owned backtrace state that is never reset during shutdown, and it '
            . 'is the basis of the confirmed mod_php RCE.',
            ($patched === true
                ? 'Patched, so this is informational.'
                : 'Set fatal_error_backtraces=0 administratively and restart every worker. This removes '
                  . 'the confirmed RCE producer but not other state families.'));
    } else {
        add('PASS', '109619', 'fatal_error_backtraces (PHP 8.5)',
            'Off, removing the confirmed RCE producer.', '');
    }
} elseif ($feb !== false && is_truthy($feb)) {
    add('INFO', '109619', 'fatal_error_backtraces',
        'On, but the advisory ties this producer to PHP 8.5. This branch is ' . $branch . '.', '');
}

// Pre-init INI diagnostics: the advisory's named examples
$diag = [];
if (is_truthy(ini_get('auto_detect_line_endings'))) {
    $diag[] = 'auto_detect_line_endings=1 (deprecated)';
}
if (version_compare($branch, '8.5', '>=')) {
    if (ini_get('report_memleaks') !== false && !is_truthy(ini_get('report_memleaks'))) {
        $diag[] = 'report_memleaks=0 (emits a diagnostic on 8.5)';
    }
    $iel = ini_get('intl.error_level');
    if ($iel !== false && (int) $iel !== 0) {
        $diag[] = 'intl.error_level=' . $iel . ' (nonzero emits a diagnostic on 8.5)';
    }
}
if (trim((string) ini_get('date.timezone')) === '') {
    $diag[] = 'date.timezone is empty';
}
$obd = (string) ini_get('open_basedir');
if ($obd !== '') {
    foreach (['session.save_path' => save_path_dir(ini_get('session.save_path')),
              'upload_tmp_dir'    => (string) ini_get('upload_tmp_dir'),
              'sys_temp_dir'      => (string) ini_get('sys_temp_dir'),
              'error_log'         => (string) ini_get('error_log')] as $k => $p) {
        if ($p !== '' && $p[0] === '/' && !within_open_basedir($p, $obd)) {
            $diag[] = $k . '=' . $p . ' falls outside open_basedir';
        }
    }
}
if ($diag) {
    add(sev($patched, 'WARN'), '109619', 'Settings that emit pre-init diagnostics',
        implode('; ', $diag) . '. Any warning, notice or deprecation raised during early INI application '
        . 'can act as the consumer, even when not displayed or logged.',
        'Remove or correct these. Changing error_reporting, using @, or disabling display_errors or '
        . 'log_errors does NOT prevent the path.');
} else {
    add('PASS', '109619', 'Settings that emit pre-init diagnostics',
        'None of the advisory\'s named diagnostic-emitting settings are in a risky state here.',
        'Not exhaustive — the advisory also lists legacy assert.* (8.3+), legacy session settings '
        . '(8.4+), invalid zend.assertions or extension values, and malformed quantities. Confirm with '
        . 'your startup log: php -i 2>&1 | grep -i startup, plus the FPM/Apache error log.');
}

// Timeouts: a named 109619 producer
$met = (int) ini_get('max_execution_time');
add('INFO', '109619', 'Execution timeout',
    'max_execution_time = ' . ($met === 0 ? '0 (no limit)' : $met . 's') . '. "Maximum execution time '
    . 'exceeded" is a fatal error and a named producer of stale state.',
    'Prevent predictable timeouts on attacker-reachable paths. Raising the limit alone does not '
    . 'mitigate this; fix the slow paths instead.');

if (PHP_SAPI === 'fpm-fcgi') {
    add('INFO', '109619', 'FPM worker recycling',
        'The advisory suggests pm.max_requests=1 if performance allows, since both requests must be '
        . 'handled by the same worker.',
        'This cannot be read from inside PHP — check your pool configuration. Recycling lowers the '
        . 'success rate but does not remove the condition.');
}

// .user.ini overrides
$userIni = (string) ini_get('user_ini.filename');
if ($userIni !== '' && $DOCROOT !== '' && @is_dir($DOCROOT)) {
    $found = [];
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($DOCROOT, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        $seen = 0;
        foreach ($it as $f) {
            if (++$seen > 200000) {
                break;
            }
            if ($f->getFilename() !== $userIni || !$f->isReadable()) {
                continue;
            }
            $body = (string) @file_get_contents($f->getPathname(), false, null, 0, 65536);
            if (preg_match('/^\s*(session\.upload_progress|memory_limit|post_max_size|'
                . 'upload_max_filesize|fatal_error_backtraces|max_input_nesting_level)/mi', $body)) {
                $found[] = $f->getPathname();
            }
        }
    } catch (Throwable $e) {
        add('INFO', '109619', '.user.ini scan', 'Could not walk ' . $DOCROOT . ': ' . $e->getMessage(), '');
    }
    if ($found) {
        add(sev($patched, 'WARN'), '109619', '.user.ini overrides present',
            count($found) . ' ' . $userIni . ' file(s) set a directive relevant to these advisories: '
            . implode(', ', array_slice($found, 0, 10)) . (count($found) > 10 ? ', ...' : ''),
            'Per-directory files are applied per request. The advisories say not to rely on them for '
            . 'these mitigations — move the settings to php_admin_value so nothing can override them.');
    } else {
        add('PASS', '109619', '.user.ini overrides',
            'No ' . $userIni . ' under ' . $DOCROOT . ' touches the advisory directives.', '');
    }
} elseif ($userIni !== '') {
    add('INFO', '109619', '.user.ini scan skipped',
        'No document root known, so per-directory overrides were not checked.',
        'Re-run with --docroot=/path/to/webroot, or under the web SAPI.');
}

// Logging posture for the audit the advisory recommends
$logErrors = is_truthy(ini_get('log_errors'));
$errLog    = (string) ini_get('error_log');
$erAll     = ((int) ini_get('error_reporting') === E_ALL);
if (!$logErrors || ($errLog === '' && PHP_SAPI !== 'apache2handler') || !$erAll) {
    add('INFO', '109619', 'Audit logging posture',
        'log_errors=' . ($logErrors ? 'On' : 'Off') . ', error_log=' . ($errLog !== '' ? $errLog : '(SAPI default)')
        . ', error_reporting=' . (int) ini_get('error_reporting') . ($erAll ? ' (E_ALL)' : ' (not E_ALL)') . '.',
        'For the log review the advisory recommends, set log_errors=On, a working error_log and '
        . 'error_reporting=E_ALL in startup config, then look for repeated pre-script warnings or '
        . 'deprecations, diagnostics during cleanup, fatal/parse/uncaught errors, and "Maximum execution '
        . 'time exceeded". Absence of entries does not prove safety: a crash can happen before PHP logs.');
} else {
    add('PASS', '109619', 'Audit logging posture',
        'log_errors=On, error_log set, error_reporting=E_ALL — suitable for the advisory\'s log review.',
        'Look for repeated pre-script diagnostics, cleanup diagnostics, fatal/parse/uncaught errors and '
        . '"Maximum execution time exceeded". Absence of entries does not prove safety.');
}

add('INFO', '109619', 'Worker coverage',
    'This result describes one worker' . ($pid ? ' (PID ' . $pid . ')' : '') . '. Both CVEs require the '
    . 'same worker to handle the producing and consuming request.',
    'A worker started before a config change keeps the old values, which is why both advisories say to '
    . 'restart every worker. Run this check repeatedly and compare PIDs to sample more workers.');

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
$counts = ['PASS' => 0, 'FAIL' => 0, 'WARN' => 0, 'INFO' => 0, 'UNKNOWN' => 0];
foreach ($CHECKS as $c) {
    $counts[$c['status']]++;
}

if ($WANT_JSON) {
    echo json_encode([
        'script'         => 'verify_php2shell',
        'author'         => 'Poellie (https://github.com/Poellie01)',
        'generated'      => gmdate('c'),
        'php_version'    => PHP_VERSION,
        'sapi'           => PHP_SAPI,
        'pid'            => $pid ?: null,
        'branch'         => $branch,
        'patched'        => $patched,
        'fixed_versions' => FIXED,
        'counts'         => $counts,
        'checks'         => $CHECKS,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    exit($counts['FAIL'] > 0 ? 1 : 0);
}

$colour  = $IS_CLI && function_exists('posix_isatty') && @posix_isatty(STDOUT);
$palette = ['PASS' => "\033[32m", 'FAIL' => "\033[31m", 'WARN' => "\033[33m",
            'INFO' => "\033[36m", 'UNKNOWN' => "\033[35m"];

function out($s = '')
{
    echo $s . "\n";
}

function wrap($text, $indent)
{
    $pad = str_repeat(' ', $indent);
    return $pad . implode("\n" . $pad, explode("\n", wordwrap($text, max(40, 100 - $indent), "\n", false)));
}

out(<<<'ART'
 ___          _ _ _
| _ \___  ___| | (_)___     PHP2Shell verification
|  _/ _ \/ -_) | | / -_)    by Poellie - github.com/Poellie01
|_| \___/\___|_|_|_\___|
ART);
out();
out('CVE-2026-109618 (OOM corruption) / CVE-2026-109619 (stale global state)');
out('Advisories of 2026-10-21. Fixed in 8.2.35, 8.3.36, 8.4.27, 8.5.12.');
out(str_repeat('=', 82));
out();

foreach ($CHECKS as $c) {
    $tag = $colour
        ? $palette[$c['status']] . $c['status'] . "\033[0m" . str_repeat(' ', 7 - strlen($c['status']))
        : str_pad($c['status'], 7);
    $cve = $c['cve'] === '-' ? '' : ' [' . ($c['cve'] === 'both' ? 'both CVEs' : 'CVE-2026-' . $c['cve']) . ']';
    out($tag . ' ' . $c['title'] . $cve);
    out(wrap($c['detail'], 8));
    if ($c['action'] !== '') {
        out(wrap('-> ' . $c['action'], 8));
    }
    out();
}

out(str_repeat('=', 82));
out(sprintf('Summary: %d FAIL, %d WARN, %d UNKNOWN, %d PASS',
    $counts['FAIL'], $counts['WARN'], $counts['UNKNOWN'], $counts['PASS']));
out();
if ($patched === true) {
    out('PATCHED. Both CVEs are fixed in this build. WARN/INFO items above are');
    out('hardening and defence in depth, not open vulnerabilities.');
} elseif ($patched === false) {
    out('UNPATCHED. Update PHP — both advisories state that is the only complete');
    out('mitigation. The items above only reduce exposure to specific paths.');
} else {
    out('PATCH STATUS UNKNOWN. Confirm with your vendor before treating this host');
    out('as safe. Treat it as vulnerable until you have that confirmation.');
}
if (!$IS_CLI) {
    out();
    out('Remove this file from the document root now that you have the result.');
}

exit($counts['FAIL'] > 0 ? 1 : 0);
