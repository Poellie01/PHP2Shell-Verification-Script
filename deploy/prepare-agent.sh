#!/bin/sh
# Prepare a token-configured copy of verify_php2shell.php for HTTP deployment.
#
# Prefer `php2shell_verify.py --ssh` where you have shell access: it writes
# nothing to the remote host, so there is no file to remember to delete. Use
# this only when the agent must be reachable over HTTP.
#
# Usage: deploy/prepare-agent.sh [output-path]
#
# Author: Poellie -- https://github.com/Poellie01
set -eu

here=$(dirname "$0")
src="$here/../verify_php2shell.php"
out=${1:-./verify_php2shell.configured.php}

[ -f "$src" ] || { echo "cannot find $src" >&2; exit 1; }

if command -v php >/dev/null 2>&1; then
    token=$(php -r 'echo bin2hex(random_bytes(16));')
elif command -v openssl >/dev/null 2>&1; then
    token=$(openssl rand -hex 16)
else
    token=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
fi

[ -n "$token" ] || { echo "could not generate a token" >&2; exit 1; }

sed "s|^const ACCESS_TOKEN = '';|const ACCESS_TOKEN = '$token';|" "$src" > "$out"
chmod 600 "$out"

grep -q "const ACCESS_TOKEN = '$token';" "$out" || {
    echo "token injection failed" >&2; rm -f "$out"; exit 1; }

cat <<EOF
Wrote $out with a fresh token.

  token: $token

Deploy, check, then remove it again:

  scp $out user@host:/var/www/html/verify_php2shell.php
  ./php2shell_verify.py -u host --token $token
  ssh user@host 'rm -f /var/www/html/verify_php2shell.php'

Leaving this file reachable is the same mistake as leaving a phpinfo() page up.
Do not commit $out -- it contains a live token.
EOF
