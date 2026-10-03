#!/bin/bash
# Daily backup, run by launchd on the Mac host / cron on Linux (installed by deploy.sh): MySQL dump + the JWT signing key.
# Keeps 7 days in ~/mirattic-auth-backups (outside ~/Documents: launchd can't read TCC-protected folders).
set -euo pipefail
export PATH=/opt/homebrew/bin:/usr/local/bin:$HOME/.orbstack/bin:$PATH
umask 077
dir=$HOME/mirattic-auth-backups
mkdir -p "$dir"
# Prune first, so a failing dump never keeps old dumps (and deleted accounts) past the retention.
find "$dir" \( -name 'mirattic-auth-*.sql.gz*' -o -name 'signing-key-*.jwk.json*' \) -mtime +6 -delete
stamp=$(date +%Y%m%d-%H%M)
file=$dir/mirattic-auth-$stamp.sql.gz
key=$dir/signing-key-$stamp.jwk.json
trap 'rm -f "$file.tmp" "$key.tmp"' EXIT
docker exec mirattic-auth-mysql-1 sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump -uroot --single-transaction --no-tablespaces mirattic_auth' \
  | gzip > "$file.tmp"
mv "$file.tmp" "$file"
# The signing key is a secret: same 0600 dir, never leaves the host. Losing it = every token invalid.
# Straight from the volume: works with the app stopped too (the Lightsail move stops it before the last backup).
docker run --rm -v mirattic-auth_signing-key:/keys:ro busybox cat /keys/signing-key.jwk.json > "$key.tmp"
mv "$key.tmp" "$key"
echo "backup $file $key"
