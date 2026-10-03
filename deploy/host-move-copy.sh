#!/bin/sh
# Lightsail move (docs/deployment.md "Host move"), run on the admin Mac:
#   sh deploy/host-move-copy.sh [auth] [sync] [flow]
# Takes a fresh backup on the Mac host of each service named (stop its app container first at cutover), then sends
# the newest Auth / Sync / Flow dumps, the Auth signing key and the three env files to the new host's ~/move (0700).
# Streams through this Mac without saving anything here.
set -eu
for s in "$@"; do case $s in auth|sync|flow) ;; *) echo "usage: host-move-copy.sh [auth] [sync] [flow]" >&2; exit 2 ;; esac; done
# Fresh backups with this checkout's backup.sh (Flow's and Sync's from the sibling repos).
here=$(cd "$(dirname "$0")" && pwd)
for s in "$@"; do
  case $s in auth) b=$here/backup.sh ;; sync) b=$here/../../sync/deploy/backup.sh ;; flow) b=$here/../../flow/backup.sh ;; esac
  ssh giseok@ssh.mirattic.com 'bash -s' < "$b" >/dev/null
done
ssh giseok@ssh.mirattic.com "set -eu
export PATH=/opt/homebrew/bin:/usr/local/bin:\$PATH
cd ~
flow=\$(docker inspect -f '{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}' mirattic-flow-prod-mysql-1)
COPYFILE_DISABLE=1 tar -cz \
  \"\$(ls -t mirattic-auth-backups/mirattic-auth-*.sql.gz | head -1)\" \
  \"\$(ls -t mirattic-auth-backups/signing-key-*.jwk.json | head -1)\" \
  \"\$(ls -t mirattic-sync-backups/mirattic-*.sql.gz | head -1)\" \
  \"\$(ls -t mirattic-flow-backups/mirattic-flow-*.sql.gz | head -1)\" \
  Documents/mirattic-auth/deploy/.env Documents/mirattic-sync/deploy/.env \
  -C \"\$flow\" .env.prod" \
| ssh -i ~/.ssh/mirattic-deploy-lightsail deploy@<LIGHTSAIL_IP> 'umask 077; rm -rf ~/move/mirattic-*-backups ~/move/Documents ~/move/.env.prod; mkdir -p ~/move; tar -xz -C ~/move; find ~/move -type f ! -name restore.sh | sed "s#.*/move/##"'
