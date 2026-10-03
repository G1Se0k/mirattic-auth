#!/bin/sh
# Lightsail move, on the new host as deploy (copied to ~/move/restore.sh): sh ~/move/restore.sh auth|sync|flow —
# wipes that service's stack on this host, restores the
# newest dump from ~/move into a fresh MySQL (Auth: also the signing key into its volume). The app is started
# afterwards by deploy.sh. Runbook: Mirattic Auth docs/deployment.md "Host move".
set -eu
m=$HOME/move
svc=${1:-}
case "$svc" in
  auth) cd ~/apps/mirattic-auth/deploy; set -- docker compose; dump=$(ls -t $m/mirattic-auth-backups/*.sql.gz | head -1) ;;
  sync) cd ~/apps/mirattic-sync/deploy; set -- docker compose; dump=$(ls -t $m/mirattic-sync-backups/*.sql.gz | head -1) ;;
  flow) cd ~/apps/mirattic-flow; set -- docker compose -f docker-compose.prod.yml --env-file .env.prod
        dump=$(ls -t $m/mirattic-flow-backups/*.sql.gz | head -1) ;;
  *) echo "usage: restore.sh auth|sync|flow" >&2; exit 2 ;;
esac
"$@" down -v
"$@" up -d --wait mysql
gunzip -c "$dump" | "$@" exec -T mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -uroot "$MYSQL_DATABASE"'
if [ "$svc" = auth ]; then
  "$@" up keys-init
  key=$(ls -t $m/mirattic-auth-backups/signing-key-*.jwk.json | head -1)
  docker run --rm -i -v mirattic-auth_signing-key:/keys busybox \
    sh -c "cat > /keys/signing-key.jwk.json && chown 65534:65534 /keys/signing-key.jwk.json && chmod 600 /keys/signing-key.jwk.json" < "$key"
fi
echo "restored $dump"
