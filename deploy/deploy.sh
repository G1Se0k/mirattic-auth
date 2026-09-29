#!/bin/sh
# Runs on the deploy host after CI has `docker load`ed mirattic-auth:<tag>:
#   sh ~/Documents/mirattic-auth/deploy/deploy.sh <tag>
# Switches :current to the new image and rolls back if the health check fails.
set -eu
export PATH=/opt/homebrew/bin:/usr/local/bin:$PATH
cd "$(dirname "$0")"
image=mirattic-auth

if [ ! -f .env ]; then
  # First deploy: generate the secrets here so they never leave the host.
  umask 077
  sync_secret=$(openssl rand -base64 32 | tr -d '\n')
  flow_secret=$(openssl rand -base64 32 | tr -d '\n')
  hash() { printf "{bcrypt}%s" "$(htpasswd -bnBC 12 "" "$1" | tr -d ':\n')"; }
  {
    echo "DB_PASSWORD=$(openssl rand -hex 24)"
    echo "MYSQL_ROOT_PASSWORD=$(openssl rand -hex 24)"
    echo "SYNC_CLIENT_SECRET_HASH='$(hash "$sync_secret")'"
    echo "FLOW_CLIENT_SECRET_HASH='$(hash "$flow_secret")'"
    echo "MAIL_HOST="
    echo "MAIL_PORT=587"
    echo "MAIL_USERNAME="
    echo "MAIL_PASSWORD="
  } > .env
  # Raw client secrets: copy each to its product server's env, then delete this file.
  printf 'MIRATTIC_SYNC_CLIENT_SECRET=%s\nMIRATTIC_FLOW_CLIENT_SECRET=%s\n' "$sync_secret" "$flow_secret" > client-secrets.txt
  echo "Created deploy/.env and deploy/client-secrets.txt. Fill MAIL_* in .env, hand out client-secrets.txt, rerun." >&2
fi
if ! grep -q '^MAIL_HOST=..*' .env; then
  echo "deploy/.env: MAIL_HOST is empty (password reset mail needs SMTP). Not deploying." >&2
  exit 1
fi

# Daily DB + signing-key backup (backup.sh) as a launchd agent, refreshed on every deploy.
support="$HOME/Library/Application Support/mirattic-auth"
agent="$HOME/Library/LaunchAgents/com.mirattic.auth.backup.plist"
mkdir -p "$support" "$HOME/Library/LaunchAgents"
cp backup.sh "$support/backup.sh"
cat > "$agent" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.mirattic.auth.backup</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$support/backup.sh</string></array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>4</integer><key>Minute</key><integer>30</integer></dict>
  <key>StandardOutPath</key><string>$HOME/mirattic-auth-backups/backup.log</string>
  <key>StandardErrorPath</key><string>$HOME/mirattic-auth-backups/backup.log</string>
</dict></plist>
PLIST
mkdir -p "$HOME/mirattic-auth-backups" && chmod 700 "$HOME/mirattic-auth-backups"
launchctl bootout "gui/$(id -u)/com.mirattic.auth.backup" 2>/dev/null || true
# Fails the deploy before the image switch: a deploy must not report success with backups stopped.
launchctl bootstrap "gui/$(id -u)" "$agent"
launchctl print "gui/$(id -u)/com.mirattic.auth.backup" >/dev/null

healthy() {
  for _ in $(seq 60); do
    curl -fsS http://127.0.0.1:8091/actuator/health >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

previous=$(docker image inspect -f '{{.Id}}' "$image:current" 2>/dev/null || true)
docker tag "$image:$1" "$image:current"

# `if` keeps set -e from exiting on a failed `compose up`: every failure goes through the rollback below.
if docker compose up -d && healthy; then
  echo "deployed $1"
  # Keep the five newest tagged images for manual rollback.
  docker images "$image" --format '{{.Tag}}' | grep -v '^current$' | tail -n +6 | xargs -I{} docker rmi "$image:{}" >/dev/null 2>&1 || true
  exit 0
fi

echo "deploy of $1 failed" >&2
docker compose logs --tail 80 auth >&2 || true
if [ -n "$previous" ]; then
  docker tag "$previous" "$image:current"
  if docker compose up -d && healthy; then
    echo "rolled back to the previous image" >&2
  else
    echo "rollback failed too" >&2
  fi
fi
exit 1
