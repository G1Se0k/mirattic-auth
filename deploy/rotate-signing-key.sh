#!/usr/bin/env bash
# Signing key rotation on the deploy host (docs/deployment.md "Signing Keys"). Nobody is signed out:
#   rotate  — the current key becomes the previous one (still in the JWKS, no longer signing); Auth restarts and
#             generates a new current key. Tokens signed before keep verifying until they expire (15 min).
#   retire  — at least an hour later (a day is comfortable): the previous key leaves the JWKS.
# Run a backup first (backup.sh): the new key is only in the volume until the next nightly backup.
set -euo pipefail
cd "$(dirname "$0")"
keys=/keys/signing-key.jwk.json
previous=/keys/signing-key.previous.jwk.json

kid() {
  docker compose exec -T auth sh -c "cat $1" | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p'
}

healthy() {
  for _ in $(seq 1 30); do
    curl -fsS http://127.0.0.1:8091/actuator/health >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

case "${1:-}" in
  rotate)
    old=$(kid "$keys")
    docker compose exec -T auth sh -c "mv $keys $previous"
    docker compose restart auth
    healthy || { echo "Auth did not come back; the old key is at $previous (move it back to $keys)." >&2; exit 1; }
    echo "rotated: current $(kid "$keys"), previous $old (published). Run '$0 retire' in a day."
    ;;
  retire)
    docker compose exec -T auth sh -c "rm -f $previous"
    docker compose restart auth
    healthy || { echo "Auth did not come back after retiring the previous key." >&2; exit 1; }
    echo "retired: JWKS has only $(kid "$keys")."
    ;;
  *)
    echo "usage: $0 rotate|retire" >&2
    exit 2
    ;;
esac
