# Deployment / Operations

## Domains
```text
auth.mirattic.com
sync.mirattic.com
flow.mirattic.com
```

## MVP Topology
```text
Caddy
  ├─ auth.mirattic.com → Auth Spring Boot
  ├─ sync.mirattic.com → Sync
  └─ flow.mirattic.com → Flow

MySQL
  ├─ mirattic_auth
  ├─ mirattic_sync
  └─ mirattic_flow
```

Separate logical DBs even if one MySQL server is used.

## TLS
HTTPS required in production.

## Production Runbook (files in `deploy/`, same host pattern as Mirattic Sync)
```bash
./mvnw package && docker build -t mirattic-auth:current .      # image
cp deploy/.env.example deploy/.env && chmod 600 deploy/.env     # fill secrets (see comments inside)
docker compose -f deploy/compose.yml up -d                      # mysql + auth on 127.0.0.1:8091
# host Caddy: add deploy/Caddyfile block (auth.mirattic.com → 127.0.0.1:8091), DNS via Cloudflare
```
- Signing key: generated once into the `signing-key` volume on first start (0600, uid 65534), reused after.
  **Back it up separately** (`docker run --rm -v mirattic-auth_signing-key:/k busybox cat /k/signing-key.jwk.json`)
  and store it like a password. Losing it = every issued token invalid (users re-login), not data loss.
- Verified locally 2026-09-29 with this compose: issuer via proxy headers, key persisted across restart
  (same `kid`), login redirect `https://…/login`, cookie `Secure; HttpOnly; SameSite=Lax`, 429 on the 21st `POST /login`.
- Not yet: CI image build, deploy script with rollback, automated DB/key backup (Sync has these; port when deploying).

## Signing Keys
Do not generate ephemeral signing keys on every restart.

Plan for:
- persistent private key
- `kid`
- current key
- previous public key during rotation
- secure backup

## Email
Suggested sender:
`noreply@mirattic.com`

Use transactional email provider + SPF/DKIM/DMARC.

## Backups
Auth DB backup is critical.
Signing private keys require separate secure backup.

## Monitoring
Minimum:
- login failures
- signup rate
- email send failures
- token endpoint errors
- refresh/revoke errors
- DB errors
- latency / 5xx

Never include sensitive tokens in logs/monitoring.

## Availability
Single instance is acceptable for MVP.
Scale only when metrics justify it.

## Local Development
```bash
docker compose up -d                                        # MySQL 8.4 on 3307 + Mailpit (SMTP 1025, UI 8025)
./mvnw spring-boot:run -Dspring-boot.run.profiles=local     # http://localhost:9000
./mvnw test                                                 # Testcontainers (Docker required)
```
`local` profile generates `.local/signing-key.jwk.json` (0600) on first run. Production must mount a key via `AUTH_SIGNING_KEY_PATH`.

## Environment
| var | default |
|---|---|
| `AUTH_ISSUER` | `http://localhost:9000` (prod: `https://auth.mirattic.com`) |
| `AUTH_SIGNING_KEY_PATH` | `./.local/signing-key.jwk.json` |
| `DB_URL` / `DB_USERNAME` / `DB_PASSWORD` | local MySQL on 3307 |
| `PORT` | `9000` |
| `AUTH_SIGNING_KEY_GENERATE` | `false`; `true` only with a persistent key location (prod compose volume) |
| `SERVER_SERVLET_SESSION_COOKIE_SECURE` | unset locally (http); `true` in prod compose |
| `SPRING_MAIL_HOST` / `SPRING_MAIL_PORT` / `SPRING_MAIL_USERNAME` / `SPRING_MAIL_PASSWORD` | local: Mailpit `localhost:1025`. Required in prod (no mail config → server does not start) |
| `AUTH_MAIL_FROM` | `noreply@mirattic.com` |
| `SYNC_CLIENT_SECRET_HASH` / `FLOW_CLIENT_SECRET_HASH` | none — required in prod; `{bcrypt}` hash, see `clients.md` |
