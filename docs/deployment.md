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

## Production Deploy (automated, same pipeline as Mirattic Sync)
Push to `main` → `.github/workflows/ci.yml`: `./mvnw test` → arm64 image → `docker load` over SSH on
`giseok@ssh.mirattic.com` → `deploy/deploy.sh <sha>` (health check on `127.0.0.1:8091`, automatic rollback
to the previous image, keeps 5 tagged images). The deploy job runs only when the repo variable
`DEPLOY_ENABLED` is `true`.

### One-time setup
1. Host: clone the repo to `~/Documents/mirattic-auth` (read-only deploy key for the private repo).
2. GitHub repo `G1Se0k/mirattic-auth`: secrets `DEPLOY_SSH_KEY`, `DEPLOY_KNOWN_HOSTS` (same values as Sync's),
   variable `DEPLOY_ENABLED=true`.
3. Host: run `sh ~/Documents/mirattic-auth/deploy/deploy.sh x` once. It creates (0600, gitignored):
   - `deploy/.env`: DB passwords, `{bcrypt}` client-secret hashes (single-quoted), empty `MAIL_*`
   - `deploy/client-secrets.txt`: the raw Sync / Flow client secrets → put each into its product server's
     env, then delete the file.
   It stops there until `MAIL_HOST` is filled in. Fill `MAIL_*` (transactional provider SMTP).
4. Host Caddy: add the `deploy/Caddyfile` block (`auth.mirattic.com → 127.0.0.1:8091`); DNS via Cloudflare.
5. Push to `main` (or rerun the workflow) → deployed.

### Setup status (2026-09-29)
- [x] repo cloned on host (`~/Documents/mirattic-auth`, host's own GitHub key)
- [x] GitHub secrets `DEPLOY_SSH_KEY` (same key as Sync's CI), `DEPLOY_KNOWN_HOSTS` (scanned, matched local known_hosts)
- [x] first `deploy.sh` run on host: `deploy/.env` + `deploy/client-secrets.txt` generated (0600)
- [x] host Caddy: `auth.mirattic.com` block added (backup `/opt/homebrew/etc/Caddyfile.before-auth-*`),
      Let's Encrypt cert obtained; Sync / Flow unaffected. DNS already proxied by Cloudflare.
- [x] CI test job green on GitHub
- [x] mail provider decided: **Resend** (SMTP `smtp.resend.com:587`, user `resend`); host/port/user set in host `.env`
- [x] Resend API key → host `.env` `MAIL_PASSWORD` (SMTP auth OK)
- [x] Resend domain **`mail.mirattic.com`** verified (DKIM `resend._domainkey.mail`, SPF/MX `send.mail`);
      SMTP test send from `noreply@mail.mirattic.com` accepted
- [x] DMARC `_dmarc.mail.mirattic.com` TXT `v=DMARC1; p=none; adkim=s; aspf=s` (→ `p=quarantine` once mails
      are seen landing in inboxes)
- [x] repo variable `DEPLOY_ENABLED=true` → first deploy (manual redeploy: `gh workflow run CI`)
- [x] **Live 2026-09-29** at https://auth.mirattic.com: health / discovery / JWKS 200, issuer correct,
      authorize → login, cookie `Secure; HttpOnly; SameSite=Lax`, HSTS, backup agent loaded; Sync / Flow unaffected.
      End-to-end reset mail from the running app (test account → `delivered@resend.dev`) sent; test data removed.
- [ ] raw client secrets → Sync / Flow server env (Phase 3 / 4), then delete `client-secrets.txt`

### Backups
`deploy.sh` installs launchd agent `com.mirattic.auth.backup` (daily 04:30, deploy fails if it can't):
`deploy/backup.sh` → `~/mirattic-auth-backups/` (0700): MySQL dump + signing key, 7 days retention.
Losing the signing key = every issued token invalid (users re-login), not data loss.

### Manual run (without CI)
```bash
./mvnw package && docker build -t mirattic-auth:manual .
sh deploy/deploy.sh manual
```

Verified locally 2026-09-29: prod compose (issuer via proxy headers, key persisted across restart, Secure
cookie, 429 on 21st `POST /login`); first-run secret generation (hash verifies against raw secret, compose
passes `$` unchanged into the container). Not run: the CI deploy job and launchd on the real host.

## Signing Keys
Do not generate ephemeral signing keys on every restart.

Plan for:
- persistent private key
- `kid`
- current key
- previous public key during rotation
- secure backup

## Email
Provider: Resend (SMTP). Verified domain `mail.mirattic.com`; sender `noreply@mail.mirattic.com`
(`AUTH_MAIL_FROM`, set in `deploy/compose.yml`). SPF + DKIM records are in Cloudflare DNS; add DMARC. Free tier 3,000 mails / month;
reset mail is limited to one per account per day.

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
| `KAKAO_CLIENT_ID` / `KAKAO_CLIENT_SECRET` / `NAVER_CLIENT_ID` / `NAVER_CLIENT_SECRET` | local: dummies (buttons fail). Required in prod (`deploy.sh` refuses without them); copied from the old Flow backend's apps |
| `SIGNUP_IP_KEY` | HMAC key for signup-per-network hashes; `deploy.sh` generates it once on the host. Local/tests: random |
