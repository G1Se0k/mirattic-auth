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

## Host move: Mac → AWS Lightsail (done 2026-10-03)
**Production now runs on Lightsail** (Flow 17:09, Sync 17:26, Auth 17:40, mirattic.com 17:46 KST). Admin:
`ssh -i ~/.ssh/mirattic-prod.pem ubuntu@<LIGHTSAIL_IP>` (sudo, Caddy at `/etc/caddy/Caddyfile`); services as
`deploy` under `~/apps/mirattic-{auth,sync,flow}`, mirattic.com files in `/var/www/mirattic`. The sections above
that name the Mac host (`~/Documents/…`, launchd, Homebrew Caddy) describe the old host; CI targets the new one
through the repo variables / secrets below. Mac cleaned 2026-10-03: Mirattic containers, images, build cache,
launchd backup agents, clones (with their env files), old backups, Caddy blocks (only monivillage left; previous
file `Caddyfile.before-lightsail-cleanup`) and the CI keys of the moved repos are gone. Kept for rollback until
about 2026-10-17: volumes `mirattic-{auth,sync}_mysql-data`, `mirattic-flow-prod_mysql-data`,
`mirattic-auth_signing-key` and the older `miratticflow_mysql-data` (compose files from git, env files from the
new host).
New host: Lightsail Seoul, 4 GB general purpose ($24/mo), Ubuntu 24.04 x86_64, static IP `<LIGHTSAIL_IP>`, KST.
Set up: 2 GB swap, docker.io + compose v2, Caddy 2.11 (official apt repo; 2.6 lacks `client_ip_headers`), fail2ban,
ufw (22 open for CI, key-only; 80/443 only from Cloudflare's ranges — refresh from cloudflare.com/ips if they change;
Cloudflare SSL mode Full (strict) since 2026-10-03, a Configuration Rule keeps `monivillage` (Mac, `tls internal`) on Full),
cron active. User `deploy` (docker group) for CI; its key is `~/.ssh/mirattic-deploy-lightsail` on the admin Mac
(not yet in any GitHub secret). Admin login: `ubuntu` with the Lightsail key.

Moving: Auth, Sync, Flow and mirattic.com (static, `Mirattic/main`). monivillagebot stays on the Mac.

All three pipelines deploy to the Mac until switched. Each `deploy.sh` installs its daily backup with launchd on the
Mac and with the deploy user's crontab on Linux (Auth 04:30, Sync 04:00, Flow 04:15; 7 days in `~/mirattic-*-backups`).
CI no longer needs a git clone on the host: Auth / Sync tar `deploy/` over SSH, Flow builds its two images in CI
(native runner: `ubuntu-24.04-arm` for the Mac, `ubuntu-latest` for amd64) and scp's them with its compose and
scripts. Memory limits for 4 GB: Auth 768m, Sync 1280m (load test was at 2560m), Flow backend 768m.
Verified on the new host 2026-10-03 with dummy env: all three deploy, backups, Flow rollback (also with no
`:current` image), crontab kept other jobs. All seven containers: 2.8 GB used of 3.7, swap unused.

Rehearsal 2026-10-03 with the real 04:00 / 04:30 / 16:49 backups and env files (`deploy/host-move-copy.sh`, then
`deploy/host-move-restore.sh` as `~/move/restore.sh` + each `deploy.sh`, images built on the host): restore + start
per service 35–57 s; tables restored (auth 11, sync 10, flow 12); JWKS kid = production's current key; through
Caddy (rehearsal config with `tls internal`, curl `--resolve`): Auth health / discovery (issuer
`https://auth.mirattic.com`) / login (Kakao, Naver, Google), Sync health, Flow `/`, `/login`, `/api/users/me` 401,
`/auth/start` → Auth authorize → `/login`. Memory with all seven containers: 2.8 GB of 3.7, swap 46 MB.
Not testable before the DNS switch: a browser login (HSTS needs the real certificate).
The previous signing key (`signing-key.previous.jwk.json`, from the 2026-09-30 rotation) is not in the backups, so
the new host publishes only the current key — the same as running `retire`. Tokens signed with the old key expired
long ago.

Cutover, one service at a time (Flow → Sync → Auth, then mirattic.com), each with the user's approval:
1. Auth / Sync: repo variable `DEPLOY_ENABLED=false`; Flow: disable the Deploy workflow.
2. Mac: stop that service's app container (`docker stop mirattic-<…>-1`).
3. Admin Mac: `sh deploy/host-move-copy.sh <service>` (fresh dump of that service + the env files to `~/move`).
4. New host: `sh ~/move/restore.sh <service>`, then a CI run against the new host (step 6) or `deploy.sh` with
   an image built there. Auth: the restore puts the signing key into the volume before the app's first start
   (else a new key is generated and every token breaks).
5. Caddy: the real site block (no `tls internal`); Cloudflare DNS → `<LIGHTSAIL_IP>` (proxied). Caddy then gets the
   certificate by HTTP-01 through Cloudflare (as on the Mac), so expect a few seconds of errors. Check health, a
   browser login, Sync and Flow.
6. Point CI at the new host: Auth / Sync repo variables `DEPLOY_HOST=deploy@<LIGHTSAIL_IP>`,
   `DEPLOY_DIR=apps/mirattic-<name>`, `DEPLOY_PLATFORM=linux/amd64`, secrets `DEPLOY_SSH_KEY` (new key) and
   `DEPLOY_KNOWN_HOSTS` (new host key); Flow: secrets `DEPLOY_HOST/USER/PATH/SSH_KEY`,
   `DEPLOY_HOST_FINGERPRINT`, variable `DEPLOY_PLATFORM=linux/amd64`. Re-enable deploys, run one.
Lessons from the Flow cutover (2026-10-03):
- Put the site block into Caddy only once DNS points here: before that its HTTP-01 challenge reaches the Mac and
  fails, and Caddy's retry backoff kept Flow down ~8 min instead of ~2.
- appleboy (Flow) checks the ECDSA host key: `DEPLOY_HOST_FINGERPRINT` =
  `SHA256:7Bw1x5VStCaYjcTP1tD+gMKCViR+c/FH+ySqrZziPR0` (ED25519 is `SHA256:utgeijagYu2g…`). For Auth / Sync
  `DEPLOY_KNOWN_HOSTS` = `ssh-keyscan <LIGHTSAIL_IP>` (all key types), checked against the host's own keys.
- Writing GitHub secrets (the deploy key) is done by the user (`gh secret set`): blocked for Claude.
Rollback: DNS back to the Mac and start its container again (its data is untouched; writes after the switch are
lost).
After the move: `rotate-signing-key.sh retire`, Lightsail automatic snapshots, Mac kept 1–2 weeks.

## Signing Keys
Do not generate ephemeral signing keys on every restart.

- Current key: private RSA JWK in the `signing-key` volume (`/keys/signing-key.jwk.json`), generated once,
  `kid` = RFC 7638 thumbprint. Backed up nightly (`backup.sh`).
- Rotation (Phase 7), on the host, nobody signed out:
  1. `deploy/backup.sh` (keep a copy of the old key), then `deploy/rotate-signing-key.sh rotate`: the current key
     becomes `/keys/signing-key.previous.jwk.json`, Auth restarts and generates a new current key.
     JWKS = new + previous (public); only the new key signs (`SigningKeyConfig.jwtEncoder`). Tokens signed before
     (access / ID tokens, 15 min) keep verifying; refresh tokens are opaque and unaffected. Sync / Flow decoders
     refetch the JWKS on an unknown `kid`.
  2. A day later: `deploy/rotate-signing-key.sh retire` removes the previous key from the JWKS. `rotate` refuses to
     run while a previous key is still published (it would drop a key unexpired tokens need).
  3. `deploy/backup.sh` again (the new key).
- When: on suspicion of exposure (then retire after 15 minutes, not a day), otherwise yearly.

## Email
Provider: Resend (SMTP). Verified domain `mail.mirattic.com`; sender `noreply@mail.mirattic.com`
(`AUTH_MAIL_FROM`, set in `deploy/compose.yml`). SPF + DKIM records are in Cloudflare DNS; add DMARC. Free tier 3,000 mails / month;
reset mail is limited to one per account per day.

## Backups
Auth DB backup is critical.
Signing private keys require separate secure backup.

## Monitoring
Uptime (Phase 7): `.github/workflows/uptime.yml` in the **public** Mirattic Flow repo (free Actions minutes) checks
every 5 minutes, 3 tries 20 s apart: Auth and Sync `/actuator/health` 200, Flow `/login` 200 and `/api/users/me` 401
(backend up). A failed run makes GitHub mail the account that last changed the workflow (Settings → Notifications →
Actions: email on failed workflows). Limits: GitHub may start scheduled runs minutes late; schedules stop after 60
days without repository activity; during an outage every run mails.

Not yet (metrics):
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
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | local: dummy (button fails). Required in prod (`deploy.sh` refuses without them). Google Cloud console → OAuth client "Web application", redirect URI `https://auth.mirattic.com/login/oauth2/code/google`, consent screen scopes `openid`, `.../auth/userinfo.email`, `.../auth/userinfo.profile` |
| `FLOW_ACCOUNT_DELETION_URL` / `SYNC_ACCOUNT_DELETION_URL` | optional; default `https://{flow,sync}.mirattic.com/api/internal/account-deletion` (`api.md` "Account Deletion"). Local profile: the products' dev ports |
| `SIGNUP_IP_KEY` | HMAC key for signup-per-network hashes; `deploy.sh` generates it once on the host. Local/tests: random |
| `EMAIL_LOGIN` | `true` reopens email sign-in / sign-up / reset. Default `false` (social only) |
