# Current Phase
Auth is live at https://auth.mirattic.com (2026-09-29).
Phase 4 — Mirattic Flow Migration (done 2026-09-29: Kakao / Naver in Auth, Flow on Auth tokens in HttpOnly cookies, legacy Flow auth removed; Flow test data reset). Phase 3 (Sync) done earlier the same day.

## Goal
Create the central Mirattic Auth project and finalize the first deployable authentication architecture.

## Phase Plan

### Phase 0 — Bootstrap
- repository/project structure
- DB schema
- Spring Authorization Server base
- signing keys
- OIDC discovery / JWKS
- local development setup

### Phase 1 — Local Account
- signup
- login
- password reset
- account profile

### Phase 2 — OAuth/OIDC Clients
- Sync/Flow client registrations
- Authorization Code + PKCE
- ID/access tokens
- refresh rotation/revoke
- UserInfo

### Phase 3 — Mirattic Sync Migration
- preserve UID where possible
- dual acceptance
- extension cutover (desktop not served)
- legacy auth removal

### Phase 4 — Mirattic Flow Migration (done 2026-09-29, `migration.md` "Flow")
- Auth: Kakao / Naver sign-in (`SocialLogin`, `SocialReauth`), `prompt=login` bound to the demanding request,
  `auth_time` in access tokens, OIDC RP-initiated logout with Flow's post-logout URI.
- Flow: confidential client, HttpOnly cookies, CSRF header, WebSocket cookie auth + close at token exp / logout /
  withdrawal, withdrawal only through Auth re-authentication, enrollment boundary (`auth_time`) and withdrawal
  record so old logins never reach a re-joined user; legacy auth removed.
- Validation: Codex Sol 11 passes (FAIL ×10 → all findings fixed → PASS); Auth 51, Flow 108, Sync 57 tests; local
  browser E2E of the whole Flow flow.

### Phase 5 — Account Center (done 2026-09-29; user decisions the same day)
- sessions + session revoke: device list with per-device sign-out (`api.md` "Devices") — done
- identity management: link / unlink Kakao and Naver only (adding email + password later) — done
- account deletion: Auth orders Flow then Sync to delete their data (Auth-signed back-channel JWT, `api.md`
  "Account Deletion"), deletes only if both succeed; Flow may refuse (workspace owner) — done
- Validation: Codex quota exhausted → Claude reviewed directly (not a PASS). Auth 60, Flow 117, Sync 63 tests.

### Phase 6 — External Providers
- Google
- Apple
- explicit linking

### Phase 7 — Hardening / Production (done 2026-09-29 except as noted; user decisions the same day)
- rate limits: already (per-IP 20/min on password POSTs, reset mail limits)
- key rotation: previous key published during a rotation, only the current key signs (`SigningKeyConfig`),
  `deploy/rotate-signing-key.sh rotate|retire` (`deployment.md` "Signing Keys"). First rotate on the host 2026-09-30.
- security events: `security.md` "Security Events", shown on the account page
- backups: already daily on the host (7 days); off-host copy still open
- monitoring: 5-minute uptime check with failure mail from the public Flow repo (`deployment.md` "Monitoring")
- Validation: Claude review, then Codex Sol (Phases 5 + 7, 2026-09-29): FAIL ×4 → fixed (deletion needs exactly
  204; a link after deletion adds nothing; unlink ends other sessions and app logins; no second rotate before
  retire). Codex re-review + Flow / Sync reviews: FAIL → fixed (unlink also ends this browser if it signed in with
  the removed method; deletion fences the account first so no product profile is re-created mid-deletion; Flow
  counts owners with a locking read). Round 3: FAIL → fixed (fence lifted on any failure before the final commit;
  sessions of non-ACTIVE accounts signed out per request; Flow keeps a per-UID deletion boundary even without a
  profile, sign-in and deletion serialized per UID; names replaced by position and length). Round 4: Auth PASS.
  Flow rounds 4–7 (2026-09-30): lock order, locking reads, name-bearing writes and membership creation serialized
  with withdrawal, indexes; verified on MySQL 8.4 (123 tests). Final Flow verdict FAIL on one accepted limitation
  (project creation racing a withdrawal; Flow phase-19 doc). Sync: see Known Issues.

## Required Tests
- Authorization Code + PKCE success/failure
- redirect URI validation
- issuer/audience validation
- refresh rotation/revocation/reuse behavior
- password reset one-time/expiry
- account enumeration resistance
- explicit identity linking
- disabled/deleted account behavior
- key rotation compatibility

## Known Decisions
- central Auth owns identity
- products do not read Auth DB
- global UID is OIDC `sub`
- OAuth 2.0 + OIDC
- Authorization Code + PKCE
- asymmetric JWT signing
- explicit account linking

## Auth-only Work While Waiting, part 2 (2026-09-29)
- Deploy automation: `.github/workflows/ci.yml` (test → arm64 image → SSH → `deploy/deploy.sh`, gated by repo variable `DEPLOY_ENABLED`), `deploy.sh` (first-run secret generation incl. client secrets, health check, rollback), `backup.sh` (daily DB + signing key, 7 days)
- Browser sessions in MySQL (Spring Session JDBC, V3); password change ends other sessions, reset ends all
- Decision: no email verification for now → one LOCAL signup per network (IPv4 / IPv6 /64) per 24 h (V4 `signup_ips`, hashes only)
- 35 tests pass

## Auth-only Work While Waiting (2026-09-29)
- Hourly cleanup: expired `oauth2_authorization` (+ cascaded rotation rows) and reset tokens, 1 day slack
- Rate limits: per-IP 20/min on password POSTs (before Security), 1 reset mail/min per account
- Session cookie SameSite=Lax + HttpOnly; Secure in prod
- Deploy files: `Dockerfile`, `deploy/compose.yml`, `deploy/Caddyfile`, `deploy/.env.example`; prod compose smoke-tested locally
- 33 tests pass

## Phase 3 Status (2026-09-29)
- Decision: option B — extension holds Auth tokens, Sync relays refresh (`migration.md`)
- Auth: refresh reuse detection (V2 `rotated_refresh_tokens`; reuse after 10 s grace → whole authorization removed, owner client only); rotation is a row-locked compare-and-swap. 27 tests pass.
- Sync-side work list written in `migration.md`; not started (user: no Sync changes yet).

## Phase 2 Status (2026-09-29)
Done:
- Clients `mirattic-sync`, `mirattic-flow` registered (prod + dev redirect URIs) — `docs/clients.md`
- Dev client `mirattic-dev` removed; tests use `mirattic-sync`
- Test: unregistered redirect URI (prod URI under local, other path, other host) → 400, no redirect.
- Confidential clients (`client_secret_basic` + PKCE), secrets as BCrypt hash env vars; refresh tokens issued, rotated (`reuse-refresh-tokens: false`), access 15 min / refresh 30 days
- Fixed: disabled accounts could still refresh / exchange codes → token customizer requires `ACTIVE` for every JWT
- `OAuthClientTest` (6): secret + verifier required, code one-time, refresh rotation, revoke, password change ends refresh, disabled account blocked.
- Token values stored hashed (`HashedTokenAuthorizationService`); startup refuses `reuse-refresh-tokens: true`
- ID token + `/userinfo` claims by scope (`name`, `email`, `email_verified: false`); UserInfo live from DB, 401 for non-ACTIVE
- `OAuthClientTest` +3: hashed storage, code replay revokes tokens, claims/UserInfo.
- After Codex review: UserInfo limited to the access token's own scopes (downscoped refresh), `state` lookups not hashed. +2 tests. Total 23 tests pass.

## Phase 1 Status (2026-09-29)
Done:
- Thymeleaf pages: `/login` (custom, links to signup/reset), `/signup`, `/password/reset`, `/password/reset/confirm`, `/account` (name, password change, logout) — Korean UI, light/dark
- `AccountService` (JdbcTemplate): signup, reset request/confirm, change password/name. DB clock for all times.
- `PasswordResetMailer`: SMTP via `JavaMailSender`; the whole reset request is `@Async`. Local: Mailpit in docker-compose (UI http://localhost:8025)
- Password change/reset deletes the user's OAuth authorizations
- `Referrer-Policy: no-referrer`; mail health indicator off (SMTP outage must not mark Auth DOWN)
- Tests: `AccountFlowTest` 7 + `AuthBootstrapTest` 4 = 11 pass. Includes end-to-end signup → login → authorize (PKCE) → token, asserting ID/access token `sub` = UID, `nonce`, `iss`.
- Manual smoke (local): signup → reset mail in Mailpit → login → account page

## Phase 0 Status (2026-09-29)
Done:
- Maven project (Spring Boot 4.1.1, Java 21, `spring-boot-starter-security-oauth2-authorization-server` = Spring Security 7.1.1 AS)
- Flyway `V1__baseline.sql`: `users`, `user_identities`, `password_reset_tokens` + SAS `oauth2_authorization`, `oauth2_authorization_consent`
- `users.id` VARCHAR(36) — same type as Sync `users.id`, so Sync UUIDs import unchanged
- OIDC enabled; authorization/consent stored via JDBC (survives restarts)
- RS256 signing key: JWK JSON file (`AUTH_SIGNING_KEY_PATH`), `kid` = RFC 7638 thumbprint; auto-generated only in `local` profile
- Login: LOCAL identity by normalized email → principal name = `users.id` (so `sub` = Mirattic UID); non-ACTIVE users disabled
- `/actuator/health` public; everything else authenticated
- Local: `docker compose up -d` (MySQL on 3307), `./mvnw spring-boot:run -Dspring-boot.run.profiles=local` (port 9000), dev public client `mirattic-dev` (PKCE required, redirect `http://127.0.0.1:8081/callback`)
- Tests: `AuthBootstrapTest` (discovery, JWKS public-only, health/authorize→login, email→UID mapping, disabled user) — 4/4 pass

Not changed: Sync / Flow code (user request: do not touch yet).

## Existing Identity Models (inspected, read-only)
| | Sync | Flow |
|---|---|---|
| UID | `users.id` VARCHAR(36) UUID | `users.id` BIGINT AUTO_INCREMENT |
| identities | `user_identities` (LOCAL, provider/subject) — same shape as Auth | single `users` row: `provider` LOCAL/KAKAO/NAVER + `provider_id` |
| password hash | DelegatingPasswordEncoder (`{bcrypt}...`) → import as-is | raw BCrypt (no prefix) → import as `{bcrypt}` + hash |
| tokens | HS256 JWT, iss `mirattic`, opaque refresh (SHA-256, family reuse detection) | jjwt JWT, refresh stored raw |
| schema mgmt | Flyway | `ddl-auto=update` (no migrations) |
| deletion | hard delete (cascade) | soft delete `deleted_at`, PII cleared |

## Validation
- 2026-09-29 Codex Sol review of sessions / signup limit / deploy automation (gpt-6-sol, high): pass, no findings. Session survival across a server restart verified on a running server.
- 2026-09-29 Codex Sol hardening review (gpt-6-sol, high): encoded-path limiter bypass (high, reproduced: `POST /lo%67in` reached login) → decoded path match; concurrent reset mails (medium) → user row lock; limiter map scan/growth (medium) → scheduled eviction, 100k cap, IPv6 /64 keys. All fixed/tested; limiter re-verified on a running server.
- 2026-09-29 Codex Sol reuse-detection review (gpt-6-sol, high), 2 rounds: concurrent refresh false reuse (high) → CAS; cross-client revoke (medium) → owner check; overlapping late duplicate revoking the winner (high) → 10 s grace (known trade-off, documented). All fixed/tested.
- 2026-09-29 Codex Sol Phase 2 review (gpt-6-sol, high): 2 findings, both fixed — UserInfo disclosed claims beyond a downscoped access token (medium); STATE lookups were hashed and always missed (low, consent/PAR not enabled).
- 2026-09-29 Codex Sol Phase 1 review (gpt-6-sol, high): 2 findings, both fixed — reset-request timing (whole request now async), password change now invalidates outstanding reset links.
- 2026-09-29 Codex Sol (gpt-6-sol, high): 5 findings.
  - fixed: loaded signing key without `kid` now refused; dev client no longer claims refresh/offline_access.
  - recorded below: disabled-user SSO session, raw refresh-token storage, public-client refresh.
  - by design: loopback redirect port (see security.md).

## Known Issues
- The deploy that introduced keyed signup-IP hashes makes the older unkeyed rows stop matching: the one-signup-per-network
  limit restarts once (≤ 1 day).
- Same-browser race: a login callback already in flight when the user logs out of Flow can finish afterwards and sign
  that browser back in (needs the same user within a fraction of a second; not fixed).
- Social accounts can't be linked to an existing account yet (a first Kakao / Naver sign-in always makes a new one).
- No email verification (decided 2026-09-29): anyone can sign up with an email they don't own (the owner can take it over via reset). Mitigated by one signup per network per day.
- Shared networks (office / campus / mobile CGNAT) get one signup per day in total.
- Flow (accepted, user 2026-09-30): two co-owners withdrawing at the same moment can deadlock (one gets 500, rolled
  back, retry); a project created at the exact moment of its creator's withdrawal can survive it (one-line fix:
  lockNamed in ProjectService.create).
- Sync: a Sync callback holding tokens issued just before the deletion fence can create a Sync profile after Sync
  answered 204 (Codex Sol, Sync review 2026-09-29). Flow closes this with a per-UID deletion boundary under a lock;
  Sync needs the same (Sync repo, handled by the Sync session).
- Account deletion: if Flow deleted and then Sync fails, the Auth account stays ACTIVE again (the user is told to
  retry). If Auth itself dies between the fence and the end, the account stays DISABLED (can't sign in) until fixed
  by hand (`UPDATE users SET status='ACTIVE'`, then the user retries).
- Flow: generated texts (activity chat lines, comment notifications) created before 2026-09-30 keep a deleted
  user's former name; newer ones show "탈퇴한 사용자" (user decision 2026-09-30, Flow phase 19).
- Device list: browsers signed in before 2026-09-29 (Phase 5) show "알 수 없는 브라우저" until they sign in again.
  App logins show the product name only (the token call comes from the product's server, not the device).
- Linking races with a database deadlock (a first sign-in of the same Kakao account at the same moment) end in a
  500 instead of `link_error=taken`; nothing is half-written.
- Disabling a user does not end an existing Auth browser session; `/oauth2/authorize` still issues a code, but the code can no longer be exchanged (ACTIVE check at token issuance). Session cleanup belongs to the disable/delete feature (Phase 5).
- SAS schema `timestamp` columns: MySQL 2038 limit.
- Single signing key; rotation (previous public key in JWKS) is Phase 7.
- Flow uses KAKAO / NAVER, not in Auth's LOCAL/GOOGLE/APPLE plan — needs decision.
- Flow numeric IDs need a UUID mapping (Flow keeps `users.id`, adds Mirattic UID column) — Flow change, deferred.
- Sync's one pre-migration test account (production, 2026-09-28) lost its legacy login; signing in with a Mirattic account of any email creates a separate Sync profile.

## Next Task
1. Key rotation, first run on the host 2026-09-30 05:12 KST: `rotate` → current `CKintvYOWY6h…`, previous
   `gp5pPSkcKIyO…` published (JWKS 2 public keys), a second `rotate` refused, backups before and after. Still to do:
   a Sync / Flow sign-in with the new key, then `deploy/rotate-signing-key.sh retire` from 2026-10-01.
2. Naver review (user; screenshots taken 2026-09-29, consent items: 이용자 식별자, 이름, 별명). Kakao console: app
   name "Mirattic", privacy URL https://auth.mirattic.com/privacy. Kakao unlink webhook: decided not to use.
3. Off-host backup copy (DB + signing key, encrypted); Phase 6 (Google / Apple) when their consoles are ready.
4. Codex Sol review of Phases 5 and 7 when quota returns.
5. Optional: adding email + password to a Kakao / Naver-only account (needs a decision on email ownership);
   DMARC `p=quarantine`; rotate the Resend API key (shared in chat).
