# Current Phase
Phase 1 — Local Account (done)

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
- desktop/extension cutover
- legacy auth removal

### Phase 4 — Mirattic Flow Migration
- OIDC integration
- duplicate-account policy
- SSO verification

### Phase 5 — Account Center
- sessions
- session revoke
- identity management
- account deletion

### Phase 6 — External Providers
- Google
- Apple
- explicit linking

### Phase 7 — Hardening / Production
- rate limits
- key rotation
- security events
- backups
- monitoring
- rollout

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
- 2026-09-29 Codex Sol Phase 1 review (gpt-6-sol, high): 2 findings, both fixed — reset-request timing (whole request now async), password change now invalidates outstanding reset links.
- 2026-09-29 Codex Sol (gpt-6-sol, high): 5 findings.
  - fixed: loaded signing key without `kid` now refused; dev client no longer claims refresh/offline_access.
  - recorded below: disabled-user SSO session, raw refresh-token storage, public-client refresh.
  - by design: loopback redirect port (see security.md).

## Known Issues
- Browser sessions are in-memory: password change/reset cannot end the user's other Auth browser sessions; server restart logs everyone out of Auth (not of products). Spring Session JDBC if needed.
- No rate limit yet on login / signup / reset (email bombing possible). Phase 7, or earlier before public deploy.
- No email verification: anyone can sign up with an email they don't own (then that owner can reset the password). Decide before public launch.
- Disabling a user does not end an existing Auth browser session; SSO can still issue codes. Must be solved together with the disable/delete feature (Phase 1/5): invalidate sessions + authorizations, or re-check status on /oauth2/authorize.
- SAS does not issue refresh tokens to public clients (desktop/extension). Phase 2: custom public-client refresh with rotation + reuse detection, or short sessions + silent re-auth.
- SAS `JdbcOAuth2AuthorizationService` stores refresh tokens / auth codes in plaintext (security.md wants hashes). Decide in Phase 2: hash-wrapping service or accept with DB access controls.
- SAS schema `timestamp` columns: MySQL 2038 limit.
- Server does not start without at least one registered client (Boot AS auto-config); prod clients pending redirect-URI decision.
- Single signing key; rotation (previous public key in JWKS) is Phase 7.
- Flow uses KAKAO / NAVER, not in Auth's LOCAL/GOOGLE/APPLE plan — needs decision.
- Flow numeric IDs need a UUID mapping (Flow keeps `users.id`, adds Mirattic UID column) — Flow change, deferred.
- Sync access-token `iss` is `mirattic`; Auth issuer is the URL — dual acceptance must handle both.

## Next Task
Decide (user):
1. Sync desktop / extension / Flow web redirect URIs (exact) and client IDs,
2. Flow KAKAO / NAVER: keep as Auth providers or force LOCAL,
3. Phase 2: Sync/Flow client registration, refresh strategy for public clients, UserInfo, revoke.
