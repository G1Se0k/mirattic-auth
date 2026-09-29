# Security

## Passwords
- Use a current Spring-supported secure password encoder.
- Never log or return passwords/hashes.
- Enforce sane length limits.

## Tokens
- short-lived access token
- rotated/revocable refresh token
- one-time password-reset tokens
- store server-looked-up sensitive tokens as hashes
- never place long-lived bearer secrets in URLs

## JWT
Use asymmetric signing.

Resource servers validate:
- signature
- `iss`
- `aud`
- `exp`
- required scopes

Use `kid` for key rotation.

## OAuth Browser Security
- PKCE for public clients
- `state`
- OIDC `nonce`
- exact redirect URI allow-list
- no wildcard production redirects
- loopback redirects (`http://127.0.0.1:<port>/...`) match any port (Spring default, RFC 8252); dev-only since prod registers none (`clients.md`)

## Auth Web Session
- `prompt=login` on `/oauth2/authorize` always ends the current sign-in; only the replay of that request after a
  newer sign-in passes (re-authentication before destructive client actions, `oauth-oidc.md`).
- Access tokens carry `auth_time`; products bound sessions by it (Flow withdrawal / re-join).
- Stored in MySQL (Spring Session JDBC, cookie `SESSION`): survives restarts / deploys.
- Password change ends the user's other Auth sessions (keeps the current one); password reset ends all.
- Secure (prod: `SERVER_SERVLET_SESSION_COOKIE_SECURE=true`)
- HttpOnly
- SameSite=Lax (top-level GET from products to `/oauth2/authorize` keeps SSO)
- CSRF protection for cookie-authenticated state changes

## Rate Limits
Implemented:
- per client IP, fixed 1-minute window, 20/min (`auth.rate-limit-per-minute`): `POST /login`, `/signup`,
  `/password/reset`, `/password/reset/confirm`, `/account/password` → 429. Runs before Spring Security.
  Path matched decoded / without `;` params (as Spring resolves it). IPv6 keyed per /64. At most 100k
  tracked clients per minute (new ones get 429 while full); windows evicted by a 1-minute job.
- signup: one LOCAL (email/password) account per client network per 24 h (IPv4 address / IPv6 /64;
  only SHA-256 of the key stored, purged after a day). Replaces email verification for now (decision
  2026-09-29: no email verification yet). Future social signups are exempt.
- per account: at most one reset mail per 24 h (user row locked, so concurrent requests can't bypass).
  Trade-off: a lost mail means waiting a day; the page can't say so without revealing the account.
- `/oauth2/token` is not IP-limited (every user of a product refreshes through that product's server IP);
  it requires the client secret.
- No per-account login lockout (would enable lockout DoS).
- In-memory counters: move to Redis if Auth runs more than one instance.

## Enumeration
Do not unnecessarily reveal whether an email/account exists.
- login: one generic error for unknown email, wrong password, disabled account
- password reset request: identical response; lookup + token + mail all run async, so response time does not depend on the account
- signup: DOES reveal an existing email ("이미 가입된 이메일입니다"). Accepted trade-off (no email verification, decided); per-IP rate limit bounds probing.

## Password Reset
- 32 random bytes (base64url), only SHA-256 stored, 30 min expiry
- confirm locks the row (`FOR UPDATE`); any password change (reset or `/account/password`) marks every outstanding token of the user used
- reset link is in the URL, so all pages send `Referrer-Policy: no-referrer`
- mail failure is logged by exception type only (message body contains the token)

## Signup Limit
- Signup-per-network rows are HMAC-SHA256 with a host secret (`SIGNUP_IP_KEY`), not a plain hash of the IP.

## Account Linking
Never auto-merge solely on matching email.
Explicit linking is the default. Kakao / Naver sign-ins are keyed by the provider's user id only; a first
sign-in always creates a new account, even when its email equals an existing one (`oauth-oidc.md`).
Linking (Phase 5, account page, Kakao / Naver only):
- Started by the signed-in user (POST + CSRF) with a sign-in in the last 10 minutes, else `/login?reauth`. The
  pending link lives in the session for 10 minutes and is consumed by the next provider callback; the login page
  clears it. The provider is asked to show its login (Kakao `prompt=login`, Naver `auth_type=reauthenticate`), so
  the user picks the provider account. The OAuth `state` binds the callback to that browser.
- The callback attaches the identity only to the account still signed in there. Refused: an identity that belongs
  to another account (`link_error=taken`, never moved), a second identity of the same provider (`exists`).
- Unlinking (same 10-minute rule) needs another sign-in method left; the users row is locked so two concurrent
  unlinks can't remove the last one. Email + password can't be added to a social-only account yet.

## Security Events (Phase 7, `SecurityEvents`, V5 `security_events`)
Shown to the account's owner ("최근 보안 활동", last 10 on `/account`): sign-in (method + browser kind), password
sign-in failure of an existing active email account, password change / reset, Kakao / Naver linked / unlinked,
device signed out, refresh-token reuse that revoked a login (product name). No IP, no tokens. Kept 90 days
(`ExpiredDataCleanup`), deleted with the account. Unknown-email failures are not recorded. A flood of wrong
passwords for one account is bounded by the per-IP login limit only.

## Never Log
- passwords
- raw refresh tokens
- password reset tokens
- session cookies
- authorization codes

## Refresh Reuse
Rotation + reuse detection with a 10 s grace (`clients.md`). Only the owning client can trigger the
family revoke. Trade-off: a replay within 10 s of a rotation is refused but not treated as theft.

## Token Storage
All OAuth token values in `oauth2_authorization` are stored as `sha256:<hex>`; lookups hash the presented
value. Refresh rotation is mandatory for this (startup check).

## Client Secrets
Sync/Flow are confidential clients: Auth keeps only BCrypt hashes (`*_CLIENT_SECRET_HASH`), products keep
the raw secret server-side. Details: `clients.md`.

## Account State
Tokens are minted only for `ACTIVE` accounts (checked on every code exchange and refresh).

## Secrets
Keep outside source:
- DB password
- email provider API key
- signing private key
- confidential client secrets

## Email
Use transactional email provider.
Configure:
- SPF
- DKIM
- DMARC
- sender `noreply@mail.mirattic.com` (Resend verified domain)
