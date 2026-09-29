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
- per account: at most one reset mail per minute (user row locked, so concurrent requests can't bypass).
- `/oauth2/token` is not IP-limited (every user of a product refreshes through that product's server IP);
  it requires the client secret.
- No per-account login lockout (would enable lockout DoS).
- In-memory counters: move to Redis if Auth runs more than one instance.

## Enumeration
Do not unnecessarily reveal whether an email/account exists.
- login: one generic error for unknown email, wrong password, disabled account
- password reset request: identical response; lookup + token + mail all run async, so response time does not depend on the account
- signup: DOES reveal an existing email ("이미 가입된 이메일입니다"). Accepted trade-off; hiding it needs email verification first. Rate limit (Phase 7) bounds probing.

## Password Reset
- 32 random bytes (base64url), only SHA-256 stored, 30 min expiry
- confirm locks the row (`FOR UPDATE`); any password change (reset or `/account/password`) marks every outstanding token of the user used
- reset link is in the URL, so all pages send `Referrer-Policy: no-referrer`
- mail failure is logged by exception type only (message body contains the token)

## Account Linking
Never auto-merge solely on matching email.
Explicit linking is the default.

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
- sender such as `noreply@mirattic.com`
