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
- exception: loopback redirects (`http://127.0.0.1:<port>/...`) for native desktop clients match any port (RFC 8252 §7.3, Spring default); scheme, host and path still exact

## Auth Web Session
- Secure
- HttpOnly
- appropriate SameSite
- CSRF protection for cookie-authenticated state changes

## Rate Limits
Apply to:
- login
- signup
- password reset
- token abuse paths

Avoid easy account-lockout DoS.

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
