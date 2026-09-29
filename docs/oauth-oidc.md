# OAuth 2.0 / OpenID Connect

## Public Clients
Use Authorization Code + PKCE for every client (see `clients.md`).

Never use Resource Owner Password Credentials.

## Flow
```text
Client
  → /oauth2/authorize
  → Auth login / SSO
  → authorization code
  → /oauth2/token + code_verifier
  → ID Token + Access Token + optional Refresh Token
```

## Expected OIDC Endpoints
- `/.well-known/openid-configuration`
- `/oauth2/authorize`
- `/oauth2/token`
- `/oauth2/jwks`
- `/userinfo`
- `/oauth2/revoke`

Follow Spring Authorization Server defaults where practical.

## ID Token Claims
Minimum:
```json
{
  "iss": "https://auth.mirattic.com",
  "sub": "<mirattic-user-uuid>",
  "aud": "<client-id>",
  "exp": 0,
  "iat": 0,
  "nonce": "..."
}
```

By granted scope (ID token and `/userinfo`):
- `profile` → `name` (display name)
- `email` → `email`, `email_verified` (always `false` until email verification exists — products must not
  trust it for account linking)

`/userinfo` reads the account live; ID token claims are a snapshot from issuance.

Do not put product-specific data in ID tokens.

## Scopes
Initial:
- `openid`
- `profile`
- `email`
- `offline_access`

## Clients
Registered clients, redirect URIs and per-client settings: `clients.md`.
Desktop app is not served.

## SSO
SSO comes from the Auth browser session.
Product services do not share their own cookies.

## Social Login (Kakao / Naver)
Auth is itself an OAuth client of Kakao and Naver (Spring Security `oauth2Login`, `SocialLogin`), so every
product gets them through the normal Auth login page. Buttons: `/oauth2/authorization/{kakao|naver}`;
callback `https://auth.mirattic.com/login/oauth2/code/{kakao|naver}` (must be registered in each console).
- Identity = (`KAKAO`|`NAVER`, provider's stable user id). The first sign-in creates a new Mirattic account
  (name from the nickname, contact email if the user consented); later sign-ins find it by that pair only.
- Never matched by email: the same email as a password account is a separate account (`security.md`).
- No password: the account page hides password change; password reset only concerns LOCAL identities.
- Not counted against the one-signup-per-network limit (that limit is for LOCAL signups).
- `email` claim / UserInfo: the LOCAL identity's email, else the social one's; `email_verified` stays false.
- The sign-in time is the ID token's `auth_time` (authorization-code factor), like a password sign-in.
- Failure (provider error, disabled account) → `/login?social_error`.

## Re-authentication (`prompt=login`)
`/oauth2/authorize?...&prompt=...login...` (a space-separated list) always ends the current Auth sign-in,
however recent, and sends the user through the login page (`FreshLoginFilter`). Only the replay of that very
request (same parameters) after a sign-in newer than the demand passes, once; an abandoned demand can't be
satisfied later. With Kakao / Naver the demand is forwarded (`SocialReauth`: Kakao `prompt=login`, Naver
`auth_type=reauthenticate`) so the provider asks for credentials too. Clients still check `auth_time` themselves.
Used by: Sync account deletion (`auth_time` ≤ 5 min, same `sub`), Flow withdrawal (same user, `auth_time` after the
withdrawal started), Flow's first login after a logout / withdrawal in that browser.

## `auth_time` in access tokens
Access tokens carry `auth_time` too (the sign-in behind them; a refresh keeps the original login's time). Products
use it as a boundary: Flow rejects tokens of logins older than the one that created (or re-created after a
withdrawal) the Flow user, so an old login elsewhere can't reach a re-joined account.

## Logout (OIDC RP-Initiated Logout)
`/connect/logout` (POST form, `id_token_hint` + registered `post_logout_redirect_uri` + `state`) ends the Auth
browser session. Flow sends the browser there after its own logout / withdrawal (post-logout URI
`https://flow.mirattic.com/login?logout=success`), so the next person on a shared browser is asked to sign in.
