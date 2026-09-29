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
`/oauth2/authorize?...&prompt=login` with a sign-in (password or Kakao / Naver) older than 60 s ends that Auth session, so the
login page asks for the password again and then replays the request (`FreshLoginFilter`). A fresh sign-in
passes straight through. The ID token's `auth_time` is the sign-in time (Spring Security's factor), so clients check freshness themselves — they must not rely on the redirect alone.
Used by: Sync account deletion (`auth_time` within 5 min, same `sub`; Sync `docs/protocol/rest.md`).
