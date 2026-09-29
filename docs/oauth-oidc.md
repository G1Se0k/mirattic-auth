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
