# OAuth 2.0 / OpenID Connect

## Public Clients
Use Authorization Code + PKCE for:
- desktop
- browser extension
- SPA/web where appropriate

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

Optional:
- `name`
- `email`

Do not put product-specific data in ID tokens.

## Scopes
Initial:
- `openid`
- `profile`
- `email`
- `offline_access`

## Clients
Examples:
- `mirattic-sync-desktop`
- `mirattic-sync-extension`
- `mirattic-flow-web`

Each client defines:
- exact redirect URIs
- allowed grant types
- allowed scopes
- public/confidential type

## Desktop
Prefer system-browser login.

## Extension
Use PKCE.
Do not store passwords.
Verify current browser policy before deciding refresh-token storage.

## SSO
SSO comes from the Auth browser session.
Product services do not share their own cookies.
