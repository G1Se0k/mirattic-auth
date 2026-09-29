# Account API Plan

OAuth/OIDC endpoints follow standards/Spring Authorization Server.
This file records Mirattic-specific account APIs.

## Account Pages (Phase 1, implemented)
Passwords are typed only on Auth's own pages, never into product clients, so signup / reset / profile
are server-rendered forms on `auth.mirattic.com` (form POST + CSRF token), not JSON APIs.

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET/POST | `/login` | – | Spring Security form login (`username` = email). Any failure → `/login?error` (one generic message). After login the saved `/oauth2/authorize` request resumes. |
| GET/POST | `/signup` | – | `email`, `displayName`, `password`. Creates user (UUID) + LOCAL identity, then → `/login?signup`. No auto-login. One per network per 24 h. |
| GET/POST | `/password/reset` | – | `email`. Same response whether or not the account exists. |
| GET/POST | `/password/reset/confirm` | reset token | `token`, `password`. One-time, 30 min. → `/login?reset`. |
| GET | `/account` | session | email, UID, display name. |
| POST | `/account/name` | session + CSRF | `displayName` |
| POST | `/account/password` | session + CSRF | `currentPassword`, `password`; ends the user's other Auth sessions |
| POST | `/logout` | session + CSRF | → `/login?logout` |

Validation:
- email: trimmed + lower-cased, `x@y.z` shape, ≤ 254
- display name: 1–64 chars after trim
- password: ≥ 8 chars and ≤ 72 UTF-8 bytes (BCrypt limit; longer is refused, not truncated)

Password change / reset deletes the user's `oauth2_authorization` rows (refresh tokens die).

A JSON `GET /api/account/me` was dropped for now: products get identity from ID token / UserInfo. Add it with the account center if needed.

## Sessions
- `GET /api/account/sessions`
- `DELETE /api/account/sessions/{id}`
- optional bulk revoke endpoint

## Identity Linking (later)
`POST /api/account/identities/{provider}/link`

Rules:
- user is already authenticated
- explicit linking only
- never auto-link solely because email matches

## Account Deletion
`DELETE /api/account`

Initial behavior:
- disable/delete Auth account
- revoke sessions
- notify/queue deletion event for product services
- each product applies its own data-deletion policy
