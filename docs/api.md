# Account API Plan

OAuth/OIDC endpoints follow standards/Spring Authorization Server.
This file records Mirattic-specific account APIs.

## Signup
`POST /api/account/signup`

```json
{
  "email": "user@example.com",
  "password": "********",
  "displayName": "Giseok"
}
```

Creates account + LOCAL identity.

## Current Account
`GET /api/account/me`

Returns UID, display name, status, and linked identities.

## Password Reset
- `POST /api/account/password/reset/request`
- `POST /api/account/password/reset/confirm`

Reset request must not reveal whether an email exists.

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
