# Architecture

## Recommended Stack
- Java 21
- Spring Boot
- Spring Security
- Spring Authorization Server
- Spring Data JPA
- MySQL
- Flyway
- Maven

## Components
```text
Caddy / Reverse Proxy
  ├─ auth.mirattic.com → Mirattic Auth
  ├─ sync.mirattic.com → Mirattic Sync
  └─ flow.mirattic.com → Mirattic Flow
```

## Auth owns
- global UID
- identities / credentials
- password reset
- OAuth/OIDC clients
- authorizations / refresh sessions
- signing keys / JWKS
- account state

## Product services own
- service-specific profile fields
- friends / rooms / chat
- projects / workspaces / issues
- service roles and permissions
- service settings

## Trust Boundary
Resource servers trust only tokens issued by:
`https://auth.mirattic.com`

They validate:
- signature
- issuer
- audience
- expiry
- required scopes/claims

Never trust a client-supplied user ID.

## Local User Mapping
A product may keep:
```text
service_users
- user_id UUID   # OIDC sub
- created_at
- product fields...
```

Do not duplicate credentials.

## Availability
Auth is required for:
- new login
- refresh
- account management

Auth should not be required for every API request.
Already-issued access tokens remain valid until expiry during temporary Auth outage.

## Scale
MVP:
- 1 Auth instance
- 1 MySQL
- Caddy

Later only if needed:
- multiple Auth instances
- shared DB
- Redis for justified ephemeral/shared state
- load balancer
