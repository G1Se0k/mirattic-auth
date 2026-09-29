# Migration Plan — Sync / Flow

## Goal
Move authentication ownership into Mirattic Auth without moving product-domain data.

## Sync
Sync already separates UID and login identity conceptually, which is favorable.

Preferred strategy:
- preserve existing user UUIDs as global Mirattic UID where practical
- import identities into Auth
- keep Sync product data keyed by the same UUID

## Migration Phases

### A. Build Auth beside existing login
- create Auth
- copy/import account identities
- preserve UUID
- verify password-hash compatibility
- keep legacy login temporarily

### B. Dual Acceptance
Sync temporarily accepts:
- legacy Sync token
- Mirattic Auth token

Both map to same UID.

### C. Client Cutover
- extension login → Auth (client `mirattic-sync`, see `clients.md`; desktop is not served)
- new accounts created only in Auth

### D. Remove Legacy Auth
Remove from Sync:
- signup
- login
- refresh
- password reset
- credential storage

Keep product profile/friend/room/chat data.

## Flow
If Flow has separate accounts:
- inspect UID model
- identify overlapping real users
- never auto-merge by email
- provide explicit linking/migration UX when necessary

## Password Hashes
If compatible, migrate hashes directly.
If not:
- temporary legacy verification or
- forced password reset

Never migrate plaintext passwords.

## Rollback
Before cutover:
- DB backup
- dry-run migration
- user/identity counts
- feature flag for legacy login where practical
- token rollback plan

## Final State
```text
Mirattic Auth
- users / identities / credentials / sessions

Mirattic Sync
- UID reference / friends / rooms / chat / presence

Mirattic Flow
- UID reference / workspaces / projects / issues
```
