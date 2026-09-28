# CLAUDE.md — Mirattic Auth

## Project
Mirattic Auth is the central authentication and identity service for all Mirattic products.

Initial clients:
- Mirattic Sync
- Mirattic Flow

It owns:
- global Mirattic UID
- login identities
- email/password auth
- password reset
- OAuth 2.0 / OpenID Connect
- SSO
- sessions / refresh tokens
- future Google / Apple identity linking

## Communication
- Always communicate with the user in Korean.
- Use Korean for progress, questions, summaries, validation results, and phase reports.
- Use Codex **Sol** for validation/review.
- If Codex usage/quota is exhausted, Claude must run the required tests and review directly.
- Codex unavailability is never PASS.

## Source of Truth
Read these files when relevant:
- `docs/PLAN.md`
- `docs/architecture.md`
- `docs/oauth-oidc.md`
- `docs/data-model.md`
- `docs/api.md`
- `docs/security.md`
- `docs/migration.md`
- `docs/deployment.md`
- `docs/progress.md`

Do not duplicate architecture/protocol decisions in multiple files.

## Core Rules
- Use OAuth 2.0 + OpenID Connect.
- Use Authorization Code + PKCE for public clients.
- Client services must never read the Auth DB directly.
- Client services must never store user passwords.
- Mirattic Auth owns global UID and login identities.
- Product services own only product-specific data.
- Access tokens are short-lived.
- Refresh/session secrets are revocable and rotated.
- Prefer asymmetric JWT signing and JWKS.
- Validate `iss`, `aud`, `exp`, signature, and required claims.
- Never auto-merge accounts solely because email addresses match.
- Never log passwords, raw refresh tokens, reset tokens, or auth codes.

## Phase Workflow
At the end of every phase:
1. validate with Codex Sol,
2. if Codex quota is exhausted, Claude validates directly,
3. update `docs/progress.md`,
4. update architecture/API/security docs if behavior changed,
5. record known issues,
6. state the next exact task in Korean.

Before context compaction, persist important state to files.

## First Task
Before implementation:
1. read this file,
2. read `docs/PLAN.md`,
3. read `docs/progress.md`,
4. inspect existing Sync/Flow auth code,
5. compare current identity models against `docs/migration.md`,
6. propose Phase 0 details,
7. wait for approval before destructive migration or client cutover.
