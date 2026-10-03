# Admin Console (2026-10-03)

`https://auth.mirattic.com/admin`, Auth's own pages (Thymeleaf, Auth browser session). One operator (user decision
2026-10-03): access is by Mirattic UID in `ADMIN_UIDS` (`auth.admin-uids`), checked in `SecurityConfig` for `/admin`
and `/admin/**`; anyone else signed in gets 403, signed out goes to the login page. No roles table.

## Pages
- `/admin` — dashboard (first page without a search): account counts by status; app users per product (distinct UIDs
  whose app login refreshed in the last 1 / 7 / 30 days, from `oauth2_authorization.refresh_token_issued_at`; an
  approximation: logins ended or expired over a day ago are purged); signups per day (14 days, Seoul time); each
  product's stats (below). Then the user list, newest first, 50 per page; search `q` matches a UID exactly, or a
  name / any identity's email (LIKE, wildcards escaped).
- `/admin/sync/reports`, `/admin/sync/feedback` — every Sync user report (reason, detail, the reported message as
  copied at report time, reporter and target with names) and every feedback / bug report from Sync's Settings (kind,
  text, sender), newest first, 50 per page. The dashboard's Sync card shows the latest 5 of each and links here; so
  does the header. In product tables, a UID in a column whose title contains "UID" links to
  `/admin/users/{uid}` (UUID-looking text elsewhere, e.g. in a message, stays text).
- `/admin/users/{uid}` — status, contact email, UID, sign-up, last app use; sign-in methods (provider, email, linked
  at); signed-in devices (`Devices.list`); the last 30 security events; each product's data for that UID.

Nothing secret is shown: no password hashes, tokens, session ids or IPs (the same data the user sees on their own
account page, plus status).

## Actions
POST with CSRF; a sign-in in the last 10 minutes, else `/login?reauth` (as the account page). Never on the admin's own
account (`?self`). Each is logged (`Admin {adminUid} suspended {uid}`) and recorded in the user's security log.
- **이용 정지** (`/suspend`): ACTIVE → `SUSPENDED` (V7), then every browser session and app login ends
  (`AccountService.endSessions`). Everything that checks for ACTIVE now refuses the account: password and social
  sign-in (social shows `/login?suspended` "이용이 정지된 계정입니다."), code exchange, refresh, UserInfo, browser
  sessions (`ActiveAccountFilter`). App access tokens already issued work until they expire (≤ 15 min). Only from
  ACTIVE: an account being deleted (DISABLED) or deleted is left alone (`?unchanged`).
- **정지 해제** (`/resume`): SUSPENDED → ACTIVE. The user signs in again.
- **모든 기기에서 로그아웃** (`/sign-out`): `endSessions` without a status change.

SUSPENDED is kept apart from DISABLED: DISABLED is the deletion fence, which a failed deletion lifts back to ACTIVE.
A suspended user can't delete their account (they can't sign in); deletion by the operator is not offered.

## Product reads (Sync, Flow)
`ProductAdmin`: `GET {url}/stats` and `GET {url}/users/{uid}` (Sync also `GET {url}/reports?page=N` and
`{url}/feedback?page=N`), `Authorization: Bearer <order>`, timeouts 3 s / 5 s.
The order is signed like the deletion order (`ProductOrders`, `api.md` "Account Deletion"): RS256 with Auth's key,
`aud` = the product's client id, `sub` = the admin's UID, `purpose` = `admin_read`, `exp` = 60 s, no `scope`.
Products accept only that purpose there (not an access token, not a deletion order; a deletion order is not accepted
with `admin_read` either), with the same one-minute lifetime and 5 s skew checks as Sync's deletion order.
URLs: `auth.admin.sync-url` / `flow-url` (env `SYNC_ADMIN_URL`, `FLOW_ADMIN_URL`), default
`https://{sync,flow}.mirattic.com/api/internal/admin`.

Answer (200): `{"facts": [["label", "value"], ...], "tables": [{"title", "columns": [...], "rows": [[...]]}]}`, paged
lists also `"more": true|false`. Auth
renders it as is (escaped). A product that fails or doesn't answer shows "응답을 받지 못했습니다." and the page still
renders. A UID the product doesn't know answers a "프로필 없음" fact, not 404.

What each product shows (read-only; never chat or issue contents, never what a Sync room is watching):
- Sync: profiles, 7-day sign-ups, accepted friendships, open rooms / members, chats in 24 h; the latest 5 reports
  and feedback; the full lists above (a report's copied message is what Sync keeps for operators, V9). Per user: Sync name, friend code, presence visibility,
  joined, friends, chats sent, reports made / received; rooms they are in (joined, role, member count), reports
  received, their feedback.
- Flow: users, 7-day sign-ups, workspaces, projects / issues, chats in 24 h; the latest 20 workspaces (name, members,
  projects). Per user: Flow name, email, joined, open assigned issues, chats sent; their workspaces (name, role,
  members).

## Not done (add when needed)
- Editing product data from the console (user decision: read first).
- Several operators / roles, an audit table (today: app log + the user's security log).
- MFA for the admin beyond the social provider's own.
