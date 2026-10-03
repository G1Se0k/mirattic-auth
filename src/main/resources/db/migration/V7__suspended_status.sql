-- SUSPENDED: the admin stopped the account (admin console). Like DISABLED it can't sign in or get tokens (everything
-- checks for ACTIVE), but it is kept apart from DISABLED, the deletion fence that a failed deletion lifts.
ALTER TABLE users DROP CHECK ck_users_status;
ALTER TABLE users ADD CONSTRAINT ck_users_status CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DISABLED', 'DELETED'));
