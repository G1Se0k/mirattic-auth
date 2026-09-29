-- Refresh tokens that were rotated away. Presenting one again means the token leaked:
-- the whole authorization (every token of that login) is removed. Rows die with their authorization.
CREATE TABLE rotated_refresh_tokens (
    token_hash        CHAR(71)     NOT NULL PRIMARY KEY, -- 'sha256:' + 64 hex, same as oauth2_authorization
    authorization_id  VARCHAR(100) NOT NULL,
    rotated_at        DATETIME(6)  NOT NULL,
    CONSTRAINT fk_rotated_refresh_tokens_authorization FOREIGN KEY (authorization_id)
        REFERENCES oauth2_authorization (id) ON DELETE CASCADE
);
