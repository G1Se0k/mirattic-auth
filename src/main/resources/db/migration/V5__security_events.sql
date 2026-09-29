-- What happened to an account, shown to its owner on the account page ("최근 보안 활동"). No IP, no tokens:
-- at most the browser kind ("Chrome · Mac") or a product / provider name. Kept 90 days (ExpiredDataCleanup),
-- deleted with the account.
CREATE TABLE security_events (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id     VARCHAR(36)  NOT NULL,
    type        VARCHAR(32)  NOT NULL,
    detail      VARCHAR(128) NULL,
    created_at  DATETIME(6)  NOT NULL,
    CONSTRAINT fk_security_events_user FOREIGN KEY (user_id) REFERENCES users (id),
    INDEX idx_security_events_user (user_id, created_at),
    INDEX idx_security_events_created (created_at)
);
