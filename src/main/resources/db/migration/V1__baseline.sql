-- Mirattic Auth baseline.
-- users.id is the global Mirattic UID and the OIDC `sub`. VARCHAR(36) matches Sync's users.id so
-- existing Sync UUIDs can be imported unchanged (docs/migration.md).
CREATE TABLE users (
    id            VARCHAR(36)  NOT NULL PRIMARY KEY,
    display_name  VARCHAR(64)  NOT NULL,
    status        VARCHAR(16)  NOT NULL,
    created_at    DATETIME(6)  NOT NULL,
    updated_at    DATETIME(6)  NOT NULL,
    CONSTRAINT ck_users_status CHECK (status IN ('ACTIVE', 'DISABLED', 'DELETED'))
);

-- Ways to sign in. Same email on two identities never means the same user (explicit linking only).
CREATE TABLE user_identities (
    id             VARCHAR(36)  NOT NULL PRIMARY KEY,
    user_id        VARCHAR(36)  NOT NULL,
    -- LOCAL | GOOGLE | APPLE (KAKAO / NAVER pending the Flow migration decision)
    provider       VARCHAR(16)  NOT NULL,
    -- LOCAL: normalized email. External: provider's stable subject id (never the email).
    subject        VARCHAR(255) NOT NULL,
    email          VARCHAR(254) NULL,
    -- LOCAL only. DelegatingPasswordEncoder format, e.g. {bcrypt}$2a$...
    password_hash  VARCHAR(255) NULL,
    created_at     DATETIME(6)  NOT NULL,
    updated_at     DATETIME(6)  NOT NULL,
    CONSTRAINT uk_user_identities_provider_subject UNIQUE (provider, subject),
    CONSTRAINT fk_user_identities_user FOREIGN KEY (user_id) REFERENCES users (id),
    INDEX idx_user_identities_user (user_id),
    INDEX idx_user_identities_email (email)
);

-- One-time, expiring. Only the SHA-256 of the token is stored.
CREATE TABLE password_reset_tokens (
    id           VARCHAR(36)  NOT NULL PRIMARY KEY,
    user_id      VARCHAR(36)  NOT NULL,
    token_hash   CHAR(64)     NOT NULL,
    expires_at   DATETIME(6)  NOT NULL,
    used_at      DATETIME(6)  NULL,
    created_at   DATETIME(6)  NOT NULL,
    CONSTRAINT uk_password_reset_tokens_hash UNIQUE (token_hash),
    CONSTRAINT fk_password_reset_tokens_user FOREIGN KEY (user_id) REFERENCES users (id),
    INDEX idx_password_reset_tokens_user (user_id)
);

-- Spring Authorization Server 7.1.1 bundled schema, verbatim (JdbcOAuth2AuthorizationService).
-- ponytail: `timestamp` columns hit MySQL's 2038 limit; switch to DATETIME(6) before then.
CREATE TABLE oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000) DEFAULT NULL,
    attributes blob DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value blob DEFAULT NULL,
    authorization_code_issued_at timestamp DEFAULT NULL,
    authorization_code_expires_at timestamp DEFAULT NULL,
    authorization_code_metadata blob DEFAULT NULL,
    access_token_value blob DEFAULT NULL,
    access_token_issued_at timestamp DEFAULT NULL,
    access_token_expires_at timestamp DEFAULT NULL,
    access_token_metadata blob DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value blob DEFAULT NULL,
    oidc_id_token_issued_at timestamp DEFAULT NULL,
    oidc_id_token_expires_at timestamp DEFAULT NULL,
    oidc_id_token_metadata blob DEFAULT NULL,
    refresh_token_value blob DEFAULT NULL,
    refresh_token_issued_at timestamp DEFAULT NULL,
    refresh_token_expires_at timestamp DEFAULT NULL,
    refresh_token_metadata blob DEFAULT NULL,
    user_code_value blob DEFAULT NULL,
    user_code_issued_at timestamp DEFAULT NULL,
    user_code_expires_at timestamp DEFAULT NULL,
    user_code_metadata blob DEFAULT NULL,
    device_code_value blob DEFAULT NULL,
    device_code_issued_at timestamp DEFAULT NULL,
    device_code_expires_at timestamp DEFAULT NULL,
    device_code_metadata blob DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);
