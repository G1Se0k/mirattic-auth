-- One LOCAL (email/password) signup per client network per 24 h. Only SHA-256 of the IP key
-- (IPv4 address or IPv6 /64) is stored; rows older than a day are purged hourly.
CREATE TABLE signup_ips (
    ip_hash         CHAR(64)    NOT NULL PRIMARY KEY,
    last_signup_at  DATETIME(6) NOT NULL
);
