-- Which browser an app login (authorization) was started from, for the account page's device list: logins of the
-- same product from the same browser show as one device. device_id is SHA-256 of Auth's device cookie (DeviceCookie),
-- device_label the browser kind ("Chrome · Mac"). NULL for logins from before this column or without the cookie.
ALTER TABLE oauth2_authorization
    ADD COLUMN device_id CHAR(64) NULL,
    ADD COLUMN device_label VARCHAR(64) NULL;
