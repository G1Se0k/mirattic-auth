-- Profile photo: the R2 object key (avatars/{uid}/{random}.jpg), NULL = none.
ALTER TABLE users ADD COLUMN avatar_key VARCHAR(128) NULL;
