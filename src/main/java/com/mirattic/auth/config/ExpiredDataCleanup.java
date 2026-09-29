package com.mirattic.auth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Hourly purge of rows nothing can use any more. A day of slack keeps just-expired rows around for
 * debugging. ponytail: runs on every instance; harmless (idempotent DELETEs) while there is one.
 */
@Component
class ExpiredDataCleanup {

	private static final Logger log = LoggerFactory.getLogger(ExpiredDataCleanup.class);
	// `timestamp` columns cannot hold 1970-01-01 00:00:00 in every zone; any old date works as "none".
	private static final String NONE = "'1970-01-02'";

	private final JdbcOperations jdbc;

	ExpiredDataCleanup(JdbcOperations jdbc) {
		this.jdbc = jdbc;
	}

	@Scheduled(cron = "0 17 * * * *")
	void run() {
		// An authorization dies when its last token expired. Rows with no token at all are left alone.
		// rotated_refresh_tokens rows go with it (ON DELETE CASCADE).
		int authorizations = jdbc.update("DELETE FROM oauth2_authorization WHERE "
				+ "COALESCE(authorization_code_expires_at, access_token_expires_at, refresh_token_expires_at, "
				+ "oidc_id_token_expires_at) IS NOT NULL AND GREATEST("
				+ "COALESCE(authorization_code_expires_at, " + NONE + "), COALESCE(access_token_expires_at, " + NONE
				+ "), COALESCE(refresh_token_expires_at, " + NONE + "), COALESCE(oidc_id_token_expires_at, " + NONE
				+ ")) < NOW(6) - INTERVAL 1 DAY");
		int resetTokens = jdbc.update("DELETE FROM password_reset_tokens WHERE expires_at < NOW(6) - INTERVAL 1 DAY");
		if (authorizations + resetTokens > 0) {
			log.info("Purged {} expired authorizations, {} expired reset tokens", authorizations, resetTokens);
		}
	}
}
