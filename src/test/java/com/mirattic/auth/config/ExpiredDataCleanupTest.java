package com.mirattic.auth.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.mirattic.auth.IntegrationTest;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class ExpiredDataCleanupTest extends IntegrationTest {

	@Autowired ExpiredDataCleanup cleanup;

	String authorization(String refreshExpires, String accessExpires) {
		String id = UUID.randomUUID().toString();
		jdbc.update("INSERT INTO oauth2_authorization (id, registered_client_id, principal_name, "
				+ "authorization_grant_type, refresh_token_expires_at, access_token_expires_at) VALUES (?, 'x', 'p', "
				+ "'authorization_code', " + refreshExpires + ", " + accessExpires + ")", id);
		return id;
	}

	boolean exists(String table, String id) {
		return jdbc.queryForObject("SELECT COUNT(*) FROM " + table + " WHERE id = ?", Integer.class, id) > 0;
	}

	@Test
	void purgesOnlyFullyExpiredRows() {
		String dead = authorization("NOW() - INTERVAL 2 DAY", "NOW() - INTERVAL 3 DAY");
		String refreshAlive = authorization("NOW() + INTERVAL 20 DAY", "NOW() - INTERVAL 3 DAY");
		String justExpired = authorization("NOW() - INTERVAL 1 HOUR", "NULL");
		String noTokens = authorization("NULL", "NULL");
		jdbc.update("INSERT INTO rotated_refresh_tokens VALUES (?, ?, NOW(6))",
				"sha256:" + "0".repeat(57) + UUID.randomUUID().toString().substring(0, 7), dead);

		String user = UUID.randomUUID().toString();
		jdbc.update("INSERT INTO users VALUES (?, 'x', 'ACTIVE', NOW(6), NOW(6))", user);
		String oldReset = UUID.randomUUID().toString();
		String liveReset = UUID.randomUUID().toString();
		jdbc.update("INSERT INTO password_reset_tokens VALUES (?, ?, ?, NOW(6) - INTERVAL 2 DAY, NULL, NOW(6))",
				oldReset, user, "a".repeat(56) + oldReset.substring(0, 8));
		jdbc.update("INSERT INTO password_reset_tokens VALUES (?, ?, ?, NOW(6) + INTERVAL 10 MINUTE, NULL, NOW(6))",
				liveReset, user, "b".repeat(56) + liveReset.substring(0, 8));

		jdbc.update("INSERT INTO security_events (user_id, type, created_at) VALUES "
				+ "(?, 'SIGN_IN', NOW(6) - INTERVAL 91 DAY), (?, 'SIGN_IN', NOW(6) - INTERVAL 89 DAY)", user, user);

		cleanup.run();

		assertThat(jdbc.queryForList("SELECT created_at > NOW(6) - INTERVAL 90 DAY FROM security_events WHERE user_id = ?",
				Boolean.class, user)).as("90 days kept").containsExactly(true);

		assertThat(exists("oauth2_authorization", dead)).isFalse();
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM rotated_refresh_tokens WHERE authorization_id = ?",
				Integer.class, dead)).isZero();
		assertThat(exists("oauth2_authorization", refreshAlive)).isTrue();
		assertThat(exists("oauth2_authorization", justExpired)).as("1 day slack").isTrue();
		assertThat(exists("oauth2_authorization", noTokens)).isTrue();
		assertThat(exists("password_reset_tokens", oldReset)).isFalse();
		assertThat(exists("password_reset_tokens", liveReset)).isTrue();
	}
}
