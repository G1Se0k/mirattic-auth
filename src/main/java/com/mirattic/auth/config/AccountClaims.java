package com.mirattic.auth.config;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Component;

/** OIDC claims of an account, by granted scope. Shared by ID tokens and UserInfo. */
@Component
class AccountClaims {

	private final JdbcOperations jdbc;

	AccountClaims(JdbcOperations jdbc) {
		this.jdbc = jdbc;
	}

	/**
	 * `sub` always; `name` with profile; `email` + `email_verified` (always false: no verification yet)
	 * with email. Throws `errorCode` unless the account is ACTIVE.
	 */
	Map<String, Object> forActive(String userId, Set<String> scopes, String errorCode) {
		List<Map<String, Object>> rows = jdbc.queryForList("""
				SELECT u.status, u.display_name, i.email FROM users u
				LEFT JOIN user_identities i ON i.user_id = u.id AND i.provider = 'LOCAL'
				WHERE u.id = ?
				""", userId);
		if (rows.isEmpty() || !"ACTIVE".equals(rows.getFirst().get("status"))) {
			throw new OAuth2AuthenticationException(errorCode);
		}
		Map<String, Object> row = rows.getFirst();
		Map<String, Object> claims = new LinkedHashMap<>();
		claims.put("sub", userId);
		if (scopes.contains("profile")) {
			claims.put("name", row.get("display_name"));
		}
		if (scopes.contains("email") && row.get("email") != null) {
			claims.put("email", row.get("email"));
			claims.put("email_verified", false);
		}
		return claims;
	}
}
