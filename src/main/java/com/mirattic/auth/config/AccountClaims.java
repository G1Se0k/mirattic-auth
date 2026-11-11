package com.mirattic.auth.config;

import com.mirattic.auth.account.AccountService;
import com.mirattic.auth.account.Avatars;
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
	private final Avatars avatars;

	AccountClaims(JdbcOperations jdbc, Avatars avatars) {
		this.jdbc = jdbc;
		this.avatars = avatars;
	}

	/**
	 * `sub` always; `name` + `picture` (when a photo is set) with profile; `email` + `email_verified` (always false: no verification yet)
	 * with email. Throws `errorCode` unless the account is ACTIVE.
	 */
	Map<String, Object> forActive(String userId, Set<String> scopes, String errorCode) {
		List<Map<String, Object>> rows = jdbc.queryForList(
				"SELECT u.status, u.display_name, u.avatar_key, (" + AccountService.CONTACT_EMAIL + ") AS email FROM users u WHERE u.id = ?",
				userId);
		if (rows.isEmpty() || !"ACTIVE".equals(rows.getFirst().get("status"))) {
			throw new OAuth2AuthenticationException(errorCode);
		}
		Map<String, Object> row = rows.getFirst();
		Map<String, Object> claims = new LinkedHashMap<>();
		claims.put("sub", userId);
		if (scopes.contains("profile")) {
			claims.put("name", row.get("display_name"));
			String picture = avatars.url((String) row.get("avatar_key"));
			if (picture != null) {
				claims.put("picture", picture);
			}
		}
		if (scopes.contains("email") && row.get("email") != null) {
			claims.put("email", row.get("email"));
			claims.put("email_verified", false);
		}
		return claims;
	}
}
