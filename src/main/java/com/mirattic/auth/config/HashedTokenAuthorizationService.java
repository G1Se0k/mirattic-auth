package com.mirattic.auth.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.UnaryOperator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Stores only SHA-256 of every token value (codes, access, refresh, ID tokens); lookups hash the
 * presented value. A DB leak then yields no usable bearer secret (docs/security.md).
 *
 * Works because Spring Authorization Server never returns a token value it read back from storage,
 * with one exception: `reuse-refresh-tokens: true` echoes the stored refresh token. SecurityConfig
 * refuses to start with that setting.
 *
 * Refresh reuse detection: a rotated-away refresh token is remembered (hash only); presenting it
 * again means it leaked, so the whole authorization — every token of that login — is removed, but
 * only when the presenting client owns that authorization, and only after a short grace period:
 * a duplicate within REUSE_GRACE of the rotation (client retry, overlapping requests) is refused
 * with invalid_grant without killing the login, since it is indistinguishable from the legit winner.
 *
 * Rotation is compare-and-swap: findByToken remembers which refresh token the authorization held
 * when it was read; save locks the row and fails with invalid_grant if another request rotated it
 * in between. So of two concurrent refreshes (or code exchanges) exactly one wins, and a token
 * issued to the winner is never mistaken for a reused one.
 */
class HashedTokenAuthorizationService implements OAuth2AuthorizationService {

	static final String PREFIX = "sha256:";
	private static final OAuth2TokenType STATE = new OAuth2TokenType(OAuth2ParameterNames.STATE);
	private static final Logger log = LoggerFactory.getLogger(HashedTokenAuthorizationService.class);

	/** Stored refresh hash at read time ("" = none). Carried on the authorization, stripped before storing. */
	// ponytail: fixed 10 s; a thief replaying within 10 s of a rotation is only refused, not detected.
	static final int REUSE_GRACE_SECONDS = 10;
	private static final String READ_REFRESH = HashedTokenAuthorizationService.class.getName() + ".readRefresh";

	private final OAuth2AuthorizationService delegate;
	private final JdbcOperations jdbc;
	private final TransactionTemplate tx;
	/** Told (user, registered client id) after a reused refresh token revoked a login. */
	private final BiConsumer<String, String> onReuse;

	HashedTokenAuthorizationService(OAuth2AuthorizationService delegate, JdbcOperations jdbc, TransactionTemplate tx,
			BiConsumer<String, String> onReuse) {
		this.delegate = delegate;
		this.jdbc = jdbc;
		this.tx = tx;
		this.onReuse = onReuse;
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		String readRefresh = authorization.getAttribute(READ_REFRESH);
		// Already-stored tokens come back hashed; re-saving them must not hash twice.
		OAuth2Authorization hashed = mapValues(OAuth2Authorization.from(authorization)
				.attributes(a -> a.remove(READ_REFRESH)).build(), v -> v.startsWith(PREFIX) ? v : digest(v));
		String newRefresh = hashed.getRefreshToken() == null ? null
				: hashed.getRefreshToken().getToken().getTokenValue();
		tx.executeWithoutResult(status -> {
			List<String> rows = jdbc.queryForList("SELECT CAST(refresh_token_value AS CHAR) FROM oauth2_authorization "
					+ "WHERE id = ? FOR UPDATE", String.class, hashed.getId());
			String current = rows.isEmpty() ? null : rows.getFirst();
			if (newRefresh != null && !newRefresh.equals(current)) {
				if (readRefresh != null && !readRefresh.equals(current == null ? "" : current)) {
					throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT); // lost the race
				}
				if (current != null) {
					jdbc.update("INSERT IGNORE INTO rotated_refresh_tokens (token_hash, authorization_id, rotated_at) "
							+ "VALUES (?, ?, NOW(6))", current, hashed.getId());
				}
			}
			delegate.save(hashed);
		});
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		delegate.remove(authorization);
	}

	@Override
	public OAuth2Authorization findById(String id) {
		return delegate.findById(id);
	}

	/**
	 * The presented token gets its raw value back (callers such as revocation look the token up
	 * inside the authorization by value); every other token stays hashed. `state` is not a token
	 * and is stored as is, so STATE lookups (and the untyped fallback) use the raw value.
	 */
	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
		if (token == null) {
			return null;
		}
		if (STATE.equals(tokenType)) {
			return delegate.findByToken(token, STATE);
		}
		String hashed = digest(token);
		OAuth2Authorization found = delegate.findByToken(hashed, tokenType);
		if (found != null) {
			String readRefresh = found.getRefreshToken() == null ? "" : found.getRefreshToken().getToken().getTokenValue();
			return mapValues(OAuth2Authorization.from(found).attribute(READ_REFRESH, readRefresh).build(),
					v -> v.equals(hashed) ? token : v);
		}
		if (tokenType == null || OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
			revokeIfRotated(hashed);
		}
		return tokenType == null ? delegate.findByToken(token, STATE) : null;
	}

	private void revokeIfRotated(String hashed) {
		List<String> ids = jdbc.queryForList("SELECT authorization_id FROM rotated_refresh_tokens "
				+ "WHERE token_hash = ? AND rotated_at < NOW(6) - INTERVAL " + REUSE_GRACE_SECONDS + " SECOND",
				String.class, hashed);
		for (String id : ids) {
			OAuth2Authorization family = delegate.findById(id);
			if (family != null && presentedByOwner(family)) {
				log.warn("Rotated refresh token presented again; revoking authorization {} (user {}, client {})",
						id, family.getPrincipalName(), family.getRegisteredClientId());
				delegate.remove(family);
				onReuse.accept(family.getPrincipalName(), family.getRegisteredClientId());
			}
		}
	}

	/** The token endpoints authenticate the client first; only its own authorizations may be revoked. */
	private static boolean presentedByOwner(OAuth2Authorization authorization) {
		return SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2ClientAuthenticationToken client
				&& client.getRegisteredClient() != null
				&& client.getRegisteredClient().getId().equals(authorization.getRegisteredClientId());
	}

	private static OAuth2Authorization mapValues(OAuth2Authorization authorization, UnaryOperator<String> value) {
		OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);
		// Builder.token keeps the existing metadata (invalidated flag, claims) of the replaced token.
		map(authorization.getToken(OAuth2AuthorizationCode.class), builder, value,
				(t, v) -> new OAuth2AuthorizationCode(v, t.getIssuedAt(), t.getExpiresAt()));
		map(authorization.getToken(OAuth2AccessToken.class), builder, value,
				(t, v) -> new OAuth2AccessToken(t.getTokenType(), v, t.getIssuedAt(), t.getExpiresAt(), t.getScopes()));
		map(authorization.getToken(OAuth2RefreshToken.class), builder, value,
				(t, v) -> new OAuth2RefreshToken(v, t.getIssuedAt(), t.getExpiresAt()));
		map(authorization.getToken(OidcIdToken.class), builder, value,
				(t, v) -> new OidcIdToken(v, t.getIssuedAt(), t.getExpiresAt(), t.getClaims()));
		return builder.build();
	}

	private static <T extends OAuth2Token> void map(OAuth2Authorization.Token<T> token,
			OAuth2Authorization.Builder builder, UnaryOperator<String> value, BiFunction<T, String, T> copy) {
		if (token != null) {
			String current = token.getToken().getTokenValue();
			String mapped = value.apply(current);
			if (!mapped.equals(current)) {
				builder.token(copy.apply(token.getToken(), mapped));
			}
		}
	}

	static String digest(String value) {
		try {
			return PREFIX + HexFormat.of().formatHex(
					MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
