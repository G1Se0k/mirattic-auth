package com.mirattic.auth.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.function.BiFunction;
import java.util.function.UnaryOperator;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

/**
 * Stores only SHA-256 of every token value (codes, access, refresh, ID tokens); lookups hash the
 * presented value. A DB leak then yields no usable bearer secret (docs/security.md).
 *
 * Works because Spring Authorization Server never returns a token value it read back from storage,
 * with one exception: `reuse-refresh-tokens: true` echoes the stored refresh token. SecurityConfig
 * refuses to start with that setting.
 */
class HashedTokenAuthorizationService implements OAuth2AuthorizationService {

	static final String PREFIX = "sha256:";
	private static final OAuth2TokenType STATE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private final OAuth2AuthorizationService delegate;

	HashedTokenAuthorizationService(OAuth2AuthorizationService delegate) {
		this.delegate = delegate;
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		// Already-stored tokens come back hashed; re-saving them must not hash twice.
		delegate.save(mapValues(authorization, v -> v.startsWith(PREFIX) ? v : digest(v)));
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
			return mapValues(found, v -> v.equals(hashed) ? token : v);
		}
		return tokenType == null ? delegate.findByToken(token, STATE) : null;
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
