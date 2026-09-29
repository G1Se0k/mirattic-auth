package com.mirattic.auth.account;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

/**
 * Deleting a Mirattic account (docs/api.md "Account Deletion"). The products delete their data first, over a
 * back-channel: Flow (it may refuse, e.g. a workspace only this user owns), then Sync. Only when both are done is the
 * Auth account deleted. Product deletions are idempotent, so a failure part-way is retried as a whole.
 */
@Service
public class AccountDeletion {

	/** The JWT's `purpose`: products accept only this at their deletion endpoint, and never as an access token. */
	static final String PURPOSE = "account_deletion";

	/** `clientId` is the JWT audience; `name` is shown when it refuses. */
	record Product(String clientId, String name, String url) {
	}

	private static final Logger log = LoggerFactory.getLogger(AccountDeletion.class);

	private final List<Product> products;
	private final String issuer;
	private final JwtEncoder encoder;
	private final RestClient http;
	private final JdbcTemplate jdbc;
	private final TransactionTemplate tx;
	private final AccountService accounts;

	AccountDeletion(@Value("${spring.security.oauth2.authorizationserver.issuer}") String issuer,
			@Value("${auth.account-deletion.flow-url}") String flowUrl,
			@Value("${auth.account-deletion.sync-url}") String syncUrl, JWKSource<SecurityContext> keys,
			JdbcTemplate jdbc, TransactionTemplate tx, AccountService accounts) {
		this.products = List.of(new Product("mirattic-flow", "Mirattic Flow", flowUrl),
				new Product("mirattic-sync", "Mirattic Sync", syncUrl));
		this.issuer = issuer;
		this.encoder = new NimbusJwtEncoder(keys);
		SimpleClientHttpRequestFactory timeouts = new SimpleClientHttpRequestFactory();
		timeouts.setConnectTimeout(Duration.ofSeconds(5));
		timeouts.setReadTimeout(Duration.ofSeconds(20));
		this.http = RestClient.builder().requestFactory(timeouts).build();
		this.jdbc = jdbc;
		this.tx = tx;
		this.accounts = accounts;
	}

	/**
	 * Deletes the account everywhere, or throws AccountException saying why not (nothing of Auth deleted then). The
	 * caller ends the current browser session; every other one and every app login is ended here.
	 */
	public void delete(String userId, String currentSessionId) {
		for (Product p : products) {
			deleteIn(p, userId);
		}
		tx.executeWithoutResult(s -> {
			// The row stays (DELETED) so the UID is never reused; everything that signs in or identifies goes.
			jdbc.update("UPDATE users SET status = 'DELETED', display_name = '탈퇴한 사용자', updated_at = NOW(6) "
					+ "WHERE id = ?", userId);
			jdbc.update("DELETE FROM user_identities WHERE user_id = ?", userId);
			jdbc.update("DELETE FROM password_reset_tokens WHERE user_id = ?", userId);
			jdbc.update("DELETE FROM oauth2_authorization_consent WHERE principal_name = ?", userId);
		});
		accounts.endSessions(userId, currentSessionId);
	}

	private void deleteIn(Product p, String userId) {
		try {
			http.post().uri(p.url()).headers(h -> h.setBearerAuth(token(p.clientId(), userId))).retrieve().toBodilessEntity();
		} catch (RestClientResponseException e) {
			if (e.getStatusCode().isSameCodeAs(HttpStatus.CONFLICT)) {
				String reason = reason(e);
				throw new AccountException(p.name() + "에서 먼저 정리할 것이 있습니다"
						+ (reason == null ? "." : ": " + reason));
			}
			log.warn("{} account deletion failed: HTTP {}", p.clientId(), e.getStatusCode().value());
			throw unavailable(p);
		} catch (RestClientException e) {
			log.warn("{} account deletion failed: {}", p.clientId(), e.getClass().getSimpleName());
			throw unavailable(p);
		}
	}

	/** A one-minute, single-product, single-user order, signed with Auth's key (products verify it with the JWKS). */
	private String token(String audience, String userId) {
		Instant now = Instant.now();
		JwtClaimsSet claims = JwtClaimsSet.builder().issuer(issuer).audience(List.of(audience)).subject(userId)
				.issuedAt(now).expiresAt(now.plusSeconds(60)).id(UUID.randomUUID().toString())
				.claim("purpose", PURPOSE).build();
		return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims))
				.getTokenValue();
	}

	/** The product's own words, `{"message": "..."}`, bounded. */
	private static String reason(RestClientResponseException e) {
		try {
			Map<?, ?> body = e.getResponseBodyAs(Map.class);
			if (body != null && body.get("message") instanceof String m && !m.isBlank()) {
				return m.length() > 200 ? m.substring(0, 200) : m;
			}
		} catch (RuntimeException unreadable) {
			// no reason given
		}
		return null;
	}

	private static AccountException unavailable(Product p) {
		return new AccountException(p.name() + "에 연결하지 못해 탈퇴하지 못했습니다. 잠시 후 다시 시도해주세요.");
	}
}
