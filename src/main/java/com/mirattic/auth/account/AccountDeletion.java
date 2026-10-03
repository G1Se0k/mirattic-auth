package com.mirattic.auth.account;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.JdbcTemplate;
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
	private final ProductOrders orders;
	private final RestClient http;
	private final JdbcTemplate jdbc;
	private final TransactionTemplate tx;
	private final AccountService accounts;

	AccountDeletion(@Value("${auth.account-deletion.flow-url}") String flowUrl,
			@Value("${auth.account-deletion.sync-url}") String syncUrl, ProductOrders orders,
			JdbcTemplate jdbc, TransactionTemplate tx, AccountService accounts) {
		this.products = List.of(new Product("mirattic-flow", "Mirattic Flow", flowUrl),
				new Product("mirattic-sync", "Mirattic Sync", syncUrl));
		this.orders = orders;
		SimpleClientHttpRequestFactory timeouts = new SimpleClientHttpRequestFactory();
		timeouts.setConnectTimeout(Duration.ofSeconds(5));
		timeouts.setReadTimeout(Duration.ofSeconds(20));
		// SimpleClientHttpRequestFactory follows no redirect on POST: a 3xx comes back and fails the 204 check.
		this.http = RestClient.builder().requestFactory(timeouts).build();
		this.jdbc = jdbc;
		this.tx = tx;
		this.accounts = accounts;
	}

	/**
	 * Deletes the account everywhere, or throws AccountException saying why not (nothing of Auth deleted then). The
	 * caller ends the current browser session; every other one and every app login is ended here.
	 * <p>
	 * First the account is fenced (ACTIVE → DISABLED): while the products delete, nobody can sign in, exchange a code
	 * or refresh (tokens are minted for ACTIVE accounts only), or finish a link, and sessions of a non-ACTIVE account
	 * are signed out on their next request (ActiveAccountFilter). Only one deletion of an account runs at a time.
	 * A login or token already under way when the fence goes up is the products' part: Flow records the deletion time
	 * for the UID (also when it had no profile) and creates no profile for a login older than that (`withdrawals`).
	 * Sync: see docs/progress.md (Known Issues).
	 * Any failure before the final commit lifts the fence (back to ACTIVE; the ended app logins stay ended).
	 */
	public void delete(String userId, String currentSessionId) {
		if (jdbc.update("UPDATE users SET status = 'DISABLED', updated_at = NOW(6) WHERE id = ? AND status = 'ACTIVE'",
				userId) == 0) {
			throw new AccountException("이미 탈퇴를 처리하고 있습니다.");
		}
		try {
			accounts.endSessions(userId, currentSessionId); // app logins end now: no refresh during the deletion
			for (Product p : products) {
				deleteIn(p, userId);
			}
			deleteHere(userId);
		} catch (RuntimeException e) {
			jdbc.update("UPDATE users SET status = 'ACTIVE', updated_at = NOW(6) WHERE id = ? AND status = 'DISABLED'",
					userId);
			throw e instanceof AccountException ? e
					: new AccountException("탈퇴를 마치지 못했습니다. 잠시 후 다시 시도해주세요.");
		}
		// Deleted. Sessions that appeared meanwhile end too (and could do nothing: ActiveAccountFilter).
		try {
			accounts.endSessions(userId, currentSessionId);
		} catch (RuntimeException e) {
			log.warn("Sessions of a deleted account not all ended: {}", e.getClass().getSimpleName());
		}
	}

	/** The Auth part, one transaction. The row stays (DELETED) so the UID is never reused. */
	private void deleteHere(String userId) {
		tx.executeWithoutResult(s -> {
			// Everything that signs in or identifies goes.
			jdbc.update("UPDATE users SET status = 'DELETED', display_name = '탈퇴한 사용자', updated_at = NOW(6) "
					+ "WHERE id = ?", userId);
			jdbc.update("DELETE FROM user_identities WHERE user_id = ?", userId);
			jdbc.update("DELETE FROM password_reset_tokens WHERE user_id = ?", userId);
			jdbc.update("DELETE FROM oauth2_authorization_consent WHERE principal_name = ?", userId);
			jdbc.update("DELETE FROM security_events WHERE user_id = ?", userId);
		});
	}

	private void deleteIn(Product p, String userId) {
		try {
			HttpStatusCode status = http.post().uri(p.url())
					.headers(h -> h.setBearerAuth(orders.sign(p.clientId(), userId, PURPOSE)))
					.retrieve().toBodilessEntity().getStatusCode();
			// Only 204 confirms the deletion: a 200 / 202 / redirect (a gateway, a login page) does not.
			if (!status.isSameCodeAs(HttpStatus.NO_CONTENT)) {
				log.warn("{} account deletion answered HTTP {}, not 204", p.clientId(), status.value());
				throw unavailable(p);
			}
		} catch (AccountException e) {
			throw e;
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
